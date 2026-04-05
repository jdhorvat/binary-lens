using System.IO;
using System.Text;
using BinaryLens.Models;

namespace BinaryLens.Analysis;

// ═══════════════════════════════════════════════════════════════════════════
//  VlxAnalyzer  --  Visual LISP VLX / FAS Analyzer and Decompiler
//
//  SUPPORTED FORMATS
//    FAS4-FILE  Current VLISP compiler output (AutoCAD 2000+)
//    FAS3-FILE  Older format
//    FAS2-FILE  Older format
//    FAS-FILE   Oldest format
//    VLX        Container of FAS modules + embedded DCL / TXT resources
//
//  PIPELINE
//    1. Detect format from magic bytes and text signatures
//    2. Parse text header (version, compile mode, encryption flag)
//    3. Find binary section and attempt XOR key extraction + decryption
//    4. Extract embedded files from VLX container (FAS, DCL, TXT)
//    5. Parse decrypted symbol / string table
//    6. Disassemble bytecode function stream with known opcodes
//    7. Classify extracted symbols into commands / functions / globals
//
//  ENCRYPTION
//    FAS files compiled with encryption (;fas4 crunch in header) use XOR
//    with a key embedded at the start of the binary section.
//    Key layout: [StreamBeginByte][KeyLength byte][Key bytes...][StreamEndByte]
//    The key length can be 0..127.  If key length = 0, no encryption.
//    StreamBeginByte and StreamEndByte are the same character (a marker).
//    After decryption the resource stream starts.
//
//  KNOWN OPCODES (80+ entries — see Opcodes dictionary below)
//    Derived from cross-referencing two independent projects:
//      Fas-Disasm (VB6) — InterpretStream_rek() with ~90 opcodes
//      FAS-Decompiler (C#) — FAS.cs Decompile() with ~24 opcodes
//    Key opcode families:
//      0x01–0x02     Constants (nil, T)
//      0x03–0x0C     Variable access (get/set global/local)
//      0x0D–0x0F     16-bit branch/jump
//      0x11–0x13     Stream terminators (STOP)
//      0x14–0x17     DEFUN / function definition
//      0x28–0x2A     List ops (CAR, CDR, CONS)
//      0x34–0x35     User subroutine load/call
//      0x43          Init variable table
//      0x55          Load inline string
//      0x56,0x5B     Load inline symbol
//      0x57,0x67–0x6A  32-bit branch/jump/control
//      0x5C–0x5E     16-bit local variable access
//
//  REFERENCE
//    Fas-Disasm (Hopfengetraenk/Fas-Disasm) — VB6 disassembler
//    FAS-Decompiler (datahackor/FAS-Decompiler) — C# WPF decompiler
// ═══════════════════════════════════════════════════════════════════════════

public static class VlxAnalyzer
{
    // ── Text-based FAS format signatures ─────────────────────────────────────

    private static readonly (string sig, string label)[] TextSignatures =
    [
        ("\r\n FAS4-FILE ; Do not change it!", "FAS4-FILE (Visual LISP current)"),
        ("\r\n FAS3-FILE ; Do not change it!", "FAS3-FILE (Visual LISP legacy)"),
        ("\r\n FAS2-FILE ; Do not change it!", "FAS2-FILE (Visual LISP legacy)"),
        ("\r\n FAS-FILE ; Do not change it!",  "FAS-FILE (AutoLISP classic)"),
        ("AutoCAD LT OEM Product",             "FAS (AutoCAD LT variant)"),
    ];

    // ── Binary magic signatures ───────────────────────────────────────────────

    private static readonly (string label, byte[] magic)[] BinaryMagics =
    [
        ("Visual LISP VLX",    new byte[] { 0xFD, 0x7E }),
        ("Visual LISP VLX v2", new byte[] { 0xFD, 0x7F }),
        ("Visual LISP VLX VRTLIB", new byte[] { 0x56, 0x52, 0x54, 0x4C }),  // "VRTL" — VRTLIB-1 header
        ("AutoLISP FAS",       new byte[] { 0x0C, 0x0E }),
        ("AutoLISP FAS v2",    new byte[] { 0x0C, 0x0F }),
        ("AutoLISP FAS v3",    new byte[] { 0x0C, 0x10 }),
        ("AutoLISP FAS v4",    new byte[] { 0x0C, 0x12 }),
        ("VLISP FAS",          new byte[] { 0x14, 0x0E }),
        ("VLISP FAS v2",       new byte[] { 0x14, 0x0F }),
        ("FSL (internal)",     new byte[] { 0x31, 0x59 }),   // "1Y"
    ];

    // ── Opcode table ────────────────────────────────────────────────────────
    // Derived from Fas-Disasm (VB6) and FAS-Decompiler (.NET) reference projects.
    // The FAS VM is a stack-based interpreter.  Two opcode "families" exist:
    //   • Classic FSL/FAS2/FAS3  (opcodes 0x01–0x6F, 8/16-bit operands)
    //   • FAS4  (same opcodes, occasionally extended operand widths)
    //
    // Operand encoding per opcode is handled in DisassembleFas().

    private static readonly Dictionary<byte, string> Opcodes = new()
    {
        // ── Constants & stack ────────────────────────────────────────────
        { 0x01, "PUSH nil"       },  // push NIL
        { 0x02, "PUSH T"         },  // push T (true)
        { 0x03, "VALUE"          },  // push global var by index (2-byte)
        { 0x04, "PUSH stream"    },  // push stream ref (2× 1-byte)
        { 0x05, "GET lvar8"      },  // push local var by 8-bit index
        { 0x06, "SETQ"           },  // pop → global var (2-byte index)
        { 0x07, "COPY elem"      },  // copy list element (2× 1-byte)
        { 0x08, "SET lvar8"      },  // pop → local var (8-bit index, FSL)
        { 0x09, "PUSH gvar"      },  // push global var by index (2-byte)
        { 0x0A, "POP"            },  // pop & discard
        { 0x0B, "DUP"            },  // duplicate top of stack
        { 0x0C, "PUSH gvar16"    },  // push global var (2-byte, alt)

        // ── Branching ────────────────────────────────────────────────────
        { 0x0D, "BRZ 16"         },  // branch if false (2-byte offset)
        { 0x0E, "BRNZ 16"        },  // branch if true  (2-byte offset)
        { 0x0F, "JMP 16"         },  // unconditional jump (2-byte offset)
        { 0x10, "LIST step"      },  // list iteration step (2× 1-byte)

        // ── Stream terminators ───────────────────────────────────────────
        { 0x11, "STOP"           },
        { 0x12, "STOP"           },
        { 0x13, "STOP"           },

        // ── Function definition ──────────────────────────────────────────
        { 0x14, "DEFUN"          },  // define function (4× 1-byte params)
        { 0x15, "DEFUN-Q"        },  // define quoted fn (4× 1-byte params)
        { 0x16, "END defun"      },  // end of function body
        { 0x17, "DEFUN FAS2"     },  // FAS2 defun (2-byte name index)
        { 0x18, "COPY stk→lvar" },  // copy stack to local vars
        { 0x19, "CLEAR args"     },  // clear args & locals (foreach marker)
        { 0x1A, "SETQ FSL func"  },  // FSL function assignment (2-byte)
        { 0x1B, "SETQ FSL var"   },  // FSL variable assignment (2-byte)
        { 0x1C, "COPY stk→fn"   },  // copy stack to function frame
        { 0x1D, "STOP"           },

        // ── NOP / padding ────────────────────────────────────────────────
        { 0x1E, "OP 1E"          },  // 1-byte param (unknown)
        { 0x1F, "OP 1F"          },  // 1-byte param (unknown)
        { 0x20, "NOP"            },  // space character = NOP
        { 0x21, "OP 21"          },

        // ── More terminators ─────────────────────────────────────────────
        { 0x22, "STOP"           },
        { 0x23, "NULL/NOT"       },  // null and not (same in LISP)
        { 0x24, "ATOM"           },  // atom predicate
        { 0x25, "OP 25"          },  // 1-byte param + local var ref
        { 0x26, "OP 26"          },
        { 0x27, "STOP"           },

        // ── List operations ──────────────────────────────────────────────
        { 0x28, "CAR"            },  // first element of list
        { 0x29, "CDR"            },  // rest of list
        { 0x2A, "CONS"           },  // insert element at beginning
        { 0x2B, "STOP"           },
        { 0x2C, "LENGTH"          },  // list length
        { 0x2D, "NTH"             },  // nth element from list
        { 0x2E, "STACKCALL"       },  // call from stack (1-byte paramCount)
        { 0x2F, "CALLANDJMP"      },  // call by mvar index (1-byte + 2-byte)

        // ── More terminators ─────────────────────────────────────────────
        { 0x30, "STOP"           },
        { 0x31, "STOP"           },

        // ── Constants ────────────────────────────────────────────────────
        { 0x32, "LD_INT8"        },  // push signed 8-bit integer from stream
        { 0x33, "LD_INT32"       },  // push signed 32-bit integer from stream

        // ── Function loading ─────────────────────────────────────────────
        { 0x34, "EVAL"            },  // evaluate expression (1-byte paramCount + 1-byte flags)
        { 0x35, "ld_USUBR"       },  // call user subroutine (1+2+1 bytes)
        { 0x36, "STOP"           },

        // ── List / numeric ───────────────────────────────────────────────
        { 0x37, "LD LIST B"      },  // combine N stack items into list (2-byte count)
        { 0x38, "CONVERT"        },  // convert top of stack (type coercion)

        // ── Array / symbol table ─────────────────────────────────────────
        { 0x39, "LD LIST"        },  // combine N stack items into quoted list
        { 0x3A, "DEF USUBR"      },  // define user subroutine (pop name, offset, module)
        { 0x3B, "LD REAL"        },  // load floating-point (null-terminated string)

        // ── Branch (16-bit, alt forms) ───────────────────────────────────
        { 0x3C, "BRZ 16 alt"     },  // branch if false (FAS3 variant)
        { 0x3D, "BRNZ 16 alt"    },  // branch if true  (FAS3 variant)
        { 0x3E, "POP EXIT NZ"    },  // pop and exit if not zero
        { 0x3F, "POP EXIT Z"     },  // pop and exit if zero

        // ── Misc ─────────────────────────────────────────────────────────
        { 0x40, "MEM op"         },  // memory operation (2-byte + 4-byte)
        { 0x41, "STOP"           },
        { 0x42, "STOP"           },
        { 0x43, "INIT vars"      },  // init variable table (2-byte count)
        { 0x44, "STOP"           },

        // ── RAM functions ────────────────────────────────────────────────
        { 0x45, "RAM CALL"       },  // call memory-resident func (1-byte + 4-byte)
        { 0x46, "+"              },  // addition
        { 0x47, "-"              },  // subtraction
        { 0x48, "*"              },  // multiplication
        { 0x49, "/"              },  // division
        { 0x4A, "="              },  // numeric equality
        { 0x4B, "<="             },  // comparison: less-or-equal
        { 0x4C, "<"              },  // comparison: less-than
        { 0x4D, ">"              },  // comparison: greater-than
        { 0x4E, "/="             },  // comparison: not-equal
        { 0x4F, ">="            },  // comparison: greater-or-equal
        { 0x50, "MINUSP"         },  // test if negative (unary)
        { 0x51, "FUNC"           },  // call function with extra byte (1+2+1+1 bytes)
        { 0x52, "STOP"           },
        { 0x53, "HANDLER 53"     },  // closure/exception handler (pop 2)
        { 0x54, "HANDLER 54"     },  // exception handler (pop 2)

        // ── Strings & symbols ────────────────────────────────────────────
        { 0x55, "LD STR"         },  // load string from string table
        { 0x56, "LD SYM"         },  // create symbol (FSL variant)

        // ── Far jump ─────────────────────────────────────────────────────
        { 0x57, "JMP 32"         },  // unconditional far jump (4-byte)

        { 0x58, "STOP"           },
        { 0x59, "ERR HANDLER"    },  // setup error handler (pop 9 items)
        { 0x5A, "RAM VL.ARX"     },  // call VL.ARX function (1-byte + 4-byte)
        { 0x5B, "LD SYM FAS"     },  // create symbol (FAS variant)

        // ── Local vars (FAS format, 16-bit index) ────────────────────────
        { 0x5C, "GET lvar16"     },  // push local var (16-bit index)
        { 0x5D, "SET lvar16"     },  // pop → local var (16-bit index)
        { 0x5E, "CLR lvar16"     },  // clear local var (16-bit index)
        { 0x5F, "CALL BY OFFS"   },  // call by function offset (1-byte + 4-byte)
        { 0x60, "JMP NOPOP"      },  // jump to function without stack pop (1-byte + 4-byte)
        { 0x61, "CONTINUE"       },  // continue at function offset (1-byte + 4-byte)

        // ── NOP ──────────────────────────────────────────────────────────
        { 0x62, "NOP"            },
        { 0x63, "NOP"            },

        // ── Local var (FSL, 8-bit, clear) ────────────────────────────────
        { 0x64, "CLR lvar8"      },  // clear local var (8-bit, FSL)
        { 0x65, "OP 65"          },
        { 0x66, "OP 66"          },

        // ── Control flow (32-bit offsets) ────────────────────────────────
        { 0x67, "IF 32"          },  // branch if true (4-byte offset)
        { 0x68, "OR"             },  // or short-circuit branch
        { 0x69, "BRANCH 32"      },  // general 32-bit branch
        { 0x6A, "AND/OR"         },  // AND short-circuit branch
    };

    // ── Symbol char set ───────────────────────────────────────────────────────

    private static bool IsLispSymbolChar(char c)
        => c > ' ' && c < 127
        && c != '(' && c != ')' && c != '[' && c != ']'
        && c != '{' && c != '}' && c != '"' && c != ';'
        && c != ',' && c != '`' && c != '\\';

    // ═════════════════════════════════════════════════════════════════════════
    //  PUBLIC ENTRY POINT
    // ═════════════════════════════════════════════════════════════════════════

    public static void Analyze(string filePath, AnalysisResult result,
                                IProgress<string>? progress = null)
    {
        var info = new VlxInfo
        {
            FilePath  = filePath,
            Extension = Path.GetExtension(filePath).ToUpperInvariant(),
        };
        result.VlxInfo = info;
        result.IsVlx   = true;
        result.IsValidPe = false;

        byte[] data;
        try { data = File.ReadAllBytes(filePath); }
        catch (Exception ex)
        {
            info.Error = $"Cannot read file: {ex.Message}";
            result.Errors.Add(info.Error);
            return;
        }

        info.FileSize = data.Length;
        info.HeaderHex = HexDump(data, 0, Math.Min(64, data.Length));

        progress?.Report("Detecting format...");
        DetectFormat(data, info);

        // Route to the appropriate parser
        if (info.IsTextFas)
        {
            progress?.Report("Parsing FAS text header...");
            ParseTextFasHeader(data, info);

            progress?.Report("Attempting decryption...");
            // Try the new two-stream parser first; fall back to old method if it fails
            if (!ParseFasStreams(data, info))
            {
                TryDecryptFas(data, info);
            }

            progress?.Report("Disassembling bytecode...");
            DisassembleFas(info);
        }
        else if (info.IsVlxContainer || info.Extension == ".VLX")
        {
            progress?.Report("Extracting VLX container...");
            ExtractVlxContainer(data, info);

            // Disassemble each FAS module separately
            if (info.Modules.Count > 0)
            {
                progress?.Report($"Disassembling {info.Modules.Count} FAS module(s)...");

                var allDisasm = new StringBuilder();
                var allLisp   = new StringBuilder();

                foreach (var mod in info.Modules)
                {
                    if (mod.Offset < 0 || mod.Offset + mod.Size > data.Length || mod.Size <= 0)
                        continue;

                    progress?.Report($"Disassembling module '{mod.Name}'...");

                    // Each FAS module within the VLX has its own text header and
                    // potentially encrypted bytecode.  Run it through the full
                    // FAS parsing pipeline (detect → parse header → decrypt)
                    // before handing the decrypted bytecode to the disassembler.
                    byte[] modData = data[mod.Offset..(mod.Offset + mod.Size)];

                    var modInfo = new VlxInfo
                    {
                        FasVersion    = info.FasVersion,
                        DecryptStatus = $"Module '{mod.Name}' ({mod.Size:N0} bytes)",
                        RawStrings    = info.RawStrings,  // share any pre-extracted strings
                    };

                    // Check if this module has a FAS text header
                    DetectFormat(modData, modInfo);

                    if (modInfo.IsTextFas)
                    {
                        // Full pipeline: parse header → decrypt → disassemble
                        ParseTextFasHeader(modData, modInfo);
                        // Try new two-stream parser first; fall back if it fails
                        if (!ParseFasStreams(modData, modInfo))
                        {
                            TryDecryptFas(modData, modInfo);
                        }
                    }
                    else
                    {
                        // No text header — treat as raw bytecode
                        modInfo.DecryptedData = modData;
                        modInfo.DecryptStatus += " (raw bytecode, no FAS header)";
                    }

                    DisassembleFas(modInfo);

                    // Store per-module results
                    mod.Disassembly    = modInfo.Disassembly;
                    mod.DecompiledLisp = modInfo.DecompiledLisp;
                    mod.Functions      = modInfo.FasFunctions;

                    // Also aggregate into the main info for backward compat
                    if (!string.IsNullOrEmpty(modInfo.Disassembly))
                    {
                        allDisasm.AppendLine($"; ══════════════════════════════════════════════════════════════");
                        allDisasm.AppendLine($"; MODULE: {mod.Name} ({mod.Size:N0} bytes @ 0x{mod.Offset:X6})");
                        allDisasm.AppendLine($"; ══════════════════════════════════════════════════════════════");
                        allDisasm.AppendLine(modInfo.Disassembly);
                        allDisasm.AppendLine();
                    }
                    if (!string.IsNullOrEmpty(modInfo.DecompiledLisp))
                    {
                        allLisp.AppendLine($";;; ══════════════════════════════════════════════════════════════");
                        allLisp.AppendLine($";;; MODULE: {mod.Name} ({mod.Size:N0} bytes)");
                        allLisp.AppendLine($";;; ══════════════════════════════════════════════════════════════");
                        allLisp.AppendLine(modInfo.DecompiledLisp);
                        allLisp.AppendLine();
                    }

                    info.FasFunctions.AddRange(modInfo.FasFunctions);
                }

                info.Disassembly    = allDisasm.Length > 0 ? allDisasm.ToString() : null;
                info.DecompiledLisp = allLisp.Length > 0 ? allLisp.ToString() : null;
                info.DecryptStatus  = $"Disassembled {info.Modules.Count} module(s)";
            }
            else
            {
                // No FAS modules found — try treating the whole file as raw bytecode
                progress?.Report("No FAS modules found — attempting raw disassembly...");
                info.DecryptedData = data;
                info.DecryptStatus = "Raw bytecode (no FAS modules extracted)";
                DisassembleFas(info);
            }
        }
        else
        {
            progress?.Report("Binary FAS — attempting raw disassembly...");
            // Unrecognized format — try disassembling raw data
            info.DecryptedData = data;
            info.DecryptStatus = "Raw bytecode (unrecognized format)";
            DisassembleFas(info);
        }

        progress?.Report("Extracting symbols and strings...");
        ExtractAllStrings(data, info);
        ClassifySymbols(info);

        result.FileTypeSummary = $"{info.FormatName} · {info.FileSize:N0} bytes"
            + (info.ModuleCount > 0 ? $" · {info.ModuleCount} module(s)" : "");
        result.Architecture = "N/A (LISP bytecode)";

        // Push VLX strings into the main Strings list so the tree/tab counts are correct
        foreach (var s in info.RawStrings)
        {
            result.Strings.Add(new ExtractedString
            {
                Offset   = s.Offset,
                Value    = s.Value,
                Encoding = "ASCII",
                Section  = "FAS",
            });
        }

        // Push VLX embedded files (DCL, TXT, LSP, DVB, PRV) into the main Resources list
        foreach (var ef in info.EmbeddedFiles)
        {
            result.Resources.Add(new ResourceInfo
            {
                Type = ef.FileType,
                Name = ef.FileType,
                Size = ef.Size,
            });
        }

        // Also push FAS modules as resources
        foreach (var m in info.Modules)
        {
            result.Resources.Add(new ResourceInfo
            {
                Type = "FAS Module",
                Name = m.Name,
                Size = m.Size,
            });
        }

        progress?.Report($"Done — {info.Commands.Count} commands, " +
                         $"{info.Functions.Count} functions, " +
                         $"{info.StringLiterals.Count} strings.");
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  FORMAT DETECTION
    // ═════════════════════════════════════════════════════════════════════════

    private static void DetectFormat(byte[] data, VlxInfo info)
    {
        if (data.Length < 2) { info.FormatName = "Unknown (file too short)"; return; }

        info.MagicBytes = $"{data[0]:X2} {data[1]:X2}"
                        + (data.Length > 2 ? $" {data[2]:X2}" : "")
                        + (data.Length > 3 ? $" {data[3]:X2}" : "");

        // 1. Check text-based FAS signatures (FAS4-FILE etc.)
        string asText = "";
        try { asText = Encoding.ASCII.GetString(data, 0, Math.Min(64, data.Length)); }
        catch { }

        foreach (var (sig, label) in TextSignatures)
        {
            if (asText.Contains(sig, StringComparison.OrdinalIgnoreCase))
            {
                info.FormatName = label;
                info.IsTextFas  = true;

                // Extract FAS version number: FAS4→4, FAS3→3, FAS2→2, FAS→1
                if      (sig.Contains("FAS4")) info.FasVersion = 4;
                else if (sig.Contains("FAS3")) info.FasVersion = 3;
                else if (sig.Contains("FAS2")) info.FasVersion = 2;
                else                           info.FasVersion = 1;
                return;
            }
        }

        // 2. Check binary magic signatures
        foreach (var (label, magic) in BinaryMagics)
        {
            if (data.Length >= magic.Length &&
                data.AsSpan(0, magic.Length).SequenceEqual(magic))
            {
                info.FormatName    = label;
                info.IsVlxContainer = label.StartsWith("Visual LISP VLX");
                // Infer version from binary magic when possible
                if (label.Contains("v4"))      info.FasVersion = 4;
                else if (label.Contains("v3")) info.FasVersion = 3;
                else if (label.Contains("v2")) info.FasVersion = 2;
                else if (label.Contains("FAS") || label.Contains("FSL"))
                    info.FasVersion = 1;
                return;
            }
        }

        info.FormatName = info.Extension == ".VLX"
            ? $"VLX (unrecognised magic {info.MagicBytes})"
            : $"FAS (unrecognised magic {info.MagicBytes})";
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  TEXT-BASED FAS HEADER PARSER  (FAS4-FILE / FAS3-FILE etc.)
    // ═════════════════════════════════════════════════════════════════════════

    private static void ParseTextFasHeader(byte[] data, VlxInfo info)
    {
        // Scan lines of the text header until we hit clearly binary content
        int pos = 0;
        var lines = new List<string>();

        while (pos < data.Length)
        {
            // Find end of line (\r\n or \n or binary stop)
            int lineStart = pos;
            bool lineOk   = true;

            while (pos < data.Length)
            {
                byte b = data[pos];
                if (b == 0x0D || b == 0x0A) { pos++; break; }
                if (b < 0x20 && b != 0x09)  { lineOk = false; break; }  // binary
                pos++;
            }

            if (!lineOk) { info.BinaryOffset = lineStart; break; }
            if (pos >= data.Length) { info.BinaryOffset = pos; break; }

            // Skip companion \n after \r
            if (pos < data.Length && data[pos - 1] == 0x0D && data[pos] == 0x0A) pos++;

            string line = Encoding.ASCII.GetString(data, lineStart,
                Math.Min(pos - lineStart, 256)).TrimEnd('\r', '\n', ' ');

            if (string.IsNullOrWhiteSpace(line)) continue;
            lines.Add(line);

            // Detect encryption marker
            if (line.TrimStart().StartsWith(";fas4 crunch", StringComparison.OrdinalIgnoreCase))
                info.IsEncrypted = true;

            // Detect version stamp:  ;$;A9/6/21
            if (line.TrimStart().StartsWith(";$;"))
                info.VersionWord = line.TrimStart().Substring(3);

            // Detect compile mode comment
            if (line.Contains("(vlisp-compile"))
                info.CompileMode = ExtractCompileMode(line);
        }

        info.HeaderLines = lines;
        if (info.BinaryOffset == 0) info.BinaryOffset = pos;
    }

    private static string? ExtractCompileMode(string line)
    {
        if (line.Contains("'st "))  return "Standard (st) — smallest output";
        if (line.Contains("'lsm")) return "Optimize + link indirectly (lsm)";
        if (line.Contains("'lsa")) return "Optimize + link directly (lsa)";
        return null;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  XOR DECRYPTION
    //  Key layout immediately after text header:
    //    [marker byte M]  [key_length byte N]  [N key bytes]  [marker byte M]
    //    [resource stream data ...]
    //  If key_length == 0, no encryption (just skip the markers).
    // ═════════════════════════════════════════════════════════════════════════

    // ═════════════════════════════════════════════════════════════════════════
    //  CORRECT XOR DECRYPTION
    //  Formula (from VB6 reference):
    //    KeyOld = key[0], then each iteration:
    //    KeyNew = key[i+1 mod keyLen]
    //    decrypted[i] = encrypted[i] ^ KeyNew ^ KeyOld
    //    KeyOld = KeyNew
    //  This simplifies to: decrypted[i] = encrypted[i] ^ key[(i+1) % keyLen] ^ key[i % keyLen]
    // ═════════════════════════════════════════════════════════════════════════

    private static byte[] DecryptStream(byte[] encrypted, byte[] key)
    {
        if (key.Length == 0) return (byte[])encrypted.Clone();
        byte[] decrypted = new byte[encrypted.Length];
        int kl = key.Length;
        for (int i = 0; i < encrypted.Length; i++)
            decrypted[i] = (byte)(encrypted[i] ^ key[(i + 1) % kl] ^ key[i % kl]);
        return decrypted;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  TWO-STREAM FAS PARSER
    //  Parses function and resource streams with separate headers and encryption.
    //  Returns true on success, false if parsing fails (caller can fall back to
    //  the old TryDecryptFas).
    // ═════════════════════════════════════════════════════════════════════════

    private static bool ParseFasStreams(byte[] data, VlxInfo info)
    {
        try
        {
            int pos = info.BinaryOffset;
            if (pos >= data.Length)
            {
                info.DecryptStatus = "No binary section found.";
                return false;
            }

            // Find function stream length from header lines (last numeric-only line)
            int funcStreamLen = 0;
            foreach (var line in info.HeaderLines.AsEnumerable().Reverse())
            {
                if (int.TryParse(line.Trim(), out int len))
                {
                    funcStreamLen = len;
                    break;
                }
            }

            if (funcStreamLen <= 0)
            {
                info.DecryptStatus = "Could not find function stream length in header.";
                return false;
            }

            // Parse function stream vars + terminator
            // Format at pos: [digits: varCount][whitespace][TERM char]
            int digitStart = pos;
            while (pos < data.Length && char.IsDigit((char)data[pos]))
                pos++;

            if (pos == digitStart)
            {
                info.DecryptStatus = "No var count found at binary offset.";
                return false;
            }

            if (!int.TryParse(Encoding.ASCII.GetString(data, digitStart, pos - digitStart), out int funcStreamVars))
            {
                info.DecryptStatus = "Invalid function stream var count.";
                return false;
            }

            // Skip whitespace
            while (pos < data.Length && (data[pos] == 0x20 || data[pos] == 0x09))
                pos++;

            if (pos >= data.Length)
            {
                info.DecryptStatus = "Missing terminator after function stream vars.";
                return false;
            }

            byte terminator = data[pos];
            pos++;

            // Now we're at the function stream bytecode
            int funcStreamStart = pos;
            if (funcStreamStart + funcStreamLen > data.Length)
            {
                info.DecryptStatus = "File truncated: function stream extends beyond file.";
                return false;
            }

            byte[] funcStreamEncrypted = data[funcStreamStart..(funcStreamStart + funcStreamLen)];
            pos = funcStreamStart + funcStreamLen;

            // Check encryption indicator for function stream
            if (pos >= data.Length)
            {
                info.DecryptStatus = "Missing encryption indicator for function stream.";
                return false;
            }

            byte encInd = data[pos];
            pos++;
            byte[] funcKey = new byte[0];

            if (encInd != terminator)
            {
                // It's the key length
                int keyLen = encInd;
                if (pos + keyLen > data.Length)
                {
                    info.DecryptStatus = "File truncated: function stream key extends beyond file.";
                    return false;
                }

                funcKey = data[pos..(pos + keyLen)];
                pos += keyLen;
            }

            byte[] funcStreamData = DecryptStream(funcStreamEncrypted, funcKey);
            info.FuncStreamData = funcStreamData;
            info.FuncStreamVars = funcStreamVars;
            info.KeyBytes = funcKey;

            // Skip whitespace after function stream
            while (pos < data.Length && (data[pos] == 0x20 || data[pos] == 0x09 || data[pos] == 0x0D || data[pos] == 0x0A))
                pos++;

            // Parse resource stream header (length as ASCII digits)
            digitStart = pos;
            while (pos < data.Length && char.IsDigit((char)data[pos]))
                pos++;

            if (pos == digitStart)
            {
                // No resource stream
                info.ResStreamData = new byte[0];
                info.ResStreamVars = 0;
                info.DecryptedData = funcStreamData;  // For backward compatibility
                info.DecryptStatus = $"Parsed function stream: {funcStreamVars} vars, {funcStreamData.Length:N0} bytes. " +
                                    $"No resource stream found.";
                return true;
            }

            if (!int.TryParse(Encoding.ASCII.GetString(data, digitStart, pos - digitStart), out int resStreamLen))
            {
                info.DecryptStatus = "Invalid resource stream length.";
                return false;
            }

            // Skip whitespace after length (could be space, \r\n, or both)
            while (pos < data.Length && (data[pos] == 0x20 || data[pos] == 0x09 || data[pos] == 0x0D || data[pos] == 0x0A))
                pos++;

            // Parse resource stream vars + terminator
            digitStart = pos;
            while (pos < data.Length && char.IsDigit((char)data[pos]))
                pos++;

            if (pos == digitStart)
            {
                info.DecryptStatus = "No var count found for resource stream.";
                return false;
            }

            if (!int.TryParse(Encoding.ASCII.GetString(data, digitStart, pos - digitStart), out int resStreamVars))
            {
                info.DecryptStatus = "Invalid resource stream var count.";
                return false;
            }

            // Skip whitespace
            while (pos < data.Length && (data[pos] == 0x20 || data[pos] == 0x09))
                pos++;

            if (pos >= data.Length)
            {
                info.DecryptStatus = "Missing terminator after resource stream vars.";
                return false;
            }

            byte resTerminator = data[pos];
            pos++;

            // Resource stream bytecode
            int resStreamStart = pos;
            if (resStreamStart + resStreamLen > data.Length)
            {
                info.DecryptStatus = "File truncated: resource stream extends beyond file.";
                return false;
            }

            byte[] resStreamEncrypted = data[resStreamStart..(resStreamStart + resStreamLen)];
            pos = resStreamStart + resStreamLen;

            // Check encryption indicator for resource stream
            if (pos >= data.Length)
            {
                info.DecryptStatus = "Missing encryption indicator for resource stream.";
                return false;
            }

            byte resEncInd = data[pos];
            pos++;
            byte[] resKey = new byte[0];

            if (resEncInd != resTerminator)
            {
                int keyLen = resEncInd;
                if (pos + keyLen > data.Length)
                {
                    info.DecryptStatus = "File truncated: resource stream key extends beyond file.";
                    return false;
                }

                resKey = data[pos..(pos + keyLen)];
                pos += keyLen;
            }

            byte[] resStreamData = DecryptStream(resStreamEncrypted, resKey);
            info.ResStreamData = resStreamData;
            info.ResStreamVars = resStreamVars;

            // For backward compatibility, set DecryptedData to function stream
            info.DecryptedData = funcStreamData;

            info.DecryptStatus = $"Parsed both streams: function ({funcStreamVars} vars, {funcStreamData.Length:N0} bytes), " +
                                $"resource ({resStreamVars} vars, {resStreamData.Length:N0} bytes).";
            return true;
        }
        catch (Exception ex)
        {
            info.DecryptStatus = $"ParseFasStreams error: {ex.Message}";
            return false;
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  FALLBACK: OLD DECRYPTION (for compatibility with non-standard formats)
    // ═════════════════════════════════════════════════════════════════════════

    private static void TryDecryptFas(byte[] data, VlxInfo info)
    {
        int start = info.BinaryOffset;
        if (start >= data.Length - 3)
        {
            info.DecryptStatus = "No binary section found.";
            return;
        }

        if (!info.IsEncrypted)
        {
            // No encryption — binary section is the raw bytecode
            info.DecryptStatus = "Not encrypted (*crunch-fasl* = nil). Data is plaintext.";
            info.DecryptedData = data[start..];
            return;
        }

        try
        {
            byte marker   = data[start];
            byte keyLen   = data[start + 1];

            if (keyLen > 128)
            {
                info.DecryptStatus = $"Key length {keyLen} > 128 — unexpected. Skipping decryption.";
                return;
            }

            if (start + 2 + keyLen >= data.Length)
            {
                info.DecryptStatus = "File truncated before key ends.";
                return;
            }

            byte[] key    = data[(start + 2)..(start + 2 + keyLen)];
            int    endMk  = start + 2 + keyLen;

            // Verify end marker matches start marker
            if (data[endMk] != marker)
            {
                info.DecryptStatus =
                    $"Stream markers don't match (begin=0x{marker:X2} end=0x{data[endMk]:X2}). " +
                    "Key extraction may be wrong.";
                // Try anyway
            }
            else
            {
                info.DecryptStatus = keyLen == 0
                    ? "Key length = 0 — no effective encryption."
                    : $"Key found: {keyLen} bytes, marker 0x{marker:X2}.";
            }

            info.KeyBytes = key;

            int dataStart = endMk + 1;
            if (dataStart >= data.Length)
            {
                info.DecryptStatus += " No data after key.";
                return;
            }

            byte[] encrypted  = data[dataStart..];
            byte[] decrypted  = new byte[encrypted.Length];

            if (keyLen == 0)
            {
                // No actual XOR — copy as-is
                Buffer.BlockCopy(encrypted, 0, decrypted, 0, encrypted.Length);
            }
            else
            {
                // XOR decrypt with cycling key (OLD FORMULA - kept for fallback)
                for (int i = 0; i < encrypted.Length; i++)
                    decrypted[i] = (byte)(encrypted[i] ^ key[i % keyLen]);
            }

            info.DecryptedData = decrypted;
            info.DecryptStatus += $" Decrypted {decrypted.Length:N0} bytes.";

            // Sanity check: if the first few decrypted bytes look like
            // known LISP opcodes or printable text, we're probably right
            int printable = decrypted.Take(32).Count(b => b >= 0x20 && b < 127);
            if (printable < 4)
                info.DecryptStatus += " (Note: low printable ratio — key may be wrong)";
        }
        catch (Exception ex)
        {
            info.DecryptStatus = $"Decryption error: {ex.Message}";
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  RESOURCE STREAM INTERPRETER
    //  Processes LD_SYM, LD_STR, INIT opcodes to populate mVars and funcNames
    // ═════════════════════════════════════════════════════════════════════════

    private static void InterpretResourceStream(
        byte[] resStream, int fasVer,
        Dictionary<int, string> mVars,
        Dictionary<int, string> funcNames)
    {
        var stack = new Stack<string>();
        int pos = 0;

        while (pos < resStream.Length)
        {
            byte opcode = resStream[pos];
            pos++;

            switch (opcode)
            {
                case 0x56:  // LD_SYM
                case 0x5B:
                {
                    // Read null-terminated strings in a loop until empty string
                    while (pos < resStream.Length)
                    {
                        int strStart = pos;
                        while (pos < resStream.Length && resStream[pos] != 0) pos++;

                        if (pos > strStart)
                        {
                            string sym = Encoding.ASCII.GetString(resStream, strStart, pos - strStart);
                            stack.Push(sym);
                        }

                        pos++;  // skip null terminator

                        // Check if next byte is 0 (empty string means end of symbols)
                        if (pos < resStream.Length && resStream[pos] == 0)
                        {
                            pos++;
                            break;
                        }

                        if (pos >= resStream.Length) break;
                    }
                    break;
                }

                case 0x55:  // LD_STR
                {
                    if (pos + 2 > resStream.Length) break;
                    ushort count = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;

                    for (int i = 0; i < count; i++)
                    {
                        if (pos + 2 > resStream.Length) break;
                        ushort len = BitConverter.ToUInt16(resStream, pos);
                        pos += 2;

                        if (pos + len > resStream.Length) break;
                        string str = Encoding.ASCII.GetString(resStream, pos, len);
                        stack.Push($"\"{str}\"");
                        pos += len;
                    }
                    break;
                }

                case 0x43:  // INIT vars
                {
                    if (pos + 4 > resStream.Length) break;
                    ushort startIdx = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    ushort count = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;

                    // Pop module ID (ignore it)
                    if (stack.Count > 0) stack.Pop();

                    // Pop count items into mVars[startIdx..startIdx+count-1]
                    for (int i = count - 1; i >= 0; i--)
                    {
                        if (stack.Count > 0)
                        {
                            string val = stack.Pop();
                            mVars[startIdx + i] = val;
                        }
                    }
                    break;
                }

                case 0x3A:  // DEF USUBR
                {
                    // Pop (Name, StartOffset, Module) from stack — same as VB6 reference
                    string uName   = stack.Count > 0 ? stack.Pop() : "?";
                    string uOffset = stack.Count > 0 ? stack.Pop() : "?";
                    string uModule = stack.Count > 0 ? stack.Pop() : "?";

                    // Clean up name (strip quoting)
                    string cleanName = uName.StartsWith("'") ? uName.Substring(1) : uName;
                    cleanName = cleanName.Trim('"');

                    // Register function offset → name mapping
                    if (int.TryParse(uOffset, out int funcOff))
                        funcNames[funcOff] = cleanName;

                    // Push name back — INIT (0x43) expects this item on the stack.
                    // Removing it shifts ALL mVar indices and corrupts the symbol table.
                    stack.Push(cleanName);
                    break;
                }

                case 0x14:  // DEFUN
                case 0x15:  // DEFUN-Q
                {
                    // Read function header (4 bytes: locals_lo, minArgs, maxArgs, flags)
                    if (pos + 4 <= resStream.Length)
                        pos += 4;
                    break;
                }

                case 0x01:  // nil
                {
                    stack.Push("nil");
                    break;
                }

                case 0x02:  // T
                {
                    stack.Push("T");
                    break;
                }

                case 0x32:  // LD_INT8 — push signed 8-bit integer from stream
                {
                    if (pos >= resStream.Length) break;
                    sbyte val8 = (sbyte)resStream[pos]; pos++;
                    stack.Push(val8.ToString());
                    break;
                }

                case 0x33:  // LD_INT32 — push signed 32-bit integer from stream
                {
                    if (pos + 4 > resStream.Length) break;
                    int val32 = BitConverter.ToInt32(resStream, pos); pos += 4;
                    stack.Push(val32.ToString());
                    break;
                }

                case 0x09:  // PUSH gvar
                {
                    if (pos + 2 > resStream.Length) break;
                    ushort idx = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    string val = mVars.ContainsKey(idx) ? mVars[idx] : $"#{idx}";
                    stack.Push(val);
                    break;
                }

                case 0x03:  // VALUE
                {
                    if (pos + 2 > resStream.Length) break;
                    ushort idx = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    string val = mVars.ContainsKey(idx) ? mVars[idx] : $"#{idx}";
                    stack.Push(val);
                    break;
                }

                case 0x06:  // SETQ
                {
                    if (pos + 2 > resStream.Length) break;
                    ushort idx = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    if (stack.Count > 0)
                    {
                        string val = stack.Pop();
                        mVars[idx] = val;
                    }
                    break;
                }

                case 0x0A:  // POP
                {
                    if (stack.Count > 0) stack.Pop();
                    break;
                }

                case 0x0B:  // DUP
                {
                    if (stack.Count > 0)
                    {
                        stack.Push(stack.Peek());
                    }
                    break;
                }

                case 0x39:  // LD LIST
                {
                    if (pos + 2 > resStream.Length) break;
                    ushort count = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    var listItems = new List<string>();
                    for (int i = 0; i < count && stack.Count > 0; i++)
                        listItems.Insert(0, stack.Pop());
                    stack.Push($"({string.Join(" ", listItems)})");
                    break;
                }

                case 0x2A:  // CONS
                {
                    if (stack.Count >= 2)
                    {
                        string b = stack.Pop();
                        string a = stack.Pop();
                        stack.Push($"(cons {a} {b})");
                    }
                    break;
                }

                case 0x35:  // ld_USUBR
                {
                    if (pos + 4 > resStream.Length) break;
                    byte paramCount = resStream[pos++];
                    ushort gvarIdx = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    byte flags = resStream[pos++];
                    string funcRef = mVars.ContainsKey(gvarIdx) ? mVars[gvarIdx] : $"#{gvarIdx}";
                    stack.Push(funcRef);
                    break;
                }

                case 0x51:  // FUNC
                {
                    if (pos + 5 > resStream.Length) break;
                    byte paramCount = resStream[pos++];
                    ushort gvarIdx = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    byte flags = resStream[pos++];
                    byte extra = resStream[pos++];
                    string funcRef = mVars.ContainsKey(gvarIdx) ? mVars[gvarIdx] : $"#{gvarIdx}";
                    stack.Push(funcRef);
                    break;
                }

                case 0x16:  // END defun
                {
                    // Just continue
                    break;
                }

                case 0x57:  // JMP 32
                {
                    if (pos + 4 > resStream.Length) break;
                    int offset = BitConverter.ToInt32(resStream, pos);
                    pos += 4;
                    // Don't actually jump in resource stream - just continue linearly
                    break;
                }

                case 0x67:  // BRZ 32 / branch opcodes
                case 0x68:
                case 0x69:
                case 0x6A:
                {
                    if (pos + 4 > resStream.Length) break;
                    int offset = BitConverter.ToInt32(resStream, pos);
                    pos += 4;
                    break;
                }

                case 0x0D:  // BRZ 16
                {
                    if (pos + 2 > resStream.Length) break;
                    ushort offset = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    break;
                }

                case 0x1C:  // COPY stk→fn
                {
                    // Just continue
                    break;
                }

                // ── Local variable ops (16-bit index) ─────────────────────
                case 0x5C:  // GET lvar16 — push local var onto stack
                {
                    if (pos + 2 > resStream.Length) break;
                    ushort idx = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    // Local vars don't contribute to mVars, just push placeholder
                    stack.Push($"_local{idx}");
                    break;
                }

                case 0x5D:  // SET lvar16 — pop into local var
                {
                    if (pos + 2 > resStream.Length) break;
                    pos += 2;
                    if (stack.Count > 0) stack.Pop();
                    break;
                }

                case 0x5E:  // CLR lvar16
                {
                    if (pos + 2 > resStream.Length) break;
                    pos += 2;
                    break;
                }

                // ── Arithmetic / comparison ops (no inline operands) ──────
                case 0x46: case 0x47: case 0x48: case 0x49:  // + - * /
                case 0x4A: case 0x4B: case 0x4C: case 0x4D:  // = <= < >
                case 0x4E: case 0x4F: case 0x50:             // /= >= minusp
                {
                    // Binary ops: pop 2, push result placeholder
                    if (stack.Count >= 2) { stack.Pop(); stack.Pop(); }
                    stack.Push("?");
                    break;
                }

                // ── CAR / CDR / ENTLAST ───────────────────────────────────
                case 0x28:  // CAR
                case 0x29:  // CDR
                {
                    string arg = stack.Count > 0 ? stack.Pop() : "?";
                    stack.Push(opcode == 0x28 ? $"(car {arg})" : $"(cdr {arg})");
                    break;
                }

                // ── EVAL (2-byte operand) ─────────────────────────────────
                case 0x34:
                {
                    if (pos + 2 > resStream.Length) break;
                    pos += 2;
                    break;
                }

                // ── LD REAL (null-terminated float string) ────────────────
                case 0x3B:
                {
                    int start = pos;
                    while (pos < resStream.Length && resStream[pos] != 0) pos++;
                    string numStr = Encoding.ASCII.GetString(resStream, start, pos - start);
                    pos++;  // skip null
                    stack.Push(numStr);
                    break;
                }

                // ── LD LIST B (2-byte count) ──────────────────────────────
                case 0x37:
                {
                    if (pos + 2 > resStream.Length) break;
                    ushort count = BitConverter.ToUInt16(resStream, pos);
                    pos += 2;
                    var items = new List<string>();
                    for (int i = 0; i < count && stack.Count > 0; i++)
                        items.Insert(0, stack.Pop());
                    stack.Push($"({string.Join(" ", items)})");
                    break;
                }

                // ── POP EXIT (conditional return) ─────────────────────────
                case 0x3E:  // POP EXIT NZ
                case 0x3F:  // POP EXIT Z
                {
                    if (stack.Count > 0) stack.Pop();
                    break;
                }

                // ── Other fixed-size opcodes (skip operands) ──────────────
                case 0x00:  // NOP
                case 0x38:  // CONVERT
                    break;

                case 0x04:  // PUSH stream (2 bytes)
                case 0x07:  // COPY elem (2 bytes)
                case 0x0F:  // FSL (2 bytes)
                case 0x10:  // LIST step (2 bytes)
                {
                    if (pos + 2 > resStream.Length) break;
                    pos += 2;
                    break;
                }

                case 0x05:  // GET lvar8 (1 byte)
                {
                    if (pos >= resStream.Length) break;
                    pos++;
                    stack.Push("_lvar");
                    break;
                }

                case 0x08:  // SET lvar8 (1 byte)
                {
                    if (pos >= resStream.Length) break;
                    pos++;
                    if (stack.Count > 0) stack.Pop();
                    break;
                }

                case 0x64:  // CLR lvar8 (1 byte)
                {
                    if (pos >= resStream.Length) break;
                    pos++;
                    break;
                }

                case 0x2E:  // StackCallAndJmp (1 byte)
                case 0x2F:
                {
                    if (pos >= resStream.Length) break;
                    pos++;
                    break;
                }

                case 0x45:  // RAM call (5 bytes: 1+4)
                case 0x5A:  // RAM VL.ARX call (5 bytes)
                {
                    if (pos + 5 > resStream.Length) break;
                    pos += 5;
                    stack.Push("?");
                    break;
                }

                case 0x53:  // Handler53 (pops 2)
                case 0x54:  // Handler54 (pops 2)
                {
                    if (stack.Count > 0) stack.Pop();
                    if (stack.Count > 0) stack.Pop();
                    stack.Push("?");
                    break;
                }

                case 0x13:  // STOP variants — do NOT return, resource stream may
                case 0x31:  // have multiple sections separated by STOP markers.
                case 0x44:  // Clear the stack and keep going.
                case 0x58:
                case 0x41:
                case 0x11:
                case 0x12:
                case 0x22:
                case 0x30:
                case 0x36:
                case 0x42:
                {
                    stack.Clear();
                    break;
                }

                default:
                {
                    // Unknown opcode — we don't know its data length, so we
                    // can't safely skip it. Stop here to avoid misparse.
                    return;
                }
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  BYTECODE DISASSEMBLER  (version-aware)
    //
    //  Key FAS version differences:
    //    FAS4 (version=4):  Branch opcodes 0x67/0x68/0x69/0x6A/0x57 use 32-bit
    //                       offsets.  Goto_Size = 1 + 4.
    //    FAS2/3 (version≤3): Branch opcodes use 16-bit offsets.
    //                        Goto_Size = 1 + 2.
    //  Reference: Fas_Brancher.cls → Goto_Size property, GotoTargetGet()
    // ═════════════════════════════════════════════════════════════════════════

    private static void DisassembleFas(VlxInfo info)
    {
        byte[]? code = info.FuncStreamData ?? info.DecryptedData;
        if (code == null || code.Length == 0)
        {
            info.Disassembly = "; No bytecode to disassemble.";
            return;
        }

        int fasVer = info.FasVersion;  // 0=unknown, 1=FAS, 2=FAS2, 3=FAS3, 4=FAS4

        // ── Module Variable Table ──────────────────────────────────────
        // In FAS, the symbol/string table is built DURING bytecode interpretation:
        //   0x55 (LD_STR) pushes strings onto the stack
        //   0x56/0x5B (LD_SYM) pushes symbol names onto the stack
        //   0x3A pushes function definitions onto the stack
        //   0x43 (INIT vars) pops items from the stack into MVars[startIdx..startIdx+count-1]
        // Then opcodes 0x03, 0x06, 0x09, 0x35, 0x51 etc. reference MVars by 16-bit index.
        var mVars = new Dictionary<int, string>();       // module variable table (symbol index → name)
        var funcNames = new Dictionary<int, string>();   // function offset → name

        // If a resource stream is available, interpret it first to populate mVars
        if (info.ResStreamData != null && info.ResStreamData.Length > 0)
        {
            InterpretResourceStream(info.ResStreamData, fasVer, mVars, funcNames);
        }

        var sb  = new StringBuilder(32768);
        int pos = 0;
        int instrCount = 0;
        const int MaxInstrs = 8000;

        // ── Expression reconstruction state ─────────────────────────────
        var stack       = new Stack<string>();    // value stack for s-expression reconstruction
        var lispSb      = new StringBuilder(16384);
        int indentLevel = 0;
        FasFunction? currentFunc = null;
        var localVarNames = new List<string>();    // populated by DEFUN arg handling
        int lastDefunLocalCount = 0;

        // Buffer for merging consecutive single-arg (command ...) calls
        // The VLISP compiler breaks (command "a" "b" "c") into individual calls;
        // we reassemble them here.
        var pendingCmdArgs = new List<string>();

        void FlushCommand()
        {
            if (pendingCmdArgs.Count == 0) return;
            lispSb.AppendLine($"{Indent()}(command {string.Join(" ", pendingCmdArgs)})");
            pendingCmdArgs.Clear();
        }

        sb.AppendLine("; ── FAS Bytecode Disassembly ─────────────────────────────────────");
        sb.AppendLine($"; Source: {(info.IsEncrypted ? "XOR-decrypted" : "plaintext")} stream");
        sb.AppendLine($"; Length: {code.Length:N0} bytes");
        sb.AppendLine($"; FAS version: {(fasVer > 0 ? fasVer.ToString() : "unknown (assuming FAS4)")}");
        sb.AppendLine("; Symbol table: built dynamically from LD_STR/LD_SYM/INIT opcodes");
        sb.AppendLine(";");

        lispSb.AppendLine(";;; ── Reconstructed LISP (best-effort) ───────────────────────────");
        lispSb.AppendLine($";;; FAS version {(fasVer > 0 ? fasVer.ToString() : "?")} — {code.Length:N0} bytes");
        lispSb.AppendLine();

        // Helper: resolve module variable by index, translating internal names
        string ResolveMVar(int idx)
        {
            if (!mVars.TryGetValue(idx, out var name))
                return $"#{idx}";
            if (name.StartsWith("ads-", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("_al-", StringComparison.OrdinalIgnoreCase))
                return TranslateInternalName(name);
            return name;
        }

        // Helper: resolve local variable by index
        string ResolveLVar(int idx)
            => idx >= 0 && idx < localVarNames.Count ? localVarNames[idx] : $"_local{idx}";

        // Helper: safe pop from stack
        string StackPop()
            => stack.Count > 0 ? stack.Pop() : "?";

        // Helper: pop N items from stack (top→bottom order, reversed to match push order)
        string[] StackPopArray(int count)
        {
            var items = new string[count];
            for (int i = 0; i < count; i++)
                items[i] = StackPop();
            Array.Reverse(items);
            return items;
        }

        // Helper: LISP indent
        string Indent()
            => new string(' ', Math.Max(0, indentLevel * 2));

        // Helper: read null-terminated string from bytecode
        string ReadZeroString()
        {
            var zsb = new StringBuilder();
            while (pos < code.Length)
            {
                byte b = code[pos++];
                if (b == 0) break;
                zsb.Append(b >= 32 && b < 127 ? (char)b : '.');
            }
            return zsb.ToString();
        }

        // Helper: read branch offset respecting FAS version
        // FAS4 uses 32-bit for "far" branch opcodes; FAS2/3 uses 16-bit
        (int offset, bool ok) ReadBranchOffset(bool isFarBranch)
        {
            if (isFarBranch && (fasVer == 0 || fasVer >= 4))
            {
                // FAS4 or unknown → 32-bit offset
                if (pos + 3 < code.Length)
                {
                    int rel = BitConverter.ToInt32(code, pos); pos += 4;
                    return (rel, true);
                }
            }
            else
            {
                // FAS2/3 or short branch → 16-bit offset
                if (pos + 1 < code.Length)
                {
                    short rel = BitConverter.ToInt16(code, pos); pos += 2;
                    return (rel, true);
                }
            }
            return (0, false);
        }

        while (pos < code.Length && instrCount < MaxInstrs)
        {
            int    offset = pos;
            byte   rawOp  = code[pos++];

            // ── 0x80 bit mirroring (vlinfo main-loop.txt) ──────────────
            byte   op = (rawOp > 0x80 && rawOp <= 0xEA) ? (byte)(rawOp & 0x7F) : rawOp;

            string mnemonic = Opcodes.TryGetValue(op, out var mn) ? mn : $"???_{rawOp:X2}";
            if (rawOp != op) mnemonic += " [ext]";
            string operands = "";

            // ── Flush pending (command ...) buffer only on statement-level opcodes ──
            // Do NOT flush on pure stack-manipulation ops (PUSH, VALUE, FUNC, LD_INT, etc.)
            // because they may be loading the next argument for a consecutive command call.
            // Flush on: SETQ, IF, JMP, OR, AND, DEFUN, END, SET lvar, and other emitters.
            switch (op)
            {
                case 0x06: case 0x1A: case 0x1B: // SETQ variants
                case 0x5D: case 0x5E:             // SET lvar
                case 0x14: case 0x15: case 0x17:  // DEFUN
                case 0x16:                         // END defun
                case 0x57:                         // JMP 32
                case 0x67:                         // IF 32
                case 0x68:                         // OR
                case 0x69:                         // AND
                case 0x53: case 0x54:              // exception handlers
                    FlushCommand();
                    break;
            }

            // ── Decode operands based on reference project opcode analysis ──
            switch (op)
            {
                // ── No operands (stack-only) ────────────────────────────
                case 0x01: // PUSH nil
                    stack.Push("nil");
                    break;
                case 0x02: // PUSH T
                    stack.Push("T");
                    break;
                case 0x0A: // POP — discard top of stack and emit as statement
                {
                    string discarded = StackPop();
                    if (discarded != "?" && discarded != "nil")
                    {
                        // Merge consecutive (command X) calls into (command X Y Z ...)
                        if (discarded.StartsWith("(command ")
                            && discarded.EndsWith(")")
                            && !discarded.Contains('\n'))
                        {
                            // Extract the single arg from "(command ARG)"
                            string arg = discarded.Substring(9, discarded.Length - 10);
                            pendingCmdArgs.Add(arg);
                        }
                        else
                        {
                            FlushCommand();
                            lispSb.AppendLine($"{Indent()}{discarded}");
                        }
                    }
                    break;
                }
                case 0x0B: // DUP
                    if (stack.Count > 0) stack.Push(stack.Peek());
                    else stack.Push("?");
                    break;
                case 0x11: case 0x12: case 0x13: case 0x1D: // STOP
                case 0x22: case 0x27: case 0x2B: // STOP
                case 0x30: case 0x31: case 0x36: // STOP
                case 0x41: case 0x42: case 0x44: // STOP
                case 0x52: case 0x58: // STOP
                    break;
                case 0x16: // END defun
                    FlushCommand();
                    if (currentFunc != null)
                    {
                        // Capture remaining stack as return value
                        string retVal = stack.Count > 0 ? StackPop() : "nil";
                        lispSb.AppendLine($"{Indent()}  {retVal})");
                        lispSb.AppendLine();
                        currentFunc.EndOffset = offset;
                        currentFunc.ReconstructedLisp =
                            $"({(currentFunc.IsQuoted ? "defun-q" : "defun")} {currentFunc.Name} " +
                            $"({string.Join(" " , currentFunc.LocalVarNames.Take(currentFunc.MinArgs))}) ...)";
                        info.FasFunctions.Add(currentFunc);
                        currentFunc = null;
                        indentLevel = Math.Max(0, indentLevel - 1);
                        stack.Clear();
                    }
                    break;
                case 0x20: case 0x62: case 0x63: // NOP
                    break;
                case 0x23: // NULL/NOT
                {
                    string arg = StackPop();
                    stack.Push($"(null {arg})");
                    break;
                }
                case 0x24: // ATOM
                {
                    string arg = StackPop();
                    stack.Push($"(atom {arg})");
                    break;
                }
                case 0x28: // CAR
                {
                    string arg = StackPop();
                    stack.Push($"(car {arg})");
                    break;
                }
                case 0x29: // CDR
                {
                    string arg = StackPop();
                    stack.Push($"(cdr {arg})");
                    break;
                }
                case 0x2A: // CONS
                {
                    string b = StackPop(), a = StackPop();
                    stack.Push($"(cons {a} {b})");
                    break;
                }
                case 0x38: // CONVERT — convert top of stack (int↔real etc.)
                    // No operands, just a type conversion marker
                    break;
                case 0x3E: // POP EXIT NZ
                case 0x3F: // POP EXIT Z
                    StackPop();
                    break;
                case 0x4B: // <=
                {
                    string b = StackPop(), a = StackPop();
                    stack.Push($"(<= {a} {b})");
                    break;
                }

                // ── Integer literals from stream ────────────────────────
                case 0x32: // LD_INT8 — push signed 8-bit integer
                    if (pos < code.Length)
                    {
                        sbyte val8 = (sbyte)code[pos]; pos++;
                        operands = val8.ToString();
                        stack.Push(val8.ToString());
                    }
                    break;
                case 0x33: // LD_INT32 — push signed 32-bit integer
                    if (pos + 3 < code.Length)
                    {
                        int val32 = BitConverter.ToInt32(code, pos); pos += 4;
                        operands = val32.ToString();
                        stack.Push(val32.ToString());
                    }
                    break;

                // ── 1-byte operand (8-bit local var index, FSL) ─────────
                case 0x05: // GET lvar8 — push local var (8-bit index)
                case 0x08: // SET lvar8 — pop → local var (8-bit index)
                case 0x64: // CLR lvar8 — clear local var (8-bit index)
                    if (pos < code.Length)
                    {
                        byte val = code[pos++];
                        string varName = ResolveLVar(val);
                        operands = $"lvar[{val}] {varName}";
                        if (op == 0x05)
                            stack.Push(varName);
                        else if (op == 0x08)
                        {
                            string v = StackPop();
                            lispSb.AppendLine($"{Indent()}(setq {varName} {v})");
                        }
                        // 0x64 CLR just clears the var
                    }
                    break;

                // ── LD REAL — load floating-point number (null-terminated string) ──
                case 0x3B:
                {
                    string numStr = ReadZeroString();
                    operands = numStr;
                    stack.Push(numStr);
                    break;
                }

                // ── 2× 1-byte operands ──────────────────────────────────
                case 0x04: // PUSH stream (stream, index)
                case 0x07: // COPY elem (src, dst)
                case 0x10: // LIST step
                    if (pos + 1 < code.Length)
                    {
                        byte a = code[pos++], bv = code[pos++];
                        operands = $"{a}, {bv}";
                    }
                    break;

                case 0x25: // 1-byte operand (unknown stack op)
                    if (pos < code.Length)
                    {
                        byte val = code[pos++];
                        operands = $"{val}";
                        stack.Push($"_lvar[{val}]");
                    }
                    break;

                // ── 2-byte operand (16-bit index into module var table) ──
                case 0x03: // VALUE — push value of global var
                case 0x09: // PUSH gvar — push symbol/item by index
                case 0x0C: // PUSH gvar16 alt
                    if (pos + 1 < code.Length)
                    {
                        ushort idx = BitConverter.ToUInt16(code, pos); pos += 2;
                        string sym = ResolveMVar(idx);
                        operands = $"[{idx}] {sym}";
                        stack.Push(sym);
                    }
                    break;

                case 0x06: // SETQ — pop into global var
                case 0x1A: // SETQ FSL func
                case 0x1B: // SETQ FSL var
                    if (pos + 1 < code.Length)
                    {
                        ushort idx = BitConverter.ToUInt16(code, pos); pos += 2;
                        string sym = ResolveMVar(idx);
                        operands = $"[{idx}] {sym}";
                        string val = StackPop();
                        lispSb.AppendLine($"{Indent()}(setq {sym} {val})");
                    }
                    break;

                // ── 2-byte operand (16-bit local var index, FAS) ─────────
                case 0x5C: // GET lvar16
                    if (pos + 1 < code.Length)
                    {
                        ushort idx = BitConverter.ToUInt16(code, pos); pos += 2;
                        string varName = ResolveLVar(idx);
                        operands = $"lvar[{idx}] {varName}";
                        stack.Push(varName);
                    }
                    break;
                case 0x5D: // SET lvar16
                    if (pos + 1 < code.Length)
                    {
                        ushort idx = BitConverter.ToUInt16(code, pos); pos += 2;
                        string varName = ResolveLVar(idx);
                        operands = $"lvar[{idx}] {varName}";
                        string v = StackPop();
                        lispSb.AppendLine($"{Indent()}(setq {varName} {v})");
                    }
                    break;
                case 0x5E: // CLR lvar16
                    if (pos + 1 < code.Length)
                    {
                        ushort idx = BitConverter.ToUInt16(code, pos); pos += 2;
                        string varName = ResolveLVar(idx);
                        operands = $"lvar[{idx}] {varName} (clear)";
                    }
                    break;

                // ── Branch 16-bit (relative offset) — always 16-bit ─────
                case 0x0D: // BRZ 16 — branch if false
                case 0x0E: // BRNZ 16 — branch if true
                case 0x0F: // JMP 16
                case 0x3C: // BRZ 16 alt (FAS3)
                case 0x3D: // BRNZ 16 alt (FAS3)
                    if (pos + 1 < code.Length)
                    {
                        short rel = BitConverter.ToInt16(code, pos); pos += 2;
                        int target = pos + rel;
                        operands = $"→ 0x{target:X4} (offset {rel:+#;-#;0})";

                        // Branch keyword heuristic
                        if (op is 0x0D or 0x3C) // BRZ — conditional
                        {
                            string cond = StackPop();
                            if (rel < 0)
                            {
                                lispSb.AppendLine($"{Indent()}(while {cond}");
                                indentLevel++;
                            }
                            else
                            {
                                lispSb.AppendLine($"{Indent()}(if {cond}");
                                indentLevel++;
                            }
                        }
                    }
                    break;

                // ── Far branch/control — version-aware width ─────────────
                case 0x57: // JMP 32/16 (far goto)
                {
                    var (rel, ok) = ReadBranchOffset(isFarBranch: true);
                    if (ok)
                    {
                        int target = pos + rel;
                        operands = $"→ 0x{target:X4} (offset {rel:+#;-#;0})";
                        if (rel < 0)
                        {
                            // Backward jump = end of while loop body
                            if (indentLevel > 0)
                            {
                                indentLevel--;
                                lispSb.AppendLine($"{Indent()}) ; end while");
                            }
                        }
                        else
                        {
                            // Forward jump = close the current if/else block
                            if (indentLevel > 0)
                            {
                                indentLevel--;
                                lispSb.AppendLine($"{Indent()}) ; end block");
                            }
                        }
                    }
                    break;
                }
                case 0x67: // IF 32/16
                {
                    var (rel, ok) = ReadBranchOffset(isFarBranch: true);
                    if (ok)
                    {
                        int target = pos + rel;
                        operands = $"→ 0x{target:X4} (offset {rel:+#;-#;0})";
                        string cond = StackPop();

                        if (rel < 0)
                        {
                            bool isForeach = pos < code.Length && code[pos] == 0x19;
                            if (isForeach)
                                lispSb.AppendLine($"{Indent()}(foreach ... ; detected foreach");
                            else
                                lispSb.AppendLine($"{Indent()}(while {cond}");
                            indentLevel++;
                        }
                        else
                        {
                            // Check if this is a while-loop: peek before the target
                            // address for a backward JMP (0x57). Pattern:
                            //   0x57 [4-byte offset < 0] at target-5 → while
                            bool isWhile = false;
                            int jmpPos = target - 5; // JMP 32 = 1 opcode + 4 bytes
                            if (jmpPos >= pos && jmpPos + 4 < code.Length)
                            {
                                byte peekOp = code[jmpPos];
                                if (peekOp == 0x57 || (peekOp > 0x80 && (peekOp & 0x7F) == 0x57))
                                {
                                    int jmpRel = BitConverter.ToInt32(code, jmpPos + 1);
                                    if (jmpRel < 0) // backward jump = loop-back
                                        isWhile = true;
                                }
                            }

                            if (isWhile)
                            {
                                lispSb.AppendLine($"{Indent()}(while {cond}");
                                indentLevel++;
                            }
                            else
                            {
                                lispSb.AppendLine($"{Indent()}(if {cond}");
                                indentLevel++;
                            }
                        }
                    }
                    break;
                }
                case 0x68: // OR short-circuit
                {
                    var (rel, ok) = ReadBranchOffset(isFarBranch: true);
                    if (ok)
                    {
                        int target = pos + rel;
                        operands = $"→ 0x{target:X4} (offset {rel:+#;-#;0})";
                        string cond = stack.Count > 0 ? stack.Peek() : "?";
                        lispSb.AppendLine($"{Indent()}(or {cond}");
                        indentLevel++;
                    }
                    break;
                }
                case 0x69: // BRANCH 32/16
                {
                    var (rel, ok) = ReadBranchOffset(isFarBranch: true);
                    if (ok)
                    {
                        // 0x69 also reads a second 32-bit param per reference
                        if (fasVer == 0 || fasVer >= 4)
                        {
                            if (pos + 3 < code.Length) pos += 4;
                        }
                        else
                        {
                            if (pos + 1 < code.Length) pos += 2;
                        }
                        int target = pos + rel;
                        operands = $"→ 0x{target:X4} (offset {rel:+#;-#;0})";
                    }
                    break;
                }
                case 0x6A: // AND short-circuit
                {
                    var (rel, ok) = ReadBranchOffset(isFarBranch: true);
                    if (ok)
                    {
                        int target = pos + rel;
                        operands = $"→ 0x{target:X4} (offset {rel:+#;-#;0})";
                        string cond = stack.Count > 0 ? stack.Peek() : "?";
                        // AND short-circuit: if condition false, jump to target
                        if (rel == 1 && pos < code.Length && code[pos] == 0x02)
                        {
                            // Last AND item — terminal pattern: 6A 01 00 00 00 02 (push T)
                            // Don't emit (and) here; the caller will collect items
                        }
                        else
                        {
                            lispSb.AppendLine($"{Indent()}  ; (and ... {cond})");
                        }
                    }
                    break;
                }

                // ── DEFUN / DEFUN-Q (4× 1-byte: locals, args, argsMax, flags) ──
                case 0x14: // DEFUN
                case 0x15: // DEFUN-Q
                    if (pos + 3 < code.Length)
                    {
                        byte p1 = code[pos++]; // cx (low part of local var count)
                        byte p2 = code[pos++]; // min args
                        byte p3 = code[pos++]; // max args
                        byte p4 = code[pos++]; // ax (high part + GC flag)

                        // Local var count: 15-bit value from ax:cx
                        int localVars = ((p4 & 0xFE) * 0x80) | p1;
                        bool gc = (p4 & 0x01) != 0;
                        lastDefunLocalCount = localVars;

                        operands = $"locals={localVars} args={p2}..{p3} gc={gc}";

                        // Look up function name from funcNames table (set by 0x3A)
                        string funcName;
                        if (funcNames.TryGetValue(offset, out var fn))
                            funcName = fn;
                        else
                            funcName = $"_func{info.FasFunctions.Count}";

                        currentFunc = new FasFunction
                        {
                            Name          = funcName,
                            Offset        = offset,
                            LocalVarCount = localVars,
                            MinArgs       = p2,
                            MaxArgs       = p3,
                            GcFlag        = gc,
                            IsQuoted      = op == 0x15,
                        };

                        stack.Clear();
                        indentLevel = 1;
                        string keyword = op == 0x15 ? "defun-q" : "defun";
                        lispSb.AppendLine($"({keyword} {funcName} (__DEFUN_ARGS__)");
                        lispSb.AppendLine($"  ; locals={localVars} args={p2}..{p3}");
                    }
                    break;

                // ── DEFUN FAS2 (2-byte name index) ──────────────────────
                case 0x17:
                    if (pos + 1 < code.Length)
                    {
                        ushort idx = BitConverter.ToUInt16(code, pos); pos += 2;
                        string name = ResolveMVar(idx);
                        operands = $"name=[{idx}] {name}";

                        currentFunc = new FasFunction
                        {
                            Name   = name,
                            Offset = offset,
                        };
                        stack.Clear();
                        indentLevel = 1;
                        lispSb.AppendLine($"(defun {name} (__DEFUN_ARGS__)");
                    }
                    break;

                // ── Frame setup: COPY stack→lvar (init args) ─────────────
                case 0x18:
                    if (pos + 1 < code.Length)
                    {
                        ushort paramCount = BitConverter.ToUInt16(code, pos); pos += 2;
                        int alignedCount = (paramCount / 2) * 2;
                        operands = $"params={paramCount}";

                        // Pop pairs from stack: each arg pushed (name, slot)
                        // so stack top→bottom is: slot_N, name_N, ..., slot_0, name_0
                        // Pop order: slot_N(0), name_N(1), slot_N-1(2), name_N-1(3)...
                        // Odd-indexed pops = real names (reversed order)
                        var argNames = new List<string>();
                        for (int i = 0; i < alignedCount && stack.Count > 0; i++)
                        {
                            string item = StackPop();
                            if (i % 2 == 1) // odd indices = symbol names
                                argNames.Add(item);
                        }
                        argNames.Reverse(); // restore original arg order

                        // Update current function args and localVarNames
                        if (currentFunc != null && argNames.Count > 0)
                        {
                            currentFunc.LocalVarNames = argNames;
                            localVarNames = new List<string>(argNames);
                        }

                        if (argNames.Count > 0)
                            operands += $"  ({string.Join(" ", argNames)})";

                        // Replace the DEFUN placeholder with actual arg names
                        string argsStr = argNames.Count > 0
                            ? string.Join(" ", argNames)
                            : "";
                        lispSb.Replace("(__DEFUN_ARGS__)", $"({argsStr})");
                    }
                    break;

                // ── Frame setup: CLEAR args ──────────────────────────────
                case 0x19:
                    if (pos + 1 < code.Length)
                    {
                        ushort clearCount = BitConverter.ToUInt16(code, pos); pos += 2;
                        operands = $"clear={clearCount}";
                    }
                    break;

                // ── Frame setup: COPY stack→fn ───────────────────────────
                case 0x1C:
                    operands = "(frame setup)";
                    break;

                case 0x1E: // 1-byte param (unknown)
                case 0x1F: // 1-byte param (unknown)
                    if (pos < code.Length) pos++;
                    break;

                // ── LD USUBR / CALL USUBR / FUNC ───────────────────────
                // Reference encoding (from Fas-Disasm):
                //   0x34 (EVAL): [1:paramCount] [1:flags]                    = 2 bytes
                //   0x35 (ld_USUBR): [1:paramCount] [2:GVarIdx] [1:flags]   = 4 bytes
                //   0x51 (FUNC): [1:paramCount] [2:GVarIdx] [1:flags] [1:extra] = 5 bytes
                case 0x34: // EVAL — evaluate expression
                    if (pos + 1 < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        byte flags      = code[pos++];

                        // Pop paramAbove+1 items from stack (the expression + args)
                        var evalArgs = StackPopArray(Math.Min(paramAbove + 1, stack.Count + 1));
                        string evalExpr = evalArgs.Length > 0 ? evalArgs[0] : "?";
                        string evalArgsStr = evalArgs.Length > 1
                            ? string.Join(" ", evalArgs.Skip(1))
                            : "";
                        operands = $"args={paramAbove} flags=0x{flags:X2}  (eval {evalExpr} {evalArgsStr})";
                        stack.Push($"(eval {evalExpr} {evalArgsStr})".TrimEnd());
                    }
                    break;

                case 0x35: // ld_USUBR — call user subroutine by name
                    if (pos + 3 < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        ushort gvarIdx  = BitConverter.ToUInt16(code, pos); pos += 2;
                        byte flags      = code[pos++];

                        string funcNameU = ResolveMVar(gvarIdx);
                        // Strip any quoting from symbol name for display
                        if (funcNameU.StartsWith("'")) funcNameU = funcNameU.Substring(1);

                        // Pop arguments from stack
                        var callArgs = StackPopArray(Math.Min((int)paramAbove, stack.Count + 1));
                        string argsStr = string.Join(" ", callArgs);

                        bool isAcadBuiltIn = (flags & 0x02) == 0;
                        operands = $"[{gvarIdx}] {funcNameU} args={paramAbove} flags=0x{flags:X2}"
                                 + (isAcadBuiltIn ? " (ACAD built-in)" : "");
                        stack.Push($"({funcNameU}{(argsStr.Length > 0 ? " " + argsStr : "")})");
                    }
                    break;

                case 0x51: // FUNC — call function (with extra byte)
                    if (pos + 4 < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        ushort gvarIdx  = BitConverter.ToUInt16(code, pos); pos += 2;
                        byte flags      = code[pos++];
                        byte extra      = code[pos++]; // always 0 per reference

                        string funcNameF = ResolveMVar(gvarIdx);
                        if (funcNameF.StartsWith("'")) funcNameF = funcNameF.Substring(1);

                        var callArgs = StackPopArray(Math.Min((int)paramAbove, stack.Count + 1));
                        string argsStr = string.Join(" ", callArgs);

                        bool isAcadBuiltIn = (flags & 0x02) == 0;
                        operands = $"[{gvarIdx}] {funcNameF} args={paramAbove} flags=0x{flags:X2}"
                                 + (isAcadBuiltIn ? " (ACAD built-in)" : "");
                        stack.Push($"({funcNameF}{(argsStr.Length > 0 ? " " + argsStr : "")})");
                    }
                    break;

                // ── INIT vars (pop from stack → module variable table) ──
                // Reference: 0x43 reads [2:VarPos] [2:St_init], pops moduleID from stack,
                // then pops St_init items from stack into MVars[VarPos..VarPos+St_init-1]
                case 0x43:
                    if (pos + 3 < code.Length)
                    {
                        ushort varPos = BitConverter.ToUInt16(code, pos); pos += 2;
                        ushort stInit = BitConverter.ToUInt16(code, pos); pos += 2;

                        // Pop module ID from stack (nil=0=resource stream, 1=function stream)
                        string moduleId = StackPop();

                        operands = $"start={varPos} count={stInit} module={moduleId}";

                        // Pop stInit items from stack into mVars (reverse order)
                        var namesSb = new StringBuilder();
                        for (int i = varPos + stInit - 1; i >= varPos; i--)
                        {
                            string item = StackPop();
                            mVars[i] = item;
                            if (namesSb.Length < 200) // limit display
                            {
                                if (namesSb.Length > 0) namesSb.Append(", ");
                                namesSb.Append($"[{i}]={item}");
                            }
                        }

                        if (namesSb.Length > 0)
                        {
                            operands += $"  {namesSb}";
                            if (namesSb.Length >= 200) operands += "…";
                        }

                        sb.AppendLine($"; Module vars populated: {mVars.Count} total entries");
                    }
                    break;

                // ── LD STR (load strings from stream → stack) ────────────
                // Reference: reads [2:count] then for each: [2:length] [length bytes]
                case 0x55:
                    if (pos + 1 < code.Length)
                    {
                        ushort strCount = BitConverter.ToUInt16(code, pos); pos += 2;
                        operands = $"count={strCount}";
                        var strNames = new List<string>();

                        for (int s = 0; s < strCount && pos + 1 < code.Length; s++)
                        {
                            ushort slen = BitConverter.ToUInt16(code, pos); pos += 2;
                            if (pos + slen > code.Length) break;
                            string str = SafeAscii(code, pos, slen);
                            pos += slen;
                            stack.Push($"\"{str}\"");
                            strNames.Add(str);
                        }

                        if (strNames.Count > 0)
                            operands += $"  [{string.Join(", ", strNames.Take(10))}]"
                                      + (strNames.Count > 10 ? "…" : "");
                    }
                    break;

                // ── LD SYM (load symbols from stream → stack) ────────────
                // Reference: reads null-terminated strings in a loop until empty string
                case 0x56: // FSL variant
                case 0x5B: // FAS variant
                {
                    var symNames = new List<string>();
                    while (pos < code.Length)
                    {
                        string sym = ReadZeroString();
                        if (sym.Length == 0) break;  // empty string = terminator
                        stack.Push(sym);
                        symNames.Add(sym);
                    }

                    operands = $"count={symNames.Count}";
                    if (symNames.Count > 0)
                        operands += $"  [{string.Join(", ", symNames.Take(10))}]"
                                  + (symNames.Count > 10 ? "…" : "");
                    break;
                }

                // ── LD LIST (combine N stack items into a list) ──────────
                case 0x39:
                    if (pos + 1 < code.Length)
                    {
                        ushort count = BitConverter.ToUInt16(code, pos); pos += 2;
                        operands = $"count={count}";
                        var items = StackPopArray(Math.Min((int)count, stack.Count + 1));
                        stack.Push($"'({string.Join(" ", items)})");
                    }
                    break;

                // ── DEF USUBR (define user subroutine from stack) ────────
                // Reference: pops (Name, StartOffset, Module) from stack,
                // creates function entry, pushes USUBR object back
                case 0x3A:
                {
                    string uName    = StackPop();   // function name
                    string uOffset  = StackPop();   // start offset in function stream
                    string uModule  = StackPop();   // module ID

                    // Strip quoting from name
                    string cleanName = uName.StartsWith("'") ? uName.Substring(1) : uName;
                    cleanName = cleanName.Trim('"');

                    // Try to parse offset for function name lookup
                    if (int.TryParse(uOffset, out int funcOff))
                        funcNames[funcOff] = cleanName;

                    operands = $"name={cleanName} offset={uOffset} module={uModule}";

                    // Push USUBR object back onto stack (it'll be stored in mVars by 0x43)
                    stack.Push(cleanName);
                    break;
                }

                // ── RAM function calls (memory-resident) ─────────────────
                case 0x45: // RAM call (1-byte paramCount + 4-byte address)
                    if (pos + 4 < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        int addr = BitConverter.ToInt32(code, pos); pos += 4;
                        var callArgs = StackPopArray(Math.Min((int)paramAbove, stack.Count + 1));
                        operands = $"ramcall addr=0x{addr:X8} args={paramAbove}";
                        stack.Push($"(ramcall_0x{addr:X8} {string.Join(" ", callArgs)})");
                    }
                    break;
                case 0x5A: // RAM call VL.ARX (1-byte paramCount + 4-byte address)
                    if (pos + 4 < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        int addr = BitConverter.ToInt32(code, pos); pos += 4;
                        var callArgs = StackPopArray(Math.Min((int)paramAbove, stack.Count + 1));
                        operands = $"vl-arx addr=0x{addr:X8} args={paramAbove}";
                        stack.Push($"(vl-arx_0x{addr:X8} {string.Join(" ", callArgs)})");
                    }
                    break;
                case 0x5F: // Call by offset (1-byte paramCount + 4-byte offset)
                    if (pos + 4 < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        int funcOff = BitConverter.ToInt32(code, pos); pos += 4;
                        string fName = funcNames.TryGetValue(funcOff, out var fn2)
                            ? fn2 : $"@0x{funcOff:X4}";
                        var callArgs = StackPopArray(Math.Min((int)paramAbove, stack.Count + 1));
                        operands = $"callbyoffs {fName} args={paramAbove}";
                        stack.Push($"({fName} {string.Join(" ", callArgs)})");
                    }
                    break;

                // ── Jump-to-function opcodes ─────────────────────────────
                case 0x60: // jmp2_nopop (1-byte + 4-byte offset)
                case 0x61: // continue-at (1-byte + 4-byte offset)
                    if (pos + 4 < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        int funcOff = BitConverter.ToInt32(code, pos); pos += 4;
                        string fName = funcNames.TryGetValue(funcOff, out var fn3)
                            ? fn3 : $"@0x{funcOff:X4}";
                        var callArgs = StackPopArray(Math.Min((int)paramAbove, stack.Count + 1));
                        operands = $"{(op == 0x60 ? "jmp_nopop" : "continue")} {fName} args={paramAbove}";
                        stack.Push($"({fName} {string.Join(" ", callArgs)})");
                    }
                    break;

                // ── LIST builder (combine N stack items) ──────────────────
                case 0x37:
                    if (pos + 1 < code.Length)
                    {
                        ushort count = BitConverter.ToUInt16(code, pos); pos += 2;
                        var items = StackPopArray(Math.Min((int)count, stack.Count + 1));
                        operands = $"count={count}";
                        stack.Push($"(list {string.Join(" ", items)})");
                    }
                    break;

                // ── StackCallAndJmp (call from stack) ────────────────────
                case 0x2E:
                    if (pos < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        string funcRef = StackPop();
                        var callArgs = StackPopArray(Math.Min((int)paramAbove, stack.Count + 1));
                        operands = $"args={paramAbove}";
                        stack.Push($"(apply {funcRef} {string.Join(" ", callArgs)})");
                    }
                    break;

                // ── CallAndJmp (call by mvar index) ──────────────────────
                case 0x2F:
                    if (pos + 2 < code.Length)
                    {
                        byte paramAbove = code[pos++];
                        ushort gvarIdx  = BitConverter.ToUInt16(code, pos); pos += 2;
                        string funcRef  = ResolveMVar(gvarIdx);
                        var callArgs = StackPopArray(Math.Min((int)paramAbove, stack.Count + 1));
                        operands = $"[{gvarIdx}] {funcRef} args={paramAbove}";
                        stack.Push($"({funcRef} {string.Join(" ", callArgs)})");
                    }
                    break;

                // ── Exception/error handlers ─────────────────────────────
                case 0x53: // closure handler
                case 0x54: // exception handler
                {
                    var handlerArgs = StackPopArray(Math.Min(2, stack.Count + 1));
                    operands = $"handler ({string.Join(", ", handlerArgs)})";
                    stack.Push($"(handler {string.Join(" ", handlerArgs)})");
                    break;
                }
                case 0x59: // SetupErrorHandler (pops 9 items)
                {
                    var errItems = StackPopArray(Math.Min(9, stack.Count + 1));
                    operands = $"error-handler ({errItems.Length} items)";
                    string errBody = string.Join(" ", errItems);
                    lispSb.AppendLine($"{Indent()};;; (vl-catch-all-apply ... {errBody})");
                    stack.Push($"(error-handler {errBody})");
                    break;
                }

                // ── Misc memory op ───────────────────────────────────────
                case 0x40:
                    if (pos + 5 < code.Length)
                    {
                        ushort p1 = BitConverter.ToUInt16(code, pos); pos += 2;
                        int p2 = BitConverter.ToInt32(code, pos); pos += 4;
                        operands = $"mem {p1}, 0x{p2:X8}";
                        stack.Push($"(mem {p1} 0x{p2:X8})");
                    }
                    break;

                // ── Math/comparison ops (no operands, stack-to-stack) ────
                case 0x46: // +
                case 0x47: // -
                case 0x48: // *
                case 0x49: // /
                case 0x4A: // =
                case 0x4C: // <
                case 0x4D: // >
                case 0x4E: // !=
                case 0x4F: // >= (inferred)
                case 0x50: // minusp (inferred)
                {
                    string lispOp = op switch
                    {
                        0x46 => "+", 0x47 => "-", 0x48 => "*", 0x49 => "/",
                        0x4A => "=", 0x4C => "<", 0x4D => ">", 0x4E => "/=",
                        0x4F => ">=", 0x50 => "minusp",
                        _    => "op"
                    };
                    if (op == 0x50) // unary
                    {
                        string a = StackPop();
                        stack.Push($"({lispOp} {a})");
                    }
                    else
                    {
                        string bv = StackPop(), a = StackPop();
                        stack.Push($"({lispOp} {a} {bv})");
                    }
                    break;
                }

                // ── LIST ops (no additional operands) ────────────────────
                case 0x2C: // list length
                {
                    string arg = StackPop();
                    stack.Push($"(length {arg})");
                    break;
                }
                case 0x2D: // list nth/assoc
                {
                    string idx2 = StackPop(), lst = StackPop();
                    stack.Push($"(nth {idx2} {lst})");
                    break;
                }

                // ── Remaining no-op / unknown ────────────────────────────
                case 0x21: case 0x26:
                    break;
            }

            // Format the disassembly line
            sb.AppendLine($"  {offset:X4}  {rawOp:X2}  {mnemonic,-20} {operands}");
            instrCount++;

            // Stop on stream terminators to avoid running into data
            if (op is 0x11 or 0x12 or 0x13 or 0x1D or 0x22 or 0x27
                or 0x2B or 0x30 or 0x31 or 0x36 or 0x41 or 0x42
                or 0x44 or 0x52 or 0x58)
            {
                // Close any open LISP blocks
                while (indentLevel > 0)
                {
                    indentLevel--;
                    lispSb.AppendLine($"{Indent()})");
                }
                lispSb.AppendLine();

                // Check if a new function stream follows (DEFUN opcode next)
                if (pos < code.Length && code[pos] == 0x14)
                {
                    sb.AppendLine(";");
                    sb.AppendLine("; ── New function stream ──────────────");
                    stack.Clear();
                    continue;
                }

                // Check if more valid opcodes follow (not truly end of code)
                if (pos < code.Length)
                {
                    byte nextByte = code[pos];
                    bool looksValid = Opcodes.ContainsKey(nextByte)
                        || (nextByte > 0x80 && nextByte <= 0xEA
                            && Opcodes.ContainsKey((byte)(nextByte & 0x7F)));

                    if (looksValid)
                    {
                        sb.AppendLine("; ── stream transition (continuing) ──");
                        stack.Clear();
                        continue;
                    }
                }

                sb.AppendLine("; --- stream boundary ---");
                stack.Clear();
            }
        }

        if (instrCount >= MaxInstrs)
            sb.AppendLine($"; (truncated at {MaxInstrs} instructions)");

        sb.AppendLine($"; ── End  ({instrCount} instructions decoded, {mVars.Count} module vars) ──");
        info.Disassembly = sb.ToString();

        // Store reconstructed LISP
        if (lispSb.Length > 100) // only if we actually reconstructed something
        {
            // Clean up any unreplaced DEFUN arg placeholders
            lispSb.Replace("(__DEFUN_ARGS__)", "()");
            info.DecompiledLisp = lispSb.ToString();
        }
    }

    private static string SafeAscii(byte[] data, int offset, int length)
    {
        var sb = new StringBuilder(length);
        for (int i = 0; i < length && offset + i < data.Length; i++)
        {
            byte b = data[offset + i];
            sb.Append(b >= 32 && b < 127 ? (char)b : '.');
        }
        return sb.ToString();
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  VLX CONTAINER EXTRACTOR
    //  VLX files have a "VRTLIB-1" header followed by typed resource blocks.
    //  Resource block layout:  [4-byte size][2-byte type][null-term name][data]
    //
    //  Known resource types (from VLXSpliter.cls):
    //    0x0000  RT_LSP   LISP source code
    //    0x04D8  RT_PRV   Private data
    //    0x0532  RT_FAS   Compiled FAS bytecode
    //    0x0537  RT_TXT   Text / comments
    //    0x053C  RT_DVB   VBA code
    //    0x0546  RT_DCL   DCL dialog definition
    //
    //  Falls back to signature scanning if VRTLIB-1 header not found.
    // ═════════════════════════════════════════════════════════════════════════

    private const ushort RT_LSP = 0x0000;
    private const ushort RT_PRV = 0x04D8;
    private const ushort RT_FAS = 0x0532;
    private const ushort RT_TXT = 0x0537;
    private const ushort RT_DVB = 0x053C;
    private const ushort RT_DCL = 0x0546;

    private static readonly Dictionary<ushort, string> VlxResourceTypes = new()
    {
        { RT_LSP, "LSP (LISP source)" },
        { RT_PRV, "PRV (private data)" },
        { RT_FAS, "FAS (compiled bytecode)" },
        { RT_TXT, "TXT (text/comments)" },
        { RT_DVB, "DVB (VBA code)" },
        { RT_DCL, "DCL (dialog definition)" },
    };

    // ── ADS internal name → AutoLISP user-facing name mapping ─────────────
    // FAS bytecode stores C-level ADS SDK names; map them to the AutoLISP
    // equivalents the programmer actually wrote.
    private static readonly Dictionary<string, string> AdsToLisp = new(StringComparer.OrdinalIgnoreCase)
    {
        // ── General / I-O ──────────────────────────────────────────────────
        { "ads-cmd",        "command" },
        { "ads-prin1",      "prin1" },
        { "ads-princ",      "princ" },
        { "ads-print",      "print" },
        { "ads-prompt",     "prompt" },
        { "ads-alert",      "alert" },
        { "ads-terpri",     "terpri" },

        // ── User input ─────────────────────────────────────────────────────
        { "ads-getint",     "getint" },
        { "ads-getreal",    "getreal" },
        { "ads-getstring",  "getstring" },
        { "ads-getpoint",   "getpoint" },
        { "ads-getcorner",  "getcorner" },
        { "ads-getdist",    "getdist" },
        { "ads-getangle",   "getangle" },
        { "ads-getorient",  "getorient" },
        { "ads-getkword",   "getkword" },
        { "ads-initget",    "initget" },
        { "ads-grread",     "grread" },

        // ── System variables ───────────────────────────────────────────────
        { "ads-getvar",     "getvar" },
        { "ads-setvar",     "setvar" },

        // ── Selection sets ─────────────────────────────────────────────────
        { "ads-ssget",      "ssget" },
        { "ads-ssname",     "ssname" },
        { "ads-sslength",   "sslength" },
        { "ads-ssadd",      "ssadd" },
        { "ads-ssdel",      "ssdel" },
        { "ads-ssmemb",     "ssmemb" },
        { "ads-sssetfirst", "sssetfirst" },

        // ── Entity access ──────────────────────────────────────────────────
        { "ads-entget",     "entget" },
        { "ads-entmod",     "entmod" },
        { "ads-entmake",    "entmake" },
        { "ads-entdel",     "entdel" },
        { "ads-entlast",    "entlast" },
        { "ads-entsel",     "entsel" },
        { "ads-entnext",    "entnext" },
        { "ads-entupd",     "entupd" },
        { "ads-nentsel",    "nentsel" },
        { "ads-nentselp",   "nentselp" },
        { "ads-handent",    "handent" },

        // ── Table / dictionary ─────────────────────────────────────────────
        { "ads-tblnext",    "tblnext" },
        { "ads-tblsearch",  "tblsearch" },
        { "ads-tblobjname", "tblobjname" },
        { "ads-namedobjdict","namedobjdict" },
        { "ads-dictsearch",  "dictsearch" },
        { "ads-dictnext",    "dictnext" },
        { "ads-dictadd",     "dictadd" },
        { "ads-dictremove",  "dictremove" },
        { "ads-dictrename",  "dictrename" },

        // ── String functions ───────────────────────────────────────────────
        { "ads-strcat",     "strcat" },
        { "ads-strlen",     "strlen" },
        { "ads-substr",     "substr" },
        { "ads-strcase",    "strcase" },
        { "ads-read",       "read" },

        // ── Numeric conversion ─────────────────────────────────────────────
        { "ads-atoi",       "atoi" },
        { "ads-atof",       "atof" },
        { "ads-itoa",       "itoa" },
        { "ads-rtos",       "rtos" },
        { "ads-angtos",     "angtos" },
        { "ads-angtof",     "angtof" },
        { "ads-distof",     "distof" },
        { "ads-fix",        "fix" },
        { "ads-float",      "float" },
        { "ads-cvunit",     "cvunit" },

        // ── Math ───────────────────────────────────────────────────────────
        { "ads-abs",        "abs" },
        { "ads-max",        "max" },
        { "ads-min",        "min" },
        { "ads-rem",        "rem" },
        { "ads-gcd",        "gcd" },
        { "ads-sin",        "sin" },
        { "ads-cos",        "cos" },
        { "ads-atan",       "atan" },
        { "ads-sqrt",       "sqrt" },
        { "ads-expt",       "expt" },
        { "ads-exp",        "exp" },
        { "ads-log",        "log" },

        // ── Geometry ───────────────────────────────────────────────────────
        { "ads-distance",   "distance" },
        { "ads-angle",      "angle" },
        { "ads-polar",      "polar" },
        { "ads-inters",     "inters" },
        { "ads-trans",      "trans" },
        { "ads-osnap",      "osnap" },
        { "ads-textbox",    "textbox" },

        // ── File I/O ───────────────────────────────────────────────────────
        { "ads-open",       "open" },
        { "ads-close",      "close" },
        { "ads-read-line",  "read-line" },
        { "ads-write-line", "write-line" },
        { "ads-read-char",  "read-char" },
        { "ads-write-char", "write-char" },
        { "ads-findfile",   "findfile" },

        // ── Display / redraw ───────────────────────────────────────────────
        { "ads-redraw",     "redraw" },
        { "ads-grdraw",     "grdraw" },
        { "ads-grvecs",     "grvecs" },
        { "ads-grtext",     "grtext" },
        { "ads-textscr",    "textscr" },
        { "ads-graphscr",   "graphscr" },
        { "ads-textpage",   "textpage" },

        // ── List functions ─────────────────────────────────────────────────
        { "ads-cons",       "cons" },
        { "ads-list",       "list" },
        { "ads-append",     "append" },
        { "ads-assoc",      "assoc" },
        { "ads-subst",      "subst" },
        { "ads-length",     "length" },
        { "ads-nth",        "nth" },
        { "ads-member",     "member" },
        { "ads-last",       "last" },
        { "ads-reverse",    "reverse" },
        { "ads-foreach",    "foreach" },
        { "ads-mapcar",     "mapcar" },
        { "ads-apply",      "apply" },
        { "ads-lambda",     "lambda" },
        { "ads-vl-sort",    "vl-sort" },
        { "ads-vl-remove",  "vl-remove" },
        { "ads-vl-remove-if",     "vl-remove-if" },
        { "ads-vl-remove-if-not", "vl-remove-if-not" },
        { "ads-vl-position", "vl-position" },

        // ── Type / predicate ───────────────────────────────────────────────
        { "ads-type",       "type" },
        { "ads-numberp",    "numberp" },
        { "ads-zerop",      "zerop" },
        { "ads-minusp",     "minusp" },
        { "ads-listp",      "listp" },
        { "ads-null",       "null" },
        { "ads-atom",       "atom" },
        { "ads-boundp",     "boundp" },

        // ── Misc ───────────────────────────────────────────────────────────
        { "ads-setq",       "setq" },
        { "ads-eval",       "eval" },
        { "ads-load",       "load" },
        { "ads-xload",      "xload" },
        { "ads-xunload",    "xunload" },
        { "ads-gc",         "gc" },
        { "ads-mem",        "mem" },
        { "ads-ver",        "ver" },
        { "ads-getenv",     "getenv" },
        { "ads-setenv",     "setenv" },
        { "ads-getcfg",     "getcfg" },
        { "ads-setcfg",     "setcfg" },
        { "ads-regapp",     "regapp" },
        { "ads-xdroom",     "xdroom" },
        { "ads-xdsize",     "xdsize" },
    };

    // ── VLISP compiler intrinsics (_al-*) → AutoLISP mapping ──────────────
    // The VLISP compiler emits calls to _al-* runtime helpers for certain
    // AutoLISP constructs.  Map them back to what the programmer wrote.
    private static readonly Dictionary<string, string> AlIntrinsics = new(StringComparer.OrdinalIgnoreCase)
    {
        { "_al-bind-alist",    "foreach" },
        { "_al-mapcar",        "mapcar" },
        { "_al-apply",         "apply" },
        { "_al-lambda",        "lambda" },
        { "_al-vlax-for",      "vlax-for" },
        { "_al-vl-sort",       "vl-sort" },
        { "_al-vl-sort-i",     "vl-sort-i" },
        { "_al-vl-remove-if",       "vl-remove-if" },
        { "_al-vl-remove-if-not",   "vl-remove-if-not" },
        { "_al-vl-member-if",       "vl-member-if" },
        { "_al-vl-member-if-not",   "vl-member-if-not" },
        { "_al-catch-all-apply",    "vl-catch-all-apply" },
    };

    // Translate an internal name (ads-* or _al-*) to AutoLISP equivalent.
    private static string TranslateInternalName(string name)
    {
        if (AdsToLisp.TryGetValue(name, out var lisp))
            return lisp;

        if (AlIntrinsics.TryGetValue(name, out var al))
            return al;

        // Generic fallback: strip "ads-" prefix
        if (name.StartsWith("ads-", StringComparison.OrdinalIgnoreCase))
            return name.Substring(4);

        return name;
    }

    private static void ExtractVlxContainer(byte[] data, VlxInfo info)
    {
        // Try structured VRTLIB-1 parsing first
        if (TryParseVrtlib(data, info))
        {
            info.ModuleCount = info.Modules.Count;
            return;
        }

        // Fallback: scan for FAS text signatures and DCL/TXT markers
        ExtractEmbeddedFas(data, info);
        ExtractEmbeddedDcl(data, info);
        ExtractEmbeddedText(data, info);

        info.ModuleCount = info.Modules.Count;
    }

    /// <summary>
    /// Parse VLX using the structured VRTLIB-1 resource block format.
    /// Returns true if the header was found and at least one resource extracted.
    /// </summary>
    private static bool TryParseVrtlib(byte[] data, VlxInfo info)
    {
        // Look for "VRTLIB-1" signature (8 bytes) anywhere in the first 64 bytes
        byte[] vrtSig = Encoding.ASCII.GetBytes("VRTLIB-1");
        int sigPos = -1;
        for (int i = 0; i <= Math.Min(64, data.Length - vrtSig.Length); i++)
        {
            if (data.AsSpan(i, vrtSig.Length).SequenceEqual(vrtSig))
            { sigPos = i; break; }
        }
        if (sigPos < 0) return false;

        info.FormatName += " [VRTLIB-1 container]";

        // VRTLIB-1 header: [8 "VRTLIB-1"][4 totalSize]
        // Then resource blocks follow immediately.
        // Reference: VLXSpliter.cls — VLX_Split()
        int pos = sigPos + vrtSig.Length;
        if (pos + 4 > data.Length) return false;

        int totalSize = (int)BitConverter.ToUInt32(data, pos);
        pos += 4;  // now at offset 12 — start of first resource block

        int moduleIndex = 0;

        while (pos + 7 < data.Length)
        {
            int basePosition = pos;

            // Read block size (4 bytes) — includes type + nameLen + name + data
            int blockSize = (int)BitConverter.ToUInt32(data, pos);
            pos += 4;

            if (blockSize <= 0) break;  // end marker
            if (basePosition + 4 + blockSize > data.Length) break;  // truncated

            // Read resource type (2 bytes)
            ushort resType = BitConverter.ToUInt16(data, pos);
            pos += 2;

            // Read length-prefixed name (1-byte length + chars)
            // Reference: VLXSpliter.cls line 114: OutputFileName.Name = .FixedString(.int8)
            byte nameLen = data[pos];
            pos++;
            string resName = nameLen > 0 && pos + nameLen <= data.Length
                ? Encoding.ASCII.GetString(data, pos, nameLen)
                : "";
            pos += nameLen;

            // Remaining bytes in this block are the resource data
            int dataStart = pos;
            int dataLen = blockSize - (pos - basePosition - 4);
            // Clamp: blockSize counts from after the 4-byte size field
            // Actually: data written = blockSize - (position - basePosition) per VB6
            // where position has already consumed size(4) + type(2) + nameLen(1) + name(nameLen)
            dataLen = blockSize - (pos - basePosition);
            if (dataLen < 0) dataLen = 0;
            if (dataStart + dataLen > data.Length) dataLen = data.Length - dataStart;

            string typeLabel = VlxResourceTypes.TryGetValue(resType, out var tl)
                ? tl : $"Unknown (0x{resType:X4})";

            // Classify and store the resource
            if (resType == RT_FAS)
            {
                info.Modules.Add(new VlxModule
                {
                    Index  = moduleIndex++,
                    Offset = dataStart,
                    Size   = dataLen,
                    Name   = string.IsNullOrEmpty(resName) ? $"FAS_{moduleIndex}" : resName,
                });
            }

            if (resType == RT_DCL || resType == RT_TXT || resType == RT_LSP || resType == RT_DVB)
            {
                string content = "";
                if (dataLen > 0 && dataStart + dataLen <= data.Length)
                {
                    content = Encoding.ASCII.GetString(data, dataStart,
                        Math.Min(dataLen, 8192));
                    content = content.TrimEnd('\0', '\r', '\n', ' ');
                    if (dataLen > 8192)
                        content += "\n; [truncated at 8192 chars]";
                }

                info.EmbeddedFiles.Add(new VlxEmbeddedFile
                {
                    FileType = typeLabel + (string.IsNullOrEmpty(resName) ? "" : $" ({resName})"),
                    Offset   = dataStart,
                    Size     = dataLen,
                    Content  = content,
                });
            }

            if (resType == RT_PRV)
            {
                string prvContent = "";
                if (dataLen > 0 && dataStart + dataLen <= data.Length)
                {
                    prvContent = Encoding.ASCII.GetString(data, dataStart,
                        Math.Min(dataLen, 4096)).TrimEnd('\0');
                }
                info.EmbeddedFiles.Add(new VlxEmbeddedFile
                {
                    FileType = $"PRV (private data{(string.IsNullOrEmpty(resName) ? "" : $": {resName}")})",
                    Offset   = dataStart,
                    Size     = dataLen,
                    Content  = string.IsNullOrWhiteSpace(prvContent) ? $"[binary data: {dataLen:N0} bytes]" : prvContent,
                });
            }

            // Advance past the block data, then align to 4-byte boundary
            // Reference: VLXSpliter.cls line 146: .Position = (.Position + 3) And Not 3
            pos = dataStart + dataLen;
            pos = (pos + 3) & ~3;
        }

        return info.Modules.Count > 0 || info.EmbeddedFiles.Count > 0;
    }

    private static void ExtractEmbeddedFas(byte[] data, VlxInfo info)
    {
        // Look for text FAS signatures inside the VLX binary
        byte[][] sigs =
        [
            Encoding.ASCII.GetBytes("\r\n FAS4-FILE"),
            Encoding.ASCII.GetBytes("\r\n FAS3-FILE"),
            Encoding.ASCII.GetBytes("\r\n FAS2-FILE"),
            Encoding.ASCII.GetBytes("\r\n FAS-FILE"),
        ];

        var positions = new List<int>();

        foreach (var sig in sigs)
        {
            for (int i = 0; i <= data.Length - sig.Length; i++)
            {
                if (data.AsSpan(i, sig.Length).SequenceEqual(sig))
                    positions.Add(i);
            }
        }

        // Also look for binary FAS magic sequences
        byte[][] binSigs =
        [
            new byte[] { 0x0C, 0x0E }, new byte[] { 0x0C, 0x0F },
            new byte[] { 0x0C, 0x10 }, new byte[] { 0x0C, 0x12 },
            new byte[] { 0x14, 0x0E }, new byte[] { 0x14, 0x0F },
        ];

        foreach (var sig in binSigs)
        {
            for (int i = 4; i < data.Length - 1; i++)
            {
                if (data[i] == sig[0] && data[i + 1] == sig[1]
                 && (i == 0 || data[i - 1] == 0x00 || data[i - 1] > 0x10))
                    positions.Add(i);
            }
        }

        positions.Sort();
        var seen = new HashSet<int>();

        for (int i = 0; i < positions.Count; i++)
        {
            int off = positions[i];
            if (!seen.Add(off)) continue;

            int size = (i + 1 < positions.Count) ? positions[i + 1] - off : data.Length - off;
            string name = TryReadNearbyName(data, off) ?? $"Module_{i + 1}";

            info.Modules.Add(new VlxModule
            {
                Index  = i,
                Offset = off,
                Size   = size,
                Name   = name,
            });
        }
    }

    private static void ExtractEmbeddedDcl(byte[] data, VlxInfo info)
    {
        // DCL files contain dialog definitions.  They're plain ASCII text
        // starting with keywords like "dialog", "tile:", "action:", etc.
        // Scan for "dialog : " or ": dialog" patterns.

        byte[] dclSig = Encoding.ASCII.GetBytes("dialog");
        for (int i = 0; i < data.Length - 20; i++)
        {
            if (!MatchBytes(data, i, dclSig)) continue;

            // Walk back to find start of text block
            int blockStart = i;
            while (blockStart > 0 && data[blockStart - 1] >= 0x20) blockStart--;

            // Walk forward to find end of text block
            int blockEnd = i;
            int nonPrint = 0;
            while (blockEnd < data.Length && nonPrint < 3)
            {
                byte b = data[blockEnd];
                if (b >= 0x20 || b == 0x09 || b == 0x0A || b == 0x0D)
                { blockEnd++; nonPrint = 0; }
                else
                { blockEnd++; nonPrint++; }
            }

            int blockLen = blockEnd - blockStart;
            if (blockLen < 30) continue;

            string text = Encoding.ASCII.GetString(data, blockStart, blockLen)
                          .Trim('\r', '\n', ' ', '\0');

            if (text.Contains('{') || text.Contains("action")
             || text.Contains("tile") || text.Contains("button"))
            {
                var dcl = new VlxEmbeddedFile
                {
                    FileType = "DCL (Dialog Definition)",
                    Offset   = blockStart,
                    Size     = blockLen,
                    Content  = text.Length > 4096 ? text[..4096] + "\n; [truncated]" : text,
                };
                info.EmbeddedFiles.Add(dcl);
                i = blockEnd;   // skip past this block
            }
        }
    }

    private static void ExtractEmbeddedText(byte[] data, VlxInfo info)
    {
        // Find large printable text blocks (TXT files embedded in VLX)
        int runStart = -1;
        int runLen   = 0;

        for (int i = 0; i <= data.Length; i++)
        {
            bool printable = i < data.Length &&
                (data[i] >= 0x20 || data[i] == 0x09 || data[i] == 0x0A || data[i] == 0x0D);

            if (printable)
            {
                if (runStart < 0) { runStart = i; runLen = 0; }
                runLen++;
            }
            else
            {
                if (runStart >= 0 && runLen >= 80)
                {
                    string text = Encoding.ASCII.GetString(data, runStart, runLen).Trim();
                    // Filter: must look like a real text file (spaces, newlines, words)
                    int spaces  = text.Count(c => c == ' ');
                    int newlines = text.Count(c => c == '\n');
                    if (spaces > runLen / 10 && newlines > 2)
                    {
                        // Check not already captured as DCL
                        bool alreadyCaptured = info.EmbeddedFiles.Any(f =>
                            f.Offset <= runStart && f.Offset + f.Size >= runStart + runLen);
                        if (!alreadyCaptured)
                        {
                            info.EmbeddedFiles.Add(new VlxEmbeddedFile
                            {
                                FileType = "TXT (embedded text)",
                                Offset   = runStart,
                                Size     = runLen,
                                Content  = text.Length > 2048 ? text[..2048] + "\n[truncated]" : text,
                            });
                        }
                    }
                }
                runStart = -1;
                runLen   = 0;
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  STRING EXTRACTION  (from raw data + decrypted data)
    // ═════════════════════════════════════════════════════════════════════════

    private static void ExtractAllStrings(byte[] data, VlxInfo info)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ExtractStringsFrom(data, info, seen, "raw");

        if (info.DecryptedData != null && info.DecryptedData != data)
            ExtractStringsFrom(info.DecryptedData, info, seen, "decrypted");
    }

    private static void ExtractStringsFrom(byte[] src, VlxInfo info,
                                            HashSet<string> seen, string source)
    {
        // Strategy 1: length-prefixed (1-byte len + chars)
        for (int i = 0; i < src.Length - 4; i++)
        {
            byte len = src[i];
            if (len < 3 || len > 120 || i + 1 + len > src.Length) continue;
            bool ok = true;
            for (int j = i + 1; j < i + 1 + len; j++)
                if (src[j] < 32 || src[j] >= 127) { ok = false; break; }
            if (!ok) continue;
            string s = Encoding.ASCII.GetString(src, i + 1, len);
            if (IsUsefulString(s) && seen.Add(s))
                info.RawStrings.Add(new VlxString { Value = s, Offset = i, Method = source+"/len" });
        }

        // Strategy 2: null-terminated runs
        int rs = -1;
        for (int i = 0; i <= src.Length; i++)
        {
            bool p = i < src.Length && src[i] >= 32 && src[i] < 127;
            if (p) { if (rs < 0) rs = i; }
            else
            {
                if (rs >= 0)
                {
                    int rl = i - rs;
                    if (rl >= 4)
                    {
                        string s = Encoding.ASCII.GetString(src, rs, Math.Min(rl, 256)).Trim();
                        if (IsUsefulString(s) && seen.Add(s))
                            info.RawStrings.Add(new VlxString { Value = s, Offset = rs, Method = source+"/run" });
                    }
                    rs = -1;
                }
            }
        }
    }

    private static bool IsUsefulString(string s)
    {
        if (s.Length < 2) return false;
        if (s.All(c => char.IsDigit(c) || c == '.' || c == '-')) return false;
        if (s.Distinct().Count() <= 1) return false;
        return true;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  SYMBOL CLASSIFICATION
    // ═════════════════════════════════════════════════════════════════════════

    private static void ClassifySymbols(VlxInfo info)
    {
        foreach (var raw in info.RawStrings)
        {
            string s = raw.Value.Trim();

            if (s.StartsWith("C:", StringComparison.OrdinalIgnoreCase)
             && s.Length > 2 && s[2..].All(IsLispSymbolChar))
            { info.Commands.Add(s.ToUpperInvariant()); continue; }

            if (s.StartsWith("*") && s.EndsWith("*") && s.Length > 2)
            { info.GlobalVars.Add(s); continue; }

            if (s.Length >= 2 && s.All(IsLispSymbolChar) && s.Contains('-'))
            { info.Functions.Add(s); continue; }

            if (s.Length >= 4)
                info.StringLiterals.Add(s);
        }

        info.Commands      = info.Commands.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList();
        info.Functions     = info.Functions.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList();
        info.GlobalVars    = info.GlobalVars.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList();
        info.Symbols       = info.Symbols.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).Take(300).ToList();
        info.StringLiterals = info.StringLiterals.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList();
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  HELPERS
    // ═════════════════════════════════════════════════════════════════════════

    private static string? TryReadNearbyName(byte[] data, int offset)
    {
        int start = Math.Max(0, offset - 32);
        for (int i = start; i < offset && i < data.Length - 3; i++)
        {
            if (data[i] < 32 || data[i] >= 127) continue;
            var sb = new StringBuilder();
            int j = i;
            while (j < data.Length && data[j] >= 32 && data[j] < 127) sb.Append((char)data[j++]);
            string candidate = sb.ToString().Trim();
            if (candidate.Length >= 3 && candidate.All(c =>
                char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.'))
                return candidate;
        }
        return null;
    }

    private static bool MatchBytes(byte[] data, int offset, byte[] pattern)
    {
        if (offset + pattern.Length > data.Length) return false;
        for (int i = 0; i < pattern.Length; i++)
            if (data[offset + i] != pattern[i]) return false;
        return true;
    }

    private static string HexDump(byte[] data, int offset, int length)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < length; i += 16)
        {
            sb.Append($"{offset + i:X4}  ");
            int rowLen = Math.Min(16, length - i);
            for (int j = 0; j < 16; j++)
            {
                if (j < rowLen) sb.Append($"{data[offset + i + j]:X2} ");
                else            sb.Append("   ");
                if (j == 7)     sb.Append(' ');
            }
            sb.Append(" |");
            for (int j = 0; j < rowLen; j++)
            {
                byte b = data[offset + i + j];
                sb.Append(b >= 32 && b < 127 ? (char)b : '.');
            }
            sb.AppendLine("|");
        }
        return sb.ToString();
    }
}  // end class VlxAnalyzer
