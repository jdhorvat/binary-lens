using System.IO;
using System.Text;

namespace BinaryLens.Analysis;

// ═══════════════════════════════════════════════════════════════════════════
//  PycDecoder  --  Self-contained Python bytecode decoder
//  Handles .pyc files from Python 2.7 through 3.13
//  No Python installation required.
//
//  PIPELINE
//    1. Read header  (magic → version, flags, timestamp, source size)
//    2. Read marshal data  (binary object tree starting after header)
//    3. Parse code object  (version-specific field order)
//    4. Disassemble bytecode  (version-specific instruction width + opcodes)
//    5. Recurse into nested code objects (lambdas, inner functions, classes)
// ═══════════════════════════════════════════════════════════════════════════

public static class PycDecoder
{
    public static PycDecodeResult Decode(string filePath)
    {
        var result = new PycDecodeResult();
        try
        {
            byte[] raw = File.ReadAllBytes(filePath);
            ReadHeader(raw, result);
            if (result.Error != null) return result;

            int offset = result.HeaderSize;
            var reader = new MarshalReader(raw, offset, result.PythonVersionFloat);
            object? obj = reader.ReadObject();

            if (obj is PythonCodeObject code)
            {
                result.RootCode    = code;
                result.Disassembly = BytecodeDisassembler.DisassembleAll(
                                         code, result.PythonVersionFloat);
            }
            else
            {
                result.Error = $"Expected code object at offset {offset}, got {obj?.GetType().Name ?? "null"}";
            }
        }
        catch (Exception ex)
        {
            result.Error = $"Decode failed: {ex.Message}";
        }
        return result;
    }

    // ── Header ───────────────────────────────────────────────────────────────

    private static void ReadHeader(byte[] raw, PycDecodeResult r)
    {
        if (raw.Length < 8)
        {
            r.Error = "File too short to be a valid .pyc";
            return;
        }

        ushort magic = BitConverter.ToUInt16(raw, 0);
        r.MagicNumber = magic;

        if (!MagicToVersion.TryGetValue(magic, out var ver))
            ver = ("?.?", 0f);

        r.PythonVersion      = $"Python {ver.display}";
        r.PythonVersionFloat = ver.number;

        // Python 3.8+ has a 4-byte flags field between magic and timestamp
        bool hasFlags = r.PythonVersionFloat >= 3.8f;
        r.HeaderSize = hasFlags ? 16 : (r.PythonVersionFloat >= 3.3f ? 12 : 8);

        if (hasFlags && raw.Length >= 8)
        {
            uint flags      = BitConverter.ToUInt32(raw, 4);
            r.Flags         = flags;
            r.IsHashBased   = (flags & 0x01) != 0;

            if (!r.IsHashBased && raw.Length >= 16)
            {
                r.SourceTimestamp = DateTimeOffset
                    .FromUnixTimeSeconds(BitConverter.ToUInt32(raw, 8))
                    .UtcDateTime;
                r.SourceSize = BitConverter.ToUInt32(raw, 12);
            }
        }
        else if (raw.Length >= 8)
        {
            r.SourceTimestamp = DateTimeOffset
                .FromUnixTimeSeconds(BitConverter.ToUInt32(raw, 4))
                .UtcDateTime;
            if (raw.Length >= 12)
                r.SourceSize = BitConverter.ToUInt32(raw, 8);
        }
    }

    // ── Magic number → (display string, comparable float) ───────────────────

    private static readonly Dictionary<ushort, (string display, float number)> MagicToVersion = new()
    {
        { 20121, ("1.5",   1.5f)  }, { 50428, ("1.6",  1.6f)  },
        { 60202, ("2.0",   2.0f)  }, { 60717, ("2.1",  2.1f)  },
        { 60823, ("2.2",   2.2f)  }, { 62011, ("2.3",  2.3f)  },
        { 62061, ("2.4",   2.4f)  }, { 62131, ("2.5",  2.5f)  },
        { 62161, ("2.6",   2.6f)  }, { 62211, ("2.7",  2.7f)  },
        { 3130,  ("3.0",   3.0f)  }, { 3150,  ("3.1",  3.1f)  },
        { 3180,  ("3.2",   3.2f)  }, { 3230,  ("3.3",  3.3f)  },
        { 3250,  ("3.3",   3.3f)  }, { 3310,  ("3.4",  3.4f)  },
        { 3320,  ("3.4",   3.4f)  }, { 3350,  ("3.5",  3.5f)  },
        { 3351,  ("3.5",   3.5f)  }, { 3360,  ("3.5",  3.5f)  },
        { 3361,  ("3.5",   3.5f)  }, { 3370,  ("3.6",  3.6f)  },
        { 3371,  ("3.6",   3.6f)  }, { 3372,  ("3.6",  3.6f)  },
        { 3378,  ("3.6",   3.6f)  }, { 3379,  ("3.6",  3.6f)  },
        { 3390,  ("3.7",   3.7f)  }, { 3394,  ("3.7",  3.7f)  },
        { 3395,  ("3.7",   3.7f)  }, { 3400,  ("3.8",  3.8f)  },
        { 3410,  ("3.8",   3.8f)  }, { 3413,  ("3.8",  3.8f)  },
        { 3420,  ("3.9",   3.9f)  }, { 3425,  ("3.9",  3.9f)  },
        { 3430,  ("3.10",  3.10f) }, { 3439,  ("3.10", 3.10f) },
        { 3450,  ("3.11",  3.11f) }, { 3495,  ("3.11", 3.11f) },
        { 3520,  ("3.12",  3.12f) }, { 3531,  ("3.12", 3.12f) },
        { 3550,  ("3.13",  3.13f) }, { 3571,  ("3.13", 3.13f) },
    };
}

// ═══════════════════════════════════════════════════════════════════════════
//  Result + Code Object models
// ═══════════════════════════════════════════════════════════════════════════

public class PycDecodeResult
{
    public ushort   MagicNumber         { get; set; }
    public string   PythonVersion       { get; set; } = "";
    public float    PythonVersionFloat  { get; set; }
    public uint     Flags               { get; set; }
    public bool     IsHashBased         { get; set; }
    public DateTime SourceTimestamp     { get; set; }
    public uint     SourceSize          { get; set; }
    public int      HeaderSize          { get; set; }
    public PythonCodeObject? RootCode   { get; set; }
    public string   Disassembly         { get; set; } = "";
    public string?  Error               { get; set; }

    public string TimestampDisplay => SourceTimestamp == default
        ? "N/A" : SourceTimestamp.ToString("yyyy-MM-dd HH:mm:ss UTC");
    public string MagicDisplay     => $"0x{MagicNumber:X4}";
    public string FlagsDisplay     => $"0x{Flags:X8}";
}

public class PythonCodeObject
{
    public string   Name            { get; set; } = "<unknown>";
    public string?  QualName        { get; set; }
    public string?  Filename        { get; set; }
    public int      FirstLineNo     { get; set; }
    public int      ArgCount        { get; set; }
    public int      PosOnlyArgCount { get; set; }
    public int      KwOnlyArgCount  { get; set; }
    public int      NumLocals       { get; set; }
    public int      StackSize       { get; set; }
    public int      Flags           { get; set; }
    public byte[]   Code            { get; set; } = [];
    public List<object?> Consts     { get; set; } = [];
    public List<string>  Names      { get; set; } = [];
    public List<string>  VarNames   { get; set; } = [];
    public List<string>  FreeVars   { get; set; } = [];
    public List<string>  CellVars   { get; set; } = [];
    public byte[]   Lnotab          { get; set; } = [];
    public byte[]   Linetable       { get; set; } = [];
    public byte[]   ExceptionTable  { get; set; } = [];
}

// ═══════════════════════════════════════════════════════════════════════════
//  Marshal Reader
//  Implements Python's binary object serialisation format.
//  Reference: cpython/Lib/marshal.py  and  Objects/marshal.c
// ═══════════════════════════════════════════════════════════════════════════

internal class MarshalReader
{
    private readonly byte[] _data;
    private int             _pos;
    private readonly float  _pyVer;
    private readonly List<object?> _refTable = [];

    public MarshalReader(byte[] data, int startPos, float pyVer)
    {
        _data  = data;
        _pos   = startPos;
        _pyVer = pyVer;
    }

    public object? ReadObject()
    {
        if (_pos >= _data.Length) return null;

        byte typeByte = _data[_pos++];
        bool addRef   = (typeByte & 0x80) != 0;
        char type     = (char)(typeByte & 0x7F);

        int refIdx = -1;
        if (addRef)
        {
            refIdx = _refTable.Count;
            _refTable.Add(null);
        }

        object? result = type switch
        {
            '0' or '\0' => null,
            'N'         => null,                     // None
            'F'         => false,
            'T'         => true,
            'S'         => "StopIteration",
            '.'         => "...",                    // Ellipsis
            'i'         => (object)ReadInt32(),
            'I'         => (object)ReadInt64(),
            'l'         => ReadPythonLong(),
            'f'         => ReadAsciiFloat(),
            'g'         => ReadBinaryFloat(),
            'x'         => ReadAsciiComplex(),
            'y'         => ReadBinaryComplex(),
            's'         => ReadByteString(),         // bytes
            't'         => ReadCountedString(),      // interned str
            'u'         => ReadUnicodeString(),
            'a'         => ReadAsciiString(),
            'A'         => ReadAsciiString(),        // interned
            'z'         => ReadShortAscii(),
            'Z'         => ReadShortAscii(),         // interned
            ')'         => ReadSmallTuple(),
            '('         => ReadTuple(),
            '<'         => ReadFrozenset(),
            '['         => ReadList(),
            '{'         => ReadDict(),
            'c'         => ReadCodeObject(),
            'C'         => ReadCodeObject(),         // old-style (Python 1.x)
            'r'         => ReadRef(),
            _           => null,
        };

        if (refIdx >= 0) _refTable[refIdx] = result;
        return result;
    }

    // ── Primitives ────────────────────────────────────────────────────────────

    private int    ReadInt32()  { _pos += 4; return BitConverter.ToInt32(_data, _pos - 4); }
    private long   ReadInt64()  { _pos += 8; return BitConverter.ToInt64(_data, _pos - 8); }
    private byte   ReadByte()   => _data[_pos++];
    private short  ReadInt16()  { int lo = _data[_pos++]; int hi = _data[_pos++]; return (short)(lo | (hi << 8)); }

    private object ReadPythonLong()
    {
        // Python long: 2-byte count followed by count 2-byte "digits" (base 2^15)
        int n = ReadInt32();
        bool negative = n < 0;
        int count = Math.Abs(n);
        long value = 0;
        for (int i = 0; i < count; i++)
        {
            long digit = ReadInt16();
            value |= digit << (i * 15);
        }
        return negative ? -value : value;
    }

    private double ReadAsciiFloat()
    {
        int len = ReadByte();
        string s = Encoding.ASCII.GetString(_data, _pos, len);
        _pos += len;
        return double.TryParse(s, System.Globalization.NumberStyles.Any,
                               System.Globalization.CultureInfo.InvariantCulture, out var d) ? d : 0.0;
    }

    private double ReadBinaryFloat()
    {
        double d = BitConverter.ToDouble(_data, _pos);
        _pos += 8;
        return d;
    }

    private string ReadAsciiComplex()
    {
        double re = ReadAsciiFloat();
        double im = ReadAsciiFloat();
        return $"{re}+{im}j";
    }

    private string ReadBinaryComplex()
    {
        double re = ReadBinaryFloat();
        double im = ReadBinaryFloat();
        return $"{re}+{im}j";
    }

    private byte[] ReadByteString()
    {
        int len = ReadInt32();
        if (len < 0 || _pos + len > _data.Length) return [];
        var bytes = _data[_pos..(_pos + len)];
        _pos += len;
        return bytes;
    }

    private string ReadCountedString()
    {
        int len = ReadInt32();
        if (len < 0 || _pos + len > _data.Length) return "";
        string s = Encoding.UTF8.GetString(_data, _pos, len);
        _pos += len;
        return s;
    }

    private string ReadUnicodeString()
    {
        int len = ReadInt32();
        if (len < 0 || _pos + len > _data.Length) return "";
        string s = Encoding.UTF8.GetString(_data, _pos, len);
        _pos += len;
        return s;
    }

    private string ReadAsciiString()
    {
        int len = ReadInt32();
        if (len < 0 || _pos + len > _data.Length) return "";
        string s = Encoding.ASCII.GetString(_data, _pos, len);
        _pos += len;
        return s;
    }

    private string ReadShortAscii()
    {
        int len = ReadByte();
        string s = Encoding.ASCII.GetString(_data, _pos, len);
        _pos += len;
        return s;
    }

    private object?[] ReadSmallTuple()
    {
        int n = ReadByte();
        return ReadNObjects(n);
    }

    private object?[] ReadTuple()
    {
        int n = ReadInt32();
        return ReadNObjects(n);
    }

    private object? ReadFrozenset()
    {
        int n = ReadInt32();
        return ReadNObjects(n);
    }

    private List<object?> ReadList()
    {
        int n = ReadInt32();
        var list = new List<object?>(n);
        for (int i = 0; i < n; i++) list.Add(ReadObject());
        return list;
    }

    private Dictionary<string, object?> ReadDict()
    {
        var dict = new Dictionary<string, object?>();
        while (true)
        {
            var key = ReadObject();
            if (key == null) break;
            var val = ReadObject();
            dict[key.ToString() ?? ""] = val;
        }
        return dict;
    }

    private object?[] ReadNObjects(int n)
    {
        var arr = new object?[n];
        for (int i = 0; i < n; i++) arr[i] = ReadObject();
        return arr;
    }

    private object? ReadRef()
    {
        int idx = ReadInt32();
        return idx < _refTable.Count ? _refTable[idx] : null;
    }

    // ── Code Object ───────────────────────────────────────────────────────────
    //
    //  Field order varies by Python version:
    //
    //  2.7:  argcount nlocals stacksize flags code consts names varnames
    //        freevars cellvars filename name firstlineno lnotab
    //
    //  3.0-3.7: argcount kwonlyargcount nlocals stacksize flags code consts
    //           names varnames freevars cellvars filename name firstlineno lnotab
    //
    //  3.8:  argcount posonlyargcount kwonlyargcount nlocals stacksize flags
    //        code consts names varnames freevars cellvars filename name
    //        firstlineno lnotab
    //
    //  3.11: argcount posonlyargcount kwonlyargcount nlocals stacksize flags
    //        code consts names varnames freevars cellvars filename name qualname
    //        firstlineno linetable exceptiontable
    //
    //  3.12+: same as 3.11

    private PythonCodeObject ReadCodeObject()
    {
        var co = new PythonCodeObject();

        co.ArgCount        = ReadInt32();
        if (_pyVer >= 3.8f) co.PosOnlyArgCount = ReadInt32();
        if (_pyVer >= 3.0f) co.KwOnlyArgCount  = ReadInt32();
        if (_pyVer < 3.11f) co.NumLocals       = ReadInt32();
        co.StackSize       = ReadInt32();
        co.Flags           = ReadInt32();

        // Code bytes
        var codeObj = ReadObject();
        co.Code = codeObj switch
        {
            byte[] b  => b,
            object?[] a => a.Cast<byte?>().Select(b => b ?? 0).ToArray(),
            _          => []
        };

        // Constant pool
        co.Consts   = ReadObjectAsList();
        co.Names    = ReadStringList();
        co.VarNames = ReadStringList();

        if (_pyVer >= 3.0f)
        {
            co.FreeVars  = ReadStringList();
            co.CellVars  = ReadStringList();
        }

        co.Filename    = ReadObject()?.ToString() ?? "";
        co.Name        = ReadObject()?.ToString() ?? "<unknown>";
        if (_pyVer >= 3.11f) co.QualName = ReadObject()?.ToString();
        co.FirstLineNo = ReadInt32();

        if (_pyVer >= 3.10f)
        {
            // linetable (bytes) + exceptiontable (bytes, 3.11+)
            var lt = ReadObject();
            co.Linetable = lt is byte[] lb ? lb : [];
            if (_pyVer >= 3.11f)
            {
                var et = ReadObject();
                co.ExceptionTable = et is byte[] eb ? eb : [];
            }
        }
        else
        {
            var lt = ReadObject();
            co.Lnotab = lt is byte[] lb ? lb : [];
        }

        return co;
    }

    // ── List helpers ──────────────────────────────────────────────────────────

    private List<object?> ReadObjectAsList()
    {
        var obj = ReadObject();
        return obj switch
        {
            object?[] arr => [..arr],
            List<object?> list => list,
            _ => []
        };
    }

    private List<string> ReadStringList()
    {
        var obj = ReadObject();
        IEnumerable<object?> items = obj switch
        {
            object?[] arr => arr,
            List<object?> list => list,
            _ => []
        };
        return items
            .Select(o => o?.ToString() ?? "")
            .ToList();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Bytecode Disassembler
//  Produces a human-readable listing of all instructions.
//  Handles both pre-3.6 (variable width) and 3.6+ (wordcode) formats.
// ═══════════════════════════════════════════════════════════════════════════

internal static class BytecodeDisassembler
{
    public static string DisassembleAll(PythonCodeObject root, float pyVer)
    {
        var sb = new StringBuilder(32768);
        DisassembleCode(root, pyVer, sb, 0);
        return sb.ToString();
    }

    private static void DisassembleCode(PythonCodeObject co,
                                         float pyVer,
                                         StringBuilder sb,
                                         int depth)
    {
        string pad  = new string(' ', depth * 2);
        string name = co.QualName ?? co.Name;

        sb.AppendLine();
        sb.AppendLine($"{pad}{'#',1}{'=',1}{'=',60}");
        sb.AppendLine($"{pad}# Code object : {name}");
        if (!string.IsNullOrEmpty(co.Filename))
            sb.AppendLine($"{pad}# File        : {co.Filename}");
        sb.AppendLine($"{pad}# Line        : {co.FirstLineNo}");
        sb.AppendLine($"{pad}# Args        : {co.ArgCount}" +
                      (co.PosOnlyArgCount > 0 ? $"  pos-only: {co.PosOnlyArgCount}" : "") +
                      (co.KwOnlyArgCount  > 0 ? $"  kw-only: {co.KwOnlyArgCount}"  : ""));
        sb.AppendLine($"{pad}# Locals      : {co.NumLocals}   Stack: {co.StackSize}");
        sb.AppendLine($"{pad}# Flags       : 0x{co.Flags:X4}  {DescribeCoFlags(co.Flags)}");
        sb.AppendLine($"{pad}#{'=',1}{'=',60}");
        sb.AppendLine();

        if (co.Code.Length == 0)
        {
            sb.AppendLine($"{pad}  (no bytecode)");
            return;
        }

        var opcodes    = GetOpcodeTable(pyVer);
        bool wordcode  = pyVer >= 3.6f;  // all instructions 2 bytes
        bool py311plus = pyVer >= 3.11f;

        int i         = 0;
        int extArg    = 0;
        int extShift  = 0;

        while (i < co.Code.Length)
        {
            int  offset = i;
            byte op     = co.Code[i];
            int  arg    = 0;

            if (wordcode)
            {
                arg = i + 1 < co.Code.Length ? co.Code[i + 1] : 0;
                i  += 2;
            }
            else
            {
                // Pre-3.6: HAVE_ARGUMENT = 90
                if (op >= 90)
                {
                    arg = co.Code[i + 1] | (co.Code[i + 2] << 8);
                    i  += 3;
                }
                else
                {
                    i += 1;
                }
            }

            // Handle EXTENDED_ARG (opcode 144 in all versions)
            if (op == 144)
            {
                extArg   = (extArg | arg) << 8;
                extShift += 8;
                continue;
            }
            if (extShift > 0)
            {
                arg      |= extArg;
                extArg    = 0;
                extShift  = 0;
            }

            string opName = opcodes.TryGetValue(op, out var n) ? n : $"OPCODE_{op}";

            // Skip CACHE instructions (Python 3.11+, opcode 0)
            if (py311plus && op == 0)
            {
                continue;
            }

            string argStr = ResolveArg(op, arg, co, pyVer, opcodes);

            sb.AppendLine($"{pad}  {offset,5}  {opName,-28} {arg,5}  {argStr}");
        }

        sb.AppendLine();

        // Recurse into nested code objects
        foreach (var c in co.Consts)
        {
            if (c is PythonCodeObject nested)
                DisassembleCode(nested, pyVer, sb, depth + 1);
        }
    }

    // ── Argument resolver ────────────────────────────────────────────────────

    private static string ResolveArg(byte op, int arg,
                                      PythonCodeObject co,
                                      float pyVer,
                                      Dictionary<int, string> ops)
    {
        if (!ops.TryGetValue(op, out var name)) return "";

        // Constants
        if (name is "LOAD_CONST" or "RETURN_CONST")
        {
            if (arg < co.Consts.Count)
                return FormatConst(co.Consts[arg]);
        }

        // Name-indexed opcodes
        if (name is "LOAD_NAME"  or "STORE_NAME"  or "DELETE_NAME"
                 or "LOAD_ATTR"  or "STORE_ATTR"  or "DELETE_ATTR"
                 or "IMPORT_NAME" or "IMPORT_FROM"
                 or "LOAD_METHOD" or "STORE_METHOD")
        {
            int idx = arg;
            return idx < co.Names.Count ? $"({co.Names[idx]})" : "";
        }

        // LOAD_GLOBAL: Python 3.11+ uses arg >> 1
        if (name == "LOAD_GLOBAL")
        {
            int idx = pyVer >= 3.11f ? arg >> 1 : arg;
            return idx < co.Names.Count ? $"({co.Names[idx]})" : "";
        }

        // STORE_GLOBAL / DELETE_GLOBAL
        if (name is "STORE_GLOBAL" or "DELETE_GLOBAL")
        {
            return arg < co.Names.Count ? $"({co.Names[arg]})" : "";
        }

        // Fast locals
        if (name is "LOAD_FAST" or "STORE_FAST" or "DELETE_FAST"
                 or "LOAD_FAST_CHECK" or "LOAD_FAST_AND_CLEAR")
        {
            return arg < co.VarNames.Count ? $"({co.VarNames[arg]})" : "";
        }

        // Free/cell vars
        if (name is "LOAD_DEREF" or "STORE_DEREF" or "DELETE_DEREF"
                 or "LOAD_CLOSURE" or "MAKE_CELL" or "COPY_FREE_VARS")
        {
            var allClosure = co.CellVars.Concat(co.FreeVars).ToList();
            return arg < allClosure.Count ? $"({allClosure[arg]})" : "";
        }

        // Compare ops
        if (name == "COMPARE_OP")
        {
            string[] cmpOps = { "<", "<=", "==", "!=", ">", ">=",
                                 "in", "not in", "is", "is not",
                                 "exception match", "BAD" };
            int idx = pyVer >= 3.12f ? arg >> 4 : arg;
            return idx < cmpOps.Length ? $"({cmpOps[idx]})" : "";
        }

        // BINARY_OP (Python 3.11+)
        if (name == "BINARY_OP")
        {
            string[] binOps = { "+", "&", "//", "<<", "@", "*",
                                 "%", "|", "**", ">>", "-", "/",
                                 "^", "+=", "&=", "//=", "<<=", "@=",
                                 "*=", "%=", "|=", "**=", ">>=", "-=",
                                 "/=", "^=" };
            return arg < binOps.Length ? $"({binOps[arg]})" : "";
        }

        // Jump targets
        if (name is "JUMP_FORWARD" or "JUMP_ABSOLUTE" or "FOR_ITER"
                 or "JUMP_IF_TRUE_OR_POP" or "JUMP_IF_FALSE_OR_POP"
                 or "POP_JUMP_IF_TRUE" or "POP_JUMP_IF_FALSE"
                 or "POP_JUMP_FORWARD_IF_TRUE"  or "POP_JUMP_FORWARD_IF_FALSE"
                 or "POP_JUMP_BACKWARD_IF_TRUE" or "POP_JUMP_BACKWARD_IF_FALSE"
                 or "POP_JUMP_FORWARD_IF_NONE"  or "POP_JUMP_FORWARD_IF_NOT_NONE"
                 or "JUMP_BACKWARD" or "JUMP_BACKWARD_NO_INTERRUPT"
                 or "SEND" or "SETUP_FINALLY" or "SETUP_WITH")
        {
            return $"(→ {arg})";
        }

        return "";
    }

    private static string FormatConst(object? c) => c switch
    {
        null           => "(None)",
        string s       => $"({(s.Length > 40 ? s[..40] + "…" : s)!.Replace("\n", "\\n")})",
        bool b         => b ? "(True)" : "(False)",
        PythonCodeObject co => $"(<code: {co.Name}>)",
        byte[] b       => $"(<bytes len={b.Length}>)",
        _              => $"({c})",
    };

    // ── CO flags description ──────────────────────────────────────────────────

    private static string DescribeCoFlags(int flags)
    {
        var parts = new List<string>();
        if ((flags & 0x04) != 0) parts.Add("*args");
        if ((flags & 0x08) != 0) parts.Add("**kwargs");
        if ((flags & 0x20) != 0) parts.Add("generator");
        if ((flags & 0x100) != 0) parts.Add("async");
        if ((flags & 0x200) != 0) parts.Add("coroutine");
        return parts.Count > 0 ? string.Join(" ", parts) : "";
    }

    // ══════════════════════════════════════════════════════════════════════
    //  OPCODE TABLES
    //  One table per major version group.  Only opcodes that differ
    //  significantly between groups need separate entries.
    //  Reference: cpython/Lib/opcode.py for each version.
    // ══════════════════════════════════════════════════════════════════════

    public static Dictionary<int, string> GetOpcodeTable(float ver)
    {
        if (ver >= 3.12f) return Opcodes312;
        if (ver >= 3.11f) return Opcodes311;
        if (ver >= 3.6f)  return Opcodes36;
        if (ver >= 3.0f)  return Opcodes30;
        return Opcodes27;
    }

    // ── Python 2.7 ───────────────────────────────────────────────────────────

    private static readonly Dictionary<int, string> Opcodes27 = new()
    {
        {   1, "POP_TOP"              }, {   2, "ROT_TWO"            },
        {   3, "ROT_THREE"            }, {   4, "DUP_TOP"            },
        {   5, "ROT_FOUR"             }, {   9, "NOP"                },
        {  10, "UNARY_POSITIVE"       }, {  11, "UNARY_NEGATIVE"     },
        {  12, "UNARY_NOT"            }, {  13, "UNARY_CONVERT"      },
        {  15, "UNARY_INVERT"         }, {  19, "BINARY_POWER"       },
        {  20, "BINARY_MULTIPLY"      }, {  21, "BINARY_DIVIDE"      },
        {  22, "BINARY_MODULO"        }, {  23, "BINARY_ADD"         },
        {  24, "BINARY_SUBTRACT"      }, {  25, "BINARY_SUBSCR"      },
        {  26, "BINARY_FLOOR_DIVIDE"  }, {  27, "BINARY_TRUE_DIVIDE" },
        {  28, "INPLACE_FLOOR_DIVIDE" }, {  29, "INPLACE_TRUE_DIVIDE"},
        {  30, "SLICE+0"              }, {  54, "INPLACE_ADD"        },
        {  55, "INPLACE_SUBTRACT"     }, {  56, "INPLACE_MULTIPLY"   },
        {  57, "INPLACE_DIVIDE"       }, {  58, "INPLACE_MODULO"     },
        {  59, "STORE_SUBSCR"         }, {  60, "DELETE_SUBSCR"      },
        {  61, "BINARY_LSHIFT"        }, {  62, "BINARY_RSHIFT"      },
        {  63, "BINARY_AND"           }, {  64, "BINARY_XOR"         },
        {  65, "BINARY_OR"            }, {  66, "INPLACE_POWER"      },
        {  67, "GET_ITER"             }, {  70, "PRINT_EXPR"         },
        {  71, "PRINT_ITEM"           }, {  72, "PRINT_NEWLINE"      },
        {  73, "PRINT_ITEM_TO"        }, {  74, "PRINT_NEWLINE_TO"   },
        {  75, "INPLACE_LSHIFT"       }, {  76, "INPLACE_RSHIFT"     },
        {  77, "INPLACE_AND"          }, {  78, "INPLACE_XOR"        },
        {  79, "INPLACE_OR"           }, {  80, "BREAK_LOOP"         },
        {  82, "LOAD_LOCALS"          }, {  83, "RETURN_VALUE"       },
        {  84, "IMPORT_STAR"          }, {  85, "EXEC_STMT"          },
        {  86, "YIELD_VALUE"          }, {  87, "POP_BLOCK"          },
        {  88, "END_FINALLY"          }, {  89, "BUILD_CLASS"        },
        {  90, "STORE_NAME"           }, {  91, "DELETE_NAME"        },
        {  92, "UNPACK_SEQUENCE"      }, {  93, "FOR_ITER"           },
        {  94, "LIST_APPEND"          }, {  95, "STORE_ATTR"         },
        {  96, "DELETE_ATTR"          }, {  97, "STORE_GLOBAL"       },
        {  98, "DELETE_GLOBAL"        }, {  99, "DUP_TOPX"          },
        { 100, "LOAD_CONST"           }, { 101, "LOAD_NAME"          },
        { 102, "BUILD_TUPLE"          }, { 103, "BUILD_LIST"         },
        { 104, "BUILD_SET"            }, { 105, "BUILD_MAP"          },
        { 106, "LOAD_ATTR"            }, { 107, "COMPARE_OP"         },
        { 108, "IMPORT_NAME"          }, { 109, "IMPORT_FROM"        },
        { 110, "JUMP_FORWARD"         }, { 111, "JUMP_IF_FALSE_OR_POP"},
        { 112, "JUMP_IF_TRUE_OR_POP"  }, { 113, "JUMP_ABSOLUTE"      },
        { 114, "POP_JUMP_IF_FALSE"    }, { 115, "POP_JUMP_IF_TRUE"   },
        { 116, "LOAD_GLOBAL"          }, { 119, "CONTINUE_LOOP"      },
        { 120, "SETUP_LOOP"           }, { 121, "SETUP_EXCEPT"       },
        { 122, "SETUP_FINALLY"        }, { 124, "LOAD_FAST"          },
        { 125, "STORE_FAST"           }, { 126, "DELETE_FAST"        },
        { 130, "RAISE_VARARGS"        }, { 131, "CALL_FUNCTION"      },
        { 132, "MAKE_FUNCTION"        }, { 133, "BUILD_SLICE"        },
        { 134, "MAKE_CLOSURE"         }, { 135, "LOAD_CLOSURE"       },
        { 136, "LOAD_DEREF"           }, { 137, "STORE_DEREF"        },
        { 140, "CALL_FUNCTION_VAR"    }, { 141, "CALL_FUNCTION_KW"   },
        { 142, "CALL_FUNCTION_VAR_KW" }, { 143, "SETUP_WITH"         },
        { 144, "EXTENDED_ARG"         }, { 145, "LIST_APPEND"        },
        { 146, "SET_ADD"              }, { 147, "MAP_ADD"             },
    };

    // ── Python 3.0 – 3.5 ─────────────────────────────────────────────────────

    private static readonly Dictionary<int, string> Opcodes30 = new(Opcodes27)
    {
        [  2] = "ROT_TWO",           [  5] = "NOP", // ROT_FOUR removed
        [  9] = "NOP",
        [ 21] = "BINARY_FLOOR_DIVIDE",  // replaces BINARY_DIVIDE
        [ 22] = "BINARY_TRUE_DIVIDE",
        [ 54] = "INPLACE_MULTIPLY",
        [ 70] = "PRINT_EXPR",        // PRINT_ITEM gone
        [ 71] = "LOAD_BUILD_CLASS",
        [ 72] = "YIELD_FROM",
        [ 73] = "GET_AITER",
        [ 74] = "GET_ANEXT",
        [ 75] = "BEFORE_ASYNC_WITH",
        [ 80] = "BREAK_LOOP",
        [ 82] = "WITH_CLEANUP",
        [ 85] = "SETUP_ANNOTATIONS",
        [ 86] = "YIELD_VALUE",
        [ 87] = "POP_BLOCK",
        [ 88] = "END_FINALLY",
        [ 89] = "POP_EXCEPT",
        [ 94] = "UNPACK_EX",
        [ 99] = "BUILD_TUPLE_UNPACK",
        [130] = "RAISE_VARARGS",
        [138] = "DELETE_DEREF",
        [141] = "CALL_FUNCTION_KW",
        [142] = "CALL_FUNCTION_EX",
        [143] = "SETUP_WITH",
        [148] = "LOAD_CLASSDEREF",
    };

    // ── Python 3.6 – 3.10 (wordcode: all instructions 2 bytes) ──────────────

    private static readonly Dictionary<int, string> Opcodes36 = new()
    {
        {   1, "POP_TOP"              }, {   2, "ROT_TWO"            },
        {   3, "ROT_THREE"            }, {   4, "DUP_TOP"            },
        {   5, "DUP_TOP_TWO"          }, {   6, "ROT_FOUR"           },
        {   9, "NOP"                  }, {  10, "UNARY_POSITIVE"     },
        {  11, "UNARY_NEGATIVE"       }, {  12, "UNARY_NOT"          },
        {  15, "UNARY_INVERT"         }, {  16, "BINARY_MATRIX_MULTIPLY"},
        {  17, "INPLACE_MATRIX_MULTIPLY"},{  19, "BINARY_POWER"      },
        {  20, "BINARY_MULTIPLY"      }, {  22, "BINARY_MODULO"      },
        {  23, "BINARY_ADD"           }, {  24, "BINARY_SUBTRACT"    },
        {  25, "BINARY_SUBSCR"        }, {  26, "BINARY_FLOOR_DIVIDE"},
        {  27, "BINARY_TRUE_DIVIDE"   }, {  28, "INPLACE_FLOOR_DIVIDE"},
        {  29, "INPLACE_TRUE_DIVIDE"  }, {  50, "GET_AITER"          },
        {  51, "GET_ANEXT"            }, {  52, "BEFORE_ASYNC_WITH"  },
        {  53, "BEGIN_FINALLY"        }, {  54, "END_ASYNC_FOR"      },
        {  55, "INPLACE_ADD"          }, {  56, "INPLACE_SUBTRACT"   },
        {  57, "INPLACE_MULTIPLY"     }, {  59, "INPLACE_MODULO"     },
        {  60, "STORE_SUBSCR"         }, {  61, "DELETE_SUBSCR"      },
        {  62, "BINARY_LSHIFT"        }, {  63, "BINARY_RSHIFT"      },
        {  64, "BINARY_AND"           }, {  65, "BINARY_XOR"         },
        {  66, "BINARY_OR"            }, {  67, "INPLACE_POWER"      },
        {  68, "GET_ITER"             }, {  69, "GET_YIELD_FROM_ITER"},
        {  70, "PRINT_EXPR"           }, {  71, "LOAD_BUILD_CLASS"   },
        {  72, "YIELD_FROM"           }, {  73, "GET_AWAITABLE"      },
        {  75, "INPLACE_LSHIFT"       }, {  76, "INPLACE_RSHIFT"     },
        {  77, "INPLACE_AND"          }, {  78, "INPLACE_XOR"        },
        {  79, "INPLACE_OR"           }, {  80, "WITH_CLEANUP_START" },
        {  81, "WITH_CLEANUP_FINISH"  }, {  82, "RETURN_VALUE"       },
        {  83, "IMPORT_STAR"          }, {  84, "SETUP_ANNOTATIONS"  },
        {  85, "YIELD_VALUE"          }, {  86, "POP_BLOCK"          },
        {  87, "END_FINALLY"          }, {  88, "POP_EXCEPT"         },
        {  89, "HAVE_ARGUMENT"        }, {  90, "STORE_NAME"         },
        {  91, "DELETE_NAME"          }, {  92, "UNPACK_SEQUENCE"    },
        {  93, "FOR_ITER"             }, {  94, "UNPACK_EX"          },
        {  95, "STORE_ATTR"           }, {  96, "DELETE_ATTR"        },
        {  97, "STORE_GLOBAL"         }, {  98, "DELETE_GLOBAL"      },
        { 100, "LOAD_CONST"           }, { 101, "LOAD_NAME"          },
        { 102, "BUILD_TUPLE"          }, { 103, "BUILD_LIST"         },
        { 104, "BUILD_SET"            }, { 105, "BUILD_MAP"          },
        { 106, "LOAD_ATTR"            }, { 107, "COMPARE_OP"         },
        { 108, "IMPORT_NAME"          }, { 109, "IMPORT_FROM"        },
        { 110, "JUMP_FORWARD"         }, { 111, "JUMP_IF_FALSE_OR_POP"},
        { 112, "JUMP_IF_TRUE_OR_POP"  }, { 113, "JUMP_ABSOLUTE"      },
        { 114, "POP_JUMP_IF_FALSE"    }, { 115, "POP_JUMP_IF_TRUE"   },
        { 116, "LOAD_GLOBAL"          }, { 117, "IS_OP"              },
        { 118, "CONTAINS_OP"          }, { 119, "RERAISE"            },
        { 120, "JUMP_IF_NOT_EXC_MATCH"}, { 121, "SETUP_FINALLY"      },
        { 122, "LOAD_FAST_CHECK"      }, { 124, "LOAD_FAST"          },
        { 125, "STORE_FAST"           }, { 126, "DELETE_FAST"        },
        { 127, "ROT_N"                }, { 130, "RAISE_VARARGS"      },
        { 131, "CALL_FUNCTION"        }, { 132, "MAKE_FUNCTION"      },
        { 133, "BUILD_SLICE"          }, { 135, "LOAD_CLOSURE"       },
        { 136, "LOAD_DEREF"           }, { 137, "STORE_DEREF"        },
        { 138, "DELETE_DEREF"         }, { 141, "CALL_FUNCTION_KW"   },
        { 142, "CALL_FUNCTION_EX"     }, { 143, "SETUP_WITH"         },
        { 144, "EXTENDED_ARG"         }, { 145, "LIST_APPEND"        },
        { 146, "SET_ADD"              }, { 147, "MAP_ADD"             },
        { 148, "LOAD_CLASSDEREF"      }, { 149, "MATCH_CLASS"        },
        { 152, "SETUP_ASYNC_WITH"     }, { 154, "FORMAT_VALUE"       },
        { 155, "BUILD_CONST_KEY_MAP"  }, { 156, "BUILD_STRING"       },
        { 158, "BUILD_TUPLE_UNPACK_WITH_CALL" },
        { 160, "LOAD_METHOD"          }, { 161, "CALL_METHOD"        },
        { 162, "LIST_EXTEND"          }, { 163, "SET_UPDATE"         },
        { 164, "DICT_MERGE"           }, { 165, "DICT_UPDATE"        },
        { 166, "PRECALL"              }, { 171, "CALL"               },
        { 172, "KW_NAMES"             },
    };

    // ── Python 3.11 ───────────────────────────────────────────────────────────

    private static readonly Dictionary<int, string> Opcodes311 = new()
    {
        {   0, "CACHE"                }, {   1, "POP_TOP"            },
        {   2, "PUSH_NULL"            }, {   3, "PUSH_NULL"          },
        {   5, "PUSH_NULL"            }, {   6, "END_FOR"            },
        {   9, "NOP"                  }, {  11, "UNARY_NEGATIVE"     },
        {  12, "UNARY_NOT"            }, {  15, "UNARY_INVERT"       },
        {  16, "BINARY_OP"            }, {  17, "BINARY_SUBSCR"      },
        {  25, "BINARY_SUBSCR"        }, {  26, "BINARY_SLICE"       },
        {  27, "STORE_SLICE"          }, {  35, "GET_LEN"            },
        {  36, "MATCH_MAPPING"        }, {  37, "MATCH_SEQUENCE"     },
        {  38, "MATCH_KEYS"           }, {  40, "PUSH_EXC_INFO"      },
        {  41, "CHECK_EXC_MATCH"      }, {  42, "CHECK_EG_MATCH"     },
        {  49, "WITH_EXCEPT_START"    }, {  50, "GET_AITER"          },
        {  51, "GET_ANEXT"            }, {  52, "BEFORE_ASYNC_WITH"  },
        {  53, "BEFORE_WITH"          }, {  54, "END_ASYNC_FOR"      },
        {  55, "STORE_SUBSCR"         }, {  56, "DELETE_SUBSCR"      },
        {  59, "GET_ITER"             }, {  60, "GET_YIELD_FROM_ITER"},
        {  62, "LOAD_BUILD_CLASS"     }, {  64, "LOAD_ASSERTION_ERROR"},
        {  65, "RETURN_GENERATOR"     }, {  68, "IMPORT_STAR"        },
        {  69, "SETUP_ANNOTATIONS"    }, {  70, "YIELD_VALUE"        },
        {  71, "RESUME"               }, {  72, "YIELD_FROM"         },
        {  73, "SEND"                 }, {  74, "HAVE_ARGUMENT"      },
        {  75, "UNARY_POSITIVE"       }, {  77, "GET_AWAITABLE"      },
        {  78, "MAKE_FUNCTION"        }, {  79, "POP_JUMP_BACKWARD_IF_NOT_NONE"},
        {  80, "POP_JUMP_BACKWARD_IF_FALSE"},{  81, "POP_JUMP_BACKWARD_IF_TRUE"},
        {  82, "LOAD_ATTR"            }, {  83, "LOAD_GLOBAL"        },
        {  84, "IS_OP"                }, {  85, "CONTAINS_OP"        },
        {  86, "RERAISE"              }, {  87, "COPY"               },
        {  88, "RETURN_CONST"         }, {  89, "BINARY_OP"          },
        {  90, "STORE_NAME"           }, {  91, "DELETE_NAME"        },
        {  92, "UNPACK_SEQUENCE"      }, {  93, "FOR_ITER"           },
        {  94, "UNPACK_EX"            }, {  95, "STORE_ATTR"         },
        {  96, "DELETE_ATTR"          }, {  97, "STORE_GLOBAL"       },
        {  98, "DELETE_GLOBAL"        }, {  99, "SWAP"               },
        { 100, "LOAD_CONST"           }, { 101, "LOAD_NAME"          },
        { 102, "BUILD_TUPLE"          }, { 103, "BUILD_LIST"         },
        { 104, "BUILD_SET"            }, { 105, "BUILD_MAP"          },
        { 106, "LOAD_ATTR"            }, { 107, "COMPARE_OP"         },
        { 108, "IMPORT_NAME"          }, { 109, "IMPORT_FROM"        },
        { 110, "JUMP_FORWARD"         }, { 111, "JUMP_BACKWARD"      },
        { 112, "POP_JUMP_FORWARD_IF_TRUE"  },
        { 113, "POP_JUMP_FORWARD_IF_FALSE" },
        { 114, "POP_JUMP_FORWARD_IF_NONE"  },
        { 115, "POP_JUMP_FORWARD_IF_NOT_NONE"},
        { 116, "LOAD_GLOBAL"          }, { 117, "LOAD_FAST_CHECK"    },
        { 118, "POP_JUMP_BACKWARD_IF_NONE" },
        { 119, "POP_JUMP_BACKWARD_IF_NOT_NONE"},
        { 120, "JUMP_BACKWARD_NO_INTERRUPT"},
        { 121, "MAKE_CELL"            }, { 122, "LOAD_CLOSURE"       },
        { 123, "COPY_FREE_VARS"       }, { 124, "LOAD_FAST"          },
        { 125, "STORE_FAST"           }, { 126, "DELETE_FAST"        },
        { 127, "LOAD_FAST_AND_CLEAR"  }, { 128, "RAISE_VARARGS"      },
        { 130, "RAISE_VARARGS"        }, { 131, "CALL"               },
        { 132, "MAKE_FUNCTION"        }, { 133, "BUILD_SLICE"        },
        { 135, "LOAD_DEREF"           }, { 136, "LOAD_DEREF"         },
        { 137, "STORE_DEREF"          }, { 138, "DELETE_DEREF"       },
        { 141, "CALL_FUNCTION_EX"     }, { 142, "CALL_INTRINSIC_1"   },
        { 143, "CALL_INTRINSIC_2"     }, { 144, "EXTENDED_ARG"       },
        { 145, "LIST_APPEND"          }, { 146, "SET_ADD"             },
        { 147, "MAP_ADD"              }, { 148, "LOAD_CLASSDEREF"    },
        { 149, "COPY_FREE_VARS"       }, { 150, "RESUME"             },
        { 152, "MATCH_CLASS"          }, { 154, "FORMAT_VALUE"       },
        { 155, "BUILD_CONST_KEY_MAP"  }, { 156, "BUILD_STRING"       },
        { 160, "LOAD_METHOD"          }, { 162, "LIST_EXTEND"        },
        { 163, "SET_UPDATE"           }, { 164, "DICT_MERGE"         },
        { 165, "DICT_UPDATE"          }, { 166, "RETURN_VALUE"       },
        { 167, "KW_NAMES"             }, { 168, "CALL"               },
        { 171, "CALL"                 }, { 172, "KW_NAMES"           },
    };

    // ── Python 3.12 / 3.13 ───────────────────────────────────────────────────

    private static readonly Dictionary<int, string> Opcodes312 = new(Opcodes311)
    {
        [  1] = "RESUME",
        [  2] = "PUSH_NULL",
        [  3] = "INTERPRETER_EXIT",
        [  5] = "END_FOR",
        [  6] = "END_SEND",
        [  7] = "TO_BOOL",
        [  8] = "UNARY_NEGATIVE",
        [  9] = "UNARY_NOT",
        [ 10] = "UNARY_INVERT",
        [ 11] = "RESERVED",
        [ 16] = "BINARY_SUBSCR",
        [ 17] = "STORE_SUBSCR",
        [ 18] = "DELETE_SUBSCR",
        [ 25] = "BINARY_SLICE",
        [ 26] = "STORE_SLICE",
        [ 35] = "GET_LEN",
        [ 55] = "STORE_SUBSCR",
        [ 56] = "DELETE_SUBSCR",
        [ 59] = "GET_ITER",
        [ 83] = "RETURN_VALUE",
        [ 84] = "RETURN_CONST",
        [ 85] = "YIELD_VALUE",
        [ 88] = "RETURN_CONST",
        [ 89] = "BINARY_OP",
        [ 99] = "SWAP",
        [106] = "LOAD_ATTR",       // now also handles LOAD_METHOD via flag
        [111] = "JUMP_BACKWARD",
        [116] = "LOAD_GLOBAL",
        [124] = "LOAD_FAST",
        [125] = "STORE_FAST",
        [126] = "DELETE_FAST",
        [129] = "LOAD_FAST_CHECK",
        [130] = "RAISE_VARARGS",
        [131] = "CALL",
        [132] = "MAKE_FUNCTION",
        [171] = "CALL",
        [173] = "CALL_KW",
    };
}
