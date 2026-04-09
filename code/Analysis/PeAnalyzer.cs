using System.IO;
using BinaryLens.Models;
using PeNet;

namespace BinaryLens.Analysis;

/// <summary>
/// Parses PE structure using PeNet v4.
/// PeNet v4 has a unified OptionalHeader (no separate 32/64 types),
/// enum-typed Characteristics, and no ForwardedName on exports.
/// </summary>
public static class PeAnalyzer
{
    // ── Machine type lookup ───────────────────────────────────────────────────

    private static readonly Dictionary<uint, string> MachineTypes = new()
    {
        { 0x014C, "x86 (32-bit)"    },
        { 0x8664, "x86-64 (64-bit)" },
        { 0xAA64, "ARM64"           },
        { 0x01C4, "ARM"             },
        { 0x0200, "Intel Itanium"   },
    };

    // ── Subsystem lookup ──────────────────────────────────────────────────────

    private static readonly Dictionary<uint, string> Subsystems = new()
    {
        { 0,  "Unknown"            }, { 1,  "Native"             },
        { 2,  "Windows GUI"        }, { 3,  "Windows Console"    },
        { 5,  "OS/2 Console"       }, { 7,  "POSIX Console"      },
        { 9,  "Windows CE GUI"     }, { 10, "EFI Application"    },
        { 11, "EFI Boot Service"   }, { 12, "EFI Runtime Driver" },
        { 14, "EFI ROM"            }, { 15, "Xbox"               },
        { 16, "Windows Boot App"   },
    };

    // ── Public entry point ────────────────────────────────────────────────────

    public static void Analyze(string filePath, AnalysisResult result)
    {
        PeFile pe;
        try
        {
            pe = new PeFile(filePath);
        }
        catch (Exception ex)
        {
            result.Errors.Add($"PeNet parse error: {ex.Message}");
            result.IsValidPe = false;
            return;
        }

        // PeNet v4 has no IsValidPeFile property — if constructor didn't throw
        // and ImageNtHeaders is present, it's a valid PE.
        result.IsValidPe = pe.ImageNtHeaders != null;
        if (!result.IsValidPe)
        {
            result.Errors.Add("File does not appear to be a valid PE binary.");
            return;
        }

        result.Is64Bit  = pe.Is64Bit;
        result.IsDotNet = pe.IsDotNet;

        AnalyzePeHeader(pe, filePath, result);
        AnalyzeImports(pe, result);
        AnalyzeExports(pe, result);
        AnalyzeResources(pe, filePath, result);

        result.Architecture    = result.Is64Bit ? "x64" : "x86";
        result.FileTypeSummary = BuildTypeSummary(result);
    }

    // ── PE Header ─────────────────────────────────────────────────────────────

    private static void AnalyzePeHeader(PeFile pe, string filePath, AnalysisResult result)
    {
        try
        {
            var fh = pe.ImageNtHeaders!.FileHeader;
            var oh = pe.ImageNtHeaders.OptionalHeader;
            var info = result.PeInfo;

            // Machine type — enum, cast to uint for lookup
            uint machineVal = (uint)fh.Machine;
            info.MachineType = MachineTypes.TryGetValue(machineVal, out var mt)
                ? mt : $"Unknown (0x{machineVal:X4})";

            // Timestamp
            info.TimeDateStamp = DateTimeOffset
                .FromUnixTimeSeconds(fh.TimeDateStamp)
                .UtcDateTime;

            // Linker version
            info.LinkerVersion = oh != null
                ? $"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}"
                : "";

            // Subsystem
            if (oh != null)
            {
                uint ss = (uint)oh.Subsystem;
                info.Subsystem = Subsystems.TryGetValue(ss, out var sub)
                    ? sub : $"0x{ss:X4}";

                info.EntryPoint  = $"0x{oh.AddressOfEntryPoint:X8}";
                info.ImageBase   = result.Is64Bit
                    ? $"0x{oh.ImageBase:X16}"
                    : $"0x{oh.ImageBase:X8}";
                info.RawImageBase = oh.ImageBase;
                info.SizeOfImage = $"0x{oh.SizeOfImage:X8}";
            }

            // Characteristics — FileCharacteristicsType enum
            ushort chars = (ushort)fh.Characteristics;
            if ((chars & 0x0002) != 0) { info.Characteristics.Add("Executable"); info.IsExe = true; }
            if ((chars & 0x2000) != 0) { info.Characteristics.Add("DLL");        info.IsDll = true; }
            if ((chars & 0x0020) != 0) info.Characteristics.Add("Large address aware");
            if ((chars & 0x0100) != 0) info.Characteristics.Add("32-bit");
            if ((chars & 0x0200) != 0) info.Characteristics.Add("Debug stripped");

            // Sections
            if (pe.ImageSectionHeaders != null)
            {
                foreach (var sec in pe.ImageSectionHeaders)
                {
                    string secName = "";
                    try { secName = sec.Name; } catch { }

                    info.Sections.Add(new PeSection
                    {
                        Name           = string.IsNullOrEmpty(secName) ? "[unnamed]" : secName,
                        VirtualAddress = $"0x{sec.VirtualAddress:X8}",
                        VirtualSize    = $"0x{sec.VirtualSize:X8}",
                        RawSize        = $"0x{sec.SizeOfRawData:X8}",
                        Characteristics = DescribeSectionChars((uint)sec.Characteristics),
                        Entropy        = ComputeSectionEntropy(filePath, sec.PointerToRawData, sec.SizeOfRawData),
                        RawVirtualAddress = sec.VirtualAddress,
                        RawVirtualSize    = sec.VirtualSize,
                        RawPointerToData  = sec.PointerToRawData,
                        RawSizeOfData     = sec.SizeOfRawData,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"PE header analysis error: {ex.Message}");
        }
    }

    // ── Imports ───────────────────────────────────────────────────────────────

    private static void AnalyzeImports(PeFile pe, AnalysisResult result)
    {
        try
        {
            if (pe.ImportedFunctions == null) return;
            foreach (var fn in pe.ImportedFunctions)
            {
                result.Imports.Add(new ImportEntry
                {
                    DllName      = fn.DLL ?? "",
                    FunctionName = fn.Name ?? "",
                    Hint         = fn.Hint.ToString(),
                    IsOrdinal    = string.IsNullOrEmpty(fn.Name),
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Import analysis error: {ex.Message}");
        }
    }

    // ── Exports ───────────────────────────────────────────────────────────────

    private static void AnalyzeExports(PeFile pe, AnalysisResult result)
    {
        try
        {
            if (pe.ExportedFunctions == null) return;
            foreach (var fn in pe.ExportedFunctions)
            {
                result.Exports.Add(new ExportEntry
                {
                    Name       = fn.Name ?? "",
                    RvaAddress = $"0x{fn.Address:X8}",
                    Ordinal    = fn.Ordinal,
                    // ForwardedName removed — not present in PeNet v4 API
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Export analysis error: {ex.Message}");
        }
    }

    // ── Resources ─────────────────────────────────────────────────────────────
    // PeNet v4's Resources type does not expose a public generic traversal API.
    // We use reflection to read whatever typed properties it does expose,
    // so we're never blocked by a missing property name.

    private static void AnalyzeResources(PeFile pe, string filePath, AnalysisResult result)
    {
        try
        {
            var res = pe.Resources;
            if (res == null) return;

            // Walk every public readable property on the Resources object.
            // Anything non-null becomes a resource entry.
            foreach (var prop in res.GetType().GetProperties(
                System.Reflection.BindingFlags.Public |
                System.Reflection.BindingFlags.Instance))
            {
                try
                {
                    var value = prop.GetValue(res);
                    if (value == null) continue;

                    // String property (e.g. Manifest XML)
                    if (value is string s && !string.IsNullOrWhiteSpace(s))
                    {
                        result.Resources.Add(new ResourceInfo
                        {
                            Type = prop.Name,
                            Name = "#1",
                            Language = "0",
                            Size = s.Length,
                        });
                    }
                    // Collection property (e.g. GroupIconDirectories)
                    else if (value is System.Collections.IEnumerable enumerable
                          && value is not string)
                    {
                        int idx = 1;
                        foreach (var _ in enumerable)
                        {
                            result.Resources.Add(new ResourceInfo
                            {
                                Type = prop.Name,
                                Name = $"#{idx++}",
                                Language = "0",
                                Size = 0,
                            });
                        }
                    }
                    // Other non-null object (e.g. VsVersionInfo)
                    else if (value.GetType().IsClass)
                    {
                        result.Resources.Add(new ResourceInfo
                        {
                            Type = prop.Name,
                            Name = "#1",
                            Language = "0",
                            Size = 0,
                        });
                    }
                }
                catch { /* skip unreadable property */ }
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Resource analysis error: {ex.Message}");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string DescribeSectionChars(uint c)
    {
        var parts = new List<string>();
        if ((c & 0x00000020) != 0) parts.Add("CODE");
        if ((c & 0x00000040) != 0) parts.Add("INIT_DATA");
        if ((c & 0x00000080) != 0) parts.Add("UNINIT_DATA");
        if ((c & 0x20000000) != 0) parts.Add("EXEC");
        if ((c & 0x40000000) != 0) parts.Add("READ");
        if ((c & 0x80000000) != 0) parts.Add("WRITE");
        return parts.Count > 0 ? string.Join(" | ", parts) : $"0x{c:X8}";
    }

    private static double ComputeSectionEntropy(string filePath, uint rawOffset, uint rawSize)
    {
        try
        {
            if (rawSize == 0 || rawOffset == 0) return 0;
            int size = (int)Math.Min(rawSize, 65536);
            var buf  = new byte[size];
            using var fs = File.OpenRead(filePath);
            fs.Seek(rawOffset, SeekOrigin.Begin);
            int read = fs.Read(buf, 0, size);
            if (read == 0) return 0;
            return CalculateEntropy(buf, read);
        }
        catch { return 0; }
    }

    private static double CalculateEntropy(byte[] data, int length)
    {
        var freq = new int[256];
        for (int i = 0; i < length; i++) freq[data[i]]++;
        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static string BuildTypeSummary(AnalysisResult r)
    {
        var parts = new List<string>
        {
            r.Is64Bit ? "PE32+" : "PE32",
            r.PeInfo.IsDll ? "DLL" : "EXE",
        };
        if (r.IsDotNet)  parts.Add(".NET");
        if (r.IsArx)     parts.Add("AutoCAD ARX");
        if (!r.IsValidPe) parts.Add("⚠ Invalid PE");
        return string.Join(" · ", parts);
    }
}
