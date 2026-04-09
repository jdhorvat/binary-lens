using BinaryLens.Models;

namespace BinaryLens.Analysis;

/// <summary>
/// Identifies AutoCAD ARX (AutoCAD Runtime Extension) characteristics.
///
/// ARX files are Win32 DLLs that extend AutoCAD.  Detection strategy:
///   1. Export table  -- acrxEntryPoint is the required ARX entry hook
///   2. Import table  -- references to core AutoCAD DLLs
///   3. String table  -- AcRx / AcDb / AcGe / AcAp class name prefixes
///   4. Managed check -- references to AcMgd.dll / acdbmgd.dll = managed ARX
/// </summary>
public static class ArxAnalyzer
{
    // ── AutoCAD DLL identifiers ───────────────────────────────────────────────

    private static readonly HashSet<string> ArxCoreDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "acad.exe", "accore.dll", "acrx20.dll",
        "acdb23.dll", "acdb24.dll", "acdb25.dll", "acdb26.dll",
        "acge22.dll", "acge23.dll", "acge24.dll", "acge25.dll",
        "acutil23.dll", "acutil24.dll", "acutil25.dll",
        "acapp.dll",    "acappui.dll", "acgui.dll",
        "rxapi.dll",    "acpal.dll"
    };

    private static readonly HashSet<string> ManagedArxDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "acmgd.dll", "acdbmgd.dll", "accoremgd.dll",
        "acadservices.dll", "acmgdinternal.dll"
    };

    // ── AutoCAD SDK version hints from DLL version numbers ───────────────────

    private static readonly Dictionary<string, string> VersionHints =
        new(StringComparer.OrdinalIgnoreCase)
    {
        { "acdb23.dll",  "AutoCAD 2020 (SDK 23)" },
        { "acdb24.dll",  "AutoCAD 2021 (SDK 24)" },
        { "acdb25.dll",  "AutoCAD 2022 (SDK 25)" },
        { "acdb26.dll",  "AutoCAD 2023–2024 (SDK 26)" },
        { "acge22.dll",  "AutoCAD 2019–2020" },
        { "acge24.dll",  "AutoCAD 2021–2022" },
        { "acutil23.dll","AutoCAD 2020" },
        { "acutil24.dll","AutoCAD 2021" },
    };

    // ── Well-known ObjectARX class prefixes ───────────────────────────────────

    private static readonly string[] AcClassPrefixes =
    [
        "AcRx", "AcDb", "AcGe", "AcAp", "AcEd", "AcGi",
        "AcBr", "AcDl", "AcFd", "AcPl", "AcGs",
        "AcString", "AcArray",
        // Plant 3D / Civil 3D
        "AcPp", "AcPipe", "AcDwg",
        // Managed namespaces
        "Autodesk.AutoCAD", "Autodesk.Civil", "Autodesk.Plant"
    ];

    // ── Public entry point ───────────────────────────────────────────────────

    public static void Analyze(AnalysisResult result)
    {
        if (!result.IsValidPe) return;

        var arxInfo = new ArxInfo();

        CheckExports(result.Exports, arxInfo);
        CheckImports(result.Imports, arxInfo);
        CheckStrings(result.Strings, arxInfo);
        CheckManagedTypes(result, arxInfo);

        // An ARX binary must have the entry point OR heavy AutoCAD imports
        result.IsArx = arxInfo.HasArxEntryPoint
                    || arxInfo.AutocadImports.Count >= 3;

        if (result.IsArx)
            result.ArxInfo = arxInfo;
    }

    // ── Checks ────────────────────────────────────────────────────────────────

    private static void CheckExports(List<ExportEntry> exports, ArxInfo info)
    {
        foreach (var exp in exports)
        {
            string name = exp.Name;

            // Primary ARX hook
            if (name.Equals("acrxEntryPoint", StringComparison.OrdinalIgnoreCase))
            {
                info.HasArxEntryPoint = true;
                info.EntryPointName   = name;
            }

            // Exported command names typically follow: acedRegCmds->addCommand(...)
            // They often show up as exports matching ACAD command naming patterns
            if (name.StartsWith("acad", StringComparison.OrdinalIgnoreCase)
             || name.StartsWith("acrx", StringComparison.OrdinalIgnoreCase)
             || name.StartsWith("acdb", StringComparison.OrdinalIgnoreCase))
            {
                if (!info.CommandExports.Contains(name))
                    info.CommandExports.Add(name);
            }
        }
    }

    private static void CheckImports(List<ImportEntry> imports, ArxInfo info)
    {
        var seenDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var imp in imports)
        {
            string dll = imp.DllName;

            if (ArxCoreDlls.Contains(dll) && seenDlls.Add(dll))
            {
                info.AutocadImports.Add(dll);

                // Version hint
                if (info.DetectedAcadVersion == null
                    && VersionHints.TryGetValue(dll, out var hint))
                {
                    info.DetectedAcadVersion = hint;
                }
            }

            if (ManagedArxDlls.Contains(dll))
            {
                info.IsManagedArx = true;
                if (!info.AutocadImports.Contains(dll))
                    info.AutocadImports.Add(dll);
            }
        }
    }

    private static void CheckStrings(List<ExtractedString> strings, ArxInfo info)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var s in strings)
        {
            string val = s.Value;
            if (val.Length < 4 || val.Length > 128) continue;

            foreach (var prefix in AcClassPrefixes)
            {
                if (val.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    // Only keep distinct class-like strings (e.g. "AcDbLine")
                    if (seen.Add(val) && info.AcClassStrings.Count < 200)
                        info.AcClassStrings.Add(val);
                    break;
                }
            }
        }
    }

    private static void CheckManagedTypes(AnalysisResult result, ArxInfo info)
    {
        // For managed ARX, the decompiled source will have been generated by
        // DotNetDecompiler -- scan it for Autodesk namespace usage
        if (!result.IsDotNet) return;

        info.IsManagedArx = true;

        // Mine type names from strings as a lightweight alternative
        foreach (var s in result.Strings)
        {
            if (s.Value.StartsWith("Autodesk.AutoCAD", StringComparison.OrdinalIgnoreCase)
             || s.Value.StartsWith("AcMgd",            StringComparison.OrdinalIgnoreCase))
            {
                if (info.ManagedTypes.Count < 100
                    && !info.ManagedTypes.Contains(s.Value))
                {
                    info.ManagedTypes.Add(s.Value);
                }
            }
        }
    }
}
