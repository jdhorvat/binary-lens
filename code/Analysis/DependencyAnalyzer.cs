using System.IO;
using BinaryLens.Models;
using PeNet;

namespace BinaryLens.Analysis;

/// <summary>
/// Builds a recursive dependency tree by resolving each imported DLL
/// from the system PATH, System32, and the file's own directory.
/// Recursion is capped at depth 3 to avoid exploding on system DLLs.
/// </summary>
public static class DependencyAnalyzer
{
    private const int MaxDepth = 3;

    // ── Well-known system DLL prefixes (don't recurse into these) ────────────

    private static readonly string[] SystemPrefixes =
    [
        "ntdll", "kernel32", "kernelbase", "user32", "gdi32",
        "advapi32", "ole32", "oleaut32", "comctl32", "comdlg32",
        "shell32", "msvcrt", "ucrtbase", "vcruntime", "msvcp",
        "winmm", "ws2_32", "wsock32", "winspool", "rpcrt4",
        "secur32", "crypt32", "imm32", "version", "shlwapi",
        "bcrypt", "ncrypt", "cfgmgr32", "setupapi", "d3d",
        "opengl32", "dbghelp", "psapi", "userenv", "wtsapi32",
        "dwmapi", "uxtheme", "combase", "clbcatq",
    ];

    // ── AutoCAD DLL identifiers ───────────────────────────────────────────────

    private static readonly HashSet<string> AutocadDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "acad.exe","accore.dll","acrx20.dll",
        "acdb23.dll","acdb24.dll","acdb25.dll","acdb26.dll",
        "acge22.dll","acge23.dll","acge24.dll",
        "acmgd.dll","acdbmgd.dll","accoremgd.dll",
        "acutil23.dll","acutil24.dll",
    };

    // ── Search paths ─────────────────────────────────────────────────────────

    private static readonly List<string> SearchPaths;

    static DependencyAnalyzer()
    {
        SearchPaths = new List<string>();

        string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string sysWow = Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.Windows), "SysWOW64");

        if (Directory.Exists(sys32))   SearchPaths.Add(sys32);
        if (Directory.Exists(sysWow))  SearchPaths.Add(sysWow);

        // Add PATH entries
        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (pathEnv != null)
        {
            foreach (var p in pathEnv.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                if (Directory.Exists(p) && !SearchPaths.Contains(p))
                    SearchPaths.Add(p);
            }
        }
    }

    // ── Public entry point ───────────────────────────────────────────────────

    public static void BuildTree(AnalysisResult result,
                                 IProgress<string>? progress = null)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Application directory
        var appDir = Path.GetDirectoryName(result.FilePath);
        var searchPaths = appDir != null
            ? new List<string> { appDir }.Concat(SearchPaths).ToList()
            : SearchPaths;

        var root = new DependencyNode
        {
            Name  = result.FileName,
            Found = File.Exists(result.FilePath),
            ResolvedPath = result.FilePath,
            Depth = 0,
        };
        seen.Add(result.FileName);

        // Walk direct imports from the top-level analysis
        foreach (var importGroup in result.Imports
            .GroupBy(i => i.DllName, StringComparer.OrdinalIgnoreCase))
        {
            string dll = importGroup.Key;
            if (string.IsNullOrEmpty(dll)) continue;

            var child = BuildNode(dll, searchPaths, seen, 1, progress);
            root.Children.Add(child);
        }

        result.DependencyRoot = root;
    }

    // ── Recursive node builder ────────────────────────────────────────────────

    private static DependencyNode BuildNode(string dllName,
                                             List<string> searchPaths,
                                             HashSet<string> seen,
                                             int depth,
                                             IProgress<string>? progress)
    {
        string? resolved = Resolve(dllName, searchPaths);
        bool isSystem    = IsSystemDll(dllName);
        bool isAutocad   = AutocadDlls.Contains(dllName);

        progress?.Report($"Resolving: {dllName}");

        var node = new DependencyNode
        {
            Name         = dllName,
            ResolvedPath = resolved,
            Found        = resolved != null,
            IsSystem     = isSystem,
            IsAutocad    = isAutocad,
            Depth        = depth,
        };

        // Stop recursion: already seen, system DLL, or max depth
        if (seen.Contains(dllName) || isSystem || depth >= MaxDepth || resolved == null)
            return node;

        seen.Add(dllName);

        // Recurse into this DLL's own imports
        try
        {
            var childPe = new PeFile(resolved);
            if (childPe.ImportedFunctions == null) return node;

            foreach (var childGroup in childPe.ImportedFunctions
                .Where(f => !string.IsNullOrEmpty(f.DLL))
                .GroupBy(f => f.DLL!, StringComparer.OrdinalIgnoreCase))
            {
                string childDll = childGroup.Key;
                var childNode   = BuildNode(childDll, searchPaths, seen, depth + 1, progress);
                node.Children.Add(childNode);
            }
        }
        catch { /* PeNet failed on child -- stop here */ }

        return node;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string? Resolve(string dllName, List<string> searchPaths)
    {
        if (Path.IsPathRooted(dllName) && File.Exists(dllName)) return dllName;

        foreach (var dir in searchPaths)
        {
            string candidate = Path.Combine(dir, dllName);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    private static bool IsSystemDll(string name)
    {
        string lower = name.ToLowerInvariant().Replace(".dll", "").Replace(".exe", "");
        return SystemPrefixes.Any(p => lower.StartsWith(p));
    }
}
