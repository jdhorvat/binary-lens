using BinaryLens.Models;

namespace BinaryLens.Analysis;

/// <summary>
/// Detects and analyses Python extension modules (.pyd files).
///
/// .pyd files are standard Windows PE DLLs compiled from C/C++ Python
/// extensions.  They are fully parsed by PeAnalyzer first; this pass
/// adds Python-specific context on top of that.
///
/// DETECTION SIGNALS:
///   • Exports PyInit_&lt;name&gt;    (Python 3 extension entry point)
///   • Exports init&lt;name&gt;       (Python 2 extension entry point)
///   • Imports python3*.dll or python27.dll
///   • Imports PyArg_ParseTuple, PyModule_Create2, etc.
/// </summary>
public static class PydAnalyzer
{
    // ── Python runtime DLL patterns ───────────────────────────────────────────

    private static readonly string[] PythonRuntimeDlls =
    [
        "python27.dll",  "python34.dll",  "python35.dll",
        "python36.dll",  "python37.dll",  "python38.dll",
        "python39.dll",  "python310.dll", "python311.dll",
        "python312.dll", "python313.dll",
    ];

    // ── Well-known Python C API function imports ───────────────────────────────

    private static readonly HashSet<string> PythonApiFunctions = new(StringComparer.Ordinal)
    {
        "PyArg_ParseTuple", "PyArg_ParseTupleAndKeywords",
        "PyModule_Create2",  "PyModule_AddObject",
        "PyErr_SetString",   "PyErr_Format",
        "Py_BuildValue",     "PyObject_CallObject",
        "PyList_New",        "PyDict_New",
        "PyLong_FromLong",   "PyFloat_FromDouble",
        "PyUnicode_FromString", "PyBytes_FromString",
        "PyImport_ImportModule", "PyObject_GetAttrString",
        "Py_INCREF",         "Py_DECREF",
        "PyType_Ready",      "PyObject_IsInstance",
    };

    // ── Python version inference from DLL name ────────────────────────────────

    private static string InferVersionFromDll(string dll)
    {
        string lower = dll.ToLowerInvariant();
        if (lower == "python27.dll")  return "Python 2.7";
        if (lower == "python34.dll")  return "Python 3.4";
        if (lower == "python35.dll")  return "Python 3.5";
        if (lower == "python36.dll")  return "Python 3.6";
        if (lower == "python37.dll")  return "Python 3.7";
        if (lower == "python38.dll")  return "Python 3.8";
        if (lower == "python39.dll")  return "Python 3.9";
        if (lower == "python310.dll") return "Python 3.10";
        if (lower == "python311.dll") return "Python 3.11";
        if (lower == "python312.dll") return "Python 3.12";
        if (lower == "python313.dll") return "Python 3.13";
        return $"Unknown ({dll})";
    }

    // ── Public entry point ───────────────────────────────────────────────────

    /// <summary>
    /// Runs after PeAnalyzer.  Populates result.PydInfo and sets result.IsPyd.
    /// </summary>
    public static void Analyze(AnalysisResult result)
    {
        if (!result.IsValidPe) return;

        var info = new PydInfo();

        ScanExports(result.Exports, info);
        ScanImports(result.Imports, info);

        // A .pyd must have either a PyInit_ export OR heavy Python API imports
        result.IsPyd = info.HasPyInit
                    || info.PythonRuntimeImport != null
                    || info.PythonApiImports.Count >= 4;

        if (result.IsPyd)
        {
            result.PydInfo = info;

            // Annotate file type summary
            result.FileTypeSummary = result.FileTypeSummary.TrimEnd()
                + $" · Python Extension ({info.PythonVersion})";
        }
    }

    // ── Scan helpers ──────────────────────────────────────────────────────────

    private static void ScanExports(List<ExportEntry> exports, PydInfo info)
    {
        foreach (var exp in exports)
        {
            string name = exp.Name;

            // Python 3: PyInit_<modulename>
            if (name.StartsWith("PyInit_", StringComparison.Ordinal))
            {
                info.HasPyInit   = true;
                info.InitFunction = name;
                info.ModuleName  = name["PyInit_".Length..];
                info.PythonMajor = 3;
                break;
            }

            // Python 2: init<modulename>  (no uppercase I)
            if (name.StartsWith("init", StringComparison.Ordinal)
             && name.Length > 4 && char.IsLower(name[4]))
            {
                info.HasPyInit   = true;
                info.InitFunction = name;
                info.ModuleName  = name[4..];
                info.PythonMajor = 2;
                break;
            }
        }
    }

    private static void ScanImports(List<ImportEntry> imports, PydInfo info)
    {
        var seenDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var imp in imports)
        {
            string dll = imp.DllName ?? "";
            string fn  = imp.FunctionName ?? "";

            // Python runtime DLL
            if (PythonRuntimeDlls.Any(p =>
                    string.Equals(dll, p, StringComparison.OrdinalIgnoreCase))
                && seenDlls.Add(dll))
            {
                info.PythonRuntimeImport = dll;
                info.PythonVersion       = InferVersionFromDll(dll);
            }

            // Python C API functions
            if (PythonApiFunctions.Contains(fn)
                && !info.PythonApiImports.Contains(fn))
            {
                info.PythonApiImports.Add(fn);
            }
        }

        // If we found a runtime DLL but no init export (odd but possible),
        // infer major from DLL name
        if (info.PythonMajor == 0 && info.PythonRuntimeImport != null)
        {
            info.PythonMajor = info.PythonRuntimeImport
                .ToLowerInvariant().Contains("python2") ? 2 : 3;
        }

        // If no runtime DLL name but we have a version from PyInit
        if (string.IsNullOrEmpty(info.PythonVersion))
            info.PythonVersion = info.PythonMajor == 2 ? "Python 2.x" : "Python 3.x";
    }
}
