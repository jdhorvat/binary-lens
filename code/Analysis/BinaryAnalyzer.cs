using System.IO;
using BinaryLens.Models;

namespace BinaryLens.Analysis;

/// <summary>
/// Orchestrates all analysis passes in the correct order.
/// PE analysis must run first (produces Imports/Exports needed by later passes).
/// </summary>
public static class BinaryAnalyzer
{
    /// <summary>
    /// Runs the full analysis pipeline on <paramref name="filePath"/>
    /// asynchronously so the UI stays responsive.
    /// </summary>
    public static async Task<AnalysisResult> AnalyzeAsync(
        string filePath,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        var result = new AnalysisResult
        {
            FilePath = filePath,
            FileName = Path.GetFileName(filePath),
            FileSize = new FileInfo(filePath).Length,
        };

        await Task.Run(() =>
        {
            string ext = Path.GetExtension(filePath).ToLowerInvariant();

            // ── .pyc  ─────────────────────────────────────────────────────
            // Python bytecode -- not a PE file, handled separately.
            if (ext == ".pyc")
            {
                progress?.Report("Detected Python bytecode (.pyc) -- skipping PE parse.");
                result.FileTypeSummary = "Python Bytecode (.pyc)";
                PycAnalyzer.Analyze(filePath, result, progress);
                progress?.Report("Analysis complete.");
                return;
            }

            // ── .vlx / .fas  ──────────────────────────────────────────────
            // Visual LISP compiled files -- proprietary binary, not PE.
            if (ext == ".vlx" || ext == ".fas")
            {
                progress?.Report($"Detected Visual LISP {ext.ToUpperInvariant()} file.");
                result.FileTypeSummary = $"Visual LISP {ext.ToUpperInvariant()}";
                VlxAnalyzer.Analyze(filePath, result, progress);
                progress?.Report("Analysis complete.");
                return;
            }

            // ── Pass 1: PE structure, imports, exports, resources ──────────
            progress?.Report("Parsing PE structure...");
            PeAnalyzer.Analyze(filePath, result);
            ct.ThrowIfCancellationRequested();

            if (!result.IsValidPe)
            {
                result.FileTypeSummary = "Not a valid PE file";
                return;
            }

            // ── Pass 2: String extraction ─────────────────────────────────
            progress?.Report("Extracting strings...");
            StringExtractor.Extract(filePath, result, progress);
            ct.ThrowIfCancellationRequested();

            // ── Pass 3a: ARX detection ────────────────────────────────────
            progress?.Report("Checking for AutoCAD ARX characteristics...");
            ArxAnalyzer.Analyze(result);
            ct.ThrowIfCancellationRequested();

            // ── Pass 3b: VB5/6 detection ─────────────────────────────────
            if (!result.IsDotNet && !result.IsArx)
            {
                progress?.Report("Checking for Visual Basic 5/6 characteristics...");
                var fileData = File.ReadAllBytes(filePath);
                VbAnalyzer.Analyze(result, fileData);
                ct.ThrowIfCancellationRequested();
            }

            // ── Pass 3c: .pyd / Python extension detection ────────────────
            if (ext == ".pyd" || (!result.IsArx && !result.IsDotNet))
            {
                progress?.Report("Checking for Python extension (.pyd) characteristics...");
                PydAnalyzer.Analyze(result);
                ct.ThrowIfCancellationRequested();
            }

            // ── Pass 4: Dependency tree ───────────────────────────────────
            progress?.Report("Building dependency tree...");
            DependencyAnalyzer.BuildTree(result, progress);
            ct.ThrowIfCancellationRequested();

            // ── Pass 5a: .NET decompilation ───────────────────────────────
            if (result.IsDotNet)
            {
                progress?.Report("Decompiling .NET assembly...");
                CodeAnalyzer.DecompileDotNet(filePath, result, progress);
                ct.ThrowIfCancellationRequested();
            }

            // ── Pass 5b: Native disassembly ───────────────────────────────
            if (!result.IsDotNet && result.IsValidPe)
            {
                progress?.Report("Disassembling native code...");
                CodeAnalyzer.DisassembleNative(filePath, result, progress);
                ct.ThrowIfCancellationRequested();
            }

            progress?.Report("Analysis complete.");

        }, ct);

        return result;
    }
}
