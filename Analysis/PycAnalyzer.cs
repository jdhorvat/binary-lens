using BinaryLens.Models;

namespace BinaryLens.Analysis;

/// <summary>
/// Analyses Python compiled bytecode (.pyc) files.
/// Uses the self-contained PycDecoder -- no Python installation required.
/// Supports Python 2.7 through 3.13.
/// </summary>
public static class PycAnalyzer
{
    public static void Analyze(string filePath, AnalysisResult result,
                                IProgress<string>? progress = null)
    {
        progress?.Report("Decoding Python bytecode (no Python installation required)...");

        PycDecodeResult decoded;
        try
        {
            decoded = PycDecoder.Decode(filePath);
        }
        catch (Exception ex)
        {
            result.Errors.Add($"PycDecoder failed: {ex.Message}");
            return;
        }

        if (decoded.Error != null)
        {
            result.Errors.Add(decoded.Error);
        }

        // Map to PycInfo model
        var info = new PycInfo
        {
            FilePath          = filePath,
            MagicNumber       = decoded.MagicNumber,
            PythonVersion     = decoded.PythonVersion,
            Flags             = decoded.Flags,
            IsHashBased       = decoded.IsHashBased,
            SourceTimestamp   = decoded.SourceTimestamp,
            SourceSize        = decoded.SourceSize,
            BytecodeOffset    = decoded.HeaderSize,
            BytecodeSize      = decoded.RootCode?.Code.Length ?? 0,
            DecompilerUsed    = "Built-in C# bytecode decoder (version-independent)",
            PythonExe         = null,    // not applicable -- no subprocess
            Error             = decoded.Error,
        };

        result.IsPyc             = true;
        result.PycInfo           = info;
        result.DecompiledSource  = string.IsNullOrWhiteSpace(decoded.Disassembly)
            ? "# No bytecode decoded."
            : decoded.Disassembly;

        // Populate file summary
        result.FileTypeSummary = $"Python Bytecode · {info.PythonVersion}";
        result.Architecture    = "N/A (bytecode)";

        if (decoded.RootCode != null)
        {
            result.IsDotNet = false;
            progress?.Report($"Decoded {CountInstructions(decoded.Disassembly):N0} instructions " +
                             $"from {info.PythonVersion} bytecode.");
        }
        else
        {
            progress?.Report("Bytecode decode produced no code object.");
        }
    }

    private static int CountInstructions(string disasm)
    {
        // Count non-comment, non-empty lines as a proxy for instruction count
        if (string.IsNullOrEmpty(disasm)) return 0;
        return disasm.Split('\n')
                     .Count(l => l.Length > 6
                              && !l.TrimStart().StartsWith('#')
                              && !l.TrimStart().StartsWith('='));
    }
}
