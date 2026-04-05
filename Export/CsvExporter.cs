using BinaryLens.Models;
using System.IO;
using System.Text;

namespace BinaryLens.Export;

/// <summary>
/// Exports analysis data as CSV files.
/// Each dataset (imports, exports, strings, resources, sections, dependencies)
/// gets its own file in a user-chosen directory, or a single combined file
/// with sections separated by headers.
/// </summary>
public static class CsvExporter
{
    /// <summary>
    /// Writes multiple CSV files to <paramref name="directory"/>:
    ///   {prefix}_imports.csv, {prefix}_exports.csv, {prefix}_strings.csv,
    ///   {prefix}_resources.csv, {prefix}_sections.csv, {prefix}_dependencies.csv
    /// Returns the list of files written.
    /// </summary>
    public static List<string> GenerateAll(AnalysisResult result, string directory, string? prefix = null)
    {
        prefix ??= Path.GetFileNameWithoutExtension(result.FileName);
        Directory.CreateDirectory(directory);
        var written = new List<string>();

        // ── Summary ──────────────────────────────────────────────────────
        var summaryPath = Path.Combine(directory, $"{prefix}_summary.csv");
        var sb = new StringBuilder();
        sb.AppendLine("Property,Value");
        CsvRow(sb, "File",         result.FileName);
        CsvRow(sb, "Path",         result.FilePath);
        CsvRow(sb, "Size",         result.FileSizeHuman);
        CsvRow(sb, "Type",         result.FileTypeSummary);
        CsvRow(sb, "Architecture", result.Architecture);
        CsvRow(sb, ".NET",         result.IsDotNet ? "Yes" : "No");
        CsvRow(sb, "ARX",          result.IsArx    ? "Yes" : "No");
        CsvRow(sb, "Machine",      result.PeInfo.MachineType);
        CsvRow(sb, "Subsystem",    result.PeInfo.Subsystem);
        CsvRow(sb, "Entry Point",  result.PeInfo.EntryPoint);
        CsvRow(sb, "Image Base",   result.PeInfo.ImageBase);
        CsvRow(sb, "Linker",       result.PeInfo.LinkerVersion);
        CsvRow(sb, "Timestamp",    result.PeInfo.TimeDateStampDisplay);
        File.WriteAllText(summaryPath, sb.ToString(), Encoding.UTF8);
        written.Add(summaryPath);

        // ── Sections ────────────────────────────────────────────────────
        if (result.PeInfo.Sections.Count > 0)
        {
            var path = Path.Combine(directory, $"{prefix}_sections.csv");
            sb.Clear();
            sb.AppendLine("Name,VirtualAddress,VirtualSize,RawSize,Entropy,Note,Characteristics");
            foreach (var s in result.PeInfo.Sections)
                sb.AppendLine($"{Esc(s.Name)},{Esc(s.VirtualAddress)},{Esc(s.VirtualSize)},{Esc(s.RawSize)},{s.Entropy:F2},{Esc(s.EntropyNote)},{Esc(s.Characteristics)}");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            written.Add(path);
        }

        // ── Imports ─────────────────────────────────────────────────────
        if (result.Imports.Count > 0)
        {
            var path = Path.Combine(directory, $"{prefix}_imports.csv");
            sb.Clear();
            sb.AppendLine("DLL,Function,Hint,IsOrdinal");
            foreach (var i in result.Imports)
                sb.AppendLine($"{Esc(i.DllName)},{Esc(i.DisplayName)},{Esc(i.Hint)},{i.IsOrdinal}");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            written.Add(path);
        }

        // ── Exports ─────────────────────────────────────────────────────
        if (result.Exports.Count > 0)
        {
            var path = Path.Combine(directory, $"{prefix}_exports.csv");
            sb.Clear();
            sb.AppendLine("Name,RVA,Ordinal,IsForwarded,ForwardTarget");
            foreach (var e in result.Exports)
                sb.AppendLine($"{Esc(e.DisplayName)},{Esc(e.RvaAddress)},{e.Ordinal},{e.IsForwarded},{Esc(e.ForwardTarget ?? "")}");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            written.Add(path);
        }

        // ── Strings ─────────────────────────────────────────────────────
        if (result.Strings.Count > 0)
        {
            var path = Path.Combine(directory, $"{prefix}_strings.csv");
            sb.Clear();
            sb.AppendLine("Offset,Encoding,Value");
            foreach (var s in result.Strings)
                sb.AppendLine($"{Esc(s.OffsetHex)},{Esc(s.Encoding)},{Esc(s.Value)}");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            written.Add(path);
        }

        // ── Resources ───────────────────────────────────────────────────
        if (result.Resources.Count > 0)
        {
            var path = Path.Combine(directory, $"{prefix}_resources.csv");
            sb.Clear();
            sb.AppendLine("Type,Name,Language,Size");
            foreach (var r2 in result.Resources)
                sb.AppendLine($"{Esc(r2.Type)},{Esc(r2.Name)},{Esc(r2.Language)},{r2.Size}");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            written.Add(path);
        }

        // ── Dependencies ────────────────────────────────────────────────
        if (result.DependencyRoot != null)
        {
            var path = Path.Combine(directory, $"{prefix}_dependencies.csv");
            sb.Clear();
            sb.AppendLine("Depth,Name,Found,IsSystem,IsAutocad,ResolvedPath");
            FlattenDep(sb, result.DependencyRoot, 0);
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            written.Add(path);
        }

        return written;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static void FlattenDep(StringBuilder sb, DependencyNode node, int depth)
    {
        sb.AppendLine($"{depth},{Esc(node.Name)},{node.Found},{node.IsSystem},{node.IsAutocad},{Esc(node.ResolvedPath ?? "")}");
        foreach (var child in node.Children)
            FlattenDep(sb, child, depth + 1);
    }

    private static void CsvRow(StringBuilder sb, string key, string value)
        => sb.AppendLine($"{Esc(key)},{Esc(value)}");

    /// <summary>RFC 4180 CSV escaping: wrap in quotes if it contains comma, quote, or newline.</summary>
    private static string Esc(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n') || value.Contains('\r'))
            return $"\"{value.Replace("\"", "\"\"")}\"";
        return value;
    }
}
