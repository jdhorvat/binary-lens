using BinaryLens.Models;
using System.Text;

namespace BinaryLens.Export;

/// <summary>
/// Generates a side-by-side HTML comparison report for two binaries.
/// Highlights differences in PE structure, imports, exports, strings, and more.
/// </summary>
public static class ComparisonReporter
{
    public static string Generate(AnalysisResult left, AnalysisResult right)
    {
        var sb = new StringBuilder(256 * 1024);

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"UTF-8\">");
        sb.AppendLine($"<title>BinaryLens — Compare: {H(left.FileName)} vs {H(right.FileName)}</title>");
        sb.AppendLine(ComparisonCss());
        sb.AppendLine("</head><body>");

        // ── Header ─────────────────────────────────────────────────────────
        sb.AppendLine("<div class=\"header\">");
        sb.AppendLine("<h1>🔬 BinaryLens Comparison Report</h1>");
        sb.AppendLine("<div class=\"compare-names\">");
        sb.AppendLine($"<span class=\"file-a\">A: {H(left.FileName)}</span>");
        sb.AppendLine("<span class=\"vs\">vs</span>");
        sb.AppendLine($"<span class=\"file-b\">B: {H(right.FileName)}</span>");
        sb.AppendLine("</div></div>");

        // ── Summary comparison ─────────────────────────────────────────────
        sb.AppendLine("<h2 class=\"section-header\">File Summary</h2>");
        sb.AppendLine("<table class=\"compare-table\">");
        sb.AppendLine("<thead><tr><th>Property</th><th class=\"col-a\">A</th><th class=\"col-b\">B</th><th>Status</th></tr></thead><tbody>");
        CompareRow(sb, "File Name",     left.FileName,        right.FileName);
        CompareRow(sb, "Size",          left.FileSizeHuman,   right.FileSizeHuman);
        CompareRow(sb, "Type",          left.FileTypeSummary, right.FileTypeSummary);
        CompareRow(sb, "Architecture",  left.Architecture,    right.Architecture);
        CompareRow(sb, ".NET",          left.IsDotNet ? "Yes" : "No",  right.IsDotNet ? "Yes" : "No");
        CompareRow(sb, "ARX",           left.IsArx ? "Yes" : "No",    right.IsArx ? "Yes" : "No");
        CompareRow(sb, "Machine",       left.PeInfo.MachineType,       right.PeInfo.MachineType);
        CompareRow(sb, "Subsystem",     left.PeInfo.Subsystem,         right.PeInfo.Subsystem);
        CompareRow(sb, "Entry Point",   left.PeInfo.EntryPoint,        right.PeInfo.EntryPoint);
        CompareRow(sb, "Image Base",    left.PeInfo.ImageBase,         right.PeInfo.ImageBase);
        CompareRow(sb, "Linker",        left.PeInfo.LinkerVersion,     right.PeInfo.LinkerVersion);
        CompareRow(sb, "Timestamp",     left.PeInfo.TimeDateStampDisplay, right.PeInfo.TimeDateStampDisplay);
        CompareRow(sb, "Imports",       left.Imports.Count.ToString(), right.Imports.Count.ToString());
        CompareRow(sb, "Exports",       left.Exports.Count.ToString(), right.Exports.Count.ToString());
        CompareRow(sb, "Strings",       left.Strings.Count.ToString(), right.Strings.Count.ToString());
        CompareRow(sb, "Resources",     left.Resources.Count.ToString(), right.Resources.Count.ToString());
        sb.AppendLine("</tbody></table>");

        // ── Sections comparison ────────────────────────────────────────────
        sb.AppendLine("<h2 class=\"section-header\">Section Table</h2>");
        CompareSections(sb, left.PeInfo.Sections, right.PeInfo.Sections);

        // ── Import diff ────────────────────────────────────────────────────
        sb.AppendLine("<h2 class=\"section-header\">Import Differences</h2>");
        CompareLists(sb,
            left.Imports.Select(i => $"{i.DllName}!{i.DisplayName}").ToHashSet(),
            right.Imports.Select(i => $"{i.DllName}!{i.DisplayName}").ToHashSet(),
            "Import");

        // ── Export diff ────────────────────────────────────────────────────
        sb.AppendLine("<h2 class=\"section-header\">Export Differences</h2>");
        CompareLists(sb,
            left.Exports.Select(e => e.DisplayName).ToHashSet(),
            right.Exports.Select(e => e.DisplayName).ToHashSet(),
            "Export");

        // ── String diff (unique strings only, limit to first 200) ─────────
        sb.AppendLine("<h2 class=\"section-header\">String Differences (first 200)</h2>");
        CompareLists(sb,
            left.Strings.Select(s => s.Value).ToHashSet(),
            right.Strings.Select(s => s.Value).ToHashSet(),
            "String",
            200);

        // ── Resource diff ──────────────────────────────────────────────────
        sb.AppendLine("<h2 class=\"section-header\">Resource Differences</h2>");
        CompareLists(sb,
            left.Resources.Select(r => $"{r.Type}/{r.Name} ({r.SizeDisplay})").ToHashSet(),
            right.Resources.Select(r => $"{r.Type}/{r.Name} ({r.SizeDisplay})").ToHashSet(),
            "Resource");

        // ── Footer ─────────────────────────────────────────────────────────
        sb.AppendLine($"<div class=\"footer\">Generated by BinaryLens · {DateTime.Now:yyyy-MM-dd HH:mm:ss}</div>");
        sb.AppendLine("</body></html>");

        return sb.ToString();
    }

    // ── Comparison helpers ──────────────────────────────────────────────────

    private static void CompareRow(StringBuilder sb, string label, string valA, string valB)
    {
        bool same = valA == valB;
        string status = same ? "<span class=\"match\">✓</span>"
                             : "<span class=\"diff\">≠</span>";
        string cls = same ? "" : " class=\"row-diff\"";
        sb.AppendLine($"<tr{cls}><td>{H(label)}</td><td>{H(valA)}</td><td>{H(valB)}</td><td>{status}</td></tr>");
    }

    private static void CompareSections(StringBuilder sb, List<PeSection> leftSecs, List<PeSection> rightSecs)
    {
        var allNames = leftSecs.Select(s => s.Name)
            .Union(rightSecs.Select(s => s.Name))
            .Distinct()
            .ToList();

        var leftMap  = leftSecs.ToDictionary(s => s.Name);
        var rightMap = rightSecs.ToDictionary(s => s.Name);

        sb.AppendLine("<table class=\"compare-table\">");
        sb.AppendLine("<thead><tr><th>Section</th><th class=\"col-a\">A: Raw Size</th><th class=\"col-a\">A: Entropy</th>" +
                      "<th class=\"col-b\">B: Raw Size</th><th class=\"col-b\">B: Entropy</th><th>Status</th></tr></thead><tbody>");

        foreach (var name in allNames)
        {
            bool inA = leftMap.TryGetValue(name, out var a);
            bool inB = rightMap.TryGetValue(name, out var b);

            if (inA && inB)
            {
                bool same = a!.RawSize == b!.RawSize && Math.Abs(a.Entropy - b.Entropy) < 0.01;
                string cls = same ? "" : " class=\"row-diff\"";
                sb.AppendLine($"<tr{cls}><td>{H(name)}</td>" +
                    $"<td>{a.RawSize}</td><td>{a.EntropyDisplay}</td>" +
                    $"<td>{b.RawSize}</td><td>{b.EntropyDisplay}</td>" +
                    $"<td>{(same ? "<span class=\"match\">✓</span>" : "<span class=\"diff\">≠</span>")}</td></tr>");
            }
            else if (inA)
            {
                sb.AppendLine($"<tr class=\"row-removed\"><td>{H(name)}</td>" +
                    $"<td>{a!.RawSize}</td><td>{a.EntropyDisplay}</td>" +
                    $"<td>—</td><td>—</td><td><span class=\"removed\">A only</span></td></tr>");
            }
            else
            {
                sb.AppendLine($"<tr class=\"row-added\"><td>{H(name)}</td>" +
                    $"<td>—</td><td>—</td>" +
                    $"<td>{b!.RawSize}</td><td>{b.EntropyDisplay}</td>" +
                    $"<td><span class=\"added\">B only</span></td></tr>");
            }
        }
        sb.AppendLine("</tbody></table>");
    }

    private static void CompareLists(StringBuilder sb, HashSet<string> leftSet,
        HashSet<string> rightSet, string itemType, int limit = 0)
    {
        var onlyA = leftSet.Except(rightSet).ToList();
        var onlyB = rightSet.Except(leftSet).ToList();
        var common = leftSet.Intersect(rightSet).Count();

        sb.AppendLine("<div class=\"diff-summary\">");
        sb.AppendLine($"<span class=\"match\">Common: {common}</span> · ");
        sb.AppendLine($"<span class=\"removed\">Only in A: {onlyA.Count}</span> · ");
        sb.AppendLine($"<span class=\"added\">Only in B: {onlyB.Count}</span>");
        sb.AppendLine("</div>");

        if (onlyA.Count == 0 && onlyB.Count == 0)
        {
            sb.AppendLine($"<p class=\"no-diff\">No {itemType.ToLower()} differences found.</p>");
            return;
        }

        sb.AppendLine("<table class=\"compare-table\">");
        sb.AppendLine($"<thead><tr><th>{itemType}</th><th>Status</th></tr></thead><tbody>");

        int count = 0;
        foreach (var item in onlyA.OrderBy(x => x))
        {
            if (limit > 0 && ++count > limit) break;
            sb.AppendLine($"<tr class=\"row-removed\"><td>{H(item)}</td><td><span class=\"removed\">A only</span></td></tr>");
        }
        foreach (var item in onlyB.OrderBy(x => x))
        {
            if (limit > 0 && ++count > limit) break;
            sb.AppendLine($"<tr class=\"row-added\"><td>{H(item)}</td><td><span class=\"added\">B only</span></td></tr>");
        }
        sb.AppendLine("</tbody></table>");
    }

    private static string H(string s) => System.Web.HttpUtility.HtmlEncode(s);

    // ── Embedded CSS ──────────────────────────────────────────────────────────

    private static string ComparisonCss() => @"<style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, 'Segoe UI', sans-serif; font-size: 13px;
               color: #1a1a1a; background: #f3f3f3; padding: 24px; }
        .header { background: #0078D4; color: white; padding: 20px 24px;
                  border-radius: 8px; margin-bottom: 24px; }
        .header h1 { font-size: 22px; margin-bottom: 10px; }
        .compare-names { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .file-a { background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 6px;
                  font-family: monospace; font-size: 12px; }
        .file-b { background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 6px;
                  font-family: monospace; font-size: 12px; }
        .vs { font-weight: 700; font-size: 14px; opacity: 0.8; }

        h2.section-header { font-size: 13px; font-weight: 700; text-transform: uppercase;
                             letter-spacing: 0.05em; color: #555; margin: 24px 0 8px;
                             padding-bottom: 6px; border-bottom: 2px solid #0078D4; }

        .compare-table { border-collapse: collapse; width: 100%; background: white;
                         border-radius: 6px; overflow: hidden;
                         box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 16px; }
        .compare-table thead th { background: #f0f0f0; padding: 8px 10px; font-size: 11px;
                                   text-align: left; font-weight: 700; color: #555;
                                   text-transform: uppercase; letter-spacing: 0.04em; }
        .compare-table th.col-a { background: #e3f2fd; }
        .compare-table th.col-b { background: #fce4ec; }
        .compare-table tbody td { padding: 5px 10px; font-family: monospace; font-size: 11px;
                                   border-top: 1px solid #f0f0f0; word-break: break-all; }
        .compare-table tbody tr:nth-child(even) { background: #fafafa; }
        .row-diff { background: #fffde7 !important; }
        .row-removed { background: #ffebee !important; }
        .row-added   { background: #e8f5e9 !important; }

        .match   { color: #2e7d32; font-weight: 600; }
        .diff    { color: #c42b1c; font-weight: 600; }
        .removed { color: #c42b1c; font-weight: 600; font-size: 11px; }
        .added   { color: #2e7d32; font-weight: 600; font-size: 11px; }

        .diff-summary { margin-bottom: 8px; font-size: 12px; }
        .no-diff { color: #888; font-style: italic; margin-bottom: 16px; }

        .footer { text-align: center; color: #888; font-size: 11px;
                  margin-top: 40px; padding-top: 16px; border-top: 1px solid #ddd; }

        @media print { body { background: white; padding: 0; }
                        .header { -webkit-print-color-adjust: exact; }
                        .row-diff, .row-removed, .row-added { -webkit-print-color-adjust: exact; } }
    </style>";
}
