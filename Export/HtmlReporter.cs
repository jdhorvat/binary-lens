using BinaryLens.Models;
using System.Text;

namespace BinaryLens.Export;

/// <summary>
/// Generates a standalone single-file HTML report with embedded CSS and JS.
/// Includes dark mode toggle, collapsible sections, table of contents,
/// and full coverage of all analysis panels (PE, Python, VLX, ARX, disassembly).
/// </summary>
public static class HtmlReporter
{
    public static string Generate(AnalysisResult result)
    {
        var sb = new StringBuilder(512 * 1024);

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"UTF-8\">");
        sb.AppendLine($"<title>BinaryLens — {H(result.FileName)}</title>");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine(EmbeddedCss());
        sb.AppendLine("</head><body>");

        // ── Header ─────────────────────────────────────────────────────────
        sb.AppendLine("<div class=\"header\">");
        sb.AppendLine("<div class=\"header-top\">");
        sb.AppendLine("<h1>🔬 BinaryLens Analysis</h1>");
        sb.AppendLine("<button class=\"theme-btn\" onclick=\"toggleTheme()\" title=\"Toggle dark mode\">🌙</button>");
        sb.AppendLine("</div>");
        sb.AppendLine($"<p class=\"subtitle\">{H(result.FilePath)}</p>");
        sb.AppendLine("<div class=\"badges\">");
        sb.AppendLine(Badge(result.Architecture, "blue"));
        if (result.IsDotNet)   sb.AppendLine(Badge(".NET", "purple"));
        if (result.IsArx)      sb.AppendLine(Badge("AutoCAD ARX", "orange"));
        if (result.IsPyc)      sb.AppendLine(Badge("Python .pyc", "green"));
        if (result.IsPyd)      sb.AppendLine(Badge("Python .pyd", "green"));
        if (result.IsVlx)      sb.AppendLine(Badge("VLX/FAS", "teal"));
        if (!result.IsValidPe) sb.AppendLine(Badge("Invalid PE", "red"));
        sb.AppendLine("</div></div>");

        // ── Table of Contents ──────────────────────────────────────────────
        sb.AppendLine("<nav class=\"toc\">");
        sb.AppendLine("<strong>Contents:</strong> ");
        sb.AppendLine("<a href=\"#sec-summary\">Summary</a>");
        if (result.PeInfo.Characteristics.Count > 0)
            sb.AppendLine(" · <a href=\"#sec-characteristics\">Characteristics</a>");
        sb.AppendLine(" · <a href=\"#sec-sections\">Sections</a>");
        sb.AppendLine(" · <a href=\"#sec-imports\">Imports</a>");
        sb.AppendLine(" · <a href=\"#sec-exports\">Exports</a>");
        sb.AppendLine(" · <a href=\"#sec-strings\">Strings</a>");
        sb.AppendLine(" · <a href=\"#sec-resources\">Resources</a>");
        if (result.DependencyRoot != null)
            sb.AppendLine(" · <a href=\"#sec-deps\">Dependencies</a>");
        if (result.IsDotNet && !string.IsNullOrEmpty(result.DecompiledSource))
            sb.AppendLine(" · <a href=\"#sec-source\">.NET Source</a>");
        if (result.Disassembly.Count > 0)
            sb.AppendLine(" · <a href=\"#sec-disasm\">Disassembly</a>");
        if (result.IsArx && result.ArxInfo != null)
            sb.AppendLine(" · <a href=\"#sec-arx\">ARX</a>");
        if (result.IsPyc && result.PycInfo != null)
            sb.AppendLine(" · <a href=\"#sec-pyc\">Python .pyc</a>");
        if (result.IsPyd && result.PydInfo != null)
            sb.AppendLine(" · <a href=\"#sec-pyd\">Python .pyd</a>");
        if (result.IsVlx && result.VlxInfo != null)
            sb.AppendLine(" · <a href=\"#sec-vlx\">VLX/FAS</a>");
        if (result.Errors.Count > 0)
            sb.AppendLine(" · <a href=\"#sec-errors\">Warnings</a>");
        sb.AppendLine("</nav>");

        // ── Toolbar ────────────────────────────────────────────────────────
        sb.AppendLine("<div class=\"toolbar\">");
        sb.AppendLine("<button onclick=\"expandAll()\">Expand All</button>");
        sb.AppendLine("<button onclick=\"collapseAll()\">Collapse All</button>");
        sb.AppendLine("</div>");

        // ── Summary table ──────────────────────────────────────────────────
        sb.AppendLine(CollapsibleSection("sec-summary", "File Summary", true));
        sb.AppendLine("<table class=\"props\">");
        Prop(sb, "File",         result.FileName);
        Prop(sb, "Size",         result.FileSizeHuman);
        Prop(sb, "Type",         result.FileTypeSummary);
        Prop(sb, "Architecture", result.Architecture);
        Prop(sb, ".NET",         result.IsDotNet ? "Yes" : "No");
        Prop(sb, "ARX",          result.IsArx    ? "Yes" : "No");
        Prop(sb, "Machine",      result.PeInfo.MachineType);
        Prop(sb, "Subsystem",    result.PeInfo.Subsystem);
        Prop(sb, "Entry Point",  result.PeInfo.EntryPoint);
        Prop(sb, "Image Base",   result.PeInfo.ImageBase);
        Prop(sb, "Size of Image",result.PeInfo.SizeOfImage);
        Prop(sb, "Linker",       result.PeInfo.LinkerVersion);
        Prop(sb, "Timestamp",    result.PeInfo.TimeDateStampDisplay);
        sb.AppendLine("</table>");
        sb.AppendLine("</div>"); // collapsible content

        // ── PE Characteristics ─────────────────────────────────────────────
        if (result.PeInfo.Characteristics.Count > 0)
        {
            sb.AppendLine(CollapsibleSection("sec-characteristics", "PE Characteristics", true));
            sb.AppendLine("<ul class=\"tags\">");
            foreach (var c in result.PeInfo.Characteristics)
                sb.AppendLine($"<li>{H(c)}</li>");
            sb.AppendLine("</ul></div>");
        }

        // ── Sections ───────────────────────────────────────────────────────
        sb.AppendLine(CollapsibleSection("sec-sections", $"Sections ({result.PeInfo.Sections.Count})", true));
        sb.AppendLine(TableHeader("Name", "Virtual Address", "Virtual Size",
                                  "Raw Size", "Entropy", "Characteristics"));
        foreach (var sec in result.PeInfo.Sections)
        {
            string entropyClass = sec.Entropy > 7.5 ? "entropy-high"
                                : sec.Entropy > 6.0 ? "entropy-mod" : "";
            sb.AppendLine(TableRow(
                sec.Name, sec.VirtualAddress, sec.VirtualSize,
                sec.RawSize,
                $"<span class=\"{entropyClass}\">{sec.EntropyDisplay}</span> {sec.EntropyNote}",
                sec.Characteristics));
        }
        sb.AppendLine("</table></div>");

        // ── Imports ────────────────────────────────────────────────────────
        sb.AppendLine(CollapsibleSection("sec-imports", $"Imports ({result.Imports.Count})", result.Imports.Count <= 200));
        sb.AppendLine(TableHeader("DLL", "Function", "Hint / Ordinal"));
        foreach (var imp in result.Imports)
            sb.AppendLine(TableRow(imp.DllName, imp.DisplayName, imp.Hint));
        sb.AppendLine("</table></div>");

        // ── Exports ────────────────────────────────────────────────────────
        sb.AppendLine(CollapsibleSection("sec-exports", $"Exports ({result.Exports.Count})", result.Exports.Count <= 200));
        sb.AppendLine(TableHeader("Name", "RVA", "Ordinal", "Forwarded?"));
        foreach (var exp in result.Exports)
        {
            sb.AppendLine(TableRow(
                exp.DisplayName, exp.RvaAddress,
                exp.Ordinal.ToString(),
                exp.IsForwarded ? $"→ {exp.ForwardTarget}" : "No"));
        }
        sb.AppendLine("</table></div>");

        // ── Strings (first 500) ────────────────────────────────────────────
        var stringsToShow = result.Strings.Take(500).ToList();
        sb.AppendLine(CollapsibleSection("sec-strings",
            $"Strings ({result.Strings.Count} total, showing first 500)", false));
        sb.AppendLine(TableHeader("Offset", "Encoding", "Value"));
        foreach (var s in stringsToShow)
            sb.AppendLine(TableRow(s.OffsetHex, s.Encoding, H(s.Value)));
        sb.AppendLine("</table></div>");

        // ── Resources ─────────────────────────────────────────────────────
        sb.AppendLine(CollapsibleSection("sec-resources", $"Resources ({result.Resources.Count})", true));
        sb.AppendLine(TableHeader("Type", "Name", "Language", "Size"));
        foreach (var res in result.Resources)
            sb.AppendLine(TableRow(res.Type, res.Name, res.Language, res.SizeDisplay));
        sb.AppendLine("</table></div>");

        // ── Dependencies ──────────────────────────────────────────────────
        if (result.DependencyRoot != null)
        {
            sb.AppendLine(CollapsibleSection("sec-deps", "Dependencies", true));
            sb.AppendLine("<div class=\"dep-legend\">");
            sb.AppendLine("<span class=\"dep-found\">🟢 Found</span>");
            sb.AppendLine("<span class=\"dep-missing\">🔴 Not found</span>");
            sb.AppendLine("<span class=\"dep-system\">⚪ System</span>");
            sb.AppendLine("<span class=\"dep-autocad\">🔵 AutoCAD</span>");
            sb.AppendLine("</div>");
            sb.AppendLine("<div class=\"deptree\">");
            RenderDepNode(sb, result.DependencyRoot, 0);
            sb.AppendLine("</div></div>");
        }

        // ── .NET Decompiled Source ─────────────────────────────────────────
        if (result.IsDotNet && !string.IsNullOrEmpty(result.DecompiledSource))
        {
            sb.AppendLine(CollapsibleSection("sec-source",
                $".NET Decompiled Source ({result.DecompiledSource.Length:N0} chars)", false));
            sb.AppendLine("<div class=\"code-block\">");
            // Show first 100KB of source to keep report size reasonable
            var src = result.DecompiledSource.Length > 102_400
                ? result.DecompiledSource[..102_400] + "\n\n// ... truncated (full source too large for HTML report) ..."
                : result.DecompiledSource;
            sb.AppendLine($"<pre><code>{H(src)}</code></pre>");
            sb.AppendLine("</div></div>");
        }

        // ── Native Disassembly ────────────────────────────────────────────
        if (result.Disassembly.Count > 0)
        {
            var disasmToShow = result.Disassembly.Take(5000).ToList();
            sb.AppendLine(CollapsibleSection("sec-disasm",
                $"Disassembly ({result.Disassembly.Count:N0} instructions, showing first 5000)", false));
            sb.AppendLine(TableHeader("Address", "Bytes", "Mnemonic", "Operands"));
            foreach (var d in disasmToShow)
                sb.AppendLine(TableRow(d.Address, d.Bytes, $"<strong>{H(d.Mnemonic)}</strong>", H(d.Operands)));
            sb.AppendLine("</table></div>");
        }

        // ── ARX Info ──────────────────────────────────────────────────────
        if (result.IsArx && result.ArxInfo != null)
        {
            var arx = result.ArxInfo;
            sb.AppendLine(CollapsibleSection("sec-arx", "AutoCAD ARX Analysis", true));
            sb.AppendLine("<table class=\"props\">");
            Prop(sb, "ARX Entry Point",   arx.HasArxEntryPoint ? $"✅ {arx.EntryPointName}" : "Not found");
            Prop(sb, "Managed ARX",       arx.IsManagedArx ? "Yes (.NET)" : "No (native C++)");
            Prop(sb, "Detected Version",  arx.DetectedAcadVersion ?? "Unknown");
            Prop(sb, "AutoCAD Imports",   string.Join(", ", arx.AutocadImports));
            Prop(sb, "Command Exports",   arx.CommandExports.Count > 0
                ? string.Join(", ", arx.CommandExports) : "None");
            sb.AppendLine("</table>");

            if (arx.AcClassStrings.Count > 0)
            {
                sb.AppendLine("<h4>ObjectARX Class Strings Found</h4>");
                sb.AppendLine("<ul class=\"tags\">");
                foreach (var cls in arx.AcClassStrings.Take(100))
                    sb.AppendLine($"<li>{H(cls)}</li>");
                sb.AppendLine("</ul>");
            }

            if (arx.ManagedTypes.Count > 0)
            {
                sb.AppendLine("<h4>Managed Types</h4>");
                sb.AppendLine("<ul class=\"tags\">");
                foreach (var t in arx.ManagedTypes.Take(100))
                    sb.AppendLine($"<li>{H(t)}</li>");
                sb.AppendLine("</ul>");
            }
            sb.AppendLine("</div>");
        }

        // ── Python .pyc ───────────────────────────────────────────────────
        if (result.IsPyc && result.PycInfo != null)
        {
            var pyc = result.PycInfo;
            sb.AppendLine(CollapsibleSection("sec-pyc", "Python Bytecode (.pyc)", true));
            sb.AppendLine("<table class=\"props\">");
            Prop(sb, "Python Version",  pyc.PythonVersion);
            Prop(sb, "Magic Number",    pyc.MagicDisplay);
            Prop(sb, "Flags",           pyc.FlagsDisplay);
            Prop(sb, "Hash-based",      pyc.IsHashBased ? "Yes" : "No");
            Prop(sb, "Source Timestamp", pyc.SourceTimestampDisplay);
            Prop(sb, "Source Size",     pyc.SourceSize > 0 ? $"{pyc.SourceSize:N0} bytes" : "N/A");
            Prop(sb, "Bytecode Offset", $"{pyc.BytecodeOffset} bytes");
            Prop(sb, "Bytecode Size",   pyc.BytecodeSizeDisplay);
            Prop(sb, "Decompiler Used", pyc.DecompilerUsed);
            if (pyc.Error != null)
                Prop(sb, "Error", pyc.Error);
            sb.AppendLine("</table>");

            // Include decompiled source if available
            if (!string.IsNullOrEmpty(result.DecompiledSource) && !result.IsDotNet)
            {
                sb.AppendLine("<h4>Decompiled / Disassembled Source</h4>");
                sb.AppendLine("<div class=\"code-block\">");
                var src = result.DecompiledSource.Length > 51_200
                    ? result.DecompiledSource[..51_200] + "\n\n# ... truncated ..."
                    : result.DecompiledSource;
                sb.AppendLine($"<pre><code>{H(src)}</code></pre>");
                sb.AppendLine("</div>");
            }
            sb.AppendLine("</div>");
        }

        // ── Python .pyd ───────────────────────────────────────────────────
        if (result.IsPyd && result.PydInfo != null)
        {
            var pyd = result.PydInfo;
            sb.AppendLine(CollapsibleSection("sec-pyd", "Python Extension Module (.pyd)", true));
            sb.AppendLine("<table class=\"props\">");
            Prop(sb, "Module Name",    pyd.ModuleName);
            Prop(sb, "Init Function",  pyd.HasPyInit ? pyd.InitFunction : "Not found");
            Prop(sb, "Python Major",   pyd.PythonMajor > 0 ? $"Python {pyd.PythonMajor}" : "Unknown");
            Prop(sb, "Python Version", pyd.PythonVersion);
            Prop(sb, "Runtime DLL",    pyd.PythonRuntimeImport ?? "Not detected");
            Prop(sb, "C API Imports",  pyd.PythonApiImports.Count.ToString());
            sb.AppendLine("</table>");

            if (pyd.PythonApiImports.Count > 0)
            {
                sb.AppendLine("<h4>Python C API Imports</h4>");
                sb.AppendLine("<ul class=\"tags\">");
                foreach (var api in pyd.PythonApiImports.Take(100))
                    sb.AppendLine($"<li>{H(api)}</li>");
                sb.AppendLine("</ul>");
            }
            sb.AppendLine("</div>");
        }

        // ── VLX / FAS ─────────────────────────────────────────────────────
        if (result.IsVlx && result.VlxInfo != null)
        {
            var vlx = result.VlxInfo;
            sb.AppendLine(CollapsibleSection("sec-vlx", "Visual LISP VLX/FAS Analysis", true));
            sb.AppendLine("<table class=\"props\">");
            Prop(sb, "Format",        vlx.FormatName);
            Prop(sb, "File Size",     vlx.FileSizeDisplay);
            Prop(sb, "Magic Bytes",   vlx.MagicBytes);
            Prop(sb, "FAS Version",   vlx.FasVersion > 0 ? $"FAS{vlx.FasVersion}" : "Unknown");
            Prop(sb, "Encrypted",     vlx.IsEncrypted ? "Yes (;fas4 crunch)" : "No");
            Prop(sb, "Compile Mode",  vlx.CompileMode ?? "—");
            Prop(sb, "Version Stamp", vlx.VersionWord ?? "—");
            Prop(sb, "Modules",       vlx.ModuleCount.ToString());
            Prop(sb, "Commands",      vlx.Commands.Count.ToString());
            Prop(sb, "Functions",     $"{vlx.Functions.Count} (decompiled: {vlx.FasFunctions.Count})");
            Prop(sb, "Global Vars",   vlx.GlobalVars.Count.ToString());
            Prop(sb, "Decrypt Status", vlx.DecryptStatus ?? "—");
            sb.AppendLine("</table>");

            if (vlx.Commands.Count > 0)
            {
                sb.AppendLine("<h4>AutoCAD Commands</h4>");
                sb.AppendLine("<ul class=\"tags\">");
                foreach (var cmd in vlx.Commands)
                    sb.AppendLine($"<li>{H(cmd)}</li>");
                sb.AppendLine("</ul>");
            }

            if (vlx.FasFunctions.Count > 0)
            {
                sb.AppendLine("<h4>Decompiled Functions</h4>");
                sb.AppendLine(TableHeader("Name", "Offset", "Locals", "Args", "Local Var Names"));
                foreach (var fn in vlx.FasFunctions.Take(100))
                {
                    string varNames = fn.LocalVarNames.Count > 0
                        ? string.Join(", ", fn.LocalVarNames.Take(10))
                          + (fn.LocalVarNames.Count > 10 ? "…" : "")
                        : "—";
                    sb.AppendLine(TableRow(
                        H(fn.Name),
                        fn.OffsetDisplay,
                        fn.LocalVarCount.ToString(),
                        $"{fn.MinArgs}..{fn.MaxArgs}",
                        H(varNames)));
                }
                sb.AppendLine("</table>");
            }

            if (vlx.Functions.Count > 0)
            {
                sb.AppendLine("<h4>All Functions (symbol table)</h4>");
                sb.AppendLine("<ul class=\"tags\">");
                foreach (var fn in vlx.Functions.Take(100))
                    sb.AppendLine($"<li>{H(fn)}</li>");
                sb.AppendLine("</ul>");
            }

            if (vlx.GlobalVars.Count > 0)
            {
                sb.AppendLine("<h4>Global Variables</h4>");
                sb.AppendLine("<ul class=\"tags\">");
                foreach (var g in vlx.GlobalVars.Take(100))
                    sb.AppendLine($"<li>{H(g)}</li>");
                sb.AppendLine("</ul>");
            }

            if (vlx.Modules.Count > 0)
            {
                sb.AppendLine("<h4>Embedded FAS Modules</h4>");
                sb.AppendLine(TableHeader("#", "Name", "Offset", "Size"));
                foreach (var m in vlx.Modules)
                    sb.AppendLine(TableRow(m.Index.ToString(), m.Name, m.OffsetDisplay, m.SizeDisplay));
                sb.AppendLine("</table>");
            }

            if (!string.IsNullOrEmpty(vlx.DecompiledLisp))
            {
                sb.AppendLine("<h4>Reconstructed LISP (best-effort)</h4>");
                sb.AppendLine("<div class=\"code-block\">");
                var lisp = vlx.DecompiledLisp.Length > 51_200
                    ? vlx.DecompiledLisp[..51_200] + "\n\n;;; ... truncated ..."
                    : vlx.DecompiledLisp;
                sb.AppendLine($"<pre><code>{H(lisp)}</code></pre>");
                sb.AppendLine("</div>");
            }

            if (!string.IsNullOrEmpty(vlx.Disassembly))
            {
                sb.AppendLine("<h4>Bytecode Disassembly</h4>");
                sb.AppendLine("<div class=\"code-block\">");
                var dis = vlx.Disassembly.Length > 51_200
                    ? vlx.Disassembly[..51_200] + "\n\n; ... truncated ..."
                    : vlx.Disassembly;
                sb.AppendLine($"<pre><code>{H(dis)}</code></pre>");
                sb.AppendLine("</div>");
            }
            sb.AppendLine("</div>");
        }

        // ── Errors ────────────────────────────────────────────────────────
        if (result.Errors.Count > 0)
        {
            sb.AppendLine(CollapsibleSection("sec-errors", "Analysis Warnings / Errors", true));
            sb.AppendLine("<ul class=\"errors\">");
            foreach (var e in result.Errors)
                sb.AppendLine($"<li>{H(e)}</li>");
            sb.AppendLine("</ul></div>");
        }

        // ── Footer ─────────────────────────────────────────────────────────
        sb.AppendLine($"<div class=\"footer\">Generated by BinaryLens · {DateTime.Now:yyyy-MM-dd HH:mm:ss}</div>");

        // ── Embedded JS ────────────────────────────────────────────────────
        sb.AppendLine(EmbeddedJs());
        sb.AppendLine("</body></html>");

        return sb.ToString();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string H(string s) => System.Web.HttpUtility.HtmlEncode(s);

    private static string CollapsibleSection(string id, string title, bool startOpen)
    {
        string openAttr = startOpen ? " open" : "";
        return $"<details id=\"{id}\" class=\"section\"{openAttr}>" +
               $"<summary class=\"section-header\">{H(title)}</summary>" +
               $"<div class=\"section-content\">";
    }

    private static string Badge(string text, string color)
        => $"<span class=\"badge badge-{color}\">{H(text)}</span>";

    private static void Prop(StringBuilder sb, string label, string value)
    {
        sb.AppendLine($"<tr><th>{H(label)}</th><td>{H(value)}</td></tr>");
    }

    private static string TableHeader(params string[] cols)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<table class=\"data-table\"><thead><tr>");
        foreach (var c in cols)
            sb.Append($"<th>{H(c)}</th>");
        sb.AppendLine("</tr></thead><tbody>");
        return sb.ToString();
    }

    private static string TableRow(params string[] cells)
    {
        var sb = new StringBuilder("<tr>");
        foreach (var c in cells)
            sb.Append($"<td>{c}</td>");   // cells may contain pre-encoded HTML
        sb.Append("</tr>");
        return sb.ToString();
    }

    private static void RenderDepNode(StringBuilder sb, DependencyNode node, int indent)
    {
        string cls = !node.Found   ? "dep-missing"
                   : node.IsAutocad ? "dep-autocad"
                   : node.IsSystem  ? "dep-system"
                   :                  "dep-found";

        string path = node.ResolvedPath != null ? $" <small>{H(node.ResolvedPath)}</small>" : "";
        sb.AppendLine($"<div class=\"dep-node {cls}\" style=\"margin-left:{indent * 24}px\">" +
                      $"{node.StatusIcon} {H(node.Name)}{path}</div>");

        foreach (var child in node.Children)
            RenderDepNode(sb, child, indent + 1);
    }

    // ── Embedded CSS ──────────────────────────────────────────────────────────

    private static string EmbeddedCss() => @"<style>
        :root {
            --bg: #f3f3f3; --surface: #ffffff; --border: #e0e0e0;
            --text: #1a1a1a; --text2: #555; --accent: #0078D4;
            --accent-dark: #005a9e; --code-bg: #f8f8f8;
            --header-bg: #0078D4; --header-text: white;
        }
        [data-theme=""dark""] {
            --bg: #1e1e1e; --surface: #2d2d2d; --border: #404040;
            --text: #d4d4d4; --text2: #999; --accent: #4fc3f7;
            --accent-dark: #0288d1; --code-bg: #1a1a2e;
            --header-bg: #1565c0; --header-text: #e0e0e0;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, 'Segoe UI', sans-serif; font-size: 13px;
               color: var(--text); background: var(--bg); padding: 24px;
               transition: background 0.3s, color 0.3s; }
        .header { background: var(--header-bg); color: var(--header-text);
                  padding: 20px 24px; border-radius: 8px; margin-bottom: 16px; }
        .header-top { display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 22px; margin-bottom: 4px; }
        .header .subtitle { opacity: 0.8; font-size: 12px; word-break: break-all; }
        .theme-btn { background: rgba(255,255,255,0.2); border: none; color: white;
                     font-size: 18px; padding: 4px 10px; border-radius: 6px;
                     cursor: pointer; transition: background 0.2s; }
        .theme-btn:hover { background: rgba(255,255,255,0.3); }
        .badges { margin-top: 10px; display: flex; gap: 6px; flex-wrap: wrap; }
        .badge { padding: 3px 10px; border-radius: 12px; font-size: 11px;
                 font-weight: 600; color: white; }
        .badge-blue   { background: #005a9e; }
        .badge-purple { background: #5c2d91; }
        .badge-orange { background: #ca5010; }
        .badge-red    { background: #c42b1c; }
        .badge-green  { background: #2e7d32; }
        .badge-teal   { background: #00838f; }

        .toc { background: var(--surface); padding: 10px 16px; border-radius: 6px;
               margin-bottom: 12px; font-size: 12px; border: 1px solid var(--border);
               line-height: 1.8; }
        .toc a { color: var(--accent); text-decoration: none; }
        .toc a:hover { text-decoration: underline; }

        .toolbar { margin-bottom: 12px; display: flex; gap: 8px; }
        .toolbar button { background: var(--surface); border: 1px solid var(--border);
                          color: var(--text2); padding: 4px 12px; border-radius: 4px;
                          font-size: 11px; cursor: pointer; }
        .toolbar button:hover { border-color: var(--accent); color: var(--accent); }

        details.section { margin-bottom: 12px; }
        summary.section-header { font-size: 13px; font-weight: 700; text-transform: uppercase;
                                  letter-spacing: 0.05em; color: var(--text2);
                                  padding: 8px 0 6px; border-bottom: 2px solid var(--accent);
                                  cursor: pointer; user-select: none; list-style: none; }
        summary.section-header::before { content: '▶ '; font-size: 10px; transition: transform 0.2s; }
        details[open] > summary.section-header::before { content: '▼ '; }
        .section-content { padding-top: 8px; }

        table.props { border-collapse: collapse; width: 100%; max-width: 600px;
                      background: var(--surface); border-radius: 6px; overflow: hidden;
                      box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 16px; }
        table.props th { width: 160px; padding: 7px 12px; font-weight: 600;
                         background: var(--code-bg); color: var(--text2);
                         font-size: 12px; text-align: left; }
        table.props td { padding: 7px 12px; font-family: monospace; font-size: 12px;
                         word-break: break-all; }
        table.props tr + tr th, table.props tr + tr td { border-top: 1px solid var(--border); }

        table.data-table { border-collapse: collapse; width: 100%;
                           background: var(--surface); border-radius: 6px; overflow: hidden;
                           box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 16px; }
        table.data-table thead th { background: var(--code-bg); padding: 8px 10px;
                                     font-size: 11px; text-align: left; font-weight: 700;
                                     color: var(--text2); text-transform: uppercase;
                                     letter-spacing: 0.04em; }
        table.data-table tbody tr:nth-child(even) { background: var(--code-bg); }
        table.data-table tbody td { padding: 5px 10px; font-family: monospace;
                                     font-size: 11px; border-top: 1px solid var(--border);
                                     word-break: break-all; }

        .dep-legend { display: flex; gap: 16px; margin-bottom: 8px; font-size: 12px; }
        .dep-node { padding: 3px 8px; margin: 2px 0; border-radius: 4px;
                    font-family: monospace; font-size: 12px; }
        .dep-found   { background: #f0fff0; }
        .dep-missing { background: #fff0f0; color: #c42b1c; }
        .dep-system  { background: var(--code-bg); color: var(--text2); }
        .dep-autocad { background: #fff4e0; color: #ca5010; font-weight: 600; }
        [data-theme=""dark""] .dep-found   { background: #1b3a1b; color: #8bc34a; }
        [data-theme=""dark""] .dep-missing { background: #3a1b1b; color: #ef9a9a; }
        [data-theme=""dark""] .dep-autocad { background: #3a2e1b; color: #ffb74d; }
        .deptree { background: var(--surface); padding: 12px; border-radius: 6px;
                   box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 16px; }

        .code-block { background: var(--code-bg); border: 1px solid var(--border);
                      border-radius: 6px; overflow: auto; max-height: 600px;
                      margin-bottom: 16px; }
        .code-block pre { margin: 0; padding: 12px; }
        .code-block code { font-family: Consolas, 'Courier New', monospace;
                           font-size: 12px; white-space: pre; color: var(--text); }

        .entropy-high { color: #c42b1c; font-weight: 700; }
        .entropy-mod  { color: #ca5010; }

        ul.tags { display: flex; flex-wrap: wrap; gap: 6px; list-style: none;
                  margin-bottom: 16px; }
        ul.tags li { background: #e8f0fe; color: #0047ab; padding: 3px 10px;
                     border-radius: 12px; font-size: 11px; font-family: monospace; }
        [data-theme=""dark""] ul.tags li { background: #1a2744; color: #90caf9; }

        ul.errors { list-style: none; margin-bottom: 16px; }
        ul.errors li { background: #fff0f0; color: #c42b1c; padding: 6px 12px;
                       border-left: 3px solid #c42b1c; margin-bottom: 4px;
                       font-size: 12px; font-family: monospace; }
        [data-theme=""dark""] ul.errors li { background: #3a1b1b; color: #ef9a9a; }

        h4 { font-size: 12px; font-weight: 600; color: var(--text2);
             margin: 12px 0 6px; }
        .footer { text-align: center; color: var(--text2); font-size: 11px;
                  margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); }

        @media print { body { background: white; padding: 0; }
                        .header { -webkit-print-color-adjust: exact; }
                        .theme-btn, .toolbar { display: none; }
                        details { display: block !important; }
                        details > summary { display: none; }
                        details > .section-content { display: block !important; } }
    </style>";

    // ── Embedded JS ──────────────────────────────────────────────────────────

    private static string EmbeddedJs() => @"<script>
    function toggleTheme() {
        const html = document.documentElement;
        const isDark = html.getAttribute('data-theme') === 'dark';
        html.setAttribute('data-theme', isDark ? '' : 'dark');
        document.querySelector('.theme-btn').textContent = isDark ? '🌙' : '☀️';
    }
    function expandAll() {
        document.querySelectorAll('details.section').forEach(d => d.open = true);
    }
    function collapseAll() {
        document.querySelectorAll('details.section').forEach(d => d.open = false);
    }
    </script>";
}
