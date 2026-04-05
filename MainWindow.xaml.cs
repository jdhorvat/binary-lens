using BinaryLens.Analysis;
using BinaryLens.Export;
using BinaryLens.Models;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;

namespace BinaryLens;

public partial class MainWindow : Window
{
    // ── State ─────────────────────────────────────────────────────────────────

    private AnalysisResult?    _result;
    private CancellationTokenSource? _cts;

    // Filtered collections for grids with live search
    private ObservableCollection<ImportEntry>    _allImports  = [];
    private ObservableCollection<ExportEntry>    _allExports  = [];
    private ObservableCollection<ExtractedString> _allStrings = [];

    // ── Constructor ───────────────────────────────────────────────────────────

    public MainWindow()
    {
        InitializeComponent();
    }

    // ── File opening ─────────────────────────────────────────────────────────

    private void MenuOpen_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title  = "Open Binary",
            Filter = "All Supported|*.dll;*.exe;*.arx;*.ocx;*.ax;*.sys;*.drv;*.pyd;*.pyc;*.vlx;*.fas|AutoLISP|*.vlx;*.fas|Python|*.pyc;*.pyd|All Files|*.*",
        };
        if (dlg.ShowDialog() == true)
            _ = AnalyzeFile(dlg.FileName);
    }

    private void DropZone_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title  = "Open Binary",
            Filter = "All Supported|*.dll;*.exe;*.arx;*.ocx;*.ax;*.sys;*.drv;*.pyd;*.pyc;*.vlx;*.fas|AutoLISP|*.vlx;*.fas|Python|*.pyc;*.pyd|All Files|*.*",
        };
        if (dlg.ShowDialog() == true)
            _ = AnalyzeFile(dlg.FileName);
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            var files = (string[]?)e.Data.GetData(DataFormats.FileDrop);
            if (files?.Length > 0)
                _ = AnalyzeFile(files[0]);
        }
    }

    private void Window_PreviewDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    // ── Analysis pipeline ─────────────────────────────────────────────────────

    private async Task AnalyzeFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            ShowStatus($"File not found: {filePath}");
            return;
        }

        // Cancel any in-progress analysis
        _cts?.Cancel();
        _cts = new CancellationTokenSource();

        // UI: loading state
        ClearResults();
        ShowStatus($"Analysing: {Path.GetFileName(filePath)}");
        ProgressBar.Visibility = Visibility.Visible;
        ProgressBar.IsIndeterminate = true;

        var progress = new Progress<string>(msg =>
        {
            ShowStatus(msg);
        });

        try
        {
            _result = await BinaryAnalyzer.AnalyzeAsync(filePath, progress, _cts.Token);
            PopulateAll(_result);
            ShowStatus($"Done — {_result.FileName}  ·  {_result.FileSizeHuman}  ·  {_result.FileTypeSummary}");
        }
        catch (OperationCanceledException)
        {
            ShowStatus("Analysis cancelled.");
        }
        catch (Exception ex)
        {
            ShowStatus($"Error: {ex.Message}");
            MessageBox.Show($"Analysis failed:\n\n{ex.Message}", "BinaryLens",
                            MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ProgressBar.Visibility      = Visibility.Hidden;
            ProgressBar.IsIndeterminate = false;
        }
    }

    // ── Populate all panels ───────────────────────────────────────────────────

    private void PopulateAll(AnalysisResult r)
    {
        PopulateHeader(r);

        // PE-specific panels — skip entirely for non-PE files
        if (r.IsValidPe)
        {
            PopulatePeStructure(r);
            PopulateImports(r);
            PopulateExports(r);
            PopulateDependencies(r);
        }

        PopulateStrings(r);
        PopulateResources(r);
        PopulateSource(r);
        PopulateVb(r);
        PopulateArx(r);
        PopulatePython(r);
        PopulateVlx(r);
        PopulateTree(r);

        // Hide tabs that have no relevant data
        UpdateTabVisibility(r);

        // Enable export menu items
        MenuExportHtml.IsEnabled = true;
        MenuExportJson.IsEnabled = true;
        MenuExportCsv.IsEnabled  = true;
        MenuSaveSource.IsEnabled = r.DecompiledSource != null || r.Disassembly.Count > 0;
    }

    private void UpdateTabVisibility(AnalysisResult r)
    {
        // PE-related tabs: hide if this isn't a valid PE (e.g. pure .pyc or .vlx)
        bool isPe = r.IsValidPe;
        TabPeStructure.Visibility = isPe ? Visibility.Visible : Visibility.Collapsed;
        TabDeps.Visibility        = isPe && r.DependencyRoot != null ? Visibility.Visible : Visibility.Collapsed;

        // Data tabs: hide if empty
        TabImports.Visibility   = r.Imports.Count   > 0 ? Visibility.Visible : Visibility.Collapsed;
        TabExports.Visibility   = r.Exports.Count   > 0 ? Visibility.Visible : Visibility.Collapsed;
        TabStrings.Visibility   = r.Strings.Count   > 0 ? Visibility.Visible : Visibility.Collapsed;
        TabResources.Visibility = r.Resources.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        // Source / Disasm: show if there's decompiled source, disassembly, or VLX bytecode
        bool hasSource = !string.IsNullOrEmpty(r.DecompiledSource) || r.Disassembly.Count > 0
            || (r.IsVlx && r.VlxInfo != null && !string.IsNullOrEmpty(r.VlxInfo.Disassembly));
        TabSource.Visibility = hasSource ? Visibility.Visible : Visibility.Collapsed;

        // Specialty tabs: only show when relevant
        TabVb.Visibility     = r.IsVb5                  ? Visibility.Visible : Visibility.Collapsed;
        TabArx.Visibility    = r.IsArx                  ? Visibility.Visible : Visibility.Collapsed;
        TabPython.Visibility = (r.IsPyc || r.IsPyd)     ? Visibility.Visible : Visibility.Collapsed;
        TabVlx.Visibility    = r.IsVlx                  ? Visibility.Visible : Visibility.Collapsed;

        // Select the first visible tab
        foreach (var item in AnalysisTabs.Items)
        {
            if (item is TabItem tab && tab.Visibility == Visibility.Visible)
            {
                AnalysisTabs.SelectedItem = tab;
                break;
            }
        }

        // Select the first tree node to match
        if (AnalysisTree.Items.Count > 0 && AnalysisTree.Items[0] is TreeViewItem firstNode)
            firstNode.IsSelected = true;
    }

    private void PopulateHeader(AnalysisResult r)
    {
        FileSummaryPanel.Visibility = Visibility.Visible;
        SumFileName.Text  = r.FileName;
        SumFileSize.Text  = r.FileSizeHuman;
        SumFileType.Text  = r.FileTypeSummary;
        BadgeDotNet.Visibility = r.IsDotNet ? Visibility.Visible : Visibility.Collapsed;
        BadgeArx.Visibility    = r.IsArx    ? Visibility.Visible : Visibility.Collapsed;
    }

    private void PopulatePeStructure(AnalysisResult r)
    {
        var info = r.PeInfo;

        // Key/value pairs for the header grid
        var props = new List<KeyValuePair<string, string>>
        {
            new("Machine Type",   info.MachineType),
            new("Subsystem",      info.Subsystem),
            new("Entry Point",    info.EntryPoint),
            new("Image Base",     info.ImageBase),
            new("Size of Image",  info.SizeOfImage),
            new("Linker Version", info.LinkerVersion),
            new("Timestamp",      info.TimeDateStampDisplay),
            new("Characteristics",string.Join(", ", info.Characteristics)),
        };
        GridPeHeader.ItemsSource = props;
        GridSections.ItemsSource = info.Sections;
        PopulateEntropyChart(info.Sections);
    }

    private void PopulateEntropyChart(List<PeSection> sections)
    {
        EntropyChart.Items.Clear();
        if (sections.Count == 0) return;

        foreach (var sec in sections)
        {
            // Bar row: label + colored bar + value
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };

            // Section name label (fixed width)
            row.Children.Add(new TextBlock
            {
                Text = sec.Name,
                Width = 80,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = (Brush)FindResource("TextPrimaryBrush"),
            });

            // Colored bar (entropy 0–8 mapped to 0–400px)
            double barWidth = Math.Max(4, (sec.Entropy / 8.0) * 400);
            var barColor = sec.Entropy switch
            {
                > 7.5 => new SolidColorBrush(Color.FromRgb(0xF4, 0x43, 0x36)),  // red
                > 6.0 => new SolidColorBrush(Color.FromRgb(0xFF, 0x98, 0x00)),  // orange
                _     => new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50)),  // green
            };

            row.Children.Add(new Border
            {
                Width = barWidth,
                Height = 18,
                Background = barColor,
                CornerRadius = new CornerRadius(3),
                Margin = new Thickness(4, 0, 8, 0),
            });

            // Entropy value text
            row.Children.Add(new TextBlock
            {
                Text = $"{sec.Entropy:F2}",
                FontSize = 11,
                FontFamily = new FontFamily("Consolas"),
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = (Brush)FindResource("TextSecondaryBrush"),
            });

            // Note (if high)
            if (sec.Entropy > 7.5)
            {
                row.Children.Add(new TextBlock
                {
                    Text = "  packed/encrypted?",
                    FontSize = 10,
                    FontStyle = FontStyles.Italic,
                    VerticalAlignment = VerticalAlignment.Center,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xF4, 0x43, 0x36)),
                });
            }

            EntropyChart.Items.Add(row);
        }
    }

    private void PopulateImports(AnalysisResult r)
    {
        _allImports = new ObservableCollection<ImportEntry>(r.Imports);
        GridImports.ItemsSource = _allImports;
        LabelImports.Text = $"IMPORTS ({r.Imports.Count:N0})";
        TabImports.Header = $"Imports ({r.Imports.Count:N0})";
    }

    private void PopulateExports(AnalysisResult r)
    {
        _allExports = new ObservableCollection<ExportEntry>(r.Exports);
        GridExports.ItemsSource = _allExports;
        LabelExports.Text = $"EXPORTS ({r.Exports.Count:N0})";
        TabExports.Header = $"Exports ({r.Exports.Count:N0})";
    }

    private void PopulateStrings(AnalysisResult r)
    {
        _allStrings = new ObservableCollection<ExtractedString>(r.Strings);
        GridStrings.ItemsSource = _allStrings;
        LabelStrings.Text = $"STRINGS ({r.Strings.Count:N0})";
        TabStrings.Header = $"Strings ({r.Strings.Count:N0})";
    }

    private void PopulateResources(AnalysisResult r)
    {
        GridResources.ItemsSource = r.Resources;
        LabelResources.Text = $"RESOURCES ({r.Resources.Count:N0})";
        TabResources.Header = $"Resources ({r.Resources.Count:N0})";
    }

    private void PopulateDependencies(AnalysisResult r)
    {
        if (r.DependencyRoot == null) return;
        DepTree.Items.Clear();
        DepTree.Items.Add(r.DependencyRoot);
        TabDeps.Header = $"Dependencies ({CountDeps(r.DependencyRoot)})";
    }

    private int CountDeps(DependencyNode node)
        => 1 + node.Children.Sum(CountDeps);

    private void PopulateSource(AnalysisResult r)
    {
        NoSourceMsg.Visibility  = Visibility.Collapsed;
        SourceBox.Visibility    = Visibility.Collapsed;
        GridDisasm.Visibility   = Visibility.Collapsed;
        BtnSaveSource.IsEnabled = false;
        BtnCopySource.IsEnabled = false;

        if (r.IsDotNet && !string.IsNullOrEmpty(r.DecompiledSource))
        {
            LabelSource.Text = $".NET DECOMPILED SOURCE ({r.DecompiledSource.Length:N0} chars)";
            TabSource.Header = $"Source / Disasm ({r.DecompiledSource.Length:N0} chars)";
            SetSourceText(r.DecompiledSource);
            SourceBox.Visibility    = Visibility.Visible;
            BtnSaveSource.IsEnabled = true;
            BtnCopySource.IsEnabled = true;
        }
        else if (r.Disassembly.Count > 0)
        {
            LabelSource.Text = $"NATIVE DISASSEMBLY ({r.Disassembly.Count:N0} instructions, first 64 KB of .text)";
            TabSource.Header = $"Source / Disasm ({r.Disassembly.Count:N0})";
            GridDisasm.ItemsSource = r.Disassembly;
            GridDisasm.Visibility  = Visibility.Visible;
            BtnSaveSource.IsEnabled = true;
            BtnCopySource.IsEnabled = true;
        }
        else
        {
            LabelSource.Text       = "SOURCE / DISASSEMBLY";
            TabSource.Header       = "Source / Disasm";
            NoSourceMsg.Visibility = Visibility.Visible;
        }
    }

    private void SetSourceText(string code)
    {
        SourceBox.Document.Blocks.Clear();
        // Simple monospace display -- for syntax highlighting, replace with AvalonEdit
        var para = new Paragraph(new Run(code))
        {
            FontFamily = new FontFamily("Consolas"),
            FontSize   = 12,
            Margin     = new Thickness(0),
        };
        SourceBox.Document.Blocks.Add(para);
    }

    private void PopulateVb(AnalysisResult r)
    {
        NoVbMsg.Visibility   = Visibility.Visible;
        VbDetails.Visibility = Visibility.Collapsed;
        TabVb.Header = "VB5/6";

        if (!r.IsVb5 || r.VbInfo == null) return;

        var vb = r.VbInfo;
        NoVbMsg.Visibility   = Visibility.Collapsed;
        VbDetails.Visibility = Visibility.Visible;
        TabVb.Header = $"VB{vb.VbVersion} 🔧";

        var props = new List<KeyValuePair<string, string>>
        {
            new("Runtime DLL",       vb.RuntimeDll),
            new("VB Version",        $"Visual Basic {vb.VbVersion}"),
            new("Compile Mode",      vb.CompileMode),
            new("Entry Point",       !string.IsNullOrEmpty(vb.EntryPoint) ? vb.EntryPoint : "—"),
            new("VB Header",         !string.IsNullOrEmpty(vb.VbHeaderOffset) ? vb.VbHeaderOffset : "Not found"),
            new("Project Name",      !string.IsNullOrEmpty(vb.ProjectName) ? vb.ProjectName : "—"),
            new("Project Exe",       !string.IsNullOrEmpty(vb.ProjectExeName) ? vb.ProjectExeName : "—"),
            new("Objects",           vb.Objects.Count.ToString()),
            new("COM Controls",      vb.ComImports.Count.ToString()),
            new("API References",    vb.ApiDeclares.Count.ToString()),
        };
        if (vb.Error != null) props.Add(new("Error", vb.Error));

        GridVbSummary.ItemsSource = props;
        GridVbObjects.ItemsSource = vb.Objects;
        GridVbCom.ItemsSource     = vb.ComImports;
        GridVbApi.ItemsSource     = vb.ApiDeclares;
        GridVbRefs.ItemsSource    = vb.References;

        // Reset detail panel
        VbObjectDetail.Visibility = Visibility.Collapsed;
        ListVbControls.ItemsSource = null;
        ListVbMethods.ItemsSource  = null;

        // Auto-select first object if any
        if (vb.Objects.Count > 0)
            GridVbObjects.SelectedIndex = 0;

        // Hide empty grids
        VbComHeader.Visibility  = vb.ComImports.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        GridVbCom.Visibility    = vb.ComImports.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        VbApiHeader.Visibility  = vb.ApiDeclares.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        GridVbApi.Visibility    = vb.ApiDeclares.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        VbRefsHeader.Visibility = vb.References.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        GridVbRefs.Visibility   = vb.References.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    // ── VB Object detail handlers ───────────────────────────────────────

    private void GridVbObjects_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (GridVbObjects.SelectedItem is not Models.VbObject obj)
        {
            VbObjectDetail.Visibility = Visibility.Collapsed;
            return;
        }

        VbObjectDetail.Visibility = Visibility.Visible;
        VbObjDetailHeader.Text = $"{obj.ObjectType.ToUpperInvariant()}: {obj.Name}";

        VbCtrlHeader.Text  = $"Controls ({obj.Controls.Count})";
        VbMethodHeader.Text = $"Methods ({obj.Methods.Count})";

        ListVbControls.ItemsSource = obj.Controls.Count > 0
            ? obj.Controls
            : new List<string> { "(none detected)" };

        ListVbMethods.ItemsSource = obj.Methods.Count > 0
            ? obj.Methods
            : new List<string> { "(none detected)" };
    }

    private void VbObjCopy_Click(object sender, RoutedEventArgs e)
    {
        if (GridVbObjects.SelectedItem is not Models.VbObject obj) return;

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"' {obj.ObjectType}: {obj.Name}");
        sb.AppendLine();

        if (obj.Controls.Count > 0)
        {
            sb.AppendLine("' Controls:");
            foreach (var c in obj.Controls)
                sb.AppendLine($"'   {c}");
            sb.AppendLine();
        }

        if (obj.Methods.Count > 0)
        {
            sb.AppendLine("' Methods:");
            foreach (var m in obj.Methods)
                sb.AppendLine($"'   {m}");
        }

        Clipboard.SetText(sb.ToString());
    }

    private void VbObjExportFrm_Click(object sender, RoutedEventArgs e)
    {
        if (GridVbObjects.SelectedItem is not Models.VbObject obj) return;
        if (_result?.VbInfo == null) return;

        var vb = _result.VbInfo;

        // Build a reconstructed .frm-style file
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("VERSION 5.00");

        // Emit control Begin/End blocks for forms
        if ((obj.ObjectType == "Form" || obj.ObjectType == "UserControl") && obj.Controls.Count > 0)
        {
            sb.AppendLine($"Begin VB.{obj.ObjectType} {obj.Name}");
            sb.AppendLine($"   Caption         =   \"{obj.Name}\"");
            sb.AppendLine($"   ClientHeight     =   3195");
            sb.AppendLine($"   ClientLeft       =   60");
            sb.AppendLine($"   ClientTop        =   345");
            sb.AppendLine($"   ClientWidth      =   4680");
            sb.AppendLine($"   ScaleHeight      =   3195");
            sb.AppendLine($"   ScaleWidth       =   4680");

            foreach (var ctrl in obj.Controls)
            {
                // Parse "ctrlName (CtrlType)" format
                string ctrlName = ctrl;
                string ctrlType = "Control";
                int paren = ctrl.IndexOf(" (");
                if (paren > 0)
                {
                    ctrlName = ctrl[..paren];
                    ctrlType = ctrl[(paren + 2)..].TrimEnd(')');
                }
                sb.AppendLine($"   Begin VB.{ctrlType} {ctrlName}");
                sb.AppendLine($"      Caption         =   \"{ctrlName}\"");
                sb.AppendLine($"      Height          =   375");
                sb.AppendLine($"      Left            =   120");
                sb.AppendLine($"      Top             =   120");
                sb.AppendLine($"      Width           =   1215");
                sb.AppendLine($"   End");
            }
            sb.AppendLine("End");
        }
        else
        {
            sb.AppendLine($"' {obj.ObjectType}: {obj.Name}");
        }

        sb.AppendLine("Attribute VB_Name = \"" + obj.Name + "\"");
        if (obj.ObjectType == "Form" || obj.ObjectType == "UserControl")
            sb.AppendLine("Attribute VB_GlobalNameSpace = False");

        // Emit method stubs
        sb.AppendLine();
        sb.AppendLine($"' ── Detected methods ({obj.Methods.Count}) ──");
        foreach (var m in obj.Methods)
        {
            // Emit as Sub stubs
            bool isEvent = m.Contains('_');
            string keyword = isEvent ? "Private Sub" : "Public Sub";
            sb.AppendLine();
            sb.AppendLine($"{keyword} {m}()");
            sb.AppendLine($"    ' [stub — detected from binary analysis]");
            sb.AppendLine($"End Sub");
        }

        // Show save dialog
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "VB Form (*.frm)|*.frm|VB Module (*.bas)|*.bas|VB Class (*.cls)|*.cls|All files|*.*",
            FileName = obj.Name + (obj.ObjectType == "Form" ? ".frm" : obj.ObjectType == "Module" ? ".bas" : ".cls"),
        };

        // Default to the correct filter based on type
        dlg.FilterIndex = obj.ObjectType switch
        {
            "Form" or "UserControl" => 1,
            "Module" => 2,
            "Class" => 3,
            _ => 4,
        };

        if (dlg.ShowDialog() == true)
        {
            System.IO.File.WriteAllText(dlg.FileName, sb.ToString());
        }
    }

    private void PopulateArx(AnalysisResult r)
    {
        if (!r.IsArx || r.ArxInfo == null)
        {
            NoArxMsg.Visibility  = Visibility.Visible;
            ArxDetails.Visibility = Visibility.Collapsed;
            TabArx.Header = "ARX";
            return;
        }

        var arx = r.ArxInfo;
        NoArxMsg.Visibility   = Visibility.Collapsed;
        ArxDetails.Visibility = Visibility.Visible;
        TabArx.Header = "ARX ✅";

        var summary = new List<KeyValuePair<string, string>>
        {
            new("ARX Entry Point",   arx.HasArxEntryPoint ? $"✅  {arx.EntryPointName}" : "Not found"),
            new("Managed (.NET) ARX", arx.IsManagedArx ? "Yes" : "No (native C++)"),
            new("Detected Version",  arx.DetectedAcadVersion ?? "Unknown"),
            new("AutoCAD Imports",   arx.AutocadImports.Count.ToString()),
            new("Command Exports",   arx.CommandExports.Count.ToString()),
            new("Class Strings",     arx.AcClassStrings.Count.ToString()),
        };

        GridArxSummary.ItemsSource = summary;
        GridArxImports.ItemsSource = arx.AutocadImports;
        GridArxClasses.ItemsSource = arx.AcClassStrings;
    }

    private void PopulateTree(AnalysisResult r)
    {
        AnalysisTree.Items.Clear();

        // PE-only nodes
        if (r.IsValidPe)
            AddTreeNode("📄 PE Structure", true);

        if (r.Imports.Count > 0)
            AddTreeNode($"📥 Imports ({r.Imports.Count:N0})", true);
        if (r.Exports.Count > 0)
            AddTreeNode($"📤 Exports ({r.Exports.Count:N0})", true);
        if (r.Strings.Count > 0)
            AddTreeNode($"🔤 Strings ({r.Strings.Count:N0})", true);
        if (r.Resources.Count > 0)
            AddTreeNode($"🗃 Resources ({r.Resources.Count:N0})", true);
        if (r.DependencyRoot != null)
            AddTreeNode($"🔗 Dependencies ({CountDeps(r.DependencyRoot):N0})", true);

        // Source / Disasm
        bool hasSource = !string.IsNullOrEmpty(r.DecompiledSource) || r.Disassembly.Count > 0
            || (r.IsVlx && r.VlxInfo != null && !string.IsNullOrEmpty(r.VlxInfo.Disassembly));
        if (hasSource)
        {
            if (r.IsDotNet && !string.IsNullOrEmpty(r.DecompiledSource))
                AddTreeNode($"💻 .NET Source ({r.DecompiledSource.Length:N0} chars)", true);
            else if (r.Disassembly.Count > 0)
                AddTreeNode($"⚙ Disassembly ({r.Disassembly.Count:N0})", true);
            else
                AddTreeNode("⚙ Source / Disasm", true);
        }

        // Specialty
        if (r.IsVb5)             AddTreeNode($"🔷 VB{r.VbInfo?.VbVersion ?? 5}/6", true);
        if (r.IsArx)             AddTreeNode("🔧 AutoCAD ARX", true);
        if (r.IsPyc || r.IsPyd) AddTreeNode("🐍 Python", true);
        if (r.IsVlx)             AddTreeNode("📜 VLX/FAS", true);
        if (r.Errors.Count > 0)  AddTreeNode($"⚠ {r.Errors.Count} warning(s)", false);
    }

    private void PopulatePython(AnalysisResult r)
    {
        NoPythonMsg.Visibility = Visibility.Visible;
        PycPanel.Visibility    = Visibility.Collapsed;
        PydPanel.Visibility    = Visibility.Collapsed;
        TabPython.Header       = "Python";

        // ── .pyc ──────────────────────────────────────────────────────────
        if (r.IsPyc && r.PycInfo != null)
        {
            NoPythonMsg.Visibility = Visibility.Collapsed;
            PycPanel.Visibility    = Visibility.Visible;
            TabPython.Header       = "Python 🐍";

            var info = r.PycInfo;
            var props = new List<KeyValuePair<string, string>>
            {
                new("Python Version",   info.PythonVersion),
                new("Magic Number",     info.MagicDisplay),
                new("Flags",            info.FlagsDisplay),
                new("Hash-based pyc",   info.IsHashBased ? "Yes" : "No"),
                new("Source Timestamp", info.SourceTimestampDisplay),
                new("Source Size",      info.SourceSize > 0 ? $"{info.SourceSize:N0} bytes" : "N/A"),
                new("Bytecode Offset",  $"{info.BytecodeOffset} bytes"),
                new("Bytecode Size",    info.BytecodeSizeDisplay),
                new("Decompiler Used",  info.DecompilerUsed),
                new("Python Exe",       info.PythonExe ?? "Not found"),
            };
            if (info.Error != null)
                props.Add(new("Error", info.Error));

            GridPycInfo.ItemsSource = props;
            SetRichText(PycSourceBox, r.DecompiledSource ?? "# No source available.");
        }

        // ── .pyd ──────────────────────────────────────────────────────────
        if (r.IsPyd && r.PydInfo != null)
        {
            NoPythonMsg.Visibility = Visibility.Collapsed;
            PydPanel.Visibility    = Visibility.Visible;
            TabPython.Header       = "Python 🐍";

            var pyd = r.PydInfo;
            var props = new List<KeyValuePair<string, string>>
            {
                new("Module Name",       pyd.ModuleName),
                new("Init Function",     pyd.HasPyInit ? pyd.InitFunction : "Not found"),
                new("Python Major",      pyd.PythonMajor > 0 ? $"Python {pyd.PythonMajor}" : "Unknown"),
                new("Python Version",    pyd.PythonVersion),
                new("Runtime DLL",       pyd.PythonRuntimeImport ?? "Not detected"),
                new("C API Imports",     pyd.PythonApiImports.Count.ToString()),
            };
            GridPydInfo.ItemsSource = props;
            GridPydApi.ItemsSource  = pyd.PythonApiImports;
        }
    }

    private void SetRichText(RichTextBox box, string text)
    {
        box.Document.Blocks.Clear();
        box.Document.Blocks.Add(new Paragraph(new Run(text))
        {
            FontFamily = new FontFamily("Consolas"),
            FontSize   = 12,
            Margin     = new Thickness(0),
        });
    }

    private void SavePycSource_Click(object sender, RoutedEventArgs e)
    {
        if (_result?.DecompiledSource == null) return;
        var dlg = new SaveFileDialog
        {
            Title    = "Save Python Source / Disassembly",
            Filter   = "Python|*.py|Text|*.txt",
            FileName = Path.GetFileNameWithoutExtension(_result.FileName) + "_decompiled.py",
        };
        if (dlg.ShowDialog() != true) return;
        File.WriteAllText(dlg.FileName, _result.DecompiledSource, System.Text.Encoding.UTF8);
        ShowStatus($"Saved: {dlg.FileName}");
    }

    private void CopyPycSource_Click(object sender, RoutedEventArgs e)
    {
        if (_result?.DecompiledSource != null)
        {
            Clipboard.SetText(_result.DecompiledSource);
            ShowStatus("Python source copied to clipboard.");
        }
    }

    private void PopulateVlx(AnalysisResult r)
    {
        NoVlxMsg.Visibility   = Visibility.Visible;
        VlxDetails.Visibility = Visibility.Collapsed;
        TabVlx.Header = "VLX/FAS";

        if (!r.IsVlx || r.VlxInfo == null) return;

        var vlx = r.VlxInfo;
        NoVlxMsg.Visibility   = Visibility.Collapsed;
        VlxDetails.Visibility = Visibility.Visible;
        TabVlx.Header = "VLX/FAS 🔧";

        var props = new List<KeyValuePair<string, string>>
        {
            new("Format",         vlx.FormatName),
            new("File Size",      vlx.FileSizeDisplay),
            new("Magic Bytes",    vlx.MagicBytes),
            new("FAS Version",    vlx.FasVersion > 0 ? $"FAS{vlx.FasVersion}" : "Unknown"),
            new("Encrypted",      vlx.IsEncrypted ? "Yes (;fas4 crunch)" : "No"),
            new("Compile Mode",   vlx.CompileMode ?? "—"),
            new("Version Stamp",  vlx.VersionWord ?? "—"),
            new("Binary Offset",  $"0x{vlx.BinaryOffset:X4}"),
            new("Decrypt Status", vlx.DecryptStatus ?? "—"),
            new("XOR Key",        vlx.KeyDisplay),
            new("Modules",        vlx.ModuleCount.ToString()),
            new("Commands",       vlx.Commands.Count.ToString()),
            new("Functions",      $"{vlx.Functions.Count} (decompiled: {vlx.FasFunctions.Count})"),
            new("Global Vars",    vlx.GlobalVars.Count.ToString()),
            new("Strings",        vlx.StringLiterals.Count.ToString()),
            new("Embedded Files", vlx.EmbeddedFiles.Count.ToString()),
        };
        if (vlx.Error != null) props.Add(new("Error", vlx.Error));
        GridVlxHeader.ItemsSource = props;

        SetRichText(VlxHexBox, vlx.HeaderHex ?? "(not available)");
        VlxModulesHeader.Text      = $"EMBEDDED FAS MODULES ({vlx.ModuleCount})";
        GridVlxModules.ItemsSource = vlx.Modules;
        VlxCommandsHeader.Text     = $"AUTOCAD COMMANDS ({vlx.Commands.Count})";
        GridVlxCommands.ItemsSource = vlx.Commands;
        VlxFunctionsHeader.Text    = $"FUNCTIONS ({vlx.Functions.Count})";
        GridVlxFunctions.ItemsSource = vlx.Functions;
        VlxGlobalsHeader.Text      = $"GLOBAL VARIABLES ({vlx.GlobalVars.Count})";
        GridVlxGlobals.ItemsSource = vlx.GlobalVars;
        VlxStringsHeader.Text      = $"ALL EXTRACTED STRINGS ({vlx.RawStrings.Count})";
        GridVlxStrings.ItemsSource = vlx.RawStrings;

        // ── Source tab ────────────────────────────────────────────────────────
        bool hasLisp = !string.IsNullOrEmpty(vlx.DecompiledLisp);
        bool hasDisasm = !string.IsNullOrEmpty(vlx.Disassembly);
        // Count modules that actually have disassembly output
        int disasmModuleCount = vlx.Modules.Count(m => !string.IsNullOrEmpty(m.Disassembly));

        // Hide all source views first
        SourceBox.Visibility       = Visibility.Collapsed;
        SourceSplitGrid.Visibility = Visibility.Collapsed;
        ModuleTabControl.Visibility = Visibility.Collapsed;
        GridDisasm.Visibility      = Visibility.Collapsed;
        NoSourceMsg.Visibility     = Visibility.Collapsed;

        if (disasmModuleCount > 1)
        {
            // ── Multi-module: one sub-tab per module ─────────────────────
            LabelSource.Text = $"FAS MODULES ({disasmModuleCount}) — {vlx.FasFunctions.Count} functions";
            ModuleTabControl.Items.Clear();
            ModuleTabControl.Visibility = Visibility.Visible;

            foreach (var mod in vlx.Modules)
            {
                if (string.IsNullOrEmpty(mod.Disassembly)) continue;

                bool modHasLisp = !string.IsNullOrEmpty(mod.DecompiledLisp);
                var tabItem = new TabItem { Header = mod.Name };

                if (modHasLisp)
                {
                    // Split pane for this module
                    var grid = new Grid();
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                    // Left: LISP
                    var leftPanel = new DockPanel();
                    var leftLabel = new TextBlock
                    {
                        Text = "RECONSTRUCTED LISP", FontWeight = FontWeights.SemiBold,
                        FontSize = 11, Foreground = (Brush)FindResource("TextSecondaryBrush"),
                        Margin = new Thickness(0, 0, 0, 4),
                    };
                    DockPanel.SetDock(leftLabel, Dock.Top);
                    leftPanel.Children.Add(leftLabel);
                    var lispBox = new RichTextBox
                    {
                        FontFamily = new FontFamily("Consolas"), FontSize = 11,
                        IsReadOnly = true, Padding = new Thickness(6),
                        Background = new SolidColorBrush(Color.FromRgb(0xF7, 0xFB, 0xF7)),
                        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                        BorderThickness = new Thickness(1),
                        BorderBrush = (Brush)FindResource("BorderBrush"),
                    };
                    SetRichText(lispBox, mod.DecompiledLisp!);
                    leftPanel.Children.Add(lispBox);
                    Grid.SetColumn(leftPanel, 0);
                    grid.Children.Add(leftPanel);

                    // Splitter
                    var splitter = new GridSplitter
                    {
                        Width = 5, HorizontalAlignment = HorizontalAlignment.Stretch,
                        Background = (Brush)FindResource("BorderBrush"),
                    };
                    Grid.SetColumn(splitter, 1);
                    grid.Children.Add(splitter);

                    // Right: Bytecode
                    var rightPanel = new DockPanel();
                    var rightLabel = new TextBlock
                    {
                        Text = "BYTECODE DISASSEMBLY", FontWeight = FontWeights.SemiBold,
                        FontSize = 11, Foreground = (Brush)FindResource("TextSecondaryBrush"),
                        Margin = new Thickness(0, 0, 0, 4),
                    };
                    DockPanel.SetDock(rightLabel, Dock.Top);
                    rightPanel.Children.Add(rightLabel);
                    var disasmBox = new RichTextBox
                    {
                        FontFamily = new FontFamily("Consolas"), FontSize = 11,
                        IsReadOnly = true, Padding = new Thickness(6),
                        Background = new SolidColorBrush(Color.FromRgb(0xFA, 0xFA, 0xFA)),
                        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                        BorderThickness = new Thickness(1),
                        BorderBrush = (Brush)FindResource("BorderBrush"),
                    };
                    SetRichText(disasmBox, mod.Disassembly!);
                    rightPanel.Children.Add(disasmBox);
                    Grid.SetColumn(rightPanel, 2);
                    grid.Children.Add(rightPanel);

                    tabItem.Content = grid;
                }
                else
                {
                    // Bytecode only for this module
                    var disasmBox = new RichTextBox
                    {
                        FontFamily = new FontFamily("Consolas"), FontSize = 11,
                        IsReadOnly = true, Padding = new Thickness(6),
                        Background = new SolidColorBrush(Color.FromRgb(0xFA, 0xFA, 0xFA)),
                        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                        BorderThickness = new Thickness(1),
                        BorderBrush = (Brush)FindResource("BorderBrush"),
                    };
                    SetRichText(disasmBox, mod.Disassembly!);
                    tabItem.Content = disasmBox;
                }

                ModuleTabControl.Items.Add(tabItem);
            }

            if (ModuleTabControl.Items.Count > 0)
                ModuleTabControl.SelectedIndex = 0;

            BtnSaveSource.Content   = "Save bytecode…";
            BtnSaveSource.IsEnabled = true;
            BtnSaveLisp.Visibility  = hasLisp ? Visibility.Visible : Visibility.Collapsed;
            BtnSaveLisp.IsEnabled   = hasLisp;
            BtnCopySource.IsEnabled = true;
        }
        else if (hasLisp && hasDisasm)
        {
            // ── Single module with LISP: use the static split pane ───────
            LabelSource.Text = $"FAS DECOMPILED LISP + BYTECODE ({vlx.FasFunctions.Count} functions)";
            SourceSplitGrid.Visibility = Visibility.Visible;

            PopulateLispPane(vlx);
            PopulateDisasmPane(vlx);

            BtnSaveSource.Content   = "Save bytecode…";
            BtnSaveSource.IsEnabled = true;
            BtnSaveLisp.Visibility  = Visibility.Visible;
            BtnSaveLisp.IsEnabled   = true;
            BtnCopySource.IsEnabled = true;
        }
        else if (hasDisasm)
        {
            // ── Bytecode only — single pane ──────────────────────────────
            LabelSource.Text = "FAS BYTECODE DISASSEMBLY";
            SourceBox.Visibility = Visibility.Visible;
            SetRichText(SourceBox, vlx.Disassembly!);
            BtnSaveSource.Content   = "Save to file…";
            BtnSaveSource.IsEnabled = true;
            BtnCopySource.IsEnabled = true;
        }

        // Store combined content for Save/Copy
        if (hasDisasm)
        {
            _result!.DecompiledSource = hasLisp
                ? vlx.DecompiledLisp
                    + "\n\n;;; ════════════════════════════════════════════════════════════\n"
                    + ";;; RAW BYTECODE DISASSEMBLY\n"
                    + ";;; ════════════════════════════════════════════════════════════\n\n"
                    + vlx.Disassembly
                : vlx.Disassembly;
        }
    }

    // ── Side-by-side pane helpers ─────────────────────────────────────────────

    /// <summary>Offset → line index maps for cross-pane highlighting.</summary>
    private Dictionary<int, int> _lispOffsetToLine  = [];
    private Dictionary<int, int> _disasmOffsetToLine = [];
    private string[] _lispLines  = [];
    private string[] _disasmLines = [];

    private void PopulateLispPane(VlxInfo vlx)
    {
        var doc = SplitLispBox.Document;
        doc.Blocks.Clear();

        _lispLines = (vlx.DecompiledLisp ?? "").Split('\n');
        _lispOffsetToLine.Clear();

        var para = new Paragraph
        {
            FontFamily = new FontFamily("Consolas"),
            FontSize   = 12,
            Margin     = new Thickness(0),
            LineHeight = 16,
        };

        for (int i = 0; i < _lispLines.Length; i++)
        {
            string line = _lispLines[i].TrimEnd('\r');
            var run = new Run(line + "\n");

            // Extract offset from LISP lines that contain function markers
            // e.g., lines starting with "(defun" map to the function's bytecode offset
            if (line.TrimStart().StartsWith("(defun") || line.TrimStart().StartsWith("(defun-q"))
            {
                // Try to find matching FasFunction
                foreach (var fn in vlx.FasFunctions)
                {
                    if (line.Contains(fn.Name))
                    {
                        _lispOffsetToLine[fn.Offset] = i;
                        break;
                    }
                }
            }

            para.Inlines.Add(run);
        }

        doc.Blocks.Add(para);
        SplitLispBox.PreviewMouseLeftButtonUp += SplitLispBox_Click;
    }

    private void PopulateDisasmPane(VlxInfo vlx)
    {
        var doc = SplitDisasmBox.Document;
        doc.Blocks.Clear();

        _disasmLines = (vlx.Disassembly ?? "").Split('\n');
        _disasmOffsetToLine.Clear();

        var para = new Paragraph
        {
            FontFamily = new FontFamily("Consolas"),
            FontSize   = 12,
            Margin     = new Thickness(0),
            LineHeight = 16,
        };

        for (int i = 0; i < _disasmLines.Length; i++)
        {
            string line = _disasmLines[i].TrimEnd('\r');
            var run = new Run(line + "\n");

            // Parse hex offset from disassembly lines: "  0A2F  14  DEFUN ..."
            string trimmed = line.TrimStart();
            if (trimmed.Length >= 4 && int.TryParse(trimmed[..4],
                System.Globalization.NumberStyles.HexNumber, null, out int offset))
            {
                _disasmOffsetToLine[offset] = i;

                // Highlight DEFUN lines with a subtle background
                if (trimmed.Contains("DEFUN") && !trimmed.Contains("END defun"))
                {
                    run.Background = new SolidColorBrush(Color.FromRgb(0xE8, 0xF0, 0xFF));
                }
            }

            para.Inlines.Add(run);
        }

        doc.Blocks.Add(para);
        SplitDisasmBox.PreviewMouseLeftButtonUp += SplitDisasmBox_Click;
    }

    /// <summary>Click a line in the LISP pane → highlight the corresponding bytecode line.</summary>
    private void SplitLispBox_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        try
        {
            var pos = SplitLispBox.GetPositionFromPoint(e.GetPosition(SplitLispBox), true);
            if (pos == null) return;

            // Find which line was clicked
            int charOffset = new TextRange(SplitLispBox.Document.ContentStart, pos).Text.Length;
            int lineIdx = (vlxLineFromChar(_lispLines, charOffset));

            // Find the closest bytecode offset mapping from this LISP line
            int bestOffset = -1;
            int bestDist = int.MaxValue;
            foreach (var (off, li) in _lispOffsetToLine)
            {
                int dist = Math.Abs(li - lineIdx);
                if (dist < bestDist) { bestDist = dist; bestOffset = off; }
            }

            // Highlight corresponding line in bytecode pane
            if (bestOffset >= 0 && _disasmOffsetToLine.TryGetValue(bestOffset, out int disasmLine))
            {
                HighlightDisasmLine(disasmLine);
            }
        }
        catch { /* best-effort highlighting */ }
    }

    /// <summary>Click a line in the bytecode pane → highlight the corresponding LISP line.</summary>
    private void SplitDisasmBox_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        try
        {
            var pos = SplitDisasmBox.GetPositionFromPoint(e.GetPosition(SplitDisasmBox), true);
            if (pos == null) return;

            int charOffset = new TextRange(SplitDisasmBox.Document.ContentStart, pos).Text.Length;
            int lineIdx = vlxLineFromChar(_disasmLines, charOffset);

            // Find the hex offset for this disassembly line
            string trimmed = (lineIdx < _disasmLines.Length ? _disasmLines[lineIdx] : "").TrimStart();
            if (trimmed.Length >= 4 && int.TryParse(trimmed[..4],
                System.Globalization.NumberStyles.HexNumber, null, out int byteOffset))
            {
                // Find closest LISP line via offset mapping
                int bestLispLine = -1;
                int bestDist = int.MaxValue;
                foreach (var (off, li) in _lispOffsetToLine)
                {
                    int dist = Math.Abs(off - byteOffset);
                    if (dist < bestDist) { bestDist = dist; bestLispLine = li; }
                }

                if (bestLispLine >= 0)
                    HighlightLispLine(bestLispLine);
            }
        }
        catch { /* best-effort highlighting */ }
    }

    private static int vlxLineFromChar(string[] lines, int charOffset)
    {
        int cum = 0;
        for (int i = 0; i < lines.Length; i++)
        {
            cum += lines[i].TrimEnd('\r').Length + 1; // +1 for \n
            if (cum >= charOffset) return i;
        }
        return lines.Length - 1;
    }

    private Paragraph? _lastHighlightedDisasm;
    private Paragraph? _lastHighlightedLisp;

    private void HighlightDisasmLine(int lineIdx)
    {
        HighlightLineInBox(SplitDisasmBox, _disasmLines, lineIdx,
            Color.FromRgb(0xFF, 0xF3, 0xCD), ref _lastHighlightedDisasm);
    }

    private void HighlightLispLine(int lineIdx)
    {
        HighlightLineInBox(SplitLispBox, _lispLines, lineIdx,
            Color.FromRgb(0xD4, 0xED, 0xDA), ref _lastHighlightedLisp);
    }

    private void HighlightLineInBox(RichTextBox box, string[] lines, int lineIdx,
        Color highlightColor, ref Paragraph? lastHighlighted)
    {
        try
        {
            var doc = box.Document;
            if (doc.Blocks.FirstBlock is not Paragraph para) return;

            // Clear previous highlight
            if (lastHighlighted != null)
            {
                foreach (var inline in lastHighlighted.Inlines)
                    if (inline is Run r) r.Background = Brushes.Transparent;
                lastHighlighted = null;
            }

            // Navigate to the target line's Run and highlight it
            int runIdx = 0;
            foreach (var inline in para.Inlines)
            {
                if (inline is Run run)
                {
                    if (runIdx == lineIdx)
                    {
                        run.Background = new SolidColorBrush(highlightColor);
                        // Scroll into view
                        var runStart = run.ContentStart;
                        if (runStart != null)
                        {
                            var rect = runStart.GetCharacterRect(LogicalDirection.Forward);
                            box.ScrollToVerticalOffset(box.VerticalOffset + rect.Top - box.ActualHeight / 3);
                        }
                        lastHighlighted = para;
                        return;
                    }
                    runIdx++;
                }
            }
        }
        catch { /* best-effort */ }
    }

    private void AddTreeNode(string text, bool ok)
    {
        var item = new TreeViewItem
        {
            Header     = text,
            FontSize   = 12,
            Foreground = ok
                ? (Brush)FindResource("TextPrimaryBrush")
                : (Brush)FindResource("WarningBrush"),
        };
        AnalysisTree.Items.Add(item);
    }

    // ── Filters ───────────────────────────────────────────────────────────────

    private void FilterImports_Changed(object sender, TextChangedEventArgs e)
    {
        if (_result == null) return;
        string q = FilterImports.Text.Trim().ToLowerInvariant();
        GridImports.ItemsSource = string.IsNullOrEmpty(q)
            ? _result.Imports
            : _result.Imports.Where(i =>
                i.DllName.Contains(q, StringComparison.OrdinalIgnoreCase)
             || i.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void FilterStrings_Changed(object sender, TextChangedEventArgs e)   => ApplyStringFilter();
    private void FilterEncoding_Changed(object sender, SelectionChangedEventArgs e) => ApplyStringFilter();

    private void ApplyStringFilter()
    {
        if (_result == null) return;
        string q   = FilterStrings.Text.Trim();
        string enc = ((ComboBoxItem)FilterEncoding.SelectedItem)?.Content?.ToString() ?? "All";

        IEnumerable<ExtractedString> filtered = _result.Strings;
        if (!string.IsNullOrEmpty(q))
            filtered = filtered.Where(s => s.Value.Contains(q, StringComparison.OrdinalIgnoreCase));
        if (enc != "All")
            filtered = filtered.Where(s => s.Encoding == enc);

        GridStrings.ItemsSource = filtered.ToList();
    }

    // ── Tree navigation ───────────────────────────────────────────────────────

    private void AnalysisTree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is not TreeViewItem item) return;
        string header = item.Header?.ToString() ?? "";

        // Map tree node to the named tab
        TabItem? target = header switch
        {
            var h when h.StartsWith("📄") => TabPeStructure,
            var h when h.StartsWith("📥") => TabImports,
            var h when h.StartsWith("📤") => TabExports,
            var h when h.StartsWith("🔤") => TabStrings,
            var h when h.StartsWith("🗃") => TabResources,
            var h when h.StartsWith("🔗") => TabDeps,
            var h when h.StartsWith("💻") => TabSource,
            var h when h.StartsWith("⚙")  => TabSource,
            var h when h.StartsWith("🔷") => TabVb,
            var h when h.StartsWith("🔧") => TabArx,
            var h when h.StartsWith("🐍") => TabPython,
            var h when h.StartsWith("📜") => TabVlx,
            _ => null,
        };
        if (target != null && target.Visibility == Visibility.Visible)
            AnalysisTabs.SelectedItem = target;
    }

    // ── Export ────────────────────────────────────────────────────────────────

    private void MenuExportHtml_Click(object sender, RoutedEventArgs e)
    {
        if (_result == null) return;
        var dlg = new SaveFileDialog
        {
            Title      = "Export HTML Report",
            Filter     = "HTML Files|*.html",
            FileName   = Path.GetFileNameWithoutExtension(_result.FileName) + "_analysis.html",
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            string html = HtmlReporter.Generate(_result);
            File.WriteAllText(dlg.FileName, html, System.Text.Encoding.UTF8);
            ShowStatus($"Report saved: {dlg.FileName}");

            if (MessageBox.Show("Open report in browser?", "BinaryLens",
                                MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = dlg.FileName,
                    UseShellExecute = true,
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "BinaryLens",
                            MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void MenuExportJson_Click(object sender, RoutedEventArgs e)
    {
        if (_result == null) return;
        var dlg = new SaveFileDialog
        {
            Title    = "Export JSON Report",
            Filter   = "JSON Files|*.json",
            FileName = Path.GetFileNameWithoutExtension(_result.FileName) + "_analysis.json",
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            string json = JsonExporter.Generate(_result);
            File.WriteAllText(dlg.FileName, json, System.Text.Encoding.UTF8);
            ShowStatus($"JSON report saved: {dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "BinaryLens",
                            MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void MenuExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (_result == null) return;

        // Use a folder browser via SaveFileDialog — user picks a "anchor" file,
        // and we write CSVs to the same directory.
        var dlg = new SaveFileDialog
        {
            Title    = "Export CSV Files — choose folder (save any name)",
            Filter   = "CSV Files|*.csv",
            FileName = Path.GetFileNameWithoutExtension(_result.FileName) + "_summary.csv",
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            string dir    = Path.GetDirectoryName(dlg.FileName)!;
            string prefix = Path.GetFileNameWithoutExtension(_result.FileName);
            var files = CsvExporter.GenerateAll(_result, dir, prefix);
            ShowStatus($"{files.Count} CSV files saved to: {dir}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "BinaryLens",
                            MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void MenuCompare_Click(object sender, RoutedEventArgs e)
    {
        // Open two files for comparison
        var dlgA = new OpenFileDialog
        {
            Title  = "Select First Binary (A)",
            Filter = "All Supported|*.dll;*.exe;*.arx;*.ocx;*.ax;*.sys;*.drv;*.pyd;*.pyc;*.vlx;*.fas|All Files|*.*",
        };
        if (dlgA.ShowDialog() != true) return;

        var dlgB = new OpenFileDialog
        {
            Title  = "Select Second Binary (B)",
            Filter = "All Supported|*.dll;*.exe;*.arx;*.ocx;*.ax;*.sys;*.drv;*.pyd;*.pyc;*.vlx;*.fas|All Files|*.*",
        };
        if (dlgB.ShowDialog() != true) return;

        _ = RunComparison(dlgA.FileName, dlgB.FileName);
    }

    private async Task RunComparison(string fileA, string fileB)
    {
        ShowStatus($"Comparing: {Path.GetFileName(fileA)} vs {Path.GetFileName(fileB)}…");
        ProgressBar.Visibility     = Visibility.Visible;
        ProgressBar.IsIndeterminate = true;

        try
        {
            var progress = new Progress<string>(msg => ShowStatus(msg));
            var cts = new CancellationTokenSource();
            var resultA = await BinaryAnalyzer.AnalyzeAsync(fileA, progress, cts.Token);
            var resultB = await BinaryAnalyzer.AnalyzeAsync(fileB, progress, cts.Token);

            var dlg = new SaveFileDialog
            {
                Title    = "Save Comparison Report",
                Filter   = "HTML Files|*.html",
                FileName = $"{Path.GetFileNameWithoutExtension(resultA.FileName)}_vs_{Path.GetFileNameWithoutExtension(resultB.FileName)}.html",
            };
            if (dlg.ShowDialog() != true) return;

            string html = ComparisonReporter.Generate(resultA, resultB);
            File.WriteAllText(dlg.FileName, html, System.Text.Encoding.UTF8);
            ShowStatus($"Comparison report saved: {dlg.FileName}");

            if (MessageBox.Show("Open report in browser?", "BinaryLens",
                                MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = dlg.FileName,
                    UseShellExecute = true,
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Comparison failed: {ex.Message}", "BinaryLens",
                            MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ProgressBar.Visibility     = Visibility.Hidden;
            ProgressBar.IsIndeterminate = false;
        }
    }

    private void MenuSaveSource_Click(object sender, RoutedEventArgs e)
        => SaveSource_Click(sender, e);

    private void SaveSource_Click(object sender, RoutedEventArgs e)
    {
        if (_result == null) return;

        bool isDotNet = _result.IsDotNet && !string.IsNullOrEmpty(_result.DecompiledSource);
        var dlg = new SaveFileDialog
        {
            Title  = "Save " + (isDotNet ? "Decompiled Source" : "Disassembly"),
            Filter = isDotNet ? "C# Source|*.cs|Text|*.txt" : "Text|*.txt|ASM|*.asm",
            FileName = Path.GetFileNameWithoutExtension(_result.FileName)
                       + (isDotNet ? "_decompiled.cs" : "_disasm.txt"),
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            if (isDotNet)
            {
                File.WriteAllText(dlg.FileName, _result.DecompiledSource!,
                                  System.Text.Encoding.UTF8);
            }
            else
            {
                var lines = _result.Disassembly
                    .Select(d => $"{d.Address}  {d.Bytes}  {d.Mnemonic,-10} {d.Operands}");
                File.WriteAllLines(dlg.FileName, lines, System.Text.Encoding.UTF8);
            }
            ShowStatus($"Saved: {dlg.FileName}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Save failed: {ex.Message}", "BinaryLens",
                            MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SaveLisp_Click(object sender, RoutedEventArgs e)
    {
        var vlx = _result?.VlxInfo;
        if (vlx == null) return;

        // Collect all available LISP sources: top-level + per-module
        var sources = new List<(string Name, string Lisp)>();
        if (!string.IsNullOrEmpty(vlx.DecompiledLisp))
            sources.Add((Path.GetFileNameWithoutExtension(_result!.FileName), vlx.DecompiledLisp!));
        foreach (var mod in vlx.Modules)
        {
            if (!string.IsNullOrEmpty(mod.DecompiledLisp))
                sources.Add((mod.Name, mod.DecompiledLisp!));
        }

        if (sources.Count == 0)
        {
            MessageBox.Show("No decompiled LISP available to save.", "BinaryLens",
                            MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // Single source → SaveFileDialog, quick path
        if (sources.Count == 1)
        {
            var dlg = new SaveFileDialog
            {
                Title    = "Save Reconstructed LISP",
                Filter   = "LISP Source|*.lsp|Text|*.txt",
                FileName = sources[0].Name + "_decompiled.lsp",
            };
            if (dlg.ShowDialog() != true) return;
            try
            {
                File.WriteAllText(dlg.FileName, sources[0].Lisp, System.Text.Encoding.UTF8);
                ShowStatus($"Saved LISP: {dlg.FileName}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Save failed: {ex.Message}", "BinaryLens",
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return;
        }

        // Multiple sources → let user pick which modules, then choose folder
        var pickWin = new Window
        {
            Title               = "Save LISP — Select Modules",
            Width               = 380,
            Height              = 320,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner               = this,
            ResizeMode          = ResizeMode.NoResize,
        };

        var panel = new StackPanel { Margin = new Thickness(12) };

        panel.Children.Add(new TextBlock
        {
            Text         = "Select which modules to save:",
            FontWeight   = FontWeights.SemiBold,
            Margin       = new Thickness(0, 0, 0, 8),
        });

        var checkBoxes = new List<CheckBox>();
        foreach (var src in sources)
        {
            var cb = new CheckBox
            {
                Content   = src.Name,
                IsChecked = true,
                Margin    = new Thickness(0, 2, 0, 2),
            };
            checkBoxes.Add(cb);
            panel.Children.Add(cb);
        }

        // Select All / None links
        var selPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 8) };
        var btnAll = new Button  { Content = "Select All",  Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(0, 0, 6, 0) };
        var btnNone = new Button { Content = "Select None", Padding = new Thickness(8, 2, 8, 2) };
        btnAll.Click  += (_, _) => { foreach (var cb in checkBoxes) cb.IsChecked = true; };
        btnNone.Click += (_, _) => { foreach (var cb in checkBoxes) cb.IsChecked = false; };
        selPanel.Children.Add(btnAll);
        selPanel.Children.Add(btnNone);
        panel.Children.Add(selPanel);

        var btnSave = new Button
        {
            Content             = "Choose Folder and Save…",
            Padding             = new Thickness(12, 6, 12, 6),
            HorizontalAlignment = HorizontalAlignment.Right,
            IsDefault           = true,
        };
        panel.Children.Add(btnSave);

        var scroll = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        pickWin.Content = scroll;

        btnSave.Click += (_, _) =>
        {
            var selected = new List<(string Name, string Lisp)>();
            for (int i = 0; i < checkBoxes.Count; i++)
            {
                if (checkBoxes[i].IsChecked == true)
                    selected.Add(sources[i]);
            }
            if (selected.Count == 0)
            {
                MessageBox.Show("No modules selected.", "BinaryLens",
                                MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var folderDlg = new OpenFolderDialog
            {
                Title = "Select Destination Folder for LISP Files",
            };
            if (folderDlg.ShowDialog() != true) return;

            string folder = folderDlg.FolderName;
            int saved = 0;
            try
            {
                foreach (var s in selected)
                {
                    string safeName = string.Join("_", s.Name.Split(Path.GetInvalidFileNameChars()));
                    string filePath = Path.Combine(folder, safeName + "_decompiled.lsp");
                    File.WriteAllText(filePath, s.Lisp, System.Text.Encoding.UTF8);
                    saved++;
                }
                ShowStatus($"Saved {saved} LISP file(s) to {folder}");
                pickWin.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Save failed: {ex.Message}", "BinaryLens",
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        };

        pickWin.ShowDialog();
    }

    private void CopySource_Click(object sender, RoutedEventArgs e)
    {
        // Multi-module mode: copy the currently selected module tab content
        if (ModuleTabControl.Visibility == Visibility.Visible &&
            ModuleTabControl.SelectedItem is TabItem selectedTab)
        {
            string text = ExtractTextFromTabContent(selectedTab.Content);
            if (!string.IsNullOrEmpty(text))
            {
                Clipboard.SetText(text);
                ShowStatus($"Module \"{selectedTab.Header}\" copied to clipboard.");
                return;
            }
        }

        // Single-module / non-VLX: decompiled source
        if (_result?.DecompiledSource != null)
        {
            Clipboard.SetText(_result.DecompiledSource);
            ShowStatus("Decompiled source copied to clipboard.");
            return;
        }

        // Native disassembly grid
        if (_result?.Disassembly.Count > 0)
        {
            var sb = new System.Text.StringBuilder();
            foreach (var line in _result.Disassembly)
                sb.AppendLine($"{line.Address,-16}{line.Bytes,-24}{line.Mnemonic,-12}{line.Operands}");
            Clipboard.SetText(sb.ToString());
            ShowStatus($"{_result.Disassembly.Count:N0} disassembly lines copied to clipboard.");
        }
    }

    /// <summary>
    /// Extracts all text from the RichTextBox(es) inside a dynamic module tab.
    /// Handles both split-pane (Grid with two RichTextBoxes) and single RichTextBox content.
    /// </summary>
    private static string ExtractTextFromTabContent(object? content)
    {
        if (content is RichTextBox singleBox)
            return new TextRange(singleBox.Document.ContentStart, singleBox.Document.ContentEnd).Text.TrimEnd();

        if (content is Grid grid)
        {
            var sb = new System.Text.StringBuilder();
            // Walk all DockPanels inside the grid to find RichTextBoxes
            foreach (var child in grid.Children.OfType<DockPanel>())
            {
                foreach (var rtb in child.Children.OfType<RichTextBox>())
                {
                    string text = new TextRange(rtb.Document.ContentStart, rtb.Document.ContentEnd).Text.TrimEnd();
                    if (sb.Length > 0 && !string.IsNullOrEmpty(text))
                        sb.AppendLine("\n;;; ════════════════════════════════════════════════════════════\n");
                    sb.Append(text);
                }
            }
            return sb.ToString();
        }

        return "";
    }

    // ── Misc menu ─────────────────────────────────────────────────────────────

    private void MenuClear_Click(object sender, RoutedEventArgs e)  => ClearResults();
    private void MenuExit_Click(object sender, RoutedEventArgs e)   => Close();

    private void MenuAbout_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            "BinaryLens — Binary Analysis Workbench\n\n" +
            "Analyzes PE binaries (DLL, EXE, ARX, OCX, SYS):\n" +
            "  • PE structure, sections, entropy\n" +
            "  • Import / export tables\n" +
            "  • Embedded string extraction\n" +
            "  • Resource enumeration\n" +
            "  • Dependency tree\n" +
            "  • .NET decompilation (ILSpy engine)\n" +
            "  • Native x86/x64 disassembly (Capstone)\n" +
            "  • AutoCAD ARX detection and analysis\n\n" +
            "Built with: PeNet · ICSharpCode.Decompiler · Capstone.NET\n\n" +
            "Drag any binary onto the window to begin.",
            "About BinaryLens",
            MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void ClearResults()
    {
        _result = null;
        _allImports.Clear();
        _allExports.Clear();
        _allStrings.Clear();

        GridPeHeader.ItemsSource  = null;
        GridSections.ItemsSource  = null;
        GridImports.ItemsSource   = null;
        GridExports.ItemsSource   = null;
        GridStrings.ItemsSource   = null;
        GridResources.ItemsSource = null;
        GridDisasm.ItemsSource    = null;
        EntropyChart.Items.Clear();
        GridVbSummary.ItemsSource  = null;
        GridVbObjects.ItemsSource  = null;
        GridVbCom.ItemsSource      = null;
        GridVbApi.ItemsSource      = null;
        GridVbRefs.ItemsSource     = null;
        ListVbControls.ItemsSource = null;
        ListVbMethods.ItemsSource  = null;
        VbObjectDetail.Visibility  = Visibility.Collapsed;
        GridArxSummary.ItemsSource = null;
        GridArxImports.ItemsSource = null;
        GridArxClasses.ItemsSource = null;
        DepTree.Items.Clear();
        AnalysisTree.Items.Clear();
        SourceBox.Document.Blocks.Clear();

        // Clear VLX/FAS source panes and grids
        SplitLispBox.Document.Blocks.Clear();
        SplitDisasmBox.Document.Blocks.Clear();
        ModuleTabControl.Items.Clear();
        ModuleTabControl.Visibility  = Visibility.Collapsed;
        SourceSplitGrid.Visibility   = Visibility.Collapsed;
        GridVlxHeader.ItemsSource    = null;
        GridVlxModules.ItemsSource   = null;
        GridVlxCommands.ItemsSource  = null;
        GridVlxFunctions.ItemsSource = null;
        GridVlxGlobals.ItemsSource   = null;
        GridVlxStrings.ItemsSource   = null;
        VlxDetails.Visibility        = Visibility.Collapsed;
        NoVlxMsg.Visibility          = Visibility.Collapsed;

        FileSummaryPanel.Visibility = Visibility.Collapsed;
        MenuExportHtml.IsEnabled    = false;
        MenuExportJson.IsEnabled    = false;
        MenuExportCsv.IsEnabled     = false;
        MenuSaveSource.IsEnabled    = false;

        TabImports.Header   = "Imports";
        TabExports.Header   = "Exports";
        TabStrings.Header   = "Strings";
        TabResources.Header = "Resources";
        TabDeps.Header      = "Dependencies";
        TabSource.Header    = "Source / Disasm";
        TabVb.Header        = "VB5/6";
        TabArx.Header       = "ARX";
        TabPython.Header    = "Python";
        TabVlx.Header       = "VLX/FAS";

        // Reset all tabs to visible
        TabPeStructure.Visibility = Visibility.Visible;
        TabImports.Visibility     = Visibility.Visible;
        TabExports.Visibility     = Visibility.Visible;
        TabStrings.Visibility     = Visibility.Visible;
        TabResources.Visibility   = Visibility.Visible;
        TabDeps.Visibility        = Visibility.Visible;
        TabSource.Visibility      = Visibility.Visible;
        TabVb.Visibility          = Visibility.Visible;
        TabArx.Visibility         = Visibility.Visible;
        TabPython.Visibility      = Visibility.Visible;
        TabVlx.Visibility         = Visibility.Visible;
    }

    private void ShowStatus(string msg) => StatusText.Text = msg;
}
