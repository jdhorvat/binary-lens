namespace BinaryLens.Models;

// ── Top-level result ──────────────────────────────────────────────────────────

/// <summary>Complete analysis result for one binary file.</summary>
public class AnalysisResult
{
    public string  FilePath     { get; set; } = "";
    public string  FileName     { get; set; } = "";
    public long    FileSize     { get; set; }
    public string  FileSizeHuman => FileSize < 1_048_576
        ? $"{FileSize / 1024.0:F1} KB"
        : $"{FileSize / 1_048_576.0:F2} MB";

    public bool    IsValidPe    { get; set; }
    public bool    Is64Bit      { get; set; }
    public bool    IsDotNet     { get; set; }
    public bool    IsArx        { get; set; }
    public string  Architecture { get; set; } = "";
    public string  FileTypeSummary { get; set; } = "";

    public PeInfo              PeInfo       { get; set; } = new();
    public List<ImportEntry>   Imports      { get; set; } = [];
    public List<ExportEntry>   Exports      { get; set; } = [];
    public List<ExtractedString> Strings    { get; set; } = [];
    public List<ResourceInfo>  Resources    { get; set; } = [];
    public DependencyNode?     DependencyRoot { get; set; }
    public string?             DecompiledSource { get; set; }
    public List<DisasmLine>    Disassembly  { get; set; } = [];
    public ArxInfo?            ArxInfo      { get; set; }

    // ── Python ────────────────────────────────────────────────────────────────
    public bool    IsPyc  { get; set; }     // .pyc bytecode file
    public bool    IsPyd  { get; set; }     // .pyd PE extension module
    public PycInfo? PycInfo { get; set; }
    public PydInfo? PydInfo { get; set; }

    // ── VB5/6 ─────────────────────────────────────────────────────────────────
    public bool    IsVb5   { get; set; }
    public VbInfo? VbInfo  { get; set; }

    // ── Visual LISP / AutoLISP ────────────────────────────────────────────────
    public bool     IsVlx   { get; set; }
    public VlxInfo? VlxInfo { get; set; }

    public List<string>        Errors       { get; set; } = [];
}

// ── PE structure ─────────────────────────────────────────────────────────────

public class PeInfo
{
    public string   MachineType     { get; set; } = "";
    public string   Subsystem       { get; set; } = "";
    public string   LinkerVersion   { get; set; } = "";
    public DateTime TimeDateStamp   { get; set; }
    public string   TimeDateStampDisplay => TimeDateStamp == DateTime.UnixEpoch
        ? "Unknown" : TimeDateStamp.ToString("yyyy-MM-dd HH:mm:ss UTC");
    public string   EntryPoint      { get; set; } = "";
    public string   ImageBase       { get; set; } = "";
    public ulong    RawImageBase    { get; set; }
    public string   SizeOfImage     { get; set; } = "";
    public bool     IsExe           { get; set; }
    public bool     IsDll           { get; set; }
    public List<string>    Characteristics { get; set; } = [];
    public List<PeSection> Sections        { get; set; } = [];
}

public class PeSection
{
    public string Name             { get; set; } = "";
    public string VirtualAddress   { get; set; } = "";
    public string VirtualSize      { get; set; } = "";
    public string RawSize          { get; set; } = "";
    public string Characteristics  { get; set; } = "";
    public double Entropy          { get; set; }

    // Raw numeric values for programmatic use (RVA → file-offset conversion)
    public uint RawVirtualAddress  { get; set; }
    public uint RawVirtualSize     { get; set; }
    public uint RawPointerToData   { get; set; }
    public uint RawSizeOfData      { get; set; }
    public string EntropyDisplay   => $"{Entropy:F2}";
    public string EntropyNote      => Entropy switch
    {
        > 7.5  => "⚠ High (packed/encrypted?)",
        > 6.0  => "Moderate",
        _      => "Normal"
    };
}

// ── Imports / Exports ─────────────────────────────────────────────────────────

public class ImportEntry
{
    public string DllName      { get; set; } = "";
    public string FunctionName { get; set; } = "";
    public string Hint         { get; set; } = "";
    public bool   IsOrdinal    { get; set; }
    public string DisplayName  => IsOrdinal ? $"Ordinal {Hint}" : FunctionName;
}

public class ExportEntry
{
    public string Name          { get; set; } = "";
    public string RvaAddress    { get; set; } = "";
    public uint   Ordinal       { get; set; }
    public bool   IsForwarded   { get; set; }
    public string? ForwardTarget { get; set; }
    public string DisplayName   => string.IsNullOrEmpty(Name) ? $"[Ordinal {Ordinal}]" : Name;
}

// ── Strings ───────────────────────────────────────────────────────────────────

public class ExtractedString
{
    public long   Offset   { get; set; }
    public string Value    { get; set; } = "";
    public string Encoding { get; set; } = "ASCII";
    public string Section  { get; set; } = "";
    public string OffsetHex => $"0x{Offset:X8}";
}

// ── Resources ─────────────────────────────────────────────────────────────────

public class ResourceInfo
{
    public string Type     { get; set; } = "";
    public string Name     { get; set; } = "";
    public string Language { get; set; } = "";
    public long   Size     { get; set; }
    public string SizeDisplay => $"{Size:N0} bytes";
    public byte[]? Data    { get; set; }
}

// ── Dependency tree ───────────────────────────────────────────────────────────

public class DependencyNode
{
    public string  Name          { get; set; } = "";
    public string? ResolvedPath  { get; set; }
    public bool    Found         { get; set; }
    public bool    IsSystem      { get; set; }
    public bool    IsAutocad     { get; set; }
    public int     Depth         { get; set; }
    public List<DependencyNode> Children { get; set; } = [];

    public string StatusIcon => Found
        ? (IsAutocad ? "🔵" : IsSystem ? "⚪" : "🟢")
        : "🔴";
    public string DisplayText => Found
        ? $"{StatusIcon} {Name}"
        : $"{StatusIcon} {Name}  [NOT FOUND]";
}

// ── Disassembly ───────────────────────────────────────────────────────────────

public class DisasmLine
{
    public string Address  { get; set; } = "";
    public string Bytes    { get; set; } = "";
    public string Mnemonic { get; set; } = "";
    public string Operands { get; set; } = "";
}

// ── ARX-specific ──────────────────────────────────────────────────────────────

public class ArxInfo
{
    /// <summary>True if the binary exports acrxEntryPoint (the ARX main hook).</summary>
    public bool   HasArxEntryPoint  { get; set; }
    public string EntryPointName    { get; set; } = "acrxEntryPoint";

    /// <summary>AutoCAD-related imports found in the import table.</summary>
    public List<string> AutocadImports   { get; set; } = [];

    /// <summary>Exported names that look like AutoCAD command registrations.</summary>
    public List<string> CommandExports   { get; set; } = [];

    /// <summary>Strings matching AcRx / AcDb / AcGe / AcAp class prefixes.</summary>
    public List<string> AcClassStrings   { get; set; } = [];

    /// <summary>Probable AutoCAD SDK version hints from import DLL names.</summary>
    public string? DetectedAcadVersion   { get; set; }

    /// <summary>True if this is a managed (.NET) ARX wrapper.</summary>
    public bool IsManagedArx            { get; set; }

    /// <summary>Managed type names found (when IsManagedArx is true).</summary>
    public List<string> ManagedTypes    { get; set; } = [];
}

// ── VB5/6 P-Code / Native ────────────────────────────────────────────────────

public class VbInfo
{
    public string RuntimeDll          { get; set; } = "";     // MSVBVM50.DLL or MSVBVM60.DLL
    public int    VbVersion           { get; set; }           // 5 or 6
    public bool   IsPCode             { get; set; }           // true = P-Code, false = native compiled
    public string CompileMode         => IsPCode ? "P-Code (interpreted)" : "Native (compiled)";

    // ── VB Project info (from PE resource or header) ─────────────────────────
    public string ProjectName         { get; set; } = "";
    public string ProjectDescription  { get; set; } = "";
    public string ProjectExeName      { get; set; } = "";
    public string ProjectHelpFile     { get; set; } = "";

    // ── Forms, modules, classes ──────────────────────────────────────────────
    public List<VbObject>  Objects    { get; set; } = [];
    public List<string>    References { get; set; } = [];  // COM type library references

    // ── Entry points & key addresses ────────────────────────────────────────
    public string EntryPoint          { get; set; } = "";   // ThunRTMain or _main
    public string VbHeaderOffset      { get; set; } = "";
    public string ProjectInfoOffset   { get; set; } = "";

    // ── Detected COM / ActiveX libraries ────────────────────────────────────
    public List<string> ComImports    { get; set; } = [];   // e.g. "Winsock Control", "Common Dialog"
    public List<string> ApiDeclares   { get; set; } = [];   // Detected Declare Function calls in strings

    public string? Error              { get; set; }
}

public class VbObject
{
    public int    Index       { get; set; }
    public string Name        { get; set; } = "";
    public string ObjectType  { get; set; } = "";   // Form, Module, Class, UserControl, MDIForm
    public int    MethodCount { get; set; }
    public int    EventCount  { get; set; }
    public bool   HasPCode    { get; set; }
    public List<string> Controls  { get; set; } = [];   // Control names on forms
    public List<string> Methods   { get; set; } = [];   // Detected method/sub/function names
    public string ControlsSummary => Controls.Count > 0 ? string.Join(", ", Controls) : "";
    public string MethodsSummary  => Methods.Count > 0 ? string.Join(", ", Methods) : "";
}

// ── Python bytecode (.pyc) ───────────────────────────────────────────────────

public class PycInfo
{
    public string  FilePath        { get; set; } = "";
    public ushort  MagicNumber     { get; set; }
    public string  PythonVersion   { get; set; } = "";
    public uint    Flags           { get; set; }
    public bool    IsHashBased     { get; set; }
    public DateTime SourceTimestamp { get; set; }
    public uint    SourceSize      { get; set; }
    public int     BytecodeOffset  { get; set; }
    public int     BytecodeSize    { get; set; }
    public string  DecompilerUsed  { get; set; } = "";
    public string? PythonExe       { get; set; }
    public string? Error           { get; set; }
    public List<string> Warnings   { get; set; } = [];

    public string SourceTimestampDisplay => SourceTimestamp == default
        ? "N/A" : SourceTimestamp.ToString("yyyy-MM-dd HH:mm:ss UTC");
    public string FlagsDisplay     => $"0x{Flags:X8}";
    public string MagicDisplay     => $"0x{MagicNumber:X4}";
    public string BytecodeSizeDisplay => $"{BytecodeSize:N0} bytes";
}

// ── Python extension module (.pyd) ───────────────────────────────────────────

public class PydInfo
{
    public string  ModuleName            { get; set; } = "";
    public string  InitFunction          { get; set; } = "";
    public bool    HasPyInit             { get; set; }
    public int     PythonMajor           { get; set; }
    public string  PythonVersion         { get; set; } = "";
    public string? PythonRuntimeImport   { get; set; }
    public List<string> PythonApiImports { get; set; } = [];
}

// ── Visual LISP / AutoLISP (.vlx / .fas) ─────────────────────────────────────

public class VlxInfo
{
    public string  FilePath       { get; set; } = "";
    public string  Extension      { get; set; } = "";
    public long    FileSize       { get; set; }
    public string  FormatName     { get; set; } = "";
    public string  MagicBytes     { get; set; } = "";
    public string? VersionWord    { get; set; }
    public string? CompileMode    { get; set; }
    public string? HeaderHex      { get; set; }
    public bool    IsEncrypted    { get; set; }
    public bool    IsTextFas      { get; set; }
    public bool    IsVlxContainer { get; set; }
    public int     BinaryOffset   { get; set; }
    public int     ModuleCount    { get; set; }
    public string? Error          { get; set; }
    public string? DecryptStatus  { get; set; }
    public string? Disassembly    { get; set; }
    public string? DecompiledLisp { get; set; }
    public byte[]? KeyBytes       { get; set; }
    public byte[]? DecryptedData  { get; set; }
    public int     FasVersion     { get; set; }    // 4=FAS4, 3=FAS3, 2=FAS2, 1=FAS, 0=unknown

    // ── Two-stream FAS parsing ────────────────────────────────────────────────
    public byte[]? FuncStreamData { get; set; }    // decrypted function stream bytecode
    public byte[]? ResStreamData  { get; set; }    // decrypted resource stream bytecode
    public int     FuncStreamVars { get; set; }    // function stream var count
    public int     ResStreamVars  { get; set; }    // resource stream var count

    public List<string>          HeaderLines    { get; set; } = [];
    public List<VlxModule>       Modules        { get; set; } = [];
    public List<VlxEmbeddedFile> EmbeddedFiles  { get; set; } = [];
    public List<VlxString>       RawStrings     { get; set; } = [];
    public List<FasFunction>     FasFunctions   { get; set; } = [];
    public List<string>          Commands       { get; set; } = [];
    public List<string>          Functions      { get; set; } = [];
    public List<string>          GlobalVars     { get; set; } = [];
    public List<string>          Symbols        { get; set; } = [];
    public List<string>          StringLiterals { get; set; } = [];

    public string FileSizeDisplay => $"{FileSize:N0} bytes";
    public string KeyDisplay => KeyBytes == null ? "—"
        : string.Join(" ", KeyBytes.Take(16).Select(b => $"{b:X2}"))
          + (KeyBytes.Length > 16 ? "…" : "");
}

public class VlxModule
{
    public int    Index         { get; set; }
    public string Name          { get; set; } = "";
    public int    Offset        { get; set; }
    public int    Size          { get; set; }
    public string? Disassembly      { get; set; }
    public string? DecompiledLisp   { get; set; }
    public List<FasFunction> Functions { get; set; } = [];
    public string OffsetDisplay => $"0x{Offset:X6}";
    public string SizeDisplay   => $"{Size:N0} bytes";
}

public class VlxEmbeddedFile
{
    public string FileType      { get; set; } = "";
    public int    Offset        { get; set; }
    public int    Size          { get; set; }
    public string Content       { get; set; } = "";
    public byte[]? RawData      { get; set; }
    public string OffsetDisplay => $"0x{Offset:X6}";
    public string SizeDisplay   => $"{Size:N0} bytes";
}

public class VlxString
{
    public string Value         { get; set; } = "";
    public int    Offset        { get; set; }
    public string Method        { get; set; } = "";
    public string OffsetDisplay => $"0x{Offset:X6}";
}

/// <summary>
/// Represents a single function extracted from FAS bytecode, including
/// its DEFUN header parameters, local variable names, and reconstructed
/// LISP source (if decompilation succeeded).
/// </summary>
public class FasFunction
{
    public string Name           { get; set; } = "";
    public int    Offset         { get; set; }
    public int    EndOffset      { get; set; }
    public int    LocalVarCount  { get; set; }
    public int    MinArgs        { get; set; }
    public int    MaxArgs        { get; set; }
    public bool   GcFlag         { get; set; }
    public bool   IsQuoted       { get; set; }  // DEFUN-Q vs DEFUN
    public List<string> LocalVarNames { get; set; } = [];
    public string? ReconstructedLisp { get; set; }
    public string OffsetDisplay  => $"0x{Offset:X4}";
}
