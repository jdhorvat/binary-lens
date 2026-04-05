using BinaryLens.Models;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BinaryLens.Export;

/// <summary>
/// Serializes the full AnalysisResult to indented JSON.
/// Binary data (byte[]) fields are excluded to keep output readable.
/// </summary>
public static class JsonExporter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented          = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy   = JsonNamingPolicy.CamelCase,
        Converters             = { new JsonStringEnumConverter() },
    };

    public static string Generate(AnalysisResult result)
    {
        // Project into a clean DTO that omits binary blobs and simplifies dep tree
        var dto = new JsonReport
        {
            FileName        = result.FileName,
            FilePath        = result.FilePath,
            FileSize        = result.FileSize,
            FileSizeHuman   = result.FileSizeHuman,
            IsValidPe       = result.IsValidPe,
            Is64Bit         = result.Is64Bit,
            IsDotNet        = result.IsDotNet,
            IsArx           = result.IsArx,
            Architecture    = result.Architecture,
            FileTypeSummary = result.FileTypeSummary,

            PeInfo = new JsonPeInfo
            {
                MachineType     = result.PeInfo.MachineType,
                Subsystem       = result.PeInfo.Subsystem,
                LinkerVersion   = result.PeInfo.LinkerVersion,
                TimeDateStamp   = result.PeInfo.TimeDateStampDisplay,
                EntryPoint      = result.PeInfo.EntryPoint,
                ImageBase       = result.PeInfo.ImageBase,
                SizeOfImage     = result.PeInfo.SizeOfImage,
                IsExe           = result.PeInfo.IsExe,
                IsDll           = result.PeInfo.IsDll,
                Characteristics = result.PeInfo.Characteristics,
                Sections        = result.PeInfo.Sections.Select(s => new JsonSection
                {
                    Name            = s.Name,
                    VirtualAddress  = s.VirtualAddress,
                    VirtualSize     = s.VirtualSize,
                    RawSize         = s.RawSize,
                    Entropy         = s.Entropy,
                    EntropyNote     = s.EntropyNote,
                    Characteristics = s.Characteristics,
                }).ToList(),
            },

            Imports = result.Imports.Select(i => new JsonImport
            {
                Dll       = i.DllName,
                Function  = i.DisplayName,
                Hint      = i.Hint,
                IsOrdinal = i.IsOrdinal,
            }).ToList(),

            Exports = result.Exports.Select(e => new JsonExport
            {
                Name          = e.DisplayName,
                Rva           = e.RvaAddress,
                Ordinal       = e.Ordinal,
                IsForwarded   = e.IsForwarded,
                ForwardTarget = e.ForwardTarget,
            }).ToList(),

            Strings = result.Strings.Select(s => new JsonString
            {
                Offset   = s.OffsetHex,
                Encoding = s.Encoding,
                Value    = s.Value,
            }).ToList(),

            Resources = result.Resources.Select(r => new JsonResource
            {
                Type     = r.Type,
                Name     = r.Name,
                Language = r.Language,
                Size     = r.Size,
            }).ToList(),

            Dependencies = result.DependencyRoot != null
                ? FlattenDeps(result.DependencyRoot)
                : [],

            ArxInfo  = result.IsArx && result.ArxInfo != null ? MapArx(result.ArxInfo) : null,
            PycInfo  = result.IsPyc && result.PycInfo != null ? MapPyc(result.PycInfo) : null,
            PydInfo  = result.IsPyd && result.PydInfo != null ? MapPyd(result.PydInfo) : null,
            VlxInfo  = result.IsVlx && result.VlxInfo != null ? MapVlx(result.VlxInfo) : null,

            Errors          = result.Errors,
            GeneratedAt     = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
            GeneratedBy     = "BinaryLens",
        };

        return JsonSerializer.Serialize(dto, Options);
    }

    // ── Flatten dependency tree ──────────────────────────────────────────────

    private static List<JsonDependency> FlattenDeps(DependencyNode node)
    {
        var list = new List<JsonDependency>();
        FlattenNode(node, 0, list);
        return list;
    }

    private static void FlattenNode(DependencyNode node, int depth, List<JsonDependency> list)
    {
        list.Add(new JsonDependency
        {
            Name         = node.Name,
            Found        = node.Found,
            IsSystem     = node.IsSystem,
            IsAutocad    = node.IsAutocad,
            ResolvedPath = node.ResolvedPath,
            Depth        = depth,
        });
        foreach (var child in node.Children)
            FlattenNode(child, depth + 1, list);
    }

    // ── Map specialty info ──────────────────────────────────────────────────

    private static JsonArxInfo MapArx(ArxInfo a) => new()
    {
        HasArxEntryPoint  = a.HasArxEntryPoint,
        EntryPointName    = a.EntryPointName,
        IsManagedArx      = a.IsManagedArx,
        DetectedVersion   = a.DetectedAcadVersion,
        AutocadImports    = a.AutocadImports,
        CommandExports    = a.CommandExports,
        AcClassStrings    = a.AcClassStrings,
    };

    private static JsonPycInfo MapPyc(PycInfo p) => new()
    {
        PythonVersion   = p.PythonVersion,
        MagicNumber     = p.MagicDisplay,
        Flags           = p.FlagsDisplay,
        IsHashBased     = p.IsHashBased,
        SourceTimestamp = p.SourceTimestampDisplay,
        SourceSize      = p.SourceSize,
        BytecodeOffset  = p.BytecodeOffset,
        BytecodeSize    = p.BytecodeSize,
    };

    private static JsonPydInfo MapPyd(PydInfo p) => new()
    {
        ModuleName       = p.ModuleName,
        InitFunction     = p.InitFunction,
        HasPyInit        = p.HasPyInit,
        PythonVersion    = p.PythonVersion,
        PythonApiImports = p.PythonApiImports,
    };

    private static JsonVlxInfo MapVlx(VlxInfo v) => new()
    {
        FormatName    = v.FormatName,
        FileSize      = v.FileSize,
        FasVersion    = v.FasVersion,
        IsEncrypted   = v.IsEncrypted,
        CompileMode   = v.CompileMode,
        ModuleCount   = v.ModuleCount,
        FunctionCount = v.FasFunctions.Count,
        Commands      = v.Commands,
        Functions     = v.Functions,
        GlobalVars    = v.GlobalVars,
    };

    // ── DTOs ────────────────────────────────────────────────────────────────

    private class JsonReport
    {
        public string  FileName        { get; set; } = "";
        public string  FilePath        { get; set; } = "";
        public long    FileSize        { get; set; }
        public string  FileSizeHuman   { get; set; } = "";
        public bool    IsValidPe       { get; set; }
        public bool    Is64Bit         { get; set; }
        public bool    IsDotNet        { get; set; }
        public bool    IsArx           { get; set; }
        public string  Architecture    { get; set; } = "";
        public string  FileTypeSummary { get; set; } = "";
        public JsonPeInfo       PeInfo       { get; set; } = new();
        public List<JsonImport>    Imports    { get; set; } = [];
        public List<JsonExport>    Exports    { get; set; } = [];
        public List<JsonString>    Strings    { get; set; } = [];
        public List<JsonResource>  Resources  { get; set; } = [];
        public List<JsonDependency> Dependencies { get; set; } = [];
        public JsonArxInfo?  ArxInfo  { get; set; }
        public JsonPycInfo?  PycInfo  { get; set; }
        public JsonPydInfo?  PydInfo  { get; set; }
        public JsonVlxInfo?  VlxInfo  { get; set; }
        public List<string>  Errors   { get; set; } = [];
        public string GeneratedAt { get; set; } = "";
        public string GeneratedBy { get; set; } = "";
    }

    private class JsonPeInfo
    {
        public string MachineType     { get; set; } = "";
        public string Subsystem       { get; set; } = "";
        public string LinkerVersion   { get; set; } = "";
        public string TimeDateStamp   { get; set; } = "";
        public string EntryPoint      { get; set; } = "";
        public string ImageBase       { get; set; } = "";
        public string SizeOfImage     { get; set; } = "";
        public bool   IsExe           { get; set; }
        public bool   IsDll           { get; set; }
        public List<string>     Characteristics { get; set; } = [];
        public List<JsonSection> Sections       { get; set; } = [];
    }

    private class JsonSection
    {
        public string Name            { get; set; } = "";
        public string VirtualAddress  { get; set; } = "";
        public string VirtualSize     { get; set; } = "";
        public string RawSize         { get; set; } = "";
        public double Entropy         { get; set; }
        public string EntropyNote     { get; set; } = "";
        public string Characteristics { get; set; } = "";
    }

    private class JsonImport
    {
        public string Dll       { get; set; } = "";
        public string Function  { get; set; } = "";
        public string Hint      { get; set; } = "";
        public bool   IsOrdinal { get; set; }
    }

    private class JsonExport
    {
        public string  Name          { get; set; } = "";
        public string  Rva           { get; set; } = "";
        public uint    Ordinal       { get; set; }
        public bool    IsForwarded   { get; set; }
        public string? ForwardTarget { get; set; }
    }

    private class JsonString
    {
        public string Offset   { get; set; } = "";
        public string Encoding { get; set; } = "";
        public string Value    { get; set; } = "";
    }

    private class JsonResource
    {
        public string Type     { get; set; } = "";
        public string Name     { get; set; } = "";
        public string Language { get; set; } = "";
        public long   Size     { get; set; }
    }

    private class JsonDependency
    {
        public string  Name         { get; set; } = "";
        public bool    Found        { get; set; }
        public bool    IsSystem     { get; set; }
        public bool    IsAutocad    { get; set; }
        public string? ResolvedPath { get; set; }
        public int     Depth        { get; set; }
    }

    private class JsonArxInfo
    {
        public bool         HasArxEntryPoint { get; set; }
        public string       EntryPointName   { get; set; } = "";
        public bool         IsManagedArx     { get; set; }
        public string?      DetectedVersion  { get; set; }
        public List<string> AutocadImports   { get; set; } = [];
        public List<string> CommandExports   { get; set; } = [];
        public List<string> AcClassStrings   { get; set; } = [];
    }

    private class JsonPycInfo
    {
        public string PythonVersion   { get; set; } = "";
        public string MagicNumber     { get; set; } = "";
        public string Flags           { get; set; } = "";
        public bool   IsHashBased     { get; set; }
        public string SourceTimestamp  { get; set; } = "";
        public uint   SourceSize      { get; set; }
        public int    BytecodeOffset  { get; set; }
        public int    BytecodeSize    { get; set; }
    }

    private class JsonPydInfo
    {
        public string       ModuleName       { get; set; } = "";
        public string       InitFunction     { get; set; } = "";
        public bool         HasPyInit        { get; set; }
        public string       PythonVersion    { get; set; } = "";
        public List<string> PythonApiImports { get; set; } = [];
    }

    private class JsonVlxInfo
    {
        public string       FormatName     { get; set; } = "";
        public long         FileSize       { get; set; }
        public int          FasVersion     { get; set; }
        public bool         IsEncrypted    { get; set; }
        public string?      CompileMode    { get; set; }
        public int          ModuleCount    { get; set; }
        public int          FunctionCount  { get; set; }
        public List<string> Commands       { get; set; } = [];
        public List<string> Functions      { get; set; } = [];
        public List<string> GlobalVars     { get; set; } = [];
    }
}
