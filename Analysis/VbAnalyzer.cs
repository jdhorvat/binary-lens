using System.Text;
using BinaryLens.Models;

namespace BinaryLens.Analysis;

/// <summary>
/// Detects Visual Basic 5/6 executables and extracts project metadata.
///
/// VB5/6 binaries are identified by:
///   1. Import of MSVBVM50.DLL or MSVBVM60.DLL
///   2. ThunRTMain as the actual entry point (called by the VB runtime)
///   3. A VB header structure at the entry point that contains project info
///
/// P-Code vs Native:
///   - P-Code binaries contain interpreted bytecode; the VB runtime VM executes them
///   - Native-compiled VB6 produces real x86 machine code
///   - Detection: P-Code imports specific opcodes from MSVBVM; native does not
///
/// VB5! Header layout (offsets from "VB5!" signature):
///   +0x00  "VB5!" magic (4 bytes)
///   +0x04  Runtime build (2 bytes)
///   +0x06  Language DLL name (14 bytes, null-padded)
///   +0x14  Backup language DLL (14 bytes)
///   +0x22  Runtime DLL version (2 bytes)
///   +0x24  LCID1 (4 bytes)
///   +0x28  LCID2 (4 bytes)
///   +0x2C  aSubMain (4 bytes, VA)
///   +0x30  aProjectInfo (4 bytes, VA)
///   +0x34  fMDLIntCtls (4 bytes)
///   +0x38  fMDLIntCtls2 (4 bytes)
///   +0x3C  ThreadFlags (4 bytes)
///   +0x40  ThreadCount (4 bytes)
///   +0x44  FormCount (2 bytes)
///   +0x46  ExternalCount (2 bytes)
///   +0x48  ThunkCount (4 bytes)
///   +0x4C  aGUITable (4 bytes, VA)
///   +0x50  aExternalTable (4 bytes, VA)
///   +0x54  aComRegData (4 bytes, VA)
///   +0x58  oProjectExeName (4 bytes, offset from start of VB header)
///   +0x5C  oProjectTitle (4 bytes, offset from start of VB header)
///   +0x60  oHelpFile (4 bytes, offset from start of VB header)
///   +0x64  oProjectName (4 bytes, offset from start of VB header)
/// </summary>
public static class VbAnalyzer
{
    // ── VB runtime DLLs ─────────────────────────────────────────────────────

    private static readonly Dictionary<string, int> VbRuntimes =
        new(StringComparer.OrdinalIgnoreCase)
    {
        { "MSVBVM50.DLL", 5 },
        { "MSVBVM60.DLL", 6 },
    };

    // ── VB header magic ─────────────────────────────────────────────────────

    private static readonly byte[] VbHeaderMagic = { 0x56, 0x42, 0x35, 0x21 };  // "VB5!"

    // ── Well-known COM / ActiveX controls ───────────────────────────────────

    private static readonly Dictionary<string, string> KnownOcxNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        { "MSCOMCTL.OCX",  "Microsoft Common Controls 6.0" },
        { "MSCOMCT2.OCX",  "Microsoft Common Controls-2 6.0" },
        { "MSWINSCK.OCX",  "Microsoft Winsock Control" },
        { "MSINET.OCX",    "Microsoft Internet Transfer" },
        { "RICHTX32.OCX",  "Microsoft Rich Textbox" },
        { "COMDLG32.OCX",  "Microsoft Common Dialog" },
        { "TABCTL32.OCX",  "Microsoft Tabbed Dialog" },
        { "MSHFLXGD.OCX",  "Microsoft Hierarchical FlexGrid" },
        { "MSFLXGRD.OCX",  "Microsoft FlexGrid" },
        { "MSCAL.OCX",     "Microsoft Calendar" },
        { "MSDATGRD.OCX",  "Microsoft DataGrid" },
        { "MSDATLST.OCX",  "Microsoft DataList" },
        { "MSDATREP.OCX",  "Microsoft DataRepeater" },
        { "MSADODC.OCX",   "Microsoft ADO Data Control" },
        { "DBGRID32.OCX",  "Apex Data Bound Grid" },
        { "DBLIST32.OCX",  "Apex Data Bound ListBox" },
        { "COMCTL32.OCX",  "Microsoft Common Controls 5.0" },
        { "SYSINFO.OCX",   "Microsoft SysInfo" },
        { "MSCOMM32.OCX",  "Microsoft Comm Control" },
        { "PICCLP32.OCX",  "Microsoft PictureClip" },
        { "MSMAPI32.OCX",  "Microsoft MAPI Controls" },
        { "CRYSTL32.OCX",  "Crystal Report Control" },
    };

    // ── VB control type names (for form control detection) ──────────────────

    private static readonly HashSet<string> VbControlTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "CommandButton", "TextBox", "Label", "ListBox", "ComboBox",
        "CheckBox", "OptionButton", "Frame", "PictureBox", "Image",
        "Timer", "DriveListBox", "DirListBox", "FileListBox",
        "HScrollBar", "VScrollBar", "Shape", "Line", "Data",
        "OLE", "Menu", "CommonDialog", "StatusBar", "Toolbar",
        "TreeView", "ListView", "TabStrip", "ProgressBar", "Slider",
        "RichTextBox", "MSFlexGrid", "MSHFlexGrid", "Winsock",
        "WebBrowser", "Animation", "ImageList", "UpDown",
        "MonthView", "DTPicker", "CoolBar",
    };

    // ── Public entry point ──────────────────────────────────────────────────

    public static void Analyze(AnalysisResult result, byte[] fileData)
    {
        if (!result.IsValidPe) return;

        var info = new VbInfo();

        // 1. Check for VB runtime import
        DetectRuntime(result, info);
        if (info.VbVersion == 0) return;   // Not a VB binary

        // 2. Check for ThunRTMain entry
        DetectEntryPoint(result, info);

        // 3. Detect P-Code vs Native
        DetectPCode(result, info);

        // 4. Scan for VB header magic "VB5!" and parse structured header
        int vbHeaderPos = FindPattern(fileData, VbHeaderMagic, 0, Math.Min(fileData.Length, 0x10000));
        if (vbHeaderPos >= 0)
        {
            info.VbHeaderOffset = $"0x{vbHeaderPos:X4}";
            ParseVbHeader(fileData, vbHeaderPos, info, result);
        }

        // 5. Detect objects from strings (fallback if header parsing found nothing)
        if (info.Objects.Count == 0)
            DetectObjects(result, fileData, info);

        // 6. Scan imports for COM/ActiveX controls
        DetectComImports(result, info);

        // 7. Scan strings for Declare Function API calls
        DetectApiDeclares(result, info);

        // 8. Scan full binary for form controls
        DetectFormControls(fileData, 0, fileData.Length, info);

        // 9. Scan full binary for method names (event handlers + procedure tables)
        DetectMethodNames(fileData, 0, fileData.Length, info);

        // 10. Scan for procedure name tables near objects (VB6 stores them clustered)
        ScanProcedureNameTables(fileData, info);

        result.IsVb5 = true;
        result.VbInfo = info;
    }

    // ── Runtime detection ────────────────────────────────────────────────────

    private static void DetectRuntime(AnalysisResult result, VbInfo info)
    {
        foreach (var imp in result.Imports)
        {
            if (VbRuntimes.TryGetValue(imp.DllName, out int ver))
            {
                info.RuntimeDll = imp.DllName.ToUpperInvariant();
                info.VbVersion = ver;
                break;
            }
        }
    }

    private static void DetectEntryPoint(AnalysisResult result, VbInfo info)
    {
        foreach (var imp in result.Imports)
        {
            string dll = imp.DllName.ToUpperInvariant();
            if (!dll.Contains("MSVBVM")) continue;

            if (imp.FunctionName.Contains("ThunRTMain", StringComparison.OrdinalIgnoreCase))
            {
                info.EntryPoint = "ThunRTMain";
                break;
            }
        }

        if (string.IsNullOrEmpty(info.EntryPoint))
        {
            foreach (var exp in result.Exports)
            {
                if (exp.Name.Contains("ThunRTMain", StringComparison.OrdinalIgnoreCase))
                {
                    info.EntryPoint = exp.Name;
                    break;
                }
            }
        }
    }

    // ── P-Code detection ────────────────────────────────────────────────────

    private static void DetectPCode(AnalysisResult result, VbInfo info)
    {
        var pcodeIndicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "EbExecuteLine", "ProcCallEngine", "EbLoadRunTime",
            "ThunRTMain", "EbMode", "EbGetExecutingProc",
        };

        int pcodeHits = 0;
        int totalVbImports = 0;

        foreach (var imp in result.Imports)
        {
            if (!imp.DllName.Contains("MSVBVM", StringComparison.OrdinalIgnoreCase))
                continue;
            totalVbImports++;
            if (pcodeIndicators.Contains(imp.FunctionName))
                pcodeHits++;
        }

        info.IsPCode = pcodeHits >= 2 || (totalVbImports > 0 && totalVbImports <= 15);
    }

    // ── VB header parsing (structured) ──────────────────────────────────────

    private static void ParseVbHeader(byte[] data, int offset, VbInfo info, AnalysisResult result)
    {
        try
        {
            // Need at least 0x68 bytes for the fixed header fields
            if (offset + 0x68 > data.Length) return;

            // ── Read string offsets from fixed header fields ──────────────
            // These are offsets from the start of the VB header to
            // null-terminated ASCII strings, NOT virtual addresses.
            uint oExeName   = ReadUInt32(data, offset + 0x58);
            uint oTitle     = ReadUInt32(data, offset + 0x5C);
            uint oHelpFile  = ReadUInt32(data, offset + 0x60);
            uint oName      = ReadUInt32(data, offset + 0x64);

            if (oName > 0 && oName < 0x10000)
                info.ProjectName = ReadNullTermString(data, offset + (int)oName, 128);
            if (oTitle > 0 && oTitle < 0x10000)
                info.ProjectDescription = ReadNullTermString(data, offset + (int)oTitle, 256);
            if (oExeName > 0 && oExeName < 0x10000)
                info.ProjectExeName = ReadNullTermString(data, offset + (int)oExeName, 128);
            if (oHelpFile > 0 && oHelpFile < 0x10000)
                info.ProjectHelpFile = ReadNullTermString(data, offset + (int)oHelpFile, 256);

            // ── Form count from header ───────────────────────────────────
            ushort formCount = ReadUInt16(data, offset + 0x44);

            // ── Chase ProjectInfo pointer (VA) → Object Table ────────────
            uint vaProjectInfo = ReadUInt32(data, offset + 0x30);
            if (vaProjectInfo != 0)
            {
                int foProjectInfo = RvaToFileOffset(vaProjectInfo, result);
                if (foProjectInfo >= 0 && foProjectInfo + 0x10 < data.Length)
                {
                    info.ProjectInfoOffset = $"0x{foProjectInfo:X4}";

                    // ProjectInfo structure:
                    //   +0x00: Version (4)
                    //   +0x04: aObjectTable (4, VA)
                    uint vaObjectTable = ReadUInt32(data, foProjectInfo + 0x04);
                    if (vaObjectTable != 0)
                    {
                        ParseObjectTableFromVA(data, vaObjectTable, result, info, formCount);
                    }
                }
            }

            // ── Fallback: if pointer chasing didn't find objects, ────────
            //    scan the header region for type library refs
            int regionEnd = Math.Min(offset + 8192, data.Length);
            var allStrings = ExtractPrintableStrings(data, offset + 4, regionEnd, minLen: 3, maxLen: 128);

            foreach (var s in allStrings)
            {
                if ((s.StartsWith("{") && s.EndsWith("}") && s.Length > 30) ||
                    s.StartsWith("*\\G{") || s.StartsWith("*\\H{"))
                {
                    if (!info.References.Contains(s))
                        info.References.Add(s);
                }
            }
        }
        catch
        {
            info.Error = "Failed to parse VB header structure";
        }
    }

    /// <summary>
    /// Parses the VB Object Table from a virtual address, chasing pointers
    /// to extract each object's name and type.
    ///
    /// Object Table layout:
    ///   +0x00: aHeapLink (4)
    ///   +0x04: aExecProj (4, VA)
    ///   +0x08: aProjectInfo2 (4, VA)
    ///   +0x0C: reserved (4)
    ///   +0x10: reserved/flags (4)
    ///   +0x14: nObjects (2) — count of objects
    ///   +0x16: padding (2)
    ///   +0x18: aObjectArray (4, VA) — pointer to first PUBLIC_OBJECT_DESCRIPTOR
    ///
    /// PUBLIC_OBJECT_DESCRIPTOR (0x30 bytes each):
    ///   +0x00: aObjectInfo (4, VA)
    ///   +0x04: reserved (4)
    ///   +0x08: aPublicBytes (4, VA)
    ///   +0x0C: aStaticBytes (4, VA)
    ///   +0x10: aModulePublic (4, VA)
    ///   +0x14: aModuleStatic (4, VA)
    ///   +0x18: aObjectName (4, VA) — pointer to object name string
    ///   +0x1C: nMethods (4)
    ///   +0x20: aMethodNames (4, VA) — pointer to method name table
    ///   +0x24: oStaticVars (4)
    ///   +0x28: fObjectType (4) — type flags
    ///   +0x2C: reserved (4)
    /// </summary>
    private static void ParseObjectTableFromVA(byte[] data, uint vaTable,
        AnalysisResult result, VbInfo info, ushort headerFormCount)
    {
        int foTable = RvaToFileOffset(vaTable, result);
        if (foTable < 0 || foTable + 0x1C > data.Length) return;

        try
        {
            ushort nObjects = ReadUInt16(data, foTable + 0x14);
            if (nObjects == 0 || nObjects > 500) return;  // sanity check

            uint vaArray = ReadUInt32(data, foTable + 0x18);
            int foArray = RvaToFileOffset(vaArray, result);
            if (foArray < 0) return;

            int descriptorSize = 0x30;  // PUBLIC_OBJECT_DESCRIPTOR is 0x30 bytes
            for (int i = 0; i < nObjects; i++)
            {
                int descOffset = foArray + (i * descriptorSize);
                if (descOffset + descriptorSize > data.Length) break;

                // Read object name pointer
                uint vaName = ReadUInt32(data, descOffset + 0x18);
                int foName = RvaToFileOffset(vaName, result);
                string objName = "";
                if (foName >= 0 && foName < data.Length)
                    objName = ReadNullTermString(data, foName, 80);

                if (string.IsNullOrWhiteSpace(objName)) continue;

                // Read method count and method names pointer
                uint nMethods = ReadUInt32(data, descOffset + 0x1C);
                uint vaMethodNames = ReadUInt32(data, descOffset + 0x20);

                // Read type flags
                uint typeFlags = ReadUInt32(data, descOffset + 0x28);
                string objectType = ClassifyObjectType(typeFlags, objName);

                var obj = new VbObject
                {
                    Index = i,
                    Name = objName,
                    ObjectType = objectType,
                    MethodCount = (int)Math.Min(nMethods, 9999),
                };

                // Chase method name table pointer
                if (nMethods > 0 && nMethods < 5000 && vaMethodNames != 0)
                {
                    int foMethods = RvaToFileOffset(vaMethodNames, result);
                    if (foMethods >= 0)
                    {
                        ParseMethodNameTable(data, foMethods, (int)nMethods, obj);
                    }
                }

                // Also try to read from the ObjectInfo structure for more detail
                uint vaObjInfo = ReadUInt32(data, descOffset + 0x00);
                if (vaObjInfo != 0)
                {
                    int foObjInfo = RvaToFileOffset(vaObjInfo, result);
                    if (foObjInfo >= 0 && foObjInfo + 0x20 < data.Length)
                    {
                        ParseObjectInfo(data, foObjInfo, obj, result);
                    }
                }

                info.Objects.Add(obj);
            }
        }
        catch
        {
            // Silently continue — partial results are still useful
        }
    }

    /// <summary>
    /// Parses the method name table. VB6 stores method names as an array
    /// of VA pointers, each pointing to a null-terminated ASCII string.
    /// Alternatively, some versions store the names as a BSTR-like table
    /// with length-prefixed entries. We try both approaches.
    /// </summary>
    private static void ParseMethodNameTable(byte[] data, int tableOffset, int count, VbObject obj)
    {
        // Approach 1: Array of VA pointers (each 4 bytes)
        // This is the most common format.
        // Note: these are typically VA pointers but in some builds they are
        // direct file offsets or offsets from the table. We try to use them
        // as offsets from the table first, then as raw values.

        // First, try reading as consecutive null-terminated strings at the table offset
        // (some VB6 binaries store names inline rather than as pointers)
        var inlineNames = TryReadInlineStringTable(data, tableOffset, count);
        if (inlineNames.Count > 0)
        {
            foreach (var name in inlineNames)
            {
                if (!obj.Methods.Contains(name) && obj.Methods.Count < 200)
                    obj.Methods.Add(name);
            }
            return;
        }

        // Approach 2: Read as array of 4-byte values and try to resolve them
        for (int i = 0; i < count && i < 200; i++)
        {
            int ptrOffset = tableOffset + (i * 4);
            if (ptrOffset + 4 > data.Length) break;

            uint val = ReadUInt32(data, ptrOffset);

            // Try as direct file offset first
            if (val > 0 && val < (uint)data.Length)
            {
                string name = ReadNullTermString(data, (int)val, 80);
                if (IsValidVbIdentifier(name) && !obj.Methods.Contains(name))
                {
                    obj.Methods.Add(name);
                    continue;
                }
            }
        }
    }

    /// <summary>
    /// Tries to read consecutive null-terminated strings starting at offset.
    /// Returns names found if they look like VB identifiers.
    /// </summary>
    private static List<string> TryReadInlineStringTable(byte[] data, int offset, int maxCount)
    {
        var result = new List<string>();
        int pos = offset;

        for (int i = 0; i < maxCount && pos < data.Length; i++)
        {
            string s = ReadNullTermString(data, pos, 80);
            if (string.IsNullOrEmpty(s) || !IsValidVbIdentifier(s))
                break;

            result.Add(s);
            pos += s.Length + 1; // skip past null terminator

            // Skip alignment padding (VB6 sometimes 4-byte aligns entries)
            while (pos < data.Length && data[pos] == 0) pos++;
        }

        // Only accept if we found a reasonable cluster
        return result.Count >= 2 ? result : new List<string>();
    }

    /// <summary>
    /// Parses the ObjectInfo structure for additional metadata.
    /// ObjectInfo can contain event count, control info pointers, etc.
    /// </summary>
    private static void ParseObjectInfo(byte[] data, int offset, VbObject obj, AnalysisResult result)
    {
        if (offset + 0x38 > data.Length) return;

        try
        {
            // ObjectInfo layout varies but commonly:
            //   +0x08: nControls (2) — number of controls on a form
            //   +0x20: aControls (4, VA) — pointer to control descriptors
            ushort nControls = ReadUInt16(data, offset + 0x08);
            if (nControls > 0 && nControls < 500)
            {
                // Try to read from the control descriptor table
                uint vaControls = ReadUInt32(data, offset + 0x20);
                if (vaControls != 0)
                {
                    int foControls = RvaToFileOffset(vaControls, result);
                    if (foControls >= 0)
                        ParseControlDescriptors(data, foControls, nControls, obj, result);
                }
            }

            // Event count at +0x0A
            ushort nEvents = ReadUInt16(data, offset + 0x0A);
            obj.EventCount = Math.Min((int)nEvents, 9999);
        }
        catch { /* partial results OK */ }
    }

    /// <summary>
    /// Reads VB6 control descriptors. Each control entry typically contains:
    ///   - Type CLSID or type name pointer
    ///   - Instance name pointer
    ///   - Various property pointers
    /// Layout varies, so we scan for string pointers in the region.
    /// </summary>
    private static void ParseControlDescriptors(byte[] data, int offset, int count,
        VbObject obj, AnalysisResult result)
    {
        // VB6 control descriptor size is typically 0x28 bytes
        // We scan each descriptor's pointer-like fields for string references
        int entrySize = 0x28;
        for (int i = 0; i < count && i < 200; i++)
        {
            int entryOff = offset + (i * entrySize);
            if (entryOff + entrySize > data.Length) break;

            // Scan each 4-byte field in the descriptor for string pointers
            string? controlName = null;
            string? controlType = null;

            for (int f = 0; f < entrySize; f += 4)
            {
                uint va = ReadUInt32(data, entryOff + f);
                int fo = RvaToFileOffset(va, result);
                if (fo < 0 || fo >= data.Length) continue;

                string s = ReadNullTermString(data, fo, 60);
                if (string.IsNullOrEmpty(s)) continue;

                if (VbControlTypes.Contains(s))
                    controlType = s;
                else if (IsValidVbIdentifier(s) && s.Length >= 2 && s.Length <= 40)
                    controlName ??= s; // first valid identifier is likely the name
            }

            if (!string.IsNullOrEmpty(controlName))
            {
                string entry = controlType != null
                    ? $"{controlName} ({controlType})"
                    : controlName;
                if (!obj.Controls.Contains(entry))
                    obj.Controls.Add(entry);
            }
        }
    }

    /// <summary>
    /// Classifies an object type from its flag field.
    /// VB6 type flags:
    ///   0x00000001 = HasOptionalInfo
    ///   0x00000002 = Form/UserDocument
    ///   0x00000008 = UserControl
    ///   0x00000010 = Class
    ///   0x00000080 = Designer
    ///   0x00000000 (no flags) = Module
    /// Falls back to name-based heuristics.
    /// </summary>
    private static string ClassifyObjectType(uint flags, string name)
    {
        if ((flags & 0x02) != 0) return "Form";
        if ((flags & 0x08) != 0) return "UserControl";
        if ((flags & 0x10) != 0) return "Class";
        if ((flags & 0x80) != 0) return "Designer";

        // Fallback to name patterns
        string lower = name.ToLowerInvariant();
        if (lower.StartsWith("frm") || lower.StartsWith("form")) return "Form";
        if (lower.StartsWith("cls") || lower.StartsWith("class")) return "Class";
        if (lower.StartsWith("mod") || lower.StartsWith("bas")) return "Module";
        if (lower.StartsWith("uc") || lower.StartsWith("ctl")) return "UserControl";

        return "Module"; // default
    }

    // ── Procedure name table scanning ───────────────────────────────────────

    /// <summary>
    /// Scans the binary for clusters of consecutive VB-style identifier strings
    /// that likely represent procedure (Sub/Function) name tables.
    /// VB6 stores procedure metadata in structured tables where names appear
    /// as consecutive null-terminated ASCII strings.
    /// </summary>
    private static void ScanProcedureNameTables(byte[] data, VbInfo info)
    {
        // Build a set of already-known names to avoid duplicates
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var obj in info.Objects)
        {
            known.Add(obj.Name);
            foreach (var m in obj.Methods) known.Add(m);
            foreach (var c in obj.Controls) known.Add(c);
        }

        // Scan the binary for clusters of identifier-like strings.
        // A "cluster" is 3+ consecutive null-terminated strings that look like
        // VB identifiers, separated only by null bytes (alignment padding).
        var positioned = ExtractPositionedStrings(data, 0, data.Length, minLen: 3, maxLen: 60);

        // Find clusters: groups of 3+ consecutive strings within small gaps
        for (int i = 0; i < positioned.Count; i++)
        {
            var cluster = new List<(int Pos, string Value)>();
            cluster.Add(positioned[i]);

            for (int j = i + 1; j < positioned.Count; j++)
            {
                int gap = positioned[j].Pos - (positioned[j - 1].Pos + positioned[j - 1].Value.Length);
                // Strings in a VB table are separated by 1-8 null bytes
                if (gap < 0 || gap > 16) break;

                if (!IsValidVbIdentifier(positioned[j].Value)) break;
                cluster.Add(positioned[j]);
            }

            if (cluster.Count < 3) continue;

            // Check if this cluster looks like procedure names
            // (not file paths, not registry keys, not random text)
            int identCount = 0;
            foreach (var (_, val) in cluster)
            {
                if (IsValidVbIdentifier(val) && !val.Contains('.') &&
                    !val.Contains('\\') && !val.Contains('/') &&
                    !val.Contains(' ') && val.Length <= 40)
                    identCount++;
            }

            // Need at least 75% valid identifiers
            if (identCount < cluster.Count * 0.75) continue;

            // Associate with the nearest object by scanning backwards for known names
            VbObject? targetObj = FindNearestObject(data, cluster[0].Pos, info);

            foreach (var (_, val) in cluster)
            {
                if (known.Contains(val)) continue;
                if (!IsValidVbIdentifier(val)) continue;

                known.Add(val);

                if (targetObj != null && !targetObj.Methods.Contains(val) && targetObj.Methods.Count < 200)
                    targetObj.Methods.Add(val);
            }

            // Skip past the cluster
            i += cluster.Count - 1;
        }
    }

    /// <summary>
    /// Finds the VB object whose name appears nearest to (before) the given file offset.
    /// </summary>
    private static VbObject? FindNearestObject(byte[] data, int offset, VbInfo info)
    {
        VbObject? best = null;
        int bestDist = int.MaxValue;

        foreach (var obj in info.Objects)
        {
            // Search backwards from the offset for the object name
            byte[] nameBytes = Encoding.ASCII.GetBytes(obj.Name);
            int searchStart = Math.Max(0, offset - 0x2000);
            int pos = FindPattern(data, nameBytes, searchStart, offset);
            if (pos >= 0)
            {
                int dist = offset - pos;
                if (dist < bestDist)
                {
                    bestDist = dist;
                    best = obj;
                }
            }
        }

        return best ?? info.Objects.FirstOrDefault();
    }

    // ── Form control detection (string-based fallback) ──────────────────────

    private static void DetectFormControls(byte[] data, int start, int end, VbInfo info)
    {
        var allStrings = ExtractPositionedStrings(data, start, end, minLen: 3, maxLen: 60);

        for (int i = 0; i < allStrings.Count - 1; i++)
        {
            var (pos, typeName) = allStrings[i];
            if (!VbControlTypes.Contains(typeName)) continue;

            for (int j = i + 1; j < Math.Min(i + 5, allStrings.Count); j++)
            {
                var (pos2, ctrlName) = allStrings[j];
                if (pos2 - pos > 300) break;

                if (ctrlName.Length >= 2 && ctrlName.Length <= 40 &&
                    char.IsLetter(ctrlName[0]) && !ctrlName.Contains(' ') &&
                    !VbControlTypes.Contains(ctrlName))
                {
                    string entry = $"{ctrlName} ({typeName})";

                    var formObj = info.Objects.FirstOrDefault(o =>
                        o.ObjectType == "Form" || o.ObjectType == "UserControl");
                    if (formObj != null && !formObj.Controls.Contains(entry))
                        formObj.Controls.Add(entry);
                    break;
                }
            }
        }
    }

    // ── Method name detection (event handler patterns) ──────────────────────

    private static void DetectMethodNames(byte[] data, int start, int end, VbInfo info)
    {
        var strings = ExtractPrintableStrings(data, start, Math.Min(end, data.Length), minLen: 4, maxLen: 60);

        var eventPattern = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "_Click", "_DblClick", "_Load", "_Unload", "_Initialize",
            "_Terminate", "_Resize", "_Paint", "_Change", "_GotFocus",
            "_LostFocus", "_KeyPress", "_KeyDown", "_KeyUp",
            "_MouseDown", "_MouseUp", "_MouseMove", "_Timer",
            "_Activate", "_Deactivate", "_QueryUnload",
            "_Scroll", "_ItemClick", "_Validate",
            // Service/non-GUI patterns
            "_Start", "_Stop", "_Pause", "_Continue",
            "_Main", "_Execute", "_Process", "_Run",
        };

        foreach (var s in strings)
        {
            foreach (var evt in eventPattern)
            {
                if (s.EndsWith(evt, StringComparison.OrdinalIgnoreCase) && s.Length > evt.Length)
                {
                    string ctrlPart = s[..^evt.Length];
                    if (ctrlPart.Length >= 1 && char.IsLetter(ctrlPart[0]) && !ctrlPart.Contains(' '))
                    {
                        var obj = info.Objects.FirstOrDefault(o =>
                            o.Name.Equals(ctrlPart, StringComparison.OrdinalIgnoreCase) ||
                            o.ObjectType == "Form");
                        if (obj != null && !obj.Methods.Contains(s) && obj.Methods.Count < 200)
                            obj.Methods.Add(s);
                        break;
                    }
                }
            }

            // Also detect Sub/Function-style names: Public/Private Sub/Function markers
            // VB6 sometimes stores "Sub Main" / "Function GetSetting" as partial strings
            if (s.StartsWith("Sub ", StringComparison.OrdinalIgnoreCase) ||
                s.StartsWith("Function ", StringComparison.OrdinalIgnoreCase))
            {
                string funcName = s.Contains(' ') ? s.Split(' ', 2)[1] : s;
                // Strip trailing parentheses
                int paren = funcName.IndexOf('(');
                if (paren > 0) funcName = funcName[..paren];

                if (IsValidVbIdentifier(funcName))
                {
                    var obj = info.Objects.FirstOrDefault();
                    if (obj != null && !obj.Methods.Contains(funcName) && obj.Methods.Count < 200)
                        obj.Methods.Add(funcName);
                }
            }
        }
    }

    // ── COM / ActiveX detection ─────────────────────────────────────────────

    private static void DetectComImports(AnalysisResult result, VbInfo info)
    {
        foreach (var imp in result.Imports)
        {
            if (KnownOcxNames.TryGetValue(imp.DllName, out string? friendlyName))
            {
                string entry = $"{friendlyName} ({imp.DllName})";
                if (!info.ComImports.Contains(entry))
                    info.ComImports.Add(entry);
            }
        }

        foreach (var s in result.Strings)
        {
            if (s.Value.EndsWith(".OCX", StringComparison.OrdinalIgnoreCase) &&
                KnownOcxNames.TryGetValue(s.Value, out string? name))
            {
                string entry = $"{name} ({s.Value})";
                if (!info.ComImports.Contains(entry))
                    info.ComImports.Add(entry);
            }
        }
    }

    // ── API Declare detection ───────────────────────────────────────────────

    private static void DetectApiDeclares(AnalysisResult result, VbInfo info)
    {
        var winApiDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "kernel32", "user32", "gdi32", "advapi32", "shell32",
            "ws2_32", "wininet", "urlmon", "ole32", "oleaut32",
            "ntdll", "msvcrt", "shlwapi", "winmm", "comdlg32",
        };

        foreach (var s in result.Strings)
        {
            string val = s.Value.Trim();
            foreach (var dll in winApiDlls)
            {
                if (val.Equals(dll, StringComparison.OrdinalIgnoreCase) ||
                    val.Equals(dll + ".dll", StringComparison.OrdinalIgnoreCase))
                {
                    if (!info.ApiDeclares.Contains(val) && info.ApiDeclares.Count < 200)
                        info.ApiDeclares.Add(val);
                }
            }
        }
    }

    // ── Object detection (string-based fallback) ────────────────────────────

    private static void DetectObjects(AnalysisResult result, byte[] data, VbInfo info)
    {
        var objectStrings = new HashSet<string>();

        foreach (var s in result.Strings)
        {
            string val = s.Value.Trim();

            if (val.StartsWith("frm", StringComparison.OrdinalIgnoreCase) && val.Length <= 40 &&
                !val.Contains(' ') && !val.Contains('.'))
                objectStrings.Add("Form:" + val);
            else if ((val.StartsWith("mod", StringComparison.OrdinalIgnoreCase) ||
                      val.StartsWith("bas", StringComparison.OrdinalIgnoreCase)) && val.Length <= 40 &&
                     !val.Contains(' ') && !val.Contains('.'))
                objectStrings.Add("Module:" + val);
            else if (val.StartsWith("cls", StringComparison.OrdinalIgnoreCase) && val.Length <= 40 &&
                     !val.Contains(' ') && !val.Contains('.'))
                objectStrings.Add("Class:" + val);
        }

        int idx = 0;
        foreach (var entry in objectStrings.OrderBy(e => e))
        {
            var parts = entry.Split(':', 2);
            info.Objects.Add(new VbObject
            {
                Index = idx++,
                Name = parts[1],
                ObjectType = parts[0],
            });
        }

        // Also detect from .frm / .bas / .cls file name strings
        foreach (var s in result.Strings)
        {
            string val = s.Value.Trim();
            string? ext = null;
            string? objType = null;

            if (val.EndsWith(".frm", StringComparison.OrdinalIgnoreCase)) { ext = ".frm"; objType = "Form"; }
            else if (val.EndsWith(".bas", StringComparison.OrdinalIgnoreCase)) { ext = ".bas"; objType = "Module"; }
            else if (val.EndsWith(".cls", StringComparison.OrdinalIgnoreCase)) { ext = ".cls"; objType = "Class"; }

            if (ext != null && objType != null)
            {
                string name = System.IO.Path.GetFileNameWithoutExtension(val);
                if (!info.Objects.Any(o => o.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    info.Objects.Add(new VbObject
                    {
                        Index = idx++,
                        Name = name,
                        ObjectType = objType,
                    });
                }
            }
        }
    }

    // ── RVA / VA → file offset conversion ───────────────────────────────────

    /// <summary>
    /// Converts a virtual address to a file offset using PE section headers.
    /// Uses the actual image base from PE optional header.
    /// Returns -1 if conversion fails.
    /// </summary>
    private static int RvaToFileOffset(uint va, AnalysisResult result)
    {
        if (va == 0) return -1;

        // Use actual image base from PE header, fall back to common defaults
        ulong actualBase = result.PeInfo.RawImageBase;
        var imageBases = new List<ulong>();
        if (actualBase != 0) imageBases.Add(actualBase);
        imageBases.AddRange(new ulong[] { 0x00400000, 0x10000000, 0x01000000, 0 });

        foreach (ulong imageBase in imageBases)
        {
            if (va <= imageBase) continue;
            uint rva = (uint)(va - imageBase);

            foreach (var sec in result.PeInfo.Sections)
            {
                if (rva >= sec.RawVirtualAddress &&
                    rva < sec.RawVirtualAddress + Math.Max(sec.RawVirtualSize, sec.RawSizeOfData))
                {
                    uint offset = sec.RawPointerToData + (rva - sec.RawVirtualAddress);
                    return (int)offset;
                }
            }
        }

        // Also try treating va as a raw RVA (no image base subtraction)
        foreach (var sec in result.PeInfo.Sections)
        {
            if (va >= sec.RawVirtualAddress &&
                va < sec.RawVirtualAddress + Math.Max(sec.RawVirtualSize, sec.RawSizeOfData))
            {
                uint offset = sec.RawPointerToData + (va - sec.RawVirtualAddress);
                return (int)offset;
            }
        }

        return -1;
    }

    // ── Utility methods ─────────────────────────────────────────────────────

    private static bool IsValidVbIdentifier(string s)
    {
        if (string.IsNullOrEmpty(s) || s.Length < 2 || s.Length > 60)
            return false;
        if (!char.IsLetter(s[0]) && s[0] != '_')
            return false;
        foreach (char c in s)
        {
            if (!char.IsLetterOrDigit(c) && c != '_')
                return false;
        }
        // Reject all-uppercase short strings that look like constants or noise
        if (s.Length <= 3 && s == s.ToUpperInvariant())
            return false;
        return true;
    }

    private static uint ReadUInt32(byte[] data, int offset)
    {
        if (offset + 4 > data.Length) return 0;
        return BitConverter.ToUInt32(data, offset);
    }

    private static ushort ReadUInt16(byte[] data, int offset)
    {
        if (offset + 2 > data.Length) return 0;
        return BitConverter.ToUInt16(data, offset);
    }

    private static string ReadNullTermString(byte[] data, int offset, int maxLen)
    {
        if (offset < 0 || offset >= data.Length) return "";
        var sb = new StringBuilder();
        for (int i = offset; i < data.Length && sb.Length < maxLen; i++)
        {
            byte b = data[i];
            if (b == 0) break;
            if (b >= 0x20 && b < 0x7F)
                sb.Append((char)b);
            else
                break; // non-printable means we hit garbage
        }
        return sb.ToString();
    }

    private static int FindPattern(byte[] data, byte[] pattern, int start, int end)
    {
        int limit = Math.Min(end, data.Length) - pattern.Length;
        for (int i = start; i <= limit; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    private static List<string> ExtractPrintableStrings(byte[] data, int start, int end, int minLen, int maxLen)
    {
        var results = new List<string>();
        var sb = new StringBuilder();

        for (int i = start; i < end && i < data.Length; i++)
        {
            byte b = data[i];
            if (b >= 0x20 && b < 0x7F)
            {
                sb.Append((char)b);
                if (sb.Length > maxLen) sb.Clear();
            }
            else
            {
                if (sb.Length >= minLen)
                    results.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= minLen)
            results.Add(sb.ToString());

        return results;
    }

    private static List<(int Pos, string Value)> ExtractPositionedStrings(
        byte[] data, int start, int end, int minLen, int maxLen)
    {
        var results = new List<(int, string)>();
        var sb = new StringBuilder();
        int strStart = start;

        for (int i = start; i < end && i < data.Length; i++)
        {
            byte b = data[i];
            if (b >= 0x20 && b < 0x7F)
            {
                if (sb.Length == 0) strStart = i;
                sb.Append((char)b);
                if (sb.Length > maxLen) sb.Clear();
            }
            else
            {
                if (sb.Length >= minLen)
                    results.Add((strStart, sb.ToString()));
                sb.Clear();
            }
        }
        if (sb.Length >= minLen)
            results.Add((strStart, sb.ToString()));

        return results;
    }
}
