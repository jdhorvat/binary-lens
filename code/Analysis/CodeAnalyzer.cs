using System.IO;
using BinaryLens.Models;
using Gee.External.Capstone;
using Gee.External.Capstone.X86;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;

namespace BinaryLens.Analysis;

/// <summary>
/// Decompiles .NET assemblies to C# source using ICSharpCode.Decompiler,
/// and disassembles native x86/x64 .text sections using the Capstone engine.
/// </summary>
public static class CodeAnalyzer
{
    /// <summary>Max bytes of .text section to disassemble (avoids huge output).</summary>
    private const int MaxDisasmBytes = 524288;   // 512 KB — covers large .text sections

    // ── .NET decompilation ────────────────────────────────────────────────────

    /// <summary>
    /// Decompiles the entire .NET assembly at <paramref name="filePath"/>
    /// to a C# source string.
    /// </summary>
    public static void DecompileDotNet(string filePath, AnalysisResult result,
                                       IProgress<string>? progress = null)
    {
        if (!result.IsDotNet) return;

        try
        {
            progress?.Report("Decompiling .NET assembly...");

            var settings = new DecompilerSettings(LanguageVersion.Latest)
            {
                ThrowOnAssemblyResolveErrors = false,
                RemoveDeadCode              = false,
                ShowXmlDocumentation        = true,
            };

            var decompiler = new CSharpDecompiler(filePath, settings);
            result.DecompiledSource = decompiler.DecompileWholeModuleAsString();

            progress?.Report($"Decompilation complete — {result.DecompiledSource.Length:N0} chars");
        }
        catch (Exception ex)
        {
            result.Errors.Add($".NET decompilation error: {ex.Message}");
            result.DecompiledSource = $"// Decompilation failed:\n// {ex.Message}";
        }
    }

    // ── Native disassembly ────────────────────────────────────────────────────

    /// <summary>
    /// Disassembles the .text section of a native binary using Capstone.
    /// </summary>
    public static void DisassembleNative(string filePath, AnalysisResult result,
                                         IProgress<string>? progress = null)
    {
        if (result.IsDotNet) return;   // use decompiler for managed code

        try
        {
            progress?.Report("Locating .text section...");

            // Find .text section from PeInfo
            var textSection = result.PeInfo.Sections
                .FirstOrDefault(s => s.Name.TrimEnd('\0')
                                      .Equals(".text", StringComparison.OrdinalIgnoreCase));

            if (textSection == null)
            {
                result.Errors.Add("Disassembly: no .text section found.");
                return;
            }

            // Re-read raw section bytes -- PeInfo has RVAs as hex strings
            if (!uint.TryParse(textSection.VirtualAddress.TrimStart('0', 'x'),
                               System.Globalization.NumberStyles.HexNumber,
                               null, out uint sectionRva))
            {
                result.Errors.Add("Disassembly: could not parse section RVA.");
                return;
            }

            // Load binary and find file offset of the section
            using var fs = File.OpenRead(filePath);
            var pe = new PeNet.PeFile(filePath);

            // Convert RVA → file offset
            uint fileOffset = 0;
            if (pe.ImageSectionHeaders != null)
            {
                foreach (var sec in pe.ImageSectionHeaders)
                {
                    if (sec.VirtualAddress == sectionRva)
                    {
                        fileOffset = sec.PointerToRawData;
                        break;
                    }
                }
            }

            if (fileOffset == 0)
            {
                result.Errors.Add("Disassembly: could not map .text RVA to file offset.");
                return;
            }

            int bytesToRead = (int)Math.Min(
                uint.Parse(textSection.RawSize.TrimStart('0', 'x'),
                           System.Globalization.NumberStyles.HexNumber),
                MaxDisasmBytes);

            var codeBytes = new byte[bytesToRead];
            fs.Seek(fileOffset, SeekOrigin.Begin);
            int read = fs.Read(codeBytes, 0, bytesToRead);
            if (read == 0) return;

            progress?.Report($"Disassembling {read:N0} bytes...");

            // Run Capstone disassembler
            var mode = result.Is64Bit ? X86DisassembleMode.Bit64 : X86DisassembleMode.Bit32;
            using var disassembler = CapstoneDisassembler.CreateX86Disassembler(mode);
            disassembler.EnableInstructionDetails = false;
            disassembler.EnableSkipDataMode       = true;

            // Base address (use ImageBase + SectionRVA for realistic addresses)
            ulong baseAddr = 0x10000000UL + sectionRva;

            var insns = disassembler.Disassemble(
                codeBytes.AsSpan(0, read).ToArray(),
                (long)baseAddr);

            foreach (var insn in insns)
            {
                result.Disassembly.Add(new DisasmLine
                {
                    Address  = $"0x{insn.Address:X8}",
                    Bytes    = BitConverter.ToString(insn.Bytes)
                                           .Replace("-", " ")
                                           .PadRight(23),
                    Mnemonic = insn.Mnemonic ?? "",
                    Operands = insn.Operand  ?? "",
                });
            }

            progress?.Report($"Disassembly complete — {result.Disassembly.Count:N0} instructions");
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Disassembly error: {ex.Message}");
        }
    }
}
