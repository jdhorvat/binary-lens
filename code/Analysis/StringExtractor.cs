using System.IO;
using BinaryLens.Models;

namespace BinaryLens.Analysis;

/// <summary>
/// Extracts printable ASCII and UTF-16 strings from binary files,
/// similar to the Sysinternals Strings utility.
/// </summary>
public static class StringExtractor
{
    /// <summary>Minimum run of printable characters to qualify as a string.</summary>
    private const int MinLength = 4;

    /// <summary>Maximum string length stored (prevents enormous blobs).</summary>
    private const int MaxLength = 512;

    public static void Extract(string filePath, AnalysisResult result,
                               IProgress<string>? progress = null)
    {
        try
        {
            byte[] data = File.ReadAllBytes(filePath);
            progress?.Report("Extracting ASCII strings...");
            var ascii   = ExtractAscii(data);
            progress?.Report("Extracting Unicode strings...");
            var unicode = ExtractUnicode(data);

            result.Strings.AddRange(ascii);
            result.Strings.AddRange(unicode);

            // Sort by offset
            result.Strings.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        }
        catch (Exception ex)
        {
            result.Errors.Add($"String extraction error: {ex.Message}");
        }
    }

    // ── ASCII extraction ──────────────────────────────────────────────────────

    private static List<ExtractedString> ExtractAscii(byte[] data)
    {
        var results = new List<ExtractedString>();
        int start   = -1;

        for (int i = 0; i <= data.Length; i++)
        {
            bool printable = i < data.Length && IsPrintableAscii(data[i]);

            if (printable)
            {
                if (start < 0) start = i;
            }
            else
            {
                if (start >= 0)
                {
                    int len = i - start;
                    if (len >= MinLength)
                    {
                        int take = Math.Min(len, MaxLength);
                        results.Add(new ExtractedString
                        {
                            Offset   = start,
                            Value    = System.Text.Encoding.ASCII.GetString(data, start, take),
                            Encoding = "ASCII",
                        });
                    }
                    start = -1;
                }
            }
        }
        return results;
    }

    // ── UTF-16 (Unicode) extraction ───────────────────────────────────────────

    private static List<ExtractedString> ExtractUnicode(byte[] data)
    {
        var results = new List<ExtractedString>();
        int start   = -1;
        int count   = 0;          // number of valid wide chars found

        // Walk in 2-byte steps
        for (int i = 0; i <= data.Length - 1; i += 2)
        {
            bool valid = i + 1 < data.Length
                && data[i + 1] == 0
                && IsPrintableAscii(data[i]);

            if (valid)
            {
                if (start < 0) { start = i; count = 0; }
                count++;
            }
            else
            {
                if (start >= 0 && count >= MinLength)
                {
                    int byteLen = count * 2;
                    int take    = Math.Min(byteLen, MaxLength * 2);
                    string s = System.Text.Encoding.Unicode.GetString(data, start, take);
                    results.Add(new ExtractedString
                    {
                        Offset   = start,
                        Value    = s,
                        Encoding = "UTF-16",
                    });
                }
                start = -1;
                count = 0;
            }
        }
        return results;
    }

    private static bool IsPrintableAscii(byte b)
        => b >= 0x20 && b <= 0x7E;
}
