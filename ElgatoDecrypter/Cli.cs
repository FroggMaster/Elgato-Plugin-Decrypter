namespace ElgatoDecrypter;

/// <summary>
/// Coloured console output helpers.
/// 
/// Prefixes map to colours:
///   [-]  → Red    (errors)
///   [!]  → Yellow (warnings)
///   [+]  → Green  (success)
///   [*]  → Lavender (info / status)
///   anything else → Lavender
/// </summary>
internal static class Cli
{
    // ANSI escape sequences for colours supported on Windows 10+ and all modern terminals.
    private const string AnsiRed     = "\x1b[38;2;255;80;80m";
    private const string AnsiYellow  = "\x1b[38;2;255;215;0m";
    private const string AnsiGreen   = "\x1b[38;2;80;220;100m";
    private const string AnsiLavender = "\x1b[38;2;180;160;255m";
    private const string AnsiReset   = "\x1b[0m";

    private static readonly bool _ansiSupported = DetectAnsi();

    private static bool DetectAnsi()
    {
        // ANSI is supported when not redirected and on a platform that supports VT sequences.
        if (Console.IsOutputRedirected) return false;
        if (!OperatingSystem.IsWindows()) return true;

        // On Windows, enable VT processing via kernel32 if needed.
        try
        {
            var handle = GetStdHandle(-11); // STD_OUTPUT_HANDLE
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return false;
            GetConsoleMode(handle, out uint mode);
            const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
            if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0) return true;
            return SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        catch
        {
            return false;
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    public static void WriteLine(string message = "")
    {
        if (!_ansiSupported)
        {
            WriteColorFallback(message);
            return;
        }

        string ansiColor = GetAnsiColor(message);
        Console.WriteLine(ansiColor + message + AnsiReset);
    }

    public static void Write(string message)
    {
        if (!_ansiSupported)
        {
            WriteColorFallbackNoLine(message);
            return;
        }

        string ansiColor = GetAnsiColor(message);
        Console.Write(ansiColor + message + AnsiReset);
    }

    private static string GetAnsiColor(string message)
    {
        if (message.Contains("[-]")) return AnsiRed;
        if (message.Contains("[!]")) return AnsiYellow;
        if (message.Contains("[+]")) return AnsiGreen;
        return AnsiLavender;
    }

    private static ConsoleColor GetFallbackColor(string message)
    {
        if (message.Contains("[-]")) return ConsoleColor.Red;
        if (message.Contains("[!]")) return ConsoleColor.Yellow;
        if (message.Contains("[+]")) return ConsoleColor.Green;
        return ConsoleColor.Cyan;
    }

    private static void WriteColorFallback(string message)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = GetFallbackColor(message);
        Console.WriteLine(message);
        Console.ForegroundColor = prev;
    }

    private static void WriteColorFallbackNoLine(string message)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = GetFallbackColor(message);
        Console.Write(message);
        Console.ForegroundColor = prev;
    }
}
