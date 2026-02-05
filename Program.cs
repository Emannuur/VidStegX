using System;
using System.Runtime.InteropServices;
using Avalonia;

namespace VidStegX
{
    sealed class Program
    {
        // 1) DllImport attribute METHOD ke bilkul upar hoga
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private const int SW_HIDE = 0;

        [STAThread]
        public static void Main(string[] args)
        {
            // 2) Yahan normal method call hoga
            var handle = GetConsoleWindow();
            if (handle != IntPtr.Zero)
                ShowWindow(handle, SW_HIDE);

            BuildAvaloniaApp()
                .StartWithClassicDesktopLifetime(args ?? Array.Empty<string>());
        }

        public static AppBuilder BuildAvaloniaApp()
            => AppBuilder.Configure<App>()
                .UsePlatformDetect()
                .WithInterFont()
                .LogToTrace();
                
    }
}
