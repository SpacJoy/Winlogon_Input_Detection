using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace AuthUnlocker.Monitor
{
    class Program
    {
        private static IntPtr _hookIDKeyboard = IntPtr.Zero;
        private static IntPtr _hookIDMouse = IntPtr.Zero;
        private static LowLevelKeyboardProc? _procKeyboard;
        private static LowLevelMouseProc? _procMouse;
        private static long _lastActivityTick = 0;
        private const long IdleThresholdTicks = 200 * 10000; // 200ms in ticks

        static void Main(string[] args)
        {
            Log("Monitor started.");
            
            // Keep delegates alive
            _procKeyboard = HookCallbackKeyboard;
            _procMouse = HookCallbackMouse;

            _hookIDKeyboard = SetHook(WH_KEYBOARD_LL, _procKeyboard);
            _hookIDMouse = SetHook(WH_MOUSE_LL, _procMouse);

            Log("Hooks installed. Waiting for input...");

            // Message Loop
            ApplicationRun();

            UnhookWindowsHookEx(_hookIDKeyboard);
            UnhookWindowsHookEx(_hookIDMouse);
            Log("Monitor exiting.");
        }

        private static void ApplicationRun()
        {
            NativeMethods.MSG msg;
            while (NativeMethods.GetMessage(out msg, IntPtr.Zero, 0, 0))
            {
                NativeMethods.TranslateMessage(ref msg);
                NativeMethods.DispatchMessage(ref msg);
            }
        }

        private static IntPtr SetHook(int idHook, Delegate proc)
        {
            return SetWindowsHookEx(idHook, proc, GetModuleHandle(null), 0);
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallbackKeyboard(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                // Key event
                HandleActivity("Keyboard");
            }
            return CallNextHookEx(_hookIDKeyboard, nCode, wParam, lParam);
        }

        private static IntPtr HookCallbackMouse(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                // Mouse event
                // We might want to ignore mouse moves that are too small or jittery, but for now catch all.
                HandleActivity("Mouse");
            }
            return CallNextHookEx(_hookIDMouse, nCode, wParam, lParam);
        }

        private static void HandleActivity(string source)
        {
            long currentTick = DateTime.Now.Ticks;
            long diff = currentTick - _lastActivityTick;

            // Update last activity
            _lastActivityTick = currentTick;

            if (diff > IdleThresholdTicks)
            {
                Log($"[Trigger] Activity detected from {source} after idle. Simulating Auth Success.");
                // Here is where we "Return validation success status"
                // For a demo, we log it. In a real scenario, this would notify the Service or Credential Provider.
            }
        }

        private static void Log(string message)
        {
            try
            {
                string logFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "monitor_log.txt");
                File.AppendAllText(logFile, $"{DateTime.Now}: {message}{Environment.NewLine}");
            }
            catch { }
        }

        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, Delegate lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);

    }

    internal static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public System.Drawing.Point pt;
        }

        [DllImport("user32.dll")]
        public static extern bool GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        public static extern bool TranslateMessage([In] ref MSG lpMsg);

        [DllImport("user32.dll")]
        public static extern IntPtr DispatchMessage([In] ref MSG lpMsg);
    }
    
    // Stub for System.Drawing.Point if not available (Console app usually doesn't reference System.Drawing)
    namespace System.Drawing
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct Point
        {
            public int x;
            public int y;
        }
    }
}
