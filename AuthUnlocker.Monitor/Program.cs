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
        private static string _logFilePath = @"C:\Windows\Temp\AuthUnlocker_Monitor.log";

        static void Main(string[] args)
        {
            Log("==========================================");
            Log($"Monitor process started. PID: {Process.GetCurrentProcess().Id}");
            Log($"Running as user: {Environment.UserName}");
            Log($"Interactive: {Environment.UserInteractive}");
            
            try 
            {
                // Keep delegates alive
                _procKeyboard = HookCallbackKeyboard;
                _procMouse = HookCallbackMouse;

                _hookIDKeyboard = SetHook(WH_KEYBOARD_LL, _procKeyboard);
                Log($"Keyboard hook set. Handle: {_hookIDKeyboard}");
                
                _hookIDMouse = SetHook(WH_MOUSE_LL, _procMouse);
                Log($"Mouse hook set. Handle: {_hookIDMouse}");

                if (_hookIDKeyboard == IntPtr.Zero || _hookIDMouse == IntPtr.Zero)
                {
                    Log($"FAILED to set hooks. Error: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    Log("Hooks installed successfully. Waiting for input...");
                }

                // Message Loop
                ApplicationRun();

                UnhookWindowsHookEx(_hookIDKeyboard);
                UnhookWindowsHookEx(_hookIDMouse);
                Log("Monitor exiting normally.");
            }
            catch (Exception ex)
            {
                Log($"CRITICAL ERROR: {ex.ToString()}");
            }
        }

        private static void ApplicationRun()
        {
            NativeMethods.MSG msg;
            int ret;
            // GetMessage returns -1 on error
            while ((ret = NativeMethods.GetMessage(out msg, IntPtr.Zero, 0, 0)) != 0)
            {
                if (ret == -1)
                {
                    Log($"GetMessage failed. Error: {Marshal.GetLastWin32Error()}");
                    break;
                }
                NativeMethods.TranslateMessage(ref msg);
                NativeMethods.DispatchMessage(ref msg);
            }
        }

        private static IntPtr SetHook(int idHook, Delegate proc)
        {
            // For global hooks in a separate process, we usually need a module handle.
            // Using GetModuleHandle(null) gets the handle of the .exe, which is valid for low-level hooks.
            IntPtr hMod = GetModuleHandle(null);
            return SetWindowsHookEx(idHook, proc, hMod, 0);
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallbackKeyboard(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                HandleActivity("Keyboard");
            }
            return CallNextHookEx(_hookIDKeyboard, nCode, wParam, lParam);
        }

        private static IntPtr HookCallbackMouse(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                // Optionally filter out mouse moves
                HandleActivity("Mouse");
            }
            return CallNextHookEx(_hookIDMouse, nCode, wParam, lParam);
        }

        private static void HandleActivity(string source)
        {
            try
            {
                long currentTick = DateTime.Now.Ticks;
                long diff = currentTick - _lastActivityTick;

                // Update last activity
                _lastActivityTick = currentTick;

                if (diff > IdleThresholdTicks)
                {
                    Log($"[Trigger] Activity detected from {source} after idle. Simulating Auth Success.");
                }
            }
            catch {}
        }

        private static void Log(string message)
        {
            try
            {
                File.AppendAllText(_logFilePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}: {message}{Environment.NewLine}");
            }
            catch (Exception ex)
            {
                // Last resort logging to console if possible, though invisible in session 0/locked desktop
                Debug.WriteLine($"Log failed: {ex.Message}");
            }
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
        public struct POINT
        {
            public int X;
            public int Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public POINT pt;
        }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        public static extern bool TranslateMessage([In] ref MSG lpMsg);

        [DllImport("user32.dll")]
        public static extern IntPtr DispatchMessage([In] ref MSG lpMsg);
    }
}
