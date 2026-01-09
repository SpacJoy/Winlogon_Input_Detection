using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace AuthUnlocker.Monitor
{
    class Program
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_LBUTTONDOWN = 0x0201;
        private const int WM_RBUTTONDOWN = 0x0204;
        private const int WM_MOUSEMOVE = 0x0200;

        private static LowLevelProc? _procKeyboard;
        private static LowLevelProc? _procMouse;
        private static IntPtr _hookIDKeyboard = IntPtr.Zero;
        private static IntPtr _hookIDMouse = IntPtr.Zero;

        private static long _lastActivityTick = 0;
        private const long IdleThresholdTicks = 200 * 10000; // 200ms in ticks
        private static string _logFilePath = @"C:\Windows\Temp\AuthUnlocker_Monitor.log";

        static void Main(string[] args)
        {
            // Emergency init log
            try { File.WriteAllText(@"C:\Windows\Temp\AuthUnlocker_Monitor_Init.log", "Entry point hit at " + DateTime.Now.ToString()); } catch { }

            Log("==========================================");
            Log($"Monitor Started. PID: {Process.GetCurrentProcess().Id}, Session: {Process.GetCurrentProcess().SessionId}");
            Log($"Running as user: {Environment.UserName}");
            
            try 
            {
                // Get current desktop name for debugging
                StringBuilder desktopName = new StringBuilder(256);
                IntPtr hCurrentDesktop = NativeMethods.GetThreadDesktop(NativeMethods.GetCurrentThreadId());
                NativeMethods.GetUserObjectInformation(hCurrentDesktop, NativeMethods.UOI_NAME, desktopName, 256, out _);
                Log($"Current Thread Desktop: {desktopName}");

                // Force switch to Winlogon desktop
                IntPtr hDesktop = NativeMethods.OpenDesktop("Winlogon", 0, false, NativeMethods.DESKTOP_ALL_ACCESS);
                if (hDesktop != IntPtr.Zero)
                {
                    if (NativeMethods.SetThreadDesktop(hDesktop))
                        Log("Successfully switched to Winlogon desktop.");
                    else
                        Log($"Failed to set thread desktop. Error: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    Log($"Failed to open Winlogon desktop. Error: {Marshal.GetLastWin32Error()}");
                }

                _lastActivityTick = DateTime.Now.Ticks;

                // Install hooks
                _procKeyboard = HookCallbackKeyboard;
                _procMouse = HookCallbackMouse;
                
                using (Process curProcess = Process.GetCurrentProcess())
                using (ProcessModule curModule = curProcess.MainModule!)
                {
                    _hookIDKeyboard = NativeMethods.SetWindowsHookEx(WH_KEYBOARD_LL, _procKeyboard, NativeMethods.GetModuleHandle(curModule.ModuleName), 0);
                    _hookIDMouse = NativeMethods.SetWindowsHookEx(WH_MOUSE_LL, _procMouse, NativeMethods.GetModuleHandle(curModule.ModuleName), 0);
                }

                if (_hookIDKeyboard == IntPtr.Zero || _hookIDMouse == IntPtr.Zero)
                {
                    Log($"Failed to install hooks. Kbd: {_hookIDKeyboard}, Mouse: {_hookIDMouse}. Error: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    Log("Hooks installed successfully. Starting message loop...");
                }

                // WinForms message loop is REQUIRED for hooks to work
                System.Windows.Forms.Application.Run();
            }
            catch (Exception ex)
            {
                Log($"CRITICAL ERROR: {ex.ToString()}");
            }
            finally
            {
                if (_hookIDKeyboard != IntPtr.Zero) NativeMethods.UnhookWindowsHookEx(_hookIDKeyboard);
                if (_hookIDMouse != IntPtr.Zero) NativeMethods.UnhookWindowsHookEx(_hookIDMouse);
                Log("Monitor exiting.");
            }
        }

        private static void TriggerVerification()
        {
            Log(">>> Input detected! Triggering verification flow...");
            Log("Verification SUCCESS. Attempting to unlock session...");
            
            int currentSessionId = Process.GetCurrentProcess().SessionId;
            bool success = NativeMethods.WTSUnLockSession(NativeMethods.WTS_CURRENT_SERVER_HANDLE, currentSessionId);
            Log($"WTSUnLockSession result: {success}. Error: {Marshal.GetLastWin32Error()}");

            System.Windows.Forms.Application.Exit();
        }

        private static IntPtr HookCallbackKeyboard(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
            {
                CheckActivity("Keyboard");
            }
            return NativeMethods.CallNextHookEx(_hookIDKeyboard, nCode, wParam, lParam);
        }

        private static IntPtr HookCallbackMouse(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int msg = (int)wParam;
                if (msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN || msg == WM_MOUSEMOVE)
                {
                    CheckActivity("Mouse");
                }
            }
            return NativeMethods.CallNextHookEx(_hookIDMouse, nCode, wParam, lParam);
        }

        private static void CheckActivity(string source)
        {
            long currentTick = DateTime.Now.Ticks;
            long lastTick = Interlocked.Exchange(ref _lastActivityTick, currentTick);
            
            if (lastTick != 0)
            {
                long diff = currentTick - lastTick;
                if (diff > IdleThresholdTicks)
                {
                    Log($"[Trigger] Activity detected from {source} after idle. Starting verification.");
                    TriggerVerification();
                }
            }
        }

        private static void Log(string message)
        {
            try
            {
                string logLine = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}: {message}{Environment.NewLine}";
                File.AppendAllText(_logFilePath, logLine);
            }
            catch { }
        }

        internal delegate IntPtr LowLevelProc(int nCode, IntPtr wParam, IntPtr lParam);
    }

    internal static class NativeMethods
    {
        public const uint DESKTOP_ALL_ACCESS = 0x01FF;
        public const int UOI_NAME = 2;
        public static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool SetThreadDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetThreadDesktop(uint dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, [Out] StringBuilder pvInfo, uint nLength, out uint lpnLengthNeeded);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSUnLockSession(IntPtr hServer, int SessionId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, Program.LowLevelProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
    }
}
