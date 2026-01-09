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
        private const int WM_MBUTTONDOWN = 0x0207;
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
            bool isChild = args.Length > 0 && args[0] == "--child";
            string finalLog = isChild ? @"C:\Windows\Temp\AuthUnlocker_CHILD.log" : @"C:\Windows\Temp\AuthUnlocker_V14.log";
            _logFilePath = finalLog;

            int currentSessionId = Process.GetCurrentProcess().SessionId;

            try
            {
                string tag = isChild ? "[CHILD]" : "[PARENT]";
                string initMsg = $"{tag} Entry. PID={Process.GetCurrentProcess().Id}, Session={currentSessionId}, Time={DateTime.Now:HH:mm:ss}";
                NativeMethods.OutputDebugString($"[AuthUnlocker] {initMsg}");

                // 简单的重试逻辑写入第一条记录
                for (int i = 0; i < 3; i++)
                {
                    try { File.AppendAllText(finalLog, initMsg + "\n"); break; }
                    catch { Thread.Sleep(100); }
                }
            }
            catch { }

            Log($"================ V14 START ({(isChild ? "CHILD" : "PARENT")}) ================");
            Log($"Running as user: {Environment.UserName}");
            Log($"Command Line: {Environment.CommandLine}");

            // 如果在 Session 0 运行且没有 --child 参数，则尝试迁移到活动会话
            if (currentSessionId == 0 && (args.Length == 0 || args[0] != "--child"))
            {
                Log("Running in Session 0, attempting to bootstrap to active session...");
                if (BootstrapToActiveSession())
                {
                    Log("Bootstrap initiated. Session 0 instance exiting.");
                    return;
                }
                else
                {
                    Log("Bootstrap failed. Continuing in Session 0 (likely won't work).");
                }
            }
            
            try 
            {
                // 确保我们尝试切换到 Winlogon 桌面
                bool desktopSwitched = false;
                string[] desktops = { "Winlogon", "Default" };
                foreach (var dsktp in desktops)
                {
                    IntPtr hDesktop = NativeMethods.OpenDesktop(dsktp, 0, false, NativeMethods.DESKTOP_ALL_ACCESS);
                    if (hDesktop != IntPtr.Zero)
                    {
                        if (NativeMethods.SetThreadDesktop(hDesktop))
                        {
                            Log($"Successfully switched to {dsktp} desktop.");
                            desktopSwitched = true;
                            break;
                        }
                    }
                }

                if (!desktopSwitched)
                {
                    Log("Failed to switch to any interactive desktop.");
                }

                _lastActivityTick = DateTime.Now.Ticks;

                // Install hooks
                _procKeyboard = HookCallbackKeyboard;
                _procMouse = HookCallbackMouse;
                
                using (Process curProcess = Process.GetCurrentProcess())
                using (ProcessModule curModule = curProcess.MainModule!)
                {
                    IntPtr hMod = NativeMethods.GetModuleHandle(curModule.ModuleName);
                    _hookIDKeyboard = NativeMethods.SetWindowsHookEx(WH_KEYBOARD_LL, _procKeyboard, hMod, 0);
                    _hookIDMouse = NativeMethods.SetWindowsHookEx(WH_MOUSE_LL, _procMouse, hMod, 0);
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

        private static bool BootstrapToActiveSession()
        {
            IntPtr hToken = IntPtr.Zero;
            IntPtr hNewToken = IntPtr.Zero;
            IntPtr lpEnvironment = IntPtr.Zero;
            try
            {
                int activeSessionId = (int)NativeMethods.WTSGetActiveConsoleSessionId();
                if (activeSessionId == 0xFFFFFFFF || activeSessionId == 0)
                {
                    Log("No active console session found.");
                    return false;
                }

                Log($"Active Console Session ID: {activeSessionId}. Attempting to steal Winlogon token...");

                // 找到目标 Session 的 winlogon 进程
                Process[] processes = Process.GetProcessesByName("winlogon");
                Process? targetWinlogon = null;
                foreach (var p in processes)
                {
                    if (p.SessionId == activeSessionId)
                    {
                        targetWinlogon = p;
                        break;
                    }
                }

                if (targetWinlogon == null)
                {
                    Log($"Could not find winlogon.exe in Session {activeSessionId}");
                    return false;
                }

                if (!NativeMethods.OpenProcessToken(targetWinlogon.Handle, NativeMethods.TOKEN_ALL_ACCESS, out hToken))
                {
                    Log($"Failed to open winlogon token. Error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                if (!NativeMethods.DuplicateTokenEx(hToken, NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero,
                    NativeMethods.SecurityImpersonation, NativeMethods.TokenPrimary, out hNewToken))
                {
                    Log($"Failed to duplicate token. Error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                NativeMethods.STARTUPINFO si = new NativeMethods.STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = null; // [V13] 不再强制启动在 Winlogon 桌面，由进程内部自行切换

                if (!NativeMethods.CreateEnvironmentBlock(out lpEnvironment, hNewToken, false))
                {
                    Log($"Failed to create environment block. Error: {Marshal.GetLastWin32Error()}");
                }

                NativeMethods.PROCESS_INFORMATION pi = new NativeMethods.PROCESS_INFORMATION();

                string appPath = Process.GetCurrentProcess().MainModule!.FileName;
                string workDir = Path.GetDirectoryName(appPath)!;

                // [V12] 尝试使用 dotnet.exe 显式启动
                string dllPath = Path.Combine(workDir, "AuthUnlocker.Monitor.dll");
                string dotnetPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
                if (!File.Exists(dotnetPath)) dotnetPath = "dotnet"; // 退而求其次使用 PATH 中的 dotnet

                string cmdLine = $"\"{dotnetPath}\" \"{dllPath}\" --child";

                Log($"Launching child via stolen token: {cmdLine}");

                bool result = NativeMethods.CreateProcessAsUser(
                    hNewToken,
                    null,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    NativeMethods.CREATE_NO_WINDOW | 0x00000400, // CREATE_UNICODE_ENVIRONMENT
                    lpEnvironment,
                    workDir,
                    ref si,
                    out pi
                );

                if (result)
                {
                    Log($"Successfully launched child monitor in Session {activeSessionId}. PID: {pi.dwProcessId}");
                    NativeMethods.CloseHandle(pi.hProcess);
                    NativeMethods.CloseHandle(pi.hThread);
                    // 稍微等待一下，确保子进程环境初始化
                    Thread.Sleep(1000);
                }
                else
                {
                    Log($"Failed to CreateProcessAsUser. Error: {Marshal.GetLastWin32Error()}");
                }

                return result;
            }
            catch (Exception ex)
            {
                Log($"Bootstrap Error: {ex.Message}");
                return false;
            }
            finally
            {
                if (hToken != IntPtr.Zero) NativeMethods.CloseHandle(hToken);
                if (hNewToken != IntPtr.Zero) NativeMethods.CloseHandle(hNewToken);
                if (lpEnvironment != IntPtr.Zero) NativeMethods.DestroyEnvironmentBlock(lpEnvironment);
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
                // 包含所有鼠标移动、左键按下、右键按下、中键按下
                if (msg == WM_MOUSEMOVE || msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN || msg == WM_MBUTTONDOWN)
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
            string logLine = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}: {message}{Environment.NewLine}";
            NativeMethods.OutputDebugString($"[AuthUnlocker] {message}");

            for (int i = 0; i < 5; i++)
            {
                try
                {
                    File.AppendAllText(_logFilePath, logLine);
                    return;
                }
                catch
                {
                    Thread.Sleep(50 * (i + 1));
                }
            }

            // 如果主日志失败，尝试记录到备用位置
            try { File.AppendAllText(@"C:\Windows\Temp\AuthUnlocker_Backup.log", $"Log error (Final): {message}\n"); } catch { }
        }

        internal delegate IntPtr LowLevelProc(int nCode, IntPtr wParam, IntPtr lParam);
    }

    internal static class NativeMethods
    {
        public const uint DESKTOP_ALL_ACCESS = 0x01FF;
        public const int UOI_NAME = 2;
        public static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const int TokenSessionId = 12;
        public const int TokenPrimary = 1;
        public const int SecurityImpersonation = 2;
        public const uint CREATE_NO_WINDOW = 0x08000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

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

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, ref int TokenInformation, int TokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string? lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern void OutputDebugString(string lpOutputString);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
