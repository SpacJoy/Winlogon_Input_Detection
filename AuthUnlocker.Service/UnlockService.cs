using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace AuthUnlocker.Service
{
    public class UnlockService
    {
        private Process? _monitorProcess;
        private const string MonitorExeName = "AuthUnlocker.Monitor.exe";
        private static string _logFilePath = @"C:\Windows\Temp\AuthUnlocker_Service.log";

        public void OnStart(string[] args)
        {
            Log("Service Started (Native).");
            EnablePrivileges();
        }

        public void OnStop()
        {
            StopMonitor();
            Log("Service Stopped.");
        }

        public void OnSessionChange(int sessionId, int reason)
        {
            Log($"Session Change: {reason} SessionId: {sessionId}");

            // WTS_SESSION_LOCK = 0x7, WTS_SESSION_UNLOCK = 0x8
            const int WTS_SESSION_LOCK = 0x7;
            const int WTS_SESSION_UNLOCK = 0x8;
            const int WTS_SESSION_LOGON = 0x5;

            switch (reason)
            {
                case WTS_SESSION_LOCK:
                    StartMonitor(sessionId);
                    break;
                case WTS_SESSION_UNLOCK:
                case WTS_SESSION_LOGON:
                    StopMonitor();
                    break;
            }
        }

        private void EnablePrivileges()
        {
            // Try to enable TCB privilege which is helpful for creating processes as user
            try {
                bool success = EnablePrivilege("SeTcbPrivilege");
                Log($"Enable SeTcbPrivilege: {success}");
                success = EnablePrivilege("SeDebugPrivilege");
                Log($"Enable SeDebugPrivilege: {success}");
                success = EnablePrivilege("SeAssignPrimaryTokenPrivilege");
                Log($"Enable SeAssignPrimaryTokenPrivilege: {success}");
                success = EnablePrivilege("SeIncreaseQuotaPrivilege");
                Log($"Enable SeIncreaseQuotaPrivilege: {success}");
            } catch (Exception ex) {
                Log($"Error enabling privileges: {ex.Message}");
            }
        }

        private bool EnablePrivilege(string privilegeName)
        {
            IntPtr hToken;
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY, out hToken))
            {
                return false;
            }

            try
            {
                NativeMethods.LUID luid;
                if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out luid))
                {
                    return false;
                }

                NativeMethods.TOKEN_PRIVILEGES tp = new NativeMethods.TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = new NativeMethods.LUID_AND_ATTRIBUTES[1];
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = NativeMethods.SE_PRIVILEGE_ENABLED;

                if (!NativeMethods.AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    return false;
                }
                
                return Marshal.GetLastWin32Error() == NativeMethods.ERROR_SUCCESS;
            }
            finally
            {
                NativeMethods.CloseHandle(hToken);
            }
        }

        private void StartMonitor(int sessionId)
        {
            try
            {
                if (_monitorProcess != null && !_monitorProcess.HasExited)
                {
                    Log("Monitor already running.");
                    return;
                }

                // Check standard deployment path first (same dir as service)
                string monitorPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, MonitorExeName);
                
                // Fallback for dev environment
                if (!File.Exists(monitorPath))
                {
                    string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                    // Try to navigate up to find the other project output
                    // D:\Code\TEST\test\AuthUnlocker.Service\bin\Debug\net8.0-windows\
                    // -> D:\Code\TEST\test\AuthUnlocker.Monitor\bin\Debug\net8.0-windows\AuthUnlocker.Monitor.exe
                    string devPath = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "AuthUnlocker.Monitor", "bin", "Debug", "net8.0-windows", MonitorExeName));
                    if (File.Exists(devPath))
                    {
                        monitorPath = devPath;
                    }
                }

                if (!File.Exists(monitorPath))
                {
                    Log($"CRITICAL: Monitor executable not found at {monitorPath}");
                    return;
                }

                Log($"Preparing to launch Monitor at {monitorPath} for Session {sessionId}");
                LaunchProcessOnWinlogon(monitorPath, sessionId);
            }
            catch (Exception ex)
            {
                Log($"Error starting monitor: {ex.ToString()}");
            }
        }

        private void StopMonitor()
        {
            try
            {
                if (_monitorProcess != null)
                {
                    Log("Stopping Monitor...");
                    if (!_monitorProcess.HasExited)
                    {
                        _monitorProcess.Kill();
                    }
                    _monitorProcess = null;
                }
            }
            catch (Exception ex)
            {
                Log($"Error stopping monitor: {ex.Message}");
            }
        }

        private void Log(string message)
        {
            try
            {
                File.AppendAllText(_logFilePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}: {message}{Environment.NewLine}");
            }
            catch { }
        }

        private void LaunchProcessOnWinlogon(string appPath, int sessionId)
        {
            IntPtr hToken = IntPtr.Zero;
            IntPtr hUserTokenDup = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;

            NativeMethods.STARTUPINFO si = new NativeMethods.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = @"WinSta0\Winlogon";

            NativeMethods.PROCESS_INFORMATION pi = new NativeMethods.PROCESS_INFORMATION();

            try 
            {
                var winlogon = GetWinlogonProcess(sessionId);
                if (winlogon == null)
                {
                    Log($"Could not find winlogon process for session {sessionId}. Is the session active?");
                    return;
                }

                Log($"Found winlogon process: PID {winlogon.Id}");

                hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_ALL_ACCESS, false, winlogon.Id);
                if (hProcess == IntPtr.Zero)
                {
                    Log($"OpenProcess failed. Error: {Marshal.GetLastWin32Error()}");
                    return;
                }
                
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_DUPLICATE | NativeMethods.TOKEN_ASSIGN_PRIMARY | NativeMethods.TOKEN_QUERY, out hToken))
                {
                    Log($"OpenProcessToken failed. Error: {Marshal.GetLastWin32Error()}");
                    return;
                }

                if (!NativeMethods.DuplicateTokenEx(hToken, NativeMethods.MAXIMUM_ALLOWED, IntPtr.Zero, 
                    NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, 
                    NativeMethods.TOKEN_TYPE.TokenPrimary, out hUserTokenDup))
                {
                    Log($"DuplicateTokenEx failed. Error: {Marshal.GetLastWin32Error()}");
                    return;
                }

                string? workingDir = Path.GetDirectoryName(appPath);

                // 使用 cmd.exe 包装启动，以便捕获可能的运行时错误
                string logFile = @"C:\Windows\Temp\Monitor_Launch_Error.log";
                string commandLine = $"cmd.exe /c \"\"{appPath}\" > \"{logFile}\" 2>&1\"";

                Log($"Token duplicated. Launching via cmd: {commandLine}");

                if (!NativeMethods.CreateProcessAsUser(hUserTokenDup, null, commandLine, IntPtr.Zero, IntPtr.Zero, false, 
                    NativeMethods.NORMAL_PRIORITY_CLASS | NativeMethods.CREATE_NO_WINDOW, 
                    IntPtr.Zero, workingDir, ref si, out pi))
                {
                    Log($"CreateProcessAsUser failed. Error: {Marshal.GetLastWin32Error()}");
                }
                else
                {
                    Log($"Monitor launched successfully. PID: {pi.dwProcessId}");
                    _monitorProcess = Process.GetProcessById(pi.dwProcessId);
                    NativeMethods.CloseHandle(pi.hProcess);
                    NativeMethods.CloseHandle(pi.hThread);
                }
            }
            catch (Exception ex)
            {
                Log($"Exception in LaunchProcessOnWinlogon: {ex.ToString()}");
            }
            finally
            {
                if (hToken != IntPtr.Zero) NativeMethods.CloseHandle(hToken);
                if (hUserTokenDup != IntPtr.Zero) NativeMethods.CloseHandle(hUserTokenDup);
                if (hProcess != IntPtr.Zero) NativeMethods.CloseHandle(hProcess);
            }
        }

        private Process? GetWinlogonProcess(int sessionId)
        {
            Process? winlogon = null;
            foreach (var p in Process.GetProcessesByName("winlogon"))
            {
                if (p.SessionId == sessionId)
                {
                    winlogon = p;
                    break;
                }
            }
            return winlogon;
        }
    }

    internal static class NativeMethods
    {
        // ... Previous definitions ...
        public const int SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        public const int SERVICE_START_PENDING = 0x00000002;
        public const int SERVICE_RUNNING = 0x00000004;
        public const int SERVICE_STOP_PENDING = 0x00000003;
        public const int SERVICE_STOPPED = 0x00000001;
        public const int SERVICE_CONTROL_STOP = 0x00000001;
        public const int SERVICE_CONTROL_SESSIONCHANGE = 0x0000000E;
        public const int SERVICE_ACCEPT_STOP = 0x00000001;
        public const int SERVICE_ACCEPT_SESSIONCHANGE = 0x00000080;
        public const int NO_ERROR = 0;
        public const int ERROR_CALL_NOT_IMPLEMENTED = 120;
        public const int ERROR_SUCCESS = 0;

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_TABLE_ENTRY
        {
            public string? lpServiceName;
            public ServiceMainCallback? lpServiceProc;
        }

        public delegate void ServiceMainCallback(int argc, IntPtr argv);
        public delegate int ServiceControlHandlerEx(int control, int eventType, IntPtr eventData, IntPtr context);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool StartServiceCtrlDispatcher(SERVICE_TABLE_ENTRY[] lpServiceStartTable);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr RegisterServiceCtrlHandlerEx(string lpServiceName, ServiceControlHandlerEx lpHandlerProc, IntPtr lpContext);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetServiceStatus(IntPtr hServiceStatus, ref SERVICE_STATUS lpServiceStatus);

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_STATUS
        {
            public int dwServiceType;
            public int dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTSSESSION_NOTIFICATION
        {
            public int cbSize;
            public int dwSessionId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
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
            public int dwProcessId;
            public int dwThreadId;
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        public const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        public const int TOKEN_DUPLICATE = 0x0002;
        public const int TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const int TOKEN_QUERY = 0x0008;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const int MAXIMUM_ALLOWED = 0x2000000;
        public const int NORMAL_PRIORITY_CLASS = 0x00000020;
        public const int CREATE_NEW_CONSOLE = 0x00000010;
        public const int CREATE_NO_WINDOW = 0x08000000;
        public const string SE_TCB_NAME = "SeTcbPrivilege";
        public const int SE_PRIVILEGE_ENABLED = 0x00000002;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, int dwDesiredAccess, IntPtr lpTokenAttributes, 
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string? lpCommandLine, 
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, 
            IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(int sessionId, out IntPtr Token);

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, 
            ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    }
}
