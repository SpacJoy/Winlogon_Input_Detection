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
        
        public void OnStart(string[] args)
        {
            Log("Service Started (Native).");
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

        private void StartMonitor(int sessionId)
        {
            try
            {
                if (_monitorProcess != null && !_monitorProcess.HasExited)
                {
                    Log("Monitor already running.");
                    return;
                }

                string monitorPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, MonitorExeName);
                if (!File.Exists(monitorPath))
                {
                    // Dev path fallback
                    monitorPath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "AuthUnlocker.Monitor", "bin", "Debug", "net8.0-windows", MonitorExeName));
                }

                if (!File.Exists(monitorPath))
                {
                    Log($"Monitor executable not found at {monitorPath}");
                    return;
                }

                Log($"Launching Monitor at {monitorPath} for Session {sessionId}");
                LaunchProcessOnWinlogon(monitorPath, sessionId);
            }
            catch (Exception ex)
            {
                Log($"Error starting monitor: {ex.Message}");
            }
        }

        private void StopMonitor()
        {
            try
            {
                if (_monitorProcess != null && !_monitorProcess.HasExited)
                {
                    Log("Stopping Monitor...");
                    _monitorProcess.Kill();
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
                File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "service_log.txt"), $"{DateTime.Now}: {message}{Environment.NewLine}");
            }
            catch { }
        }

        private void LaunchProcessOnWinlogon(string appPath, int sessionId)
        {
            // Simplified for P/Invoke implementation
            // Same logic as before
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
                    Log("Could not find winlogon process for session " + sessionId);
                    return;
                }

                hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_ALL_ACCESS, false, winlogon.Id);
                
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_DUPLICATE | NativeMethods.TOKEN_ASSIGN_PRIMARY | NativeMethods.TOKEN_QUERY, out hToken))
                {
                    Log("OpenProcessToken failed: " + Marshal.GetLastWin32Error());
                    return;
                }

                if (!NativeMethods.DuplicateTokenEx(hToken, NativeMethods.MAXIMUM_ALLOWED, IntPtr.Zero, 
                    NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, 
                    NativeMethods.TOKEN_TYPE.TokenPrimary, out hUserTokenDup))
                {
                    Log("DuplicateTokenEx failed: " + Marshal.GetLastWin32Error());
                    return;
                }

                if (!NativeMethods.CreateProcessAsUser(hUserTokenDup, appPath, null, IntPtr.Zero, IntPtr.Zero, false, 
                    NativeMethods.NORMAL_PRIORITY_CLASS | NativeMethods.CREATE_NEW_CONSOLE, 
                    IntPtr.Zero, null, ref si, out pi))
                {
                    Log("CreateProcessAsUser failed: " + Marshal.GetLastWin32Error());
                }
                else
                {
                    Log($"Monitor launched successfully. PID: {pi.dwProcessId}");
                    _monitorProcess = Process.GetProcessById(pi.dwProcessId);
                    NativeMethods.CloseHandle(pi.hProcess);
                    NativeMethods.CloseHandle(pi.hThread);
                }
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
            foreach (var p in Process.GetProcessesByName("winlogon"))
            {
                if (p.SessionId == sessionId) return p;
            }
            return null;
        }
    }

    public static class ServiceInterop
    {
        private const string ServiceName = "AuthUnlockerService";
        private static UnlockService _service = new UnlockService();
        private static IntPtr _statusHandle;
        private static NativeMethods.ServiceControlHandlerEx _handler;

        public static void Run(UnlockService service)
        {
            _service = service;
            NativeMethods.SERVICE_TABLE_ENTRY[] table = new NativeMethods.SERVICE_TABLE_ENTRY[]
            {
                new NativeMethods.SERVICE_TABLE_ENTRY { lpServiceName = ServiceName, lpServiceProc = ServiceMain },
                new NativeMethods.SERVICE_TABLE_ENTRY { lpServiceName = null, lpServiceProc = null }
            };

            NativeMethods.StartServiceCtrlDispatcher(table);
        }

        private static void ServiceMain(int argc, IntPtr argv)
        {
            _handler = HandlerEx;
            _statusHandle = NativeMethods.RegisterServiceCtrlHandlerEx(ServiceName, _handler, IntPtr.Zero);

            if (_statusHandle == IntPtr.Zero) return;

            ReportStatus(NativeMethods.SERVICE_START_PENDING, 0, 3000);

            _service.OnStart(new string[0]);

            ReportStatus(NativeMethods.SERVICE_RUNNING, 0, 0);
        }

        private static int HandlerEx(int control, int eventType, IntPtr eventData, IntPtr context)
        {
            switch (control)
            {
                case NativeMethods.SERVICE_CONTROL_STOP:
                    ReportStatus(NativeMethods.SERVICE_STOP_PENDING, 0, 0);
                    _service.OnStop();
                    ReportStatus(NativeMethods.SERVICE_STOPPED, 0, 0);
                    return NativeMethods.NO_ERROR;

                case NativeMethods.SERVICE_CONTROL_SESSIONCHANGE:
                    // eventType contains the reason (WTS_SESSION_LOCK etc)
                    // eventData contains a pointer to WTSSESSION_NOTIFICATION
                    if (eventData != IntPtr.Zero)
                    {
                        var notification = Marshal.PtrToStructure<NativeMethods.WTSSESSION_NOTIFICATION>(eventData);
                        _service.OnSessionChange(notification.dwSessionId, eventType);
                    }
                    return NativeMethods.NO_ERROR;
                
                default:
                    return NativeMethods.ERROR_CALL_NOT_IMPLEMENTED;
            }
        }

        private static void ReportStatus(int currentState, int exitCode, int waitHint)
        {
            NativeMethods.SERVICE_STATUS status = new NativeMethods.SERVICE_STATUS();
            status.dwServiceType = NativeMethods.SERVICE_WIN32_OWN_PROCESS;
            status.dwCurrentState = currentState;
            status.dwWin32ExitCode = exitCode;
            status.dwWaitHint = waitHint;

            if (currentState == NativeMethods.SERVICE_START_PENDING)
                status.dwControlsAccepted = 0;
            else
                status.dwControlsAccepted = NativeMethods.SERVICE_ACCEPT_STOP | NativeMethods.SERVICE_ACCEPT_SESSIONCHANGE;

            NativeMethods.SetServiceStatus(_statusHandle, ref status);
        }
    }

    internal static class NativeMethods
    {
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

        // Previous P/Invokes
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
        public const int MAXIMUM_ALLOWED = 0x2000000;
        public const int NORMAL_PRIORITY_CLASS = 0x00000020;
        public const int CREATE_NEW_CONSOLE = 0x00000010;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

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
    }
}
