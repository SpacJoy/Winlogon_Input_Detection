using System;
using System.Runtime.InteropServices;

namespace AuthUnlocker.Service
{
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
}
