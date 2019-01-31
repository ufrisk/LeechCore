//	leechsvc.c : Implementation the LeechSvc service related functionality.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechsvc.h"
#include "leechsvc_rpc.h"
#include "leechrpc.h"
#include <stdio.h>
#include <strsafe.h>

SERVICE_STATUS					g_SvcStatus;
SERVICE_STATUS_HANDLE			g_SvcStatusHandle;
HANDLE							g_hSvcStopEvent = NULL;

VOID SvcInstall();
VOID SvcDelete();
VOID WINAPI SvcCtrlHandler(DWORD dwCtrl);
VOID WINAPI SvcMain(DWORD dwArgc, LPWSTR* pwszArgv);
VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
VOID SvcInit();
VOID SvcReportEvent(LPWSTR wszFunction);

/*
* Delete the installed service from the services database.
*/
VOID SvcDelete()
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS schStatusService;
    // get a handle to the SCM database
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(!schSCManager) {
        printf("OpenSCManager failed (0x%08x) - missing admin privileges?\n", GetLastError());
        return;
    }
    // open service
    schService = OpenService(schSCManager, LEECHSVC_NAME, SERVICE_ALL_ACCESS);
    if(!schSCManager) {
        printf("OpenService failed (0x%08x).\n", GetLastError());
        return;
    }
    // try stop service
    ControlService(schService, SERVICE_CONTROL_STOP, &schStatusService);
    // delete service
    if(!DeleteService(schService)) {
        printf("DeleteService failed (0x%08x).\n", GetLastError());
        return;
    }
    // cleanup and return.
    printf("Service deleted successfully.\n");
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

/*
* Install the service.
*/
void SvcInstall()
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    WCHAR wszPath[MAX_PATH];
    SERVICE_DESCRIPTION svcDescr;
    // get path to current executable
    if(!GetModuleFileName(NULL, wszPath, MAX_PATH)) {
        printf("Cannot install service (0x%08x).\n", GetLastError());
        return;
    }
    // get a handle to the SCM database
    schSCManager = OpenSCManager(
        NULL,
        NULL,
        SC_MANAGER_ALL_ACCESS);
    if(!schSCManager) {
        printf("OpenSCManager failed (0x%08x) - missing admin privileges?\n", GetLastError());
        return;
    }
    // create the service
    schService = CreateService(
        schSCManager,               // SCM database 
        LEECHSVC_NAME,              // name of service 
        LEECHSVC_DISPLAY_NAME,      // service name to display 
        SERVICE_ALL_ACCESS,         // desired access 
        SERVICE_WIN32_OWN_PROCESS,  // service type 
        SERVICE_AUTO_START,         // start type 
        SERVICE_ERROR_NORMAL,       // error control type 
        wszPath,                    // path to service's binary 
        NULL,                       // no load ordering group 
        NULL,                       // no tag identifier 
        NULL,                       // no dependencies 
        NULL,                       // account (NULL=SYSTEM)
        NULL);                      // no password 
    if(!schService) {
        printf("CreateService failed (0x%08x).\n", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }
    // try set description
    svcDescr.lpDescription = LEECHSVC_DESCR_LONG;
    ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &svcDescr);
    // try start service
    StartService(schService, 0, NULL);
    // cleanup and return.
    printf("Service installed successfully.\n");
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

/*
* Main entry point for the SCM.
* -- dwArgc = # of pwszArgv.
* -- pwszArgv = arguments passed from the SCM (not currently used by function).
*/
VOID WINAPI SvcMain(DWORD dwArgc, LPWSTR *pwszArgv)
{
    // Register the handler function for the service
    g_SvcStatusHandle = RegisterServiceCtrlHandler(LEECHSVC_NAME, SvcCtrlHandler);
    if(!g_SvcStatusHandle) {
        SvcReportEvent(L"RegisterServiceCtrlHandler");
        return;
    }
    // These SERVICE_STATUS members remain as set here
    g_SvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_SvcStatus.dwServiceSpecificExitCode = 0;
    // Report initial status to the SCM
    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    // Perform service-specific initialization and work.
    SvcInit();
}

/*
* Initialize the service - this function is called on service startup.
*/
VOID SvcInit()
{
    RPC_STATUS status;
    g_hSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if(!g_hSvcStopEvent) {
        ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
    // Report service status pending (starting).
    ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    LeechRpcOnLoadInitialize();
    status = RpcStart(FALSE, TRUE);
    if(FAILED(status)) {
        RpcStop();
        ReportSvcStatus(SERVICE_STOPPED, status, 0);
        LeechRpcOnUnloadClose();
        return;
    }
    // Report running status when initialization is complete.
    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
    // Check whether to stop the service.
    WaitForSingleObject(g_hSvcStopEvent, INFINITE);
    RpcStop();
    LeechRpcOnUnloadClose();
    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

/*
* Sets the current service status and retports it the to the SCM.
* -- dwCurrentState = The current state (see SERVICE_STATUS).
* -- dwWin32ExitCode = The system error code.
*/
VOID ReportSvcStatus(
    DWORD dwCurrentState,
    DWORD dwWin32ExitCode,
    DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;
    // Fill in the SERVICE_STATUS structure.
    g_SvcStatus.dwCurrentState = dwCurrentState;
    g_SvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_SvcStatus.dwWaitHint = dwWaitHint;
    if(dwCurrentState == SERVICE_START_PENDING) {
        g_SvcStatus.dwControlsAccepted = 0;
    } else {
        g_SvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }
    if((dwCurrentState == SERVICE_RUNNING) ||
        (dwCurrentState == SERVICE_STOPPED)) {
        g_SvcStatus.dwCheckPoint = 0;
    } else {
        g_SvcStatus.dwCheckPoint = dwCheckPoint++;
    }
    // Report the status of the service to the SCM.
    SetServiceStatus(g_SvcStatusHandle, &g_SvcStatus);
}

/*
* SCM entry point. Called by SCM when a control code is sent to the service.
* -- dwCtrl = the control code sent to the service.
*/
VOID WINAPI SvcCtrlHandler(_In_ DWORD dwCtrl)
{
    if(dwCtrl == SERVICE_CONTROL_STOP) {
        ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(g_hSvcStopEvent);
    }
    ReportSvcStatus(g_SvcStatus.dwCurrentState, NO_ERROR, 0);
}

/*
* Log a message to the event log
* -- wszFunction = name of function that failed.
*/
VOID SvcReportEvent(LPWSTR wszFunction)
{
    HANDLE hEvtSrc;
    LPCWSTR wszStrings[2];
    WCHAR buf[80];
    hEvtSrc = RegisterEventSource(NULL, LEECHSVC_NAME);
    if(hEvtSrc) {
        StringCchPrintf(buf, 80, L"%s failed with (0x%08x).", wszFunction, GetLastError());
        wszStrings[0] = LEECHSVC_NAME;
        wszStrings[1] = buf;
        ReportEvent(hEvtSrc, EVENTLOG_ERROR_TYPE, 0, SVC_ERROR, NULL, 2, 0, wszStrings, NULL);
        DeregisterEventSource(hEvtSrc);
    }
}

/*
* Run the "service" in interactive mode - i.e. run it as a normal application.
*/
VOID LeechSvcInteractive(_In_ fInsecure)
{
    RPC_STATUS status;
    LeechRpcOnLoadInitialize();
    status = RpcStart(fInsecure, FALSE);
    if(FAILED(status)) {
        RpcStop();
        ReportSvcStatus(SERVICE_STOPPED, status, 0);
        return;
    }
    // Check whether to stop the service.
    while(TRUE) {
        Sleep(1000);
    }
    RpcStop();
    LeechRpcOnUnloadClose();
}

/*
* Check whether the specified argument exists in the wmain argument list.
*/
BOOL wmain_ExistsArg(int argc, wchar_t *argv[], LPWSTR wszArg)
{
    DWORD i;
    for(i = 1; i < (DWORD)argc; i++) {
        if(!_wcsicmp(wszArg, argv[i])) { return TRUE; }
    }
    return FALSE;
}

/*
* Main entry point of the service executable.
* -- argc = number of arguments.
* -- argv = arguments, vald arguments are: 'install' and 'uninstall'/'delete'.
*/
VOID wmain(int argc, wchar_t *argv[])
{
    BOOL fInsecure = wmain_ExistsArg(argc, argv, L"insecure");
    if(wmain_ExistsArg(argc, argv, L"interactive")) {
        LeechSvcInteractive(fInsecure);
        return;
    }
    if(wmain_ExistsArg(argc, argv, L"install")) {
        if(fInsecure) {
            printf(
                "Installation of the service in insecure/no security mode is not allowed.\n" \
                "Service requires mutually authenticated kerberos(domain membership).    \n" \
                "No insecure / no security mode may only be enabled in interactive mode. \n");
            return;
        }
        SvcInstall();
        return;
    }
    if(wmain_ExistsArg(argc, argv, L"uninstall") || wmain_ExistsArg(argc, argv, L"delete")) {
        SvcDelete();
        return;
    }
    if(fInsecure) {
        printf(
            "Starting the service in insecure/no security mode is not allowed.       \n" \
            "Service requires mutually authenticated kerberos(domain membership).    \n" \
            "No insecure / no security mode may only be enabled in interactive mode. \n");
        return;
    }
    // try to start the service - if the service start fails then it's likely
    // that we're running in interactive mode - then show legend.
    SERVICE_TABLE_ENTRY DispatchTable[] = {
        { LEECHSVC_NAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
        { NULL, NULL }};
    if(!StartServiceCtrlDispatcher(DispatchTable)) {
        SvcReportEvent(L"StartServiceCtrlDispatcher");
        printf(
            "LEECHSVC - The Leech Service:                                                 \n" \
            "                                                                              \n" \
            "The LeechService (LeechSvc) provides a way to connect to a remote instance of \n" \
            "the LeechCore library. This may allow remote control of PCILeech FPGA devices \n" \
            "over the network, or remote memory acquisition from live systems using loaded \n" \
            "WinPMEM driver - which may ease quick memory capture or incident response.    \n" \
            "                                                                              \n" \
            "The LeechService requires both the connecting computer and the target computer\n" \
            "to be a member of the same Kerberos Active Directory (AD) Domain to work. The \n" \
            "connection between the client is mutually authenticated, encrypted and also   \n" \
            "compressed by default.                                                        \n" \
            "                                                                              \n" \
            "The LeechService may be run as a service after being installed. In the service\n" \
            "mode only secure kerberos authenticated connections are allowed.              \n" \
            "                                                                              \n" \
            "The LeechService may also be run in interactive mode as a normal application  \n" \
            "by any user. (NB! some actions - such as loading the WinPMEM driver into the  \n" \
            "kernel may still require administrative privilegies). The default security    \n" \
            "mode is mutually authenticated kerberor, but the service may also be run in   \n" \
            "insecure / no security mode by supplying the 'insecure' option.               \n" \
            "                                                                              \n" \
            "Also note that the Windows Firewall must allow connecting remote clients to   \n" \
            "connect to incoming TCP port 28473.                                           \n" \
            "                                                                              \n" \
            "Syntax:                                                                       \n" \
            "leechsvc.exe install          (install the leech service)                     \n" \
            "leechsvc.exe uninstall        (uninstall the leech service)                   \n" \
            "leechsvc.exe interactive      (run the leech service as a normal application) \n" \
            "leechsvc.exe interactive insecure  (same as above, but with no security).     \n");
    }
}
