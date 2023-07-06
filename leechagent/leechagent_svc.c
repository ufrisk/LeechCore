//	leechagent_svc.c : Implementation of service functionality.
//                     This includes the service main function as well as
//                     Install/Uninstall functionality.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "leechagent_rpc.h"
#include "leechagent_proc.h"
#include "leechrpc.h"
#include "util.h"
#include <stdio.h>
#include <strsafe.h>
#define SECURITY_WIN32
#include <security.h>

SERVICE_STATUS					g_SvcStatus;
SERVICE_STATUS_HANDLE			g_SvcStatusHandle;
HANDLE							g_hSvcStopEvent = NULL;

//-----------------------------------------------------------------------------
// REMOTE OS QUERY FOR PROGRAM FILES DIR AND BITNESS BELOW:
// In order to access the remote registry it may be necessary to temporarily
// start the remote registry service while querying for remote program files
// directory and operating system bitness (64/32-bit). After a query the remote
// registry service is restored to original state.
//-----------------------------------------------------------------------------

/*
* Retrieve the name of the program files directory of a remote computer.
* -- wszComputer
* -- szPathProgramFiles
* -- return
*/
_Success_(return)
BOOL Util_GetRemoteProgramFilesDir(_In_ LPWSTR wszComputer, _Out_writes_(MAX_PATH) LPWSTR wszPathProgramFiles)
{
    BOOL result = FALSE;
    HKEY hHKLM = NULL, hWin = NULL;
    DWORD cchPathProgramFiles = MAX_PATH - 1;
    if(ERROR_SUCCESS != RegConnectRegistryW(wszComputer, HKEY_LOCAL_MACHINE, &hHKLM)) { goto fail; }
    if(ERROR_SUCCESS != RegOpenKeyExW(hHKLM, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &hWin)) { goto fail; }
    if(ERROR_SUCCESS != RegQueryValueExW(hWin, L"ProgramFilesDir", NULL, NULL, (LPBYTE)wszPathProgramFiles, &cchPathProgramFiles)) { goto fail; }
    result = TRUE;
fail:
    if(hWin) { RegCloseKey(hWin); }
    if(hHKLM) { RegCloseKey(hHKLM); }
    return result;
}

/*
* Retrieve the operating system bitness of a remote computer.
* -- wszComputer
* -- pfIsBitness64
* -- return
*/
_Success_(return)
BOOL Util_GetRemoteOsBitness(_In_ LPWSTR wszComputer, _Out_ PBOOL pfIsBitness64)
{
    BOOL result = FALSE;
    HKEY hHKLM = NULL, hWin = NULL;
    CHAR szArch[MAX_PATH];
    DWORD cchArch = MAX_PATH - 1;
    if(ERROR_SUCCESS != RegConnectRegistryW(wszComputer, HKEY_LOCAL_MACHINE, &hHKLM)) { goto fail; }
    if(ERROR_SUCCESS != RegOpenKeyExA(hHKLM, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_READ, &hWin)) { goto fail; }
    if(ERROR_SUCCESS != RegQueryValueExA(hWin, "PROCESSOR_ARCHITECTURE", NULL, NULL, (LPBYTE)szArch, &cchArch)) { goto fail; }
    *pfIsBitness64 = (0 == _stricmp(szArch, "AMD64")) ? TRUE : FALSE;
    result = TRUE;
fail:
    if(hWin) { RegCloseKey(hWin); }
    if(hHKLM) { RegCloseKey(hHKLM); }
    return result;
}


_Success_(return)
BOOL Util_QueryRemoteProgramFilesBitness(_In_ LPWSTR wszComputer, _Out_writes_(MAX_PATH) LPWSTR wszPathProgramFiles, _Out_ PBOOL pfIsBitness64)
{
    BOOL result = FALSE;
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    SERVICE_STATUS ServiceStatus, ServiceStatus2;
    BYTE pbBuffer[0x800] = { 0 };
    DWORD cbBuffer = 0x800;
    LPQUERY_SERVICE_CONFIGW pServiceConfig = (LPQUERY_SERVICE_CONFIGW)pbBuffer;
    // get a handle to the SCM database
    printf("LeechAgent: Connecting to remote computer service manager ...\n");
    hSCManager = OpenSCManagerW(wszComputer, NULL, SC_MANAGER_ALL_ACCESS);
    if(!hSCManager) {
        printf("LeechAgent: OpenSCManager failed (0x%08x) - missing admin privileges?\n", GetLastError());
        return FALSE;
    }
    // open service
    hService = OpenServiceW(hSCManager, L"RemoteRegistry", SERVICE_ALL_ACCESS);
    if(!hSCManager) {
        printf("LeechAgent: OpenService failed (0x%08x).\n", GetLastError());
        return FALSE;
    }
    // query service status (is running?)
    if(!QueryServiceStatus(hService, &ServiceStatus)) {
        printf("LeechAgent: QueryServiceStatus failed. (%08x)\n", GetLastError());
        goto fail;
    }
    // if service not running -> start it!
    if(ServiceStatus.dwCurrentState != SERVICE_RUNNING) {
        printf("LeechAgent: Remote Registry service not started - starting ...\n");
        // get service config
        if(!QueryServiceConfigW(hService, pServiceConfig, cbBuffer, &cbBuffer)) {
            printf("LeechAgent: QueryServiceConfigW failed. (%08x)\n", GetLastError());
            goto fail;
        }
        // change service config (if needed)
        if(pServiceConfig->dwStartType == SERVICE_DISABLED) {
            if(!ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
                printf("LeechAgent: ChangeServiceConfigW failed. (%08x)\n", GetLastError());
                goto fail;
            }
        }
        // start service
        if(!StartServiceW(hService, 0, NULL)) {
            printf("LeechAgent: StartServiceW failed. (%08x)\n", GetLastError());
            goto fail;
        }
    }
    // Query remote registry
    printf("LeechAgent: Quering configuration options ...\n");
    result =
        Util_GetRemoteProgramFilesDir(wszComputer, wszPathProgramFiles) &&
        Util_GetRemoteOsBitness(wszComputer, pfIsBitness64);
    // stop service and restore config (if needed)
    if(ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
        printf("LeechAgent: Restoring Remote Registry service ...\n");
        ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus2);
        // restore config (if needed)
        if(pServiceConfig->dwStartType == SERVICE_DISABLED) {
            ChangeServiceConfigA(hService, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        }
    }
fail:
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return result;
}

//-----------------------------------------------------------------------------
// INSTALL/UNINSTALL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Delete the installed service from the services database.
* -- wszComputer = remote computer name (NULL for local computer)
* -- fSilent = do not display error messages on screen.
* -- return
*/
_Success_(return)
BOOL LeechSvc_Delete(_In_opt_ LPWSTR wszComputer, _In_ BOOL fSilent)
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_STATUS schStatusService;
    // get a handle to the SCM database
    schSCManager = OpenSCManagerW(wszComputer, NULL, SC_MANAGER_ALL_ACCESS);
    if(!schSCManager) {
        if(!fSilent) {
            printf("LeechAgent: OpenSCManager failed (0x%08x) - missing admin privileges?\n", GetLastError());
        }
        return FALSE;
    }
    // open service
    schService = OpenService(schSCManager, LEECHSVC_NAME, SERVICE_ALL_ACCESS);
    if(!schSCManager) {
        if(!fSilent) {
            printf("LeechAgent: OpenService failed (0x%08x).\n", GetLastError());
        }
        return FALSE;
    }
    // try stop service
    ControlService(schService, SERVICE_CONTROL_STOP, &schStatusService);
    // delete service
    if(!DeleteService(schService)) {
        if(!fSilent) {
            printf("LeechAgent: DeleteService failed (0x%08x).\n", GetLastError());
        }
        return FALSE;
    }
    // cleanup and return.
    if(!fSilent) {
        printf("LeechAgent: Service deleted successfully.\n");
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return TRUE;
}

/*
* Install the service.
* -- szComputer = remote computer name (NULL for local computer).
* -- wszRemoteLocalPath = remote local path (including file) of LeechAgent.exe (if remote installation).
* -- return
*/
_Success_(return)
BOOL LeechSvc_Install(_In_opt_ LPWSTR wszComputer, _In_reads_opt_(MAX_PATH) LPWSTR wszRemoteLocalPathOpt)
{
    SC_HANDLE hSCM;
    SC_HANDLE hSVC;
    WCHAR wszPath[MAX_PATH];
    SERVICE_DESCRIPTION SvcDescr = { 0 };
    SERVICE_FAILURE_ACTIONSA SvcFailureActions = { 0 };
    SC_ACTION SvcActions[1];
    // get path to executable
    if(wszRemoteLocalPathOpt) {
        wcsncpy_s(wszPath, MAX_PATH, wszRemoteLocalPathOpt, _TRUNCATE);
    } else {
        if(!GetModuleFileName(NULL, wszPath, MAX_PATH)) {
            printf("LeechAgent: Cannot install service (0x%08x).\n", GetLastError());
            return FALSE;
        }
    }
    // get a handle to the SCM database
    hSCM = OpenSCManagerW(wszComputer, NULL, SC_MANAGER_ALL_ACCESS);
    if(!hSCM) {
        printf("LeechAgent: OpenSCManager failed (0x%08x) - missing admin privileges?\n", GetLastError());
        return FALSE;
    }
    // create the service
    hSVC = CreateService(
        hSCM,                       // SCM database 
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
    if(!hSVC) {
        printf("LeechAgent: CreateService failed (0x%08x).\n", GetLastError());
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    // try set description
    SvcDescr.lpDescription = LEECHSVC_DESCR_LONG;
    ChangeServiceConfig2(hSVC, SERVICE_CONFIG_DESCRIPTION, &SvcDescr);
    // try set recovery options
    SvcActions[0].Type = SC_ACTION_RESTART;
    SvcActions[0].Delay = 5000;    // 5s
    SvcFailureActions.cActions = 1;
    SvcFailureActions.lpsaActions = SvcActions;
    SvcFailureActions.dwResetPeriod = 60 * 60 * 24;
    ChangeServiceConfig2A(hSVC, SERVICE_CONFIG_FAILURE_ACTIONS, &SvcFailureActions);
    // try start service
    StartService(hSVC, 0, NULL);
    // cleanup and return.
    printf("LeechAgent: Service installed successfully.\n");
    CloseServiceHandle(hSVC);
    CloseServiceHandle(hSCM);
    return TRUE;
}

//-----------------------------------------------------------------------------
// EXTENDED REMOTE INSTALL/UNINSTALL FUNCTIONALITY (Service + Files):
//-----------------------------------------------------------------------------

/*
* Remove the service on a remote computer using RPC.
* -- wszComputer = remote computer name (NULL for local computer)
* -- fSilent = do not display error messages on screen.
* -- wszRemotePathOpt = remote local path (including file) of LeechAgent.exe (if remote installation).
*/
_Success_(return)
BOOL LeechSvc_DeleteRemoteRpc(_In_ LPWSTR wszComputer, _In_ BOOL fSilent, _In_opt_ LPWSTR wszRemotePathOpt)
{
    SIZE_T cch;
    BOOL fIsBitness64;
    SHFILEOPSTRUCTW FO = { 0 };
    WCHAR wszRemotePath[MAX_PATH] = { 0 };
    WCHAR wszRemoteLocalPath[MAX_PATH];
    // 1: Delete remote service silently (if exists)
    LeechSvc_Delete(wszComputer, fSilent);
    // 2: Prepare doubly NULL terminated remote path to delete
    if(wszRemotePathOpt) {
        cch = wcsnlen(wszRemotePathOpt, MAX_PATH - 2) - 1;
        memcpy(wszRemotePath, wszRemotePathOpt, cch * sizeof(WCHAR));
    } else {
        if(!Util_QueryRemoteProgramFilesBitness(wszComputer, wszRemoteLocalPath, &fIsBitness64)) { return FALSE; }
        if(((wszRemoteLocalPath[0] != L'c') && (wszRemoteLocalPath[0] != L'C')) || (wszRemoteLocalPath[1] != L':')) {
            if(!fSilent) {
                wprintf(L"LeechAgent: Remote 'Program Files' directory ('%s')is not located at C: drive.\n", wszRemoteLocalPath);
            }
            return FALSE;
        }
        Util_wcsncat_s_N(wszRemotePath, MAX_PATH - 1, _TRUNCATE, L"\\\\", wszComputer, L"\\c$", wszRemoteLocalPath + 2, L"\\LeechAgent\0\0", NULL);
    }
    // 3: Delete 'Program Files\LeechAgent' directory of the remote system recursively.
    FO.wFunc = FO_DELETE;
    FO.pFrom = wszRemotePath;
    FO.fFlags = FOF_NO_UI;
    SHFileOperationW(&FO);
    if(!fSilent) {
        wprintf(L"LeechAgent: Remote '%s\\LeechAgent' directory hopefully deleted.\n", wszRemoteLocalPath);
    }
    return TRUE;
}

/*
* Install the service on a remote computer using SMB to copy files and RPC to
* install the service via the remote service manager.
* -- wszComputer
* -- return
*/
_Success_(return)
BOOL LeechSvc_InstallRemoteRpc(_In_ LPWSTR wszComputer)
{
    BOOL fIsRemoteBitness64, fIsLocalBitness64 = FALSE;
    DWORD i;
    WCHAR wszRemotePath[MAX_PATH] = { 0 };
    WCHAR wszRemoteLocalPath[MAX_PATH];
    WCHAR wszRemotePathFile[MAX_PATH];
    WCHAR wszLocalPath[MAX_PATH] = { 0 };
    WCHAR wszLocalPathFile[MAX_PATH];
    PLEECHAGENT_REMOTE_ENTRY pe;
    SHFILEOPSTRUCTW ShFO;
    Util_GetPathDllW(wszLocalPath, NULL);
#ifdef _WIN64
    fIsLocalBitness64 = TRUE;
#endif /* _WIN64 */
    // 1: Fetch 'program files' directory and operating system 'bitness' of remote computer.
    if(!Util_QueryRemoteProgramFilesBitness(wszComputer, wszRemoteLocalPath, &fIsRemoteBitness64)) {
        printf("LeechAgent: Installation failed - failed to retrieve information from registry / services.\n");
        return FALSE;
    }
    if(((wszRemoteLocalPath[0] != L'c') && (wszRemoteLocalPath[0] != L'C')) || (wszRemoteLocalPath[1] != L':')) {
        wprintf(L"LeechAgent: Remote 'Program Files' directory ('%s')is not located at C: drive.\n", wszRemoteLocalPath);
        return FALSE;
    }
    Util_wcsncat_s_N(wszRemotePath, MAX_PATH - 1, _TRUNCATE, L"\\\\", wszComputer, L"\\c$", wszRemoteLocalPath + 2, L"\\LeechAgent\\", NULL);
    if(!fIsRemoteBitness64 && fIsLocalBitness64) {
        printf("LeechAgent: Cannot install 64-bit LeechAgent on a 32-bit remote operating system.\n");
        return FALSE;
    }
    if(fIsRemoteBitness64 && !fIsLocalBitness64) {
        printf(
            "LeechAgent: WARNING - Installing 32-bit LeechAgent on remote 64-bit system! \n" \
            "      This is not recommended. Performance and feature set will be limited. \n");
    }
    LeechSvc_DeleteRemoteRpc(wszComputer, TRUE, wszRemotePath);
    // 3: Create directory (this may fail if already existing - hence return value is ignored)
    CreateDirectoryW(wszRemotePath, NULL);
    // 4: Copy required files
    for(i = 0; i < sizeof(g_REMOTE_FILES_REQUIRED) / sizeof(LEECHAGENT_REMOTE_ENTRY); i++) {
        pe = &g_REMOTE_FILES_REQUIRED[i];
        if((!fIsRemoteBitness64 && pe->f32) || (fIsRemoteBitness64 && pe->f64)) {
            ZeroMemory(wszLocalPathFile, MAX_PATH);
            ZeroMemory(wszRemotePathFile, MAX_PATH);
            Util_wcsncat_s_N(wszLocalPathFile, MAX_PATH - 1, _TRUNCATE, wszLocalPath, pe->wsz, NULL);
            Util_wcsncat_s_N(wszRemotePathFile, MAX_PATH - 1, _TRUNCATE, wszRemotePath, pe->wsz, NULL);
            if(!CopyFileW(wszLocalPathFile, wszRemotePathFile, FALSE)) {
                printf(
                    "LeechAgent: Failed. Could not copy required files to remote host.      \n" \
                    "For additional information and installation instructions please visit: \n" \
                    "https://github.com/ufrisk/LeechCore/wiki/LeechAgent                    \n");
                goto fail_cleanup_remote;
            }
        }
    }
    // 5: Copy optional files
    for(i = 0; i < sizeof(g_REMOTE_FILES_OPTIONAL) / sizeof(LEECHAGENT_REMOTE_ENTRY); i++) {
        pe = &g_REMOTE_FILES_OPTIONAL[i];
        if((!fIsRemoteBitness64 && pe->f32) || (fIsRemoteBitness64 && pe->f64)) {
            ZeroMemory(wszLocalPathFile, MAX_PATH);
            ZeroMemory(wszRemotePathFile, MAX_PATH);
            Util_wcsncat_s_N(wszLocalPathFile, MAX_PATH - 1, _TRUNCATE, wszLocalPath, pe->wsz, NULL);
            Util_wcsncat_s_N(wszRemotePathFile, MAX_PATH - 1, _TRUNCATE, wszRemotePath, pe->wsz, NULL);
            CopyFileW(wszLocalPathFile, wszRemotePathFile, FALSE);
        }
    }
    // 6: Copy optional directories
    for(i = 0; i < sizeof(g_REMOTE_DIRS_OPTIONAL) / sizeof(LEECHAGENT_REMOTE_ENTRY); i++) {
        pe = &g_REMOTE_DIRS_OPTIONAL[i];
        if((!fIsRemoteBitness64 && pe->f32) || (fIsRemoteBitness64 && pe->f64)) {
            ZeroMemory(wszLocalPathFile, MAX_PATH);
            ZeroMemory(wszRemotePathFile, MAX_PATH);
            Util_wcsncat_s_N(wszLocalPathFile, MAX_PATH - 2, _TRUNCATE, wszLocalPath, pe->wsz, NULL);
            Util_wcsncat_s_N(wszRemotePathFile, MAX_PATH - 2, _TRUNCATE, wszRemotePath, pe->wsz, NULL);
            wszLocalPathFile[wcslen(wszLocalPathFile) + 1] = '\0';      // doubly null-terminated required by SHFileOperation
            wszRemotePathFile[wcslen(wszRemotePathFile) + 1] = '\0';    // doubly null-terminated required by SHFileOperation
            ZeroMemory(&ShFO, sizeof(SHFILEOPSTRUCTW));
            ShFO.wFunc = FO_COPY;
            ShFO.fFlags = FOF_NO_UI;
            ShFO.pFrom = wszLocalPathFile;
            ShFO.pTo = wszRemotePathFile;
            SHFileOperation(&ShFO);
        }
    }
    // 7: Install and start service
    ZeroMemory(wszRemotePathFile, MAX_PATH * sizeof(WCHAR));
    Util_wcsncat_s_N(wszRemotePathFile, MAX_PATH - 1, _TRUNCATE, wszRemoteLocalPath, L"\\LeechAgent\\", g_REMOTE_FILES_REQUIRED[0].wsz, NULL);
    if(!LeechSvc_Install(wszComputer, wszRemotePathFile)) {
        goto fail_cleanup_remote;
    }
    // 8: Finish
    wprintf(L"LeechAgent: Service successfully installed on remote computer: '%s'\n", wszComputer);
    return TRUE;
fail_cleanup_remote:
    printf("LeechAgent: Cleaning up on remote system after previous failure ... \n");
    LeechSvc_DeleteRemoteRpc(wszComputer, TRUE, wszRemotePath);
    return FALSE;
}

//-----------------------------------------------------------------------------
// CORE SERVICE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Log a message to the event log
* -- wszFunction = name of function that failed.
*/
VOID LeechSvc_ReportEvent(LPWSTR wszFunction)
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
* Sets the current service status and report it the to the SCM.
* -- dwCurrentState = The current state (see SERVICE_STATUS).
* -- dwWin32ExitCode = The system error code.
*/
VOID LeechSvc_ReportSvcStatus(
    DWORD dwCurrentState,
    DWORD dwWin32ExitCode,
    DWORD dwWaitHint
) {
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
VOID WINAPI LeechSvc_SvcCtrlHandler(_In_ DWORD dwCtrl)
{
    if(dwCtrl == SERVICE_CONTROL_STOP) {
        LeechSvc_ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(g_hSvcStopEvent);
        LeechSvc_ReportSvcStatus(g_SvcStatus.dwCurrentState, NO_ERROR, 0);
        LeechRpcOnUnloadClose();
        return;
    }
    LeechSvc_ReportSvcStatus(g_SvcStatus.dwCurrentState, NO_ERROR, 0);
}

/*
* Initialize the service - this function is called on service startup.
*/
VOID LeechSvc_SvcInit()
{
    RPC_STATUS status;
    g_hSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if(!g_hSvcStopEvent) {
        LeechSvc_ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
    // Report service status pending (starting).
    LeechSvc_ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    LeechRpcOnLoadInitialize();
    status = RpcStart(FALSE, TRUE);
    if(FAILED(status)) {
        RpcStop();
        LeechSvc_ReportSvcStatus(SERVICE_STOPPED, status, 0);
        LeechRpcOnUnloadClose();
        return;
    }
    // Report running status when initialization is complete.
    LeechSvc_ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
    // Check whether to stop the service.
    WaitForSingleObject(g_hSvcStopEvent, INFINITE);
    RpcStop();
    LeechRpcOnUnloadClose();
    LeechSvc_ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

/*
* Main entry point for the SCM.
* -- dwArgc = # of pwszArgv.
* -- pwszArgv = arguments passed from the SCM (not currently used by function).
*/
VOID WINAPI LeechSvc_SvcMain(DWORD dwArgc, LPWSTR *pwszArgv)
{
    // Register the handler function for the service
    g_SvcStatusHandle = RegisterServiceCtrlHandler(LEECHSVC_NAME, LeechSvc_SvcCtrlHandler);
    if(!g_SvcStatusHandle) {
        LeechSvc_ReportEvent(L"RegisterServiceCtrlHandler");
        return;
    }
    // These SERVICE_STATUS members remain as set here
    g_SvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_SvcStatus.dwServiceSpecificExitCode = 0;
    // Report initial status to the SCM
    LeechSvc_ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    // Perform service-specific initialization and work.
    LeechSvc_SvcInit();
}

/*
* Run the "service" in interactive mode - i.e. run it as a normal application.
* -- fInsecure
*/
VOID LeechSvc_Interactive(_In_ BOOL fInsecure)
{
    RPC_STATUS status;
    LeechRpcOnLoadInitialize();
    status = RpcStart(fInsecure, FALSE);
    if(FAILED(status)) {
        RpcStop();
        LeechSvc_ReportSvcStatus(SERVICE_STOPPED, status, 0);
        return;
    }
    // Check whether to stop the service.
    while(TRUE) {
        Sleep(1000);
    }
    RpcStop();
    LeechRpcOnUnloadClose();
}
