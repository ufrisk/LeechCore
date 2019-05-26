//	leechagent.c : Implementation the LeechAgent service related functionality.
//
// (c) Ulf Frisk, 2018-2019
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

typedef struct tdLEECHAGENT_REMOTE_ENTRY {
    BOOL f32;
    BOOL f64;
    LPWSTR wsz;
} LEECHAGENT_REMOTE_ENTRY, *PLEECHAGENT_REMOTE_ENTRY;

LEECHAGENT_REMOTE_ENTRY g_REMOTE_FILES_REQUIRED[] = {
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"leechagent.exe"}, // LeechAgent is required to be 1st entry (used in service creation)
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"leechcore.dll"},
	{.f32 = TRUE,.f64 = TRUE,.wsz = L"vcruntime140.dll"},
};
LEECHAGENT_REMOTE_ENTRY g_REMOTE_FILES_OPTIONAL[] = {
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmm.dll"},
    // Python APIs for LeechCore and MemProcFS
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmmpyc.pyd"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"leechcorepyc.pyd"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmmpy.py"},
    // 32-bit winpmem
    {.f32 = TRUE,.f64 = FALSE,.wsz = L"att_winpmem_32.sys"},
    {.f32 = TRUE,.f64 = FALSE,.wsz = L"winpmem_32.sys"},
    {.f32 = TRUE,.f64 = FALSE,.wsz = L"winpmem_x86.sys"},
    // 64-bit winpmem
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"att_winpmem_64.sys"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"winpmem_64.sys"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"winpmem_x64.sys"},
    // 64-bit HyperV saved state
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmsavedstatedumpprovider.dll"},
    // 32/64-bit FTDI driver (PCIe DMA FPGA)
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"FTD3XX.dll"},
};
LEECHAGENT_REMOTE_ENTRY g_REMOTE_DIRS_OPTIONAL[] = {
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Python"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Plugins"},
};

typedef struct tdLEECHAGENT_CONFIG {
    BOOL fInstall;
    BOOL fUpdate;
    BOOL fUninstall;
    BOOL fInteractive;
    BOOL fInsecure;
	BOOL fChildProcess;
    WCHAR wszRemote[MAX_PATH];
} LEECHSVC_CONFIG, *PEECHSVC_CONFIG;

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
BOOL SvcDelete(_In_opt_ LPWSTR wszComputer, _In_ BOOL fSilent)
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
BOOL SvcInstall(_In_opt_ LPWSTR wszComputer, _In_reads_opt_(MAX_PATH) LPWSTR wszRemoteLocalPathOpt)
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
    hSCM = OpenSCManagerW(
        wszComputer,
        NULL,
        SC_MANAGER_ALL_ACCESS);
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

_Success_(return)
BOOL SvcDeleteRemote(_In_ LPWSTR wszComputer, _In_ BOOL fSilent, _In_opt_ LPWSTR wszRemotePathOpt)
{
    SIZE_T cch;
    BOOL fIsBitness64;
    SHFILEOPSTRUCTW FO = { 0 };
    WCHAR wszRemotePath[MAX_PATH] = { 0 };
    WCHAR wszRemoteLocalPath[MAX_PATH];
    // 1: Delete remote service silently (if exists)
    SvcDelete(wszComputer, fSilent);
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

_Success_(return)
BOOL SvcInstallRemote(_In_ LPWSTR wszComputer)
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
    SvcDeleteRemote(wszComputer, TRUE, wszRemotePath);
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
    ZeroMemory(wszRemotePathFile, MAX_PATH);
    Util_wcsncat_s_N(wszRemotePathFile, MAX_PATH - 1, _TRUNCATE, wszRemoteLocalPath, L"\\LeechAgent\\", g_REMOTE_FILES_REQUIRED[0].wsz, NULL);
    if(!SvcInstall(wszComputer, wszRemotePathFile)) {
        goto fail_cleanup_remote;
    }
    // 8: Finish
    wprintf(L"LeechAgent: Service successfully installed on remote computer: '%s'\n", wszComputer);
    return TRUE;
fail_cleanup_remote:
    printf("LeechAgent: Cleaning up on remote system after previous failure ... \n");
    SvcDeleteRemote(wszComputer, TRUE, wszRemotePath);
    return FALSE;
}

//-----------------------------------------------------------------------------
// CORE SERVICE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

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
        ReportSvcStatus(g_SvcStatus.dwCurrentState, NO_ERROR, 0);
        LeechRpcOnUnloadClose();
        return;
    }
    ReportSvcStatus(g_SvcStatus.dwCurrentState, NO_ERROR, 0);
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
* Run the "service" in interactive mode - i.e. run it as a normal application.
* -- fInsecure
*/
VOID LeechSvcInteractive(_In_ BOOL fInsecure)
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

//-----------------------------------------------------------------------------
// MAIN, PARSE AND HELP FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Parse the application command line arguments.
* -- argc
* -- argc
* -- pConfig
* -- return
*/
_Success_(return)
BOOL LeechSvc_ParseArgs(_In_ DWORD argc, _In_ wchar_t *argv[], _In_ PEECHSVC_CONFIG pConfig)
{
    DWORD c = 0, i = 1;
    while(i < argc) {
        if((0 == _wcsicmp(argv[i], L"-install")) || (0 == _wcsicmp(argv[i], L"install"))) {
            pConfig->fInstall = TRUE;
            i++;
            continue;
        } else if((0 == _wcsicmp(argv[i], L"-uninstall")) || (0 == _wcsicmp(argv[i], L"uninstall")) || (0 == _wcsicmp(argv[i], L"delete"))) {
            pConfig->fUninstall = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-insecure")) {
            pConfig->fInsecure = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-interactive")) {
            pConfig->fInteractive = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-child")) {
            pConfig->fChildProcess = TRUE;
            return TRUE;
        } else if(0 == _wcsicmp(argv[i], L"-remoteinstall") && (i + 1 < argc)) {
            wcscpy_s(pConfig->wszRemote, MAX_PATH - 1, argv[i + 1]);
            pConfig->fInstall = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-remoteuninstall") && (i + 1 < argc)) {
            wcscpy_s(pConfig->wszRemote, MAX_PATH - 1, argv[i + 1]);
            pConfig->fUninstall = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-remoteupdate") && (i + 1 < argc)) {
            wcscpy_s(pConfig->wszRemote, MAX_PATH - 1, argv[i + 1]);
            pConfig->fUpdate = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-z") && (i + 1 < argc)) {
            // DumpIt.exe emits -z <filename> in livekd mode - it has no meaning
            // to the LeechAgent - but should be considered valid - so skip it!
            i += 2;
            continue;
        }
        wprintf(L"LeechAgent: invalid argument '%s'\n", argv[i]);
        return FALSE;
    }
    if(pConfig->fUpdate && !pConfig->wszRemote[0]) {
        printf("LeechAgent: Only possible to update remote service.");
        return FALSE;
    }
    if((pConfig->fInstall || pConfig->fUpdate) && (pConfig->fInsecure || pConfig->fInteractive)) {
        printf(
            "Installation of the service in insecure/no security mode is not allowed.\n" \
            "Service requires mutually authenticated kerberos(domain membership).    \n" \
            "No insecure / no security mode may only be enabled in interactive mode. \n");
        return FALSE;
    }
    c += pConfig->fInstall ? 1 : 0;
    c += pConfig->fUpdate ? 1 : 0;
    c += pConfig->fUninstall ? 1 : 0;
    if(c > 1) {
        printf("Installation/Update/Uninstallation of agent may not take place simultaneously.\n");
        return FALSE;
    }
    return TRUE;
}

/*
* Print the help text to the end user.
*/
VOID LeechSvc_PrintHelp()
{
    printf(
        "LeechAgent - The Leech Agent for Remote memory acquisition and analysis:      \n" \
        "                                                                              \n" \
        "The LeechAgent provides a way to connect to a remote instance of the LeechCore\n" \
        "library. This may allow remote control of PCILeech FPGA devices over a network\n" \
        ", or remote memory acquisition from live systems using loaded WinPMEM driver -\n" \
        "which may ease quick memory capture or incident response.If a Python/MemProcFS\n" \
        "environment is available it also allows for remote Python API based analysis  \n" \
        "of memory by the means of submitting a remote Python script.                  \n" \
        "                                                                              \n" \
        "The LeechAgent requires both the connecting computer and the target computer  \n" \
        "to be a member of the same Kerberos Active Directory (AD) Domain to work. The \n" \
        "connection between the client is by default mutually authenticated, encrypted \n" \
        "and compressed.                                                               \n" \
        "                                                                              \n" \
        "The LeechAgent may be run as a service after being installed.  In the service \n" \
        "mode only secure kerberos authenticated connections are allowed. Only install \n" \
        "the LeechAgent in service mode on Active Directory (AD) joined computers.     \n" \
        "                                                                              \n" \
        "The LeechAgent may be installed on local systems if service is located on C:\\\n" \
        "                                                                              \n" \
        "The LeechAgent may be installed on remote systems if administrative access    \n" \
        "exists, C$ share exists and and firewall openings for:                        \n" \
        "    - File and Printer Sharing (SMB-In).                                      \n" \
        "    - Remote Service Management (NP-In).                                      \n" \
        "    - Remote Service Management (RPC).                                        \n" \
        "    - Remote Service Management (RPC-EPMAP).                                  \n" \
        "    - LeechSvc / port: tcp/28473.                                             \n" \
        "The remote service will be installed in the C:\\Program Files\\LeechAgent\\   \n" \
        "directory of the remote system. Once installed only tcp/28473 is required.    \n" \

        "The LeechAgent requires external files and software. For instructions how to  \n" \
        "prepare the agent for local or remote installation please visit:              \n" \
        "https://github.com/ufrisk/LeechCore/wiki/LeechAgent                           \n" \
        "                                                                              \n" \
        "The LeechAgent may also be run in interactive mode as a normal application    \n" \
        "by any user. (NB! some actions - such as loading the WinPMEM driver into the  \n" \
        "kernel may still require administrative privilegies). The default security    \n" \
        "mode is mutually authenticated kerberor, but the service may also be run in   \n" \
        "insecure / no security mode by supplying the 'insecure' option.               \n" \
        "WARNING! - LeechAgent provides means of REMOTE CODE EXECUTION and it is very  \n" \
        "insecure in insecure mode! Please only use in lab environments at own risk!   \n" \
        "                                                                              \n" \
        "Also note that the Windows Firewall must allow connecting remote clients to   \n" \
        "connect to incoming port tcp/28473.                                           \n" \
        "                                                                              \n" \
        "Syntax:                                                                       \n" \
        "leechagent.exe -install                (install LeechAgent on local system)   \n" \
        "leechagent.exe -uninstall              (uninstall LeechAgent on local system) \n" \
        "leechagent.exe -remoteinstall <host>   (install LeechAgent on remote system)  \n" \
        "leechagent.exe -remoteupdate <host>    (update LeechAgent on remote system)   \n" \
        "leechagent.exe -remoteuninstall <host> (uninstall LeechAgent on remote system)\n" \
        "leechagent.exe -interactive            (run as a normal application)          \n" \
        "leechagent.exe -interactive -insecure  (same as above, but with no security)  \n");
}

/*
* Main entry point of the service executable.
* -- argc = number of arguments.
* -- argv = arguments, vald arguments are: 'install' and 'uninstall'/'delete'.
*/
VOID wmain(int argc, wchar_t *argv[])
{
    LEECHSVC_CONFIG cfg = { 0 };
    DWORD cchLocalUserUPN = MAX_PATH;
    WCHAR wszLocalUserUPN[MAX_PATH] = { 0 };
    g_LeechAgent_IsService = FALSE;
    // PARSE ARGUMENTS AND VALIDITY CHECK
    if(!LeechSvc_ParseArgs(argc, argv, &cfg)) { return; }
	// CHILD PROCESS MODE
	if(cfg.fChildProcess) {
        LeechAgent_ProcChild_Main(argc, argv);
        return;
	}
    // TRY RUN SERVICE IN SERVICE MODE
    if(!(cfg.fInsecure || cfg.fInstall || cfg.fUpdate || cfg.fInteractive || cfg.fUninstall)) {
        SERVICE_TABLE_ENTRY DispatchTable[] = {
            { LEECHSVC_NAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
            { NULL, NULL } };
        g_LeechAgent_IsService = TRUE;
        if(!StartServiceCtrlDispatcher(DispatchTable)) {
            SvcReportEvent(L"StartServiceCtrlDispatcher");
            LeechSvc_PrintHelp();
            return;
        }
        return;
    }
    // UNINSTALL SERVICE
    if(cfg.fUninstall) {
        if(cfg.wszRemote[0]) {
            SvcDeleteRemote(cfg.wszRemote, FALSE, NULL);
        } else {
            SvcDelete(NULL, FALSE);
        }
        return;
    }
    // INSTALL SERVICE
    if(cfg.fInstall) {
        if(cfg.wszRemote[0]) {
            SvcInstallRemote(cfg.wszRemote);
        } else {
            SvcInstall(cfg.wszRemote, NULL);
        }
        return;
    }
    // UPDATE SERVICE (UNINSTALL & INSTALL)
    if(cfg.fUpdate) {
        if(cfg.wszRemote[0]) {
            SvcDeleteRemote(cfg.wszRemote, FALSE, NULL);
            SvcInstallRemote(cfg.wszRemote);
        }
        return;
    }
    // RUN SERVICE IN INTERACTIVE MODE
    if(cfg.fInteractive) {
        if(cfg.fInsecure) {
            GetUserNameExW(NameUserPrincipal, wszLocalUserUPN, &cchLocalUserUPN);
            while(cchLocalUserUPN > 0) {
                cchLocalUserUPN--;
                if(wszLocalUserUPN[cchLocalUserUPN] == L'$') {
                    printf("LeechAgent: Insecure mode note allowed when running in SYSTEM context in AD environment.\n");
                }
            }
        }
        LeechSvcInteractive(cfg.fInsecure);
        return;
    }
    // ERROR - SHOULD NOT HAPPEN ...
    LeechSvc_PrintHelp();
}
