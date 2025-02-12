//	leechagent.c : Implementation the LeechAgent service related functionality.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "leechagent_svc.h"
#include "leechagent_rpc.h"
#include "leechagent_proc.h"
#include "leechrpc.h"
#include "util.h"
#include <stdio.h>
#include <strsafe.h>
#define SECURITY_WIN32
#include <security.h>

//-----------------------------------------------------------------------------
// MAIN, PARSE AND HELP FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Parse the application command line arguments.
* -- argc
* -- argv
* -- pConfig
* -- return
*/
_Success_(return)
BOOL LeechSvc_ParseArgs(_In_ DWORD argc, _In_ wchar_t *argv[], _In_ PLEECHSVC_CONFIG pConfig)
{
    LPWSTR wszOpt;
    LPSTR szCurrentDirectory;
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
            wcsncpy_s(pConfig->wszRemote, _countof(pConfig->wszRemote), argv[i + 1], _TRUNCATE);
            pConfig->fInstall = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-remoteuninstall") && (i + 1 < argc)) {
            wcsncpy_s(pConfig->wszRemote, _countof(pConfig->wszRemote), argv[i + 1], _TRUNCATE);
            pConfig->fUninstall = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-remoteupdate") && (i + 1 < argc)) {
            wcsncpy_s(pConfig->wszRemote, _countof(pConfig->wszRemote), argv[i + 1], _TRUNCATE);
            pConfig->fUpdate = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-z") && (i + 1 < argc)) {
            // DumpIt.exe emits -z <filename> in livekd mode - it has no meaning
            // to the LeechAgent - but should be considered valid - so skip it!
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-no-msrpc")) {
            pConfig->fMSRPC = FALSE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc")) {
            pConfig->fgRPC = TRUE;
            i++;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-tls-p12") && (i + 1 < argc)) {
            wszOpt = argv[i + 1];
            szCurrentDirectory = "";
            if((wcslen(wszOpt) > 2) && (wszOpt[0] != '/') && (wszOpt[0] != '\\') && (wszOpt[1] != ':')) {
                szCurrentDirectory = pConfig->grpc.szCurrentDirectory;
            }
            _snprintf_s(pConfig->grpc.szTlsServerP12, _countof(pConfig->grpc.szTlsServerP12), _TRUNCATE, "%s%S", szCurrentDirectory, wszOpt);
            pConfig->fgRPC = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-client-ca") && (i + 1 < argc)) {
            wszOpt = argv[i + 1];
            szCurrentDirectory = "";
            if((wcslen(wszOpt) > 2) && (wszOpt[0] != '/') && (wszOpt[0] != '\\') && (wszOpt[1] != ':')) {
                szCurrentDirectory = pConfig->grpc.szCurrentDirectory;
            }
            _snprintf_s(pConfig->grpc.szTlsClientCaCert, _countof(pConfig->grpc.szTlsClientCaCert), _TRUNCATE, "%s%S", szCurrentDirectory, wszOpt);
            pConfig->fgRPC = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-tls-p12-password") && (i + 1 < argc)) {
            _snprintf_s(pConfig->grpc.szTlsServerP12Pass, _countof(pConfig->grpc.szTlsServerP12Pass), _TRUNCATE, "%S", argv[i + 1]);
            pConfig->fgRPC = TRUE;
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-port") && (i + 1 < argc)) {
            wcsncpy_s(pConfig->wszTcpPortGRPC, _countof(pConfig->wszTcpPortGRPC), argv[i + 1], _TRUNCATE);
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-msrpc-port") && (i + 1 < argc)) {
            wcsncpy_s(pConfig->wszTcpPortMSRPC, _countof(pConfig->wszTcpPortMSRPC), argv[i + 1], _TRUNCATE);
            i += 2;
            continue;
        } else if(0 == _wcsicmp(argv[i], L"-grpc-listen-address") && (i + 1 < argc)) {
            _snprintf_s(pConfig->grpc.szListenAddress, _countof(pConfig->grpc.szListenAddress), _TRUNCATE, "%S", argv[i + 1]);
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
    if(!pConfig->fMSRPC && !pConfig->fgRPC) {
        printf("No active transport protocol. Both MS-RPC and gRPC are disabled.\n");
        return FALSE;
    }
    if(pConfig->fgRPC && !pConfig->fInsecure && (!pConfig->grpc.szTlsClientCaCert[0] || !pConfig->grpc.szTlsServerP12[0] || !pConfig->grpc.szTlsServerP12Pass[0])) {
        printf("gRPC missing required parameters: -grpc-tls-p12, -grpc-tls-p12-password, -grpc-client-ca\n");
        return FALSE;
    }
    c += pConfig->fInstall ? 1 : 0;
    c += pConfig->fUpdate ? 1 : 0;
    c += pConfig->fUninstall ? 1 : 0;
    if(c > 1) {
        printf("Installation/Update/Uninstallation of agent may not take place simultaneously.\n");
        return FALSE;
    }
    if(pConfig->fgRPC && !pConfig->hModuleGRPC) {
        pConfig->hModuleGRPC = LoadLibraryW(LEECHGRPC_LIBRARY_NAME);
        if(!pConfig->hModuleGRPC) {
            wprintf(L"Failed to load gRPC library "LEECHGRPC_LIBRARY_NAME".\n");
            return FALSE;
        }
    }
    return TRUE;
}

#define MAX_CONFIGFILE_ARGS 100
#define MAX_CONFIGFILE_ARG_LENGTH 4096

VOID LeechSvc_ParseArgs_FromConfigFile(_In_ PLEECHSVC_CONFIG pConfig)
{
    FILE *hFile;
    DWORD i, argc = 0;
    LPWSTR argv[MAX_CONFIGFILE_ARGS] = { 0 };
    CHAR szBuffer[MAX_CONFIGFILE_ARG_LENGTH];
    WCHAR wszPath[MAX_PATH] = { 0 };
    CHAR szConfigFileName[MAX_PATH] = { 0 };
    CHAR *szToken, *ctx = NULL;
    SIZE_T cch;
    ZeroMemory(pConfig, sizeof(LEECHSVC_CONFIG));
    pConfig->fMSRPC = TRUE;
    wcscpy_s(pConfig->wszTcpPortMSRPC, _countof(pConfig->wszTcpPortMSRPC), LEECHSVC_TCP_PORT_MSRPC);
    wcscpy_s(pConfig->wszTcpPortGRPC, _countof(pConfig->wszTcpPortGRPC), LEECHSVC_TCP_PORT_GRPC);
    strcpy_s(pConfig->grpc.szListenAddress, _countof(pConfig->grpc.szListenAddress), "0.0.0.0");
    // Get the path of the directory of the executable:
    Util_GetPathDllW(wszPath, NULL);
    if(wszPath[0]) {
        _snprintf_s(pConfig->grpc.szCurrentDirectory, _countof(pConfig->grpc.szCurrentDirectory), _TRUNCATE, "%S", wszPath);
    }
    _snprintf_s(szConfigFileName, _countof(szConfigFileName), _TRUNCATE, "%S%S", wszPath, LEECHAGENT_CONFIG_FILE);
    if(fopen_s(&hFile, szConfigFileName, "r")) { return; }
    while(fgets(szBuffer, sizeof(szBuffer), hFile)) {
        while((szToken = strtok_s((ctx ? NULL : szBuffer), " \n", &ctx))) {
            cch = strlen(szToken) + 1;
            argv[argc] = LocalAlloc(LMEM_ZEROINIT, cch * sizeof(WCHAR));
            if(!argv[argc]) { return; }
            MultiByteToWideChar(CP_UTF8, 0, szToken, -1, argv[argc], (int)cch);
            argc++;
            if(argc >= MAX_CONFIGFILE_ARGS) { return; }
        }
    }
    LeechSvc_ParseArgs(argc, argv, pConfig);
    for(i = 0; i < argc; i++) {
        LocalFree(argv[i]);
    }
    fclose(hFile);
}

/*
* Print the help text to the end user.
*/
VOID LeechSvc_PrintHelp()
{
    printf(
        "LeechAgent - Remote memory acquisition and analysis:                          \n" \
        "                                                                              \n" \
        "The LeechAgent provides a way to connect to remote instances of the LeechCore \n" \
        "library. This enables remote memory acquisition from live systems using the   \n" \
        "WinPMEM driver which may ease quick memory capture or incident response.      \n" \

        "Use the agent together with MemProcFS with or without the -remotefs option!   \n" \
        "Python API based analysis is also possible by submitting a Python script.     \n" \
        "                                                                              \n" \
        "The LeechAgent supports MS-RPC over SMB (tcp/445) and TCP (tcp/28473).        \n" \
        "The LeechAgent supports Kerberos, NTLM and INSECURE (no authentication).      \n" \
        "                                                                              \n" \
        "The LeechAgent supports gRPC (tcp/28474) using mTLS or INSECURE auth.         \n" \
        "gRPC is disabled by default, enable with '-grpc' command line option.         \n" \
        "To use mTLS authentication specify:                                           \n" \
        "'-grpc-client-ca', '-grpc-tls-p12' and '-grpc-tls-p12-password'.              \n" \
        "                                                                              \n" \
        "The LeechAgent may be run as a service after being installed.  In the service \n" \
        "mode only authenticated connections are allowed. Only install the LeechAgent  \n" \
        "in service mode on Active Directory (AD) joined computers.                    \n" \
        "                                                                              \n" \
        "The LeechAgent may be installed on local systems if service is located on C:\\\n" \
        "                                                                              \n" \
        "The LeechAgent may be installed on remote systems if administrative access    \n" \
        "exists, C$ share exists and and firewall openings below exists:               \n" \
        "    - File and Printer Sharing (SMB-In).                                      \n" \
        "    - Remote Service Management (NP-In).                                      \n" \
        "    - Remote Service Management (RPC).                                        \n" \
        "    - Remote Service Management (RPC-EPMAP).                                  \n" \
        "smb:// connection method only requires the above firewall openings.           \n" \
        "rpc:// connection requires the following port to be opened: tcp/28473         \n" \
        "grpc:// connection requires the following port to be opened: tcp/28474        \n" \
        "The remote service will be installed in the C:\\Program Files\\LeechAgent\\   \n" \
        "directory of the remote system.                                               \n" \
        "                                                                              \n" \
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
        "Syntax:                                                                       \n" \
        "leechagent.exe -install                (install on local system)              \n" \
        "leechagent.exe -uninstall              (uninstall LeechAgent on local system) \n" \
        "leechagent.exe -remoteinstall localhost (install locally in program files)    \n" \
        "leechagent.exe -remoteinstall <host>   (install LeechAgent on remote system)  \n" \
        "leechagent.exe -remoteupdate <host>    (update LeechAgent on remote system)   \n" \
        "leechagent.exe -remoteuninstall localhost (uninstall from program files)      \n" \
        "leechagent.exe -remoteuninstall <host> (uninstall LeechAgent on remote system)\n" \
        "leechagent.exe -interactive            (run as a normal application)          \n" \
        "leechagent.exe -interactive -insecure  (same as above, but with no security)  \n");
}

/*
* Main entry point of the service executable.
* -- argc
* -- argv
* -- return
*/
int wmain(int argc, wchar_t *argv[])
{
    LEECHSVC_CONFIG cfg = { 0 };
    DWORD cchLocalUserUPN = MAX_PATH;
    WCHAR wszLocalUserUPN[MAX_PATH] = { 0 };
    g_LeechAgent_IsService = FALSE;
    // PARSE ARGUMENTS AND VALIDITY CHECK
    LeechSvc_ParseArgs_FromConfigFile(&cfg);
    if(!LeechSvc_ParseArgs(argc, argv, &cfg)) { return; }
	// CHILD PROCESS MODE
	if(cfg.fChildProcess) {
        LeechAgent_ProcChild_Main(argc, argv);
        return 1;
	}
    // TRY RUN SERVICE IN SERVICE MODE
    if(!(cfg.fInsecure || cfg.fInstall || cfg.fUpdate || cfg.fInteractive || cfg.fUninstall)) {
        SERVICE_TABLE_ENTRY DispatchTable[] = {
            { LEECHSVC_NAME, (LPSERVICE_MAIN_FUNCTION)LeechSvc_SvcMain },
            { NULL, NULL } };
        g_LeechAgent_IsService = TRUE;
        if(!StartServiceCtrlDispatcher(DispatchTable)) {
            LeechSvc_ReportEvent(L"StartServiceCtrlDispatcher");
            LeechSvc_PrintHelp();
            return;
        }
        return;
    }
    // UNINSTALL SERVICE
    if(cfg.fUninstall) {
        if(cfg.wszRemote[0]) {
            LeechSvc_DeleteRemoteRpc(cfg.wszRemote, FALSE, NULL);
        } else {
            LeechSvc_Delete(NULL, FALSE);
        }
        return 1;
    }
    // INSTALL SERVICE
    if(cfg.fInstall) {
        if(cfg.wszRemote[0]) {
            LeechSvc_InstallRemoteRpc(cfg.wszRemote);
        } else {
            LeechSvc_Install(cfg.wszRemote, NULL);
        }
        return 1;
    }
    // UPDATE SERVICE (UNINSTALL & INSTALL)
    if(cfg.fUpdate) {
        if(cfg.wszRemote[0]) {
            LeechSvc_DeleteRemoteRpc(cfg.wszRemote, FALSE, NULL);
            LeechSvc_InstallRemoteRpc(cfg.wszRemote);
        }
        return 1;
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
        LeechSvc_Interactive(&cfg);
        return 1;
    }
    // ERROR - SHOULD NOT HAPPEN ...
    LeechSvc_PrintHelp();
    return 1;
}
