// leechagent_svc.h : definitions related to leechagent service functionality
//
// (c) Ulf Frisk, 2024-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHAGENT_SVC_H__
#define __LEECHAGENT_SVC_H__
#include <windows.h>

/*
* Log a message to the event log
* -- wszFunction = name of function that failed.
*/
VOID LeechSvc_ReportEvent(LPWSTR wszFunction);

/*
* Main entry point for the SCM.
* -- dwArgc = # of pwszArgv.
* -- pwszArgv = arguments passed from the SCM (not currently used by function).
*/
VOID WINAPI LeechSvc_SvcMain(DWORD dwArgc, LPWSTR *pwszArgv);

/*
* Run the "service" in interactive mode - i.e. run it as a normal application.
* -- pConfig
*/
VOID LeechSvc_Interactive(_In_ PLEECHSVC_CONFIG pConfig);

/*
* Install the service.
* -- szComputer = remote computer name (NULL for local computer).
* -- wszRemoteLocalPath = remote local path (including file) of LeechAgent.exe (if remote installation).
* -- return
*/
_Success_(return)
BOOL LeechSvc_Install(_In_opt_ LPWSTR wszComputer, _In_reads_opt_(MAX_PATH) LPWSTR wszRemoteLocalPathOpt);

/*
* Install the service on a remote computer using SMB to copy files and RPC to
* install the service via the remote service manager.
* -- wszComputer
* -- return
*/
_Success_(return)
BOOL LeechSvc_InstallRemoteRpc(_In_ LPWSTR wszComputer);

/*
* Delete the installed service from the services database.
* -- wszComputer = remote computer name (NULL for local computer)
* -- fSilent = do not display error messages on screen.
* -- return
*/
_Success_(return)
BOOL LeechSvc_Delete(_In_opt_ LPWSTR wszComputer, _In_ BOOL fSilent);

/*
* Remove the service on a remote computer using RPC.
* -- wszComputer = remote computer name (NULL for local computer)
* -- fSilent = do not display error messages on screen.
* -- wszRemotePathOpt = remote local path (including file) of LeechAgent.exe (if remote installation).
*/
_Success_(return)
BOOL LeechSvc_DeleteRemoteRpc(_In_ LPWSTR wszComputer, _In_ BOOL fSilent, _In_opt_ LPWSTR wszRemotePathOpt);


#endif /* __LEECHAGENT_SVC_H__ */
