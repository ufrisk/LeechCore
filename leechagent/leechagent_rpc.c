// leechsvc_rpc.c : implementation of RPC related functionality.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "leechagent_rpc.h"
#include "leechrpc_h.h"
#include "leechrpc.h"
#include <stdio.h>
#include <lm.h>
#define SECURITY_WIN32
#include <security.h>

RPC_BINDING_VECTOR *g_rpc_pbindingVector = NULL;

VOID LeechSvcRpc_WriteInfoEventLog(_In_z_ _Printf_format_string_ char const* const _Format, ...)
{
    CHAR szBuffer[0x1000] = { 0 };
    va_list argptr;
    HANDLE hEventInfoLog;
    DWORD dwSize;
    LPSTR szArgs[2] = { "LeechAgent:", "" };
    va_start(argptr, _Format);
    dwSize = (DWORD)vsnprintf(szBuffer, 0x1000 - 1, _Format, argptr);
    va_end(argptr);
    if(!dwSize) { return; }
    hEventInfoLog = RegisterEventSourceA(NULL, "LeechAgent");
    if(!hEventInfoLog) { return; }
    szArgs[1] = szBuffer;
    ReportEventA(
        hEventInfoLog,
        EVENTLOG_INFORMATION_TYPE,
        0,
        42666,
        NULL,
        2,
        0,
        (LPCSTR*)&szArgs,
        NULL
    );
    printf("%s", szBuffer);
    DeregisterEventSource(hEventInfoLog);
}

/*
* RPC callback function to authorize the connecting user. The user is will be
* authorized if it's a member of the Local 'Administrators' group.
*/
RPC_STATUS CALLBACK LeechSvcRpc_SecurityCallback(RPC_IF_HANDLE InterfaceUuid, void *Context)
{
    RPC_STATUS status;
    BYTE pbAdminSID[SECURITY_MAX_SID_SIZE] = { 0 };
    DWORD cbAdminSID;
    WCHAR wszAdministrators[MAX_PATH] = { 0 }, wszDummy[MAX_PATH] = { 0 };
    DWORD cchAdministrators = MAX_PATH, cchDummy = MAX_PATH;
    SID_NAME_USE SidNameUseAdministrators;
    DWORD cchUser = MAX_PATH;
    DWORD cchRemoteUserUPN = MAX_PATH;
    WCHAR wszUser[MAX_PATH] = { 0 };
    WCHAR wszRemoteUserUPN[MAX_PATH] = { 0 };
    CHAR szTime[MAX_PATH];
    BOOL result;
    DWORD cEntries, cTotalEntries;
    PBYTE pbLocalGroups;
    PLOCALGROUP_USERS_INFO_0 pLocalGroupInfo;
    DWORD i;
    NET_API_STATUS netApiStatus;
    // 1: Retrieve name of 'Administrators' local group (system may not be English).
    cbAdminSID = SECURITY_MAX_SID_SIZE;
    result = CreateWellKnownSid(WinBuiltinAdministratorsSid, 0, &pbAdminSID, &cbAdminSID);
    if(!result) { return RPC_S_ACCESS_DENIED; }
    result = LookupAccountSidW(NULL, (PSID)pbAdminSID, wszAdministrators, &cchAdministrators, wszDummy, &cchDummy, &SidNameUseAdministrators);
    if(!result) { return RPC_S_ACCESS_DENIED; }
    // 2: Impersonate connecting user for user name retrieval only
    status = RpcImpersonateClient(Context);
    if(status) { return RPC_S_ACCESS_DENIED; }
    result = GetUserNameExW(NameSamCompatible, wszUser, &cchUser);
    GetUserNameExW(NameUserPrincipal, wszRemoteUserUPN, &cchRemoteUserUPN);
    if((RPC_S_OK != RpcRevertToSelf()) || !result) { return RPC_S_ACCESS_DENIED; }
    // 3: Retrieve local groups (recursively) that the user is member of
    //    and check if name matches administrator group ...
    netApiStatus = NetUserGetLocalGroups(NULL, wszUser, 0, LG_INCLUDE_INDIRECT, &pbLocalGroups, MAX_PREFERRED_LENGTH, &cEntries, &cTotalEntries);
    if(netApiStatus) { return RPC_S_ACCESS_DENIED; }
    LeechSvc_GetTimeStamp(szTime);
    for(i = 0; i < cEntries; i++) {
        pLocalGroupInfo = ((PLOCALGROUP_USERS_INFO_0)pbLocalGroups) + i;
        if(!wcscmp(wszAdministrators, pLocalGroupInfo->lgrui0_name)) {
            NetApiBufferFree(pbLocalGroups);
            LeechSvcRpc_WriteInfoEventLog("[%s] LeechAgent:  INFO: User authentication: '%S'\n", szTime, wszRemoteUserUPN);
            return RPC_S_OK;
        }
    }
    NetApiBufferFree(pbLocalGroups);
    // Fail
    LeechSvcRpc_WriteInfoEventLog("[%s] LeechAgent:  FAIL: User authentication '%S' - not in Administrators group?\n", szTime, wszRemoteUserUPN);
    return RPC_S_ACCESS_DENIED;
}

RPC_STATUS CALLBACK LeechSvcRpc_SecurityCallback_AlwaysAllow(RPC_IF_HANDLE InterfaceUuid, void *Context)
{
    return RPC_S_OK;
}

RPC_STATUS RpcStart(_In_ BOOL fInsecure, _In_ BOOL fSvc)
{
    RPC_STATUS status;
    RPC_CSTR szSPN = NULL;
    // start listening on network (ncacn_ip_tcp - 0.0.0.0:28473).
    status = RpcServerUseProtseqEpA("ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, "28473", NULL);
    if(status) {
        printf("Failed: RPC: RpcServerUseProtseqEpA (0x%08x).\n", status);
        return status;
    }
    // Register the interface.
    status = RpcServerRegisterIf2(
        LeechRpc_v1_0_s_ifspec,
        NULL,
        NULL,
        RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        0x02800000,
        fInsecure ? LeechSvcRpc_SecurityCallback_AlwaysAllow : LeechSvcRpc_SecurityCallback
    );
    if(status) {
        printf("Failed: RPC: RpcServerRegisterIf2 (0x%08x).\n", status);
        return status;
    }
    // Register interface and binding with the endpoint mapper.
    status = RpcServerInqBindings(&g_rpc_pbindingVector);
    if(status) {
        printf("Failed: RPC: RpcServerInqBindings (0x%08x).\n", status);
        g_rpc_pbindingVector = NULL;
        return status;
    }
#pragma warning(suppress: 6102)
    status = RpcEpRegister(LeechRpc_v1_0_s_ifspec, g_rpc_pbindingVector, 0, LEECHSVC_TCP_PORT);
    if(status) {
        printf("Failed: RPC: RpcServerInqBindings (0x%08x).\n", status);
        return status;
    }
    // Set security mode.
    if(fInsecure) {
        printf(
            "WARNING! Starting LeechAgent in INSECURE mode! WARNING any user may\n" \
            "     connect unauthenticated to service unless properly firewalled!\n" \
            "     Ensure that port tcp/28473 is properly configured in firewall!\n" \
            "WARNING! UNAUTHENTICATED REMOTE CODE EXECUTION! LeechAgent contains\n" \
            "     agent-style functionality that allows unauthenticated users to\n" \
            "     execute arbitrary code. Use INSECURE mode with caution!\n" );
    } else {
        // enable kerberos security.
        status = RpcServerInqDefaultPrincNameA(RPC_C_AUTHN_GSS_KERBEROS, &szSPN);
        if(status) { 
            printf("Failed: RPC: RpcServerInqDefaultPrincNameA (0x%08x).\n", status);
            RpcStringFreeA(&szSPN); 
            return status; 
        }
        status = RpcServerRegisterAuthInfoA(szSPN, RPC_C_AUTHN_GSS_KERBEROS, NULL, NULL);
        if(status) {
            printf("Failed: RPC: RpcServerRegisterAuthInfoA - SPN: '%s' (0x%08x).\n", szSPN, status);
            RpcStringFreeA(&szSPN);
            return status;
        }
        printf(
            "LeechAgent starting with kerberos SPN: ' %s '\n" \
            "    (specify the SPN value in client connection string).\n" \
            "    (ensure that port tcp/28473 is open in firewall).   \n",
            szSPN);
        if(fSvc) {
            LeechSvcRpc_WriteInfoEventLog("LeechAgent started with kerberos SPN: %s\n", szSPN);
        }
        RpcStringFreeA(&szSPN);
    }
    // start accept calls and return.
    status = RpcServerListen(1, 64, TRUE);
    if(status) {
        printf("Failed: RPC: RpcServerListen (0x%08x).\n", status);
        return status;
    }
    return RPC_S_INTERNAL_ERROR;
}

void RpcStop()
{
#pragma warning(suppress: 6031)
    RpcEpUnregister(LeechRpc_v1_0_s_ifspec, g_rpc_pbindingVector, 0);
    RpcBindingVectorFree(&g_rpc_pbindingVector);
    g_rpc_pbindingVector = NULL;
}
