// leechsvc_rpc.c : implementation of RPC related functionality.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "leechagent_rpc.h"
#include "leechrpc_h.h"
#include "leechrpc.h"
#include <stdio.h>
#define SECURITY_WIN32
#include <security.h>
#include <sddl.h>
#include <leechgrpc.h>

// MS-RPC:
RPC_BINDING_VECTOR *g_rpc_pbindingVector = NULL;

// gRPC:
HANDLE g_hGRPC = NULL;

pfn_leechgrpc_server_create_insecure g_pfn_leechgrpc_server_create_insecure;
pfn_leechgrpc_server_create_secure_p12 g_pfn_leechgrpc_server_create_secure_p12;
pfn_leechgrpc_server_shutdown g_pfn_leechgrpc_server_shutdown;
VOID LeechGRPC_ReservedSubmitCommand(_In_opt_ PVOID ctx, _In_ PBYTE pbIn, _In_ SIZE_T cbIn, _Out_ PBYTE *ppbOut, _Out_ SIZE_T *pcbOut);

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
* In a NTLM authentication scenario CheckTokenMembership() may fail.
* Perform a secondary check to see if the user is a member of the local administrators group.
* -- hImpersonationToken: The impersonation token of the connecting user.
* -- return: TRUE if the user is a member of the local administrators group, FALSE otherwise.
*/
BOOL LeechSvcRpc_SecurityCallback_IsAdminNtlm(_In_ HANDLE hImpersonationToken)
{
    BOOL fResult = FALSE;
    DWORD i, cbTokenInfoLength = 0;
    PTOKEN_GROUPS pTokenGroups = NULL;
    LPWSTR wszSID = NULL;
    if(!GetTokenInformation(hImpersonationToken, TokenGroups, NULL, 0, &cbTokenInfoLength) && (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) { goto fail; }
    if(!(pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LMEM_ZEROINIT, cbTokenInfoLength))) { goto fail; }
    if(!GetTokenInformation(hImpersonationToken, TokenGroups, pTokenGroups, cbTokenInfoLength, &cbTokenInfoLength)) { goto fail; }
    for(i = 0; i < pTokenGroups->GroupCount; i++) {
        if(!ConvertSidToStringSidW(pTokenGroups->Groups[i].Sid, &wszSID) || !wszSID) {
            continue;
        }
        if(!wcscmp(wszSID, L"S-1-5-32-544")) {
            fResult = TRUE;
            break;
        }
        LocalFree(wszSID); wszSID = NULL;
    }
fail:
    LocalFree(pTokenGroups);
    LocalFree(wszSID);
    return fResult;
}

/*
* RPC callback function to authorize the connecting user. The user is will be
* authorized if it's a member of the Local 'Administrators' group.
* NB! if user is connecting locally - the user must be an elevated admin.
*/
RPC_STATUS CALLBACK LeechSvcRpc_SecurityCallback(RPC_IF_HANDLE InterfaceUuid, void *Context)
{
    BOOL result, fIsImpersonated = FALSE, fIsRpcUserAdministrator = FALSE, fIsSamAccountNameFormat = FALSE;
    PSID pAdministratorsGroupSID = NULL;
    CHAR szTime[MAX_PATH];
    WCHAR wszRemoteUserUPN[MAX_PATH] = { 0 };
    DWORD cchRemoteUserUPN = MAX_PATH;
    HANDLE hImpersonationToken = 0;
    SID_IDENTIFIER_AUTHORITY NtAuthoritySID = SECURITY_NT_AUTHORITY;
    LeechSvc_GetTimeStamp(szTime);
    if(!AllocateAndInitializeSid(&NtAuthoritySID, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroupSID)) { goto fail; }
    if(RPC_S_OK != RpcImpersonateClient(Context)) { goto fail; }
    fIsImpersonated = TRUE;
    if(!GetUserNameExW(NameUserPrincipal, wszRemoteUserUPN, &cchRemoteUserUPN)) {
        fIsSamAccountNameFormat = GetUserNameExW(NameSamCompatible, wszRemoteUserUPN, &cchRemoteUserUPN);
    }
    if(!OpenThreadToken(GetCurrentThread(), TOKEN_READ, TRUE, &hImpersonationToken)) { goto fail; }
    result = CheckTokenMembership(hImpersonationToken, pAdministratorsGroupSID, &fIsRpcUserAdministrator);
    if(result && !fIsRpcUserAdministrator && fIsSamAccountNameFormat) {
        fIsRpcUserAdministrator = LeechSvcRpc_SecurityCallback_IsAdminNtlm(hImpersonationToken);
    }
    if(result && fIsRpcUserAdministrator) {
        LeechSvcRpc_WriteInfoEventLog("[%s] LeechAgent:  INFO: User authentication: '%S'\n", szTime, wszRemoteUserUPN);
    } else {
        LeechSvcRpc_WriteInfoEventLog("[%s] LeechAgent:  FAIL: User authentication: '%S' - not in Administrators group?\n", szTime, wszRemoteUserUPN);
        fIsRpcUserAdministrator = FALSE;
    }
fail:
    if(fIsImpersonated) {
        if(RPC_S_OK != RpcRevertToSelf()) {
            fIsRpcUserAdministrator = FALSE;
        }
    }
    if(hImpersonationToken) { CloseHandle(hImpersonationToken); }
    if(pAdministratorsGroupSID) { FreeSid(pAdministratorsGroupSID); }
    return fIsRpcUserAdministrator ? RPC_S_OK : RPC_S_ACCESS_DENIED;
}

RPC_STATUS CALLBACK LeechSvcRpc_SecurityCallback_AlwaysAllow(RPC_IF_HANDLE InterfaceUuid, void *Context)
{
    return RPC_S_OK;
}

VOID RpcStopGRPC()
{
    if(g_hGRPC) {
        g_pfn_leechgrpc_server_shutdown(g_hGRPC);
        g_hGRPC = NULL;
    }
}

_Success_(return)
BOOL RpcStartGRPC(_In_ PLEECHSVC_CONFIG pConfig)
{
    DWORD dwTcpPort = 0;
    if(!pConfig->hModuleGRPC) {
        printf("Failed: gRPC: library 'leechgrpc.dll' missing - gRPC functionality is disabled.\n");
        return FALSE;
    }
    dwTcpPort = _wtoi(pConfig->wszTcpPortGRPC);
    if(!dwTcpPort) {
        printf("Failed: gRPC: Invalid port number '%i' - gRPC functionality is disabled.\n", dwTcpPort);
        return FALSE;
    }
    g_pfn_leechgrpc_server_create_insecure = (pfn_leechgrpc_server_create_insecure)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_create_insecure");
    g_pfn_leechgrpc_server_create_secure_p12 = (pfn_leechgrpc_server_create_secure_p12)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_create_secure_p12");
    g_pfn_leechgrpc_server_shutdown = (pfn_leechgrpc_server_shutdown)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_shutdown");
    if(!g_pfn_leechgrpc_server_create_insecure || !g_pfn_leechgrpc_server_create_secure_p12 || !g_pfn_leechgrpc_server_shutdown) {
        printf("Failed: gRPC: library 'leechgrpc.dll' missing required functions, gRPC functionality is disabled.\n");
        RpcStopGRPC();
        return FALSE;
    }
    if(pConfig->fInsecure) {
        g_hGRPC = g_pfn_leechgrpc_server_create_insecure(
            pConfig->grpc.szListenAddress,
            dwTcpPort,
            NULL,
            LeechGRPC_ReservedSubmitCommand
        );
    } else {
        g_hGRPC = g_pfn_leechgrpc_server_create_secure_p12(
            pConfig->grpc.szListenAddress,
            dwTcpPort,
            NULL, LeechGRPC_ReservedSubmitCommand,
            pConfig->grpc.szTlsClientCaCert,
            pConfig->grpc.szTlsServerP12,
            pConfig->grpc.szTlsServerP12Pass
        );
    }
    if(!g_hGRPC) {
        printf("Failed: gRPC: initialization failed, gRPC functionality is disabled.\n");
        RpcStopGRPC();
        return FALSE;
    }
    if(pConfig->fInsecure) {
        printf(
            "WARNING! Starting LeechAgent in INSECURE gRPC mode!                \n" \
            "     Any user may connect unauthenticated unless firewalled!       \n" \
            "     Ensure that port tcp/%i is properly configured in firewall!\n" \
            "                                                                   \n", dwTcpPort);
    } else {
        printf(
            "INFO: Starting LeechAgent in gRPC mTLS mode!                       \n" \
            "     Ensure that port tcp/%i is properly configured in firewall!\n" \
            "                                                                   \n", dwTcpPort);
    }
    return TRUE;
}

RPC_STATUS RpcStartMSRPC(_In_ BOOL fInsecure, _In_ BOOL fSvc)
{
    RPC_STATUS status;
    RPC_CSTR szSPN = NULL;
    // start listening on network (ncacn_ip_tcp - 0.0.0.0:28473)
    // and on local pipe (ncacn_np - \\pipe\\LeechAgent)
    status = RpcServerUseProtseqEpA("ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, "28473", NULL);
    if(status) {
        printf("Failed: RPC: Tcp: RpcServerUseProtseqEpA (0x%08x).\n", status);
        return status;
    }
    status = RpcServerUseProtseqEpA("ncacn_np", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, "\\pipe\\LeechAgent", NULL);
    if(status) {
        printf("Failed: RPC: LocalPipe: RpcServerUseProtseqEpA (0x%08x).\n", status);
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
    status = RpcEpRegister(LeechRpc_v1_0_s_ifspec, g_rpc_pbindingVector, 0, LEECHSVC_TCP_PORT_MSRPC);
    if(status) {
        printf("Failed: RPC: RpcServerInqBindings (0x%08x).\n", status);
        return status;
    }
    // Set security mode.
    if(fInsecure) {
        printf(
            "WARNING! Starting LeechAgent in INSECURE MS-RPC mode!              \n" \
            "     Any user may connect unauthenticated unless firewalled!       \n" \
            "     Ensure that port tcp/28473 is properly configured in firewall!\n" \
            "                                                                   \n");
    } else {
        // enable ntlm security (for local non-domain joined use case).
        status = RpcServerRegisterAuthInfoA("", RPC_C_AUTHN_WINNT, NULL, NULL);
        if(status) {
            printf("Failed: RPC: RpcServerRegisterAuthInfoA (RPC_C_AUTHN_WINNT) (0x%08x).\n", status);
            return status;
        }
        // enable kerberos security.
        status = RpcServerInqDefaultPrincNameA(RPC_C_AUTHN_GSS_KERBEROS, &szSPN);
        if(status) {
            printf("WARN: Kerberos authentication is unavailable.\n");
            printf("      NTLM authentication is available.      \n");
            RpcStringFreeA(&szSPN);
        } else {
            status = RpcServerRegisterAuthInfoA(szSPN, RPC_C_AUTHN_GSS_KERBEROS, NULL, NULL);
            if(status) {
                printf("Failed: RPC: RpcServerRegisterAuthInfoA - SPN: '%s' (0x%08x).\n", szSPN, status);
                RpcStringFreeA(&szSPN);
                return status;
            }
            printf(
                "LeechAgent started with smb/445 and tcp/28473 connectivity.\n" \
                "    Kerberos SPN : ' %s '\n" \
                "    (specify the SPN in the client connection string).\n" \
                "    ---\n" \
                "    For additional info see:\n" \
                "    https://github.com/ufrisk/LeechCore/wiki/LeechAgent\n",
                szSPN);
            if(fSvc) {
                LeechSvcRpc_WriteInfoEventLog("LeechAgent started with kerberos SPN: %s\n", szSPN);
            }
            RpcStringFreeA(&szSPN);
        }
    }
    // start accept calls and return.
    status = RpcServerListen(1, 64, TRUE);
    if(status) {
        printf("Failed: RPC: RpcServerListen (0x%08x).\n", status);
        return status;
    }
    return RPC_S_OK;
}

void RpcStop()
{
    // stop gRPC server:
    RpcStopGRPC();
    // stop MS-RPC server:
#pragma warning(suppress: 6031)
    if(g_rpc_pbindingVector) {
        RpcEpUnregister(LeechRpc_v1_0_s_ifspec, g_rpc_pbindingVector, 0);
        RpcBindingVectorFree(&g_rpc_pbindingVector);
        g_rpc_pbindingVector = NULL;
    }
}
