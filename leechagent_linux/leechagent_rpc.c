// leechsvc_rpc.c : implementation of RPC related functionality.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "leechagent_rpc.h"
#include "leechrpc.h"
#include <stdio.h>

// gRPC:
HANDLE g_hGRPC = NULL;

pfn_leechgrpc_server_create_insecure g_pfn_leechgrpc_server_create_insecure;
pfn_leechgrpc_server_create_secure_p12 g_pfn_leechgrpc_server_create_secure_p12;
pfn_leechgrpc_server_shutdown g_pfn_leechgrpc_server_shutdown;
VOID LeechGRPC_ReservedSubmitCommand(_In_opt_ PVOID ctx, _In_ PBYTE pbIn, _In_ SIZE_T cbIn, _Out_ PBYTE *ppbOut, _Out_ SIZE_T *pcbOut);

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
        printf("Failed: gRPC: library 'libleechgrpc"LC_LIBRARY_FILETYPE"' missing - gRPC functionality is disabled.\n");
        return FALSE;
    }
    dwTcpPort = atoi(pConfig->szTcpPortGRPC);
    if(!dwTcpPort) {
        printf("Failed: gRPC: Invalid port number '%i' - gRPC functionality is disabled.\n", dwTcpPort);
        return FALSE;
    }
    g_pfn_leechgrpc_server_create_insecure = (pfn_leechgrpc_server_create_insecure)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_create_insecure");
    g_pfn_leechgrpc_server_create_secure_p12 = (pfn_leechgrpc_server_create_secure_p12)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_create_secure_p12");
    g_pfn_leechgrpc_server_shutdown = (pfn_leechgrpc_server_shutdown)GetProcAddress(pConfig->hModuleGRPC, "leechgrpc_server_shutdown");
    if(!g_pfn_leechgrpc_server_create_insecure || !g_pfn_leechgrpc_server_create_secure_p12 || !g_pfn_leechgrpc_server_shutdown) {
        printf("Failed: gRPC: library 'libleechgrpc"LC_LIBRARY_FILETYPE"' missing required functions, gRPC functionality is disabled.\n");
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

void RpcStop()
{
    // stop gRPC server:
    RpcStopGRPC();
}
