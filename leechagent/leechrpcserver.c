// leechrpc.c : implementation of RPC server-side functionality.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "leechagent_proc.h"
#include "leechrpc.h"
#include "leechrpc_h.h"
#include "util.h"
#include <stdio.h>

typedef struct tdLEECHRPC_SERVER_CONTEXT {
    BOOL fValid;
    LEECHRPC_COMPRESS Compress;
    BOOL fInactivityWatcherThread;
    BOOL fInactivityWatcherThreadIsRunning;
    CRITICAL_SECTION LockClientList;
    struct {
        HANDLE hLC;
        HANDLE hPP;             // parent/child process context (used for child-process vfs operations)
        DWORD dwRpcClientID;
        DWORD cActiveRequests;
        QWORD qwLastTickCount64;
    } ClientList[LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS];
} LEECHRPC_SERVER_CONTEXT, *PLEECHRPC_SERVER_CONTEXT;

LEECHRPC_SERVER_CONTEXT ctxLeechRpc = { 0 };

//-----------------------------------------------------------------------------
// CLIENT TRACK / KEEPALIVE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return != NULL)
HANDLE LeechRPC_LcHandle_GetExisting(_In_ DWORD dwRpcClientID, _Out_opt_ PHANDLE* pphPP)
{
    DWORD i;
    HANDLE hLC = NULL;
    if(!dwRpcClientID) { return NULL; }
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID) {
            ctxLeechRpc.ClientList[i].cActiveRequests++;
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = GetTickCount64();
            if(pphPP) { *pphPP = &ctxLeechRpc.ClientList[i].hPP; }
            hLC = ctxLeechRpc.ClientList[i].hLC;
            break;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
    return hLC;
}

_Success_(return)
BOOL LeechRPC_LcHandle_New(_In_ DWORD dwRpcClientID, _In_ HANDLE hLC)
{
    DWORD i;
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(!ctxLeechRpc.ClientList[i].dwRpcClientID) {
            ctxLeechRpc.ClientList[i].hLC = hLC;
            ctxLeechRpc.ClientList[i].dwRpcClientID = dwRpcClientID;
            ctxLeechRpc.ClientList[i].cActiveRequests = 0;
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = GetTickCount64();
            LeaveCriticalSection(&ctxLeechRpc.LockClientList);
            return TRUE;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
    return FALSE;
}

VOID LeechRPC_LcHandle_Return(_In_opt_ HANDLE hLC, _In_ DWORD dwRpcClientID)
{
    DWORD i;
    if(!hLC) { return; }
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if((ctxLeechRpc.ClientList[i].hLC == hLC) && (ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID)) {
            EnterCriticalSection(&ctxLeechRpc.LockClientList);
            ctxLeechRpc.ClientList[i].cActiveRequests--;
            LeaveCriticalSection(&ctxLeechRpc.LockClientList);
            break;
        }
    }
}

VOID LeechRPC_LcHandle_Close(_In_ DWORD dwRpcClientID, _In_ BOOL fReasonTimeout)
{
    DWORD i;
    CHAR szTime[32];
    HANDLE hLC = NULL, hPP = NULL;
    EnterCriticalSection(&ctxLeechRpc.LockClientList);
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(ctxLeechRpc.ClientList[i].dwRpcClientID == dwRpcClientID) {
            while(ctxLeechRpc.ClientList[i].cActiveRequests) {
                LeaveCriticalSection(&ctxLeechRpc.LockClientList);
                Sleep(10);
                EnterCriticalSection(&ctxLeechRpc.LockClientList);
            }
            hLC = ctxLeechRpc.ClientList[i].hLC;
            hPP = ctxLeechRpc.ClientList[i].hPP;
            ctxLeechRpc.ClientList[i].hLC = NULL;
            ctxLeechRpc.ClientList[i].hPP = NULL;
            ctxLeechRpc.ClientList[i].dwRpcClientID = 0;
            ctxLeechRpc.ClientList[i].qwLastTickCount64 = 0;
            break;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockClientList);
    if(hPP) {
        LeechAgent_ProcParent_Close(hPP);
    }
    if(hLC) {
        LcClose(hLC);
        LeechSvc_GetTimeStamp(szTime);
        if(fReasonTimeout) {
            printf("[%s] LeechAgent: CLOSE: Client ID %08X timeout after %is.\n", szTime, dwRpcClientID, (LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS / 1000));
        } else {
            printf("[%s] LeechAgent: CLOSE: Client ID %08X\n", szTime, dwRpcClientID);
        }
    }
}

VOID LeechRPC_LcHandle_CloseAll()
{
    DWORD i;
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(ctxLeechRpc.ClientList[i].dwRpcClientID) {
            LeechRPC_LcHandle_Close(ctxLeechRpc.ClientList[i].dwRpcClientID, FALSE);
        }
    }
}

VOID LeechRPC_LcHandle_InactivityWatcherThread(PVOID pv)
{
    DWORD i;
    ctxLeechRpc.fInactivityWatcherThread = TRUE;
    ctxLeechRpc.fInactivityWatcherThreadIsRunning = TRUE;
    while(ctxLeechRpc.fInactivityWatcherThread) {
        Sleep(1000);
        for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
            if(ctxLeechRpc.ClientList[i].qwLastTickCount64 && (ctxLeechRpc.ClientList[i].qwLastTickCount64 + LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS < GetTickCount64())) {
                LeechRPC_LcHandle_Close(ctxLeechRpc.ClientList[i].dwRpcClientID, TRUE);
            }
        }
    }
    ctxLeechRpc.fInactivityWatcherThreadIsRunning = FALSE;
}



//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRpcOnLoadInitialize()
{
    ctxLeechRpc.fValid = TRUE;
    LeechRPC_CompressInitialize(&ctxLeechRpc.Compress);
    InitializeCriticalSection(&ctxLeechRpc.LockClientList);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechRPC_LcHandle_InactivityWatcherThread, NULL, 0, NULL);
}

VOID LeechRpcOnUnloadClose()
{
    ctxLeechRpc.fInactivityWatcherThread = FALSE;
    while(ctxLeechRpc.fInactivityWatcherThreadIsRunning) {
        SwitchToThread();
    }
    LeechRPC_LcHandle_CloseAll();
    DeleteCriticalSection(&ctxLeechRpc.LockClientList);
    LeechRPC_CompressClose(&ctxLeechRpc.Compress);
    ZeroMemory(&ctxLeechRpc, sizeof(LEECHRPC_SERVER_CONTEXT));
}

error_status_t LeechRpc_CommandReadScatter(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReq, long *pcbOut, byte **ppbOut)
{
    BOOL fOK;
    PLEECHRPC_MSG_BIN pRsp = NULL;
    PMEM_SCATTER pMEM_Src, pMEM_Dst;
    PPMEM_SCATTER ppMEMs = NULL;
    DWORD i, cMEMs, cbMax;
    PBYTE pbData = NULL, pbDataDst;
    DWORD cbDataOffset = 0, cbRead = 0;
    DWORD cbRsp;
    cMEMs = (DWORD)pReq->qwData[0];
    cbMax = (DWORD)pReq->qwData[1];
    // 1: verify incoming result
    fOK = (pReq->cb == cMEMs * sizeof(MEM_SCATTER)) && (cMEMs <= 0x2000) && (cbMax <= (cMEMs << 12));
    if(!fOK) { goto fail; }
    // 2: allocate read data buffer, ppMEMs & prepare LeechCore call
    if(!(ppMEMs = LocalAlloc(LMEM_ZEROINIT, cMEMs * sizeof(PMEM_SCATTER)))) { goto fail; }
    if(!(pbData = LocalAlloc(0, cbMax))) { goto fail; }
    pMEM_Src = (PMEM_SCATTER)pReq->pb;
    for(i = 0; i < cMEMs; i++) {
        pMEM_Src->pb = pbData + cbDataOffset;
        cbDataOffset += pMEM_Src->cb;
        ppMEMs[i] = pMEM_Src;
        pMEM_Src = pMEM_Src + 1;
    }
    if(cbDataOffset > cbMax) { goto fail; }
    // 4: call & count read data
    LcReadScatter(hLC, cMEMs, ppMEMs);
    pMEM_Src = (PMEM_SCATTER)pReq->pb;
    for(i = 0, cbRead = 0; i < cMEMs; i++) {
        if(pMEM_Src->f) {
            cbRead += pMEM_Src->cb;
        }
        pMEM_Src = pMEM_Src + 1;
    }
    // 5: allocate and prepare result
    cbRsp = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_SCATTER) + cbRead;
    if(!(pRsp = LocalAlloc(0, cbRsp))) { goto fail; }
    ZeroMemory(pRsp, sizeof(LEECHRPC_MSG_BIN));
    pRsp->cbMsg = cbRsp;
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = TRUE;
    pRsp->tpMsg = LEECHRPC_MSGTYPE_READSCATTER_RSP;
    memcpy(pRsp->pb, pReq->pb, pReq->cb);   // all MEMs
    pbDataDst = pRsp->pb + pReq->cb;        // rsp data buffer
    pMEM_Dst = (PMEM_SCATTER)pRsp->pb;
    for(i = 0, cbRead = 0; i < cMEMs; i++) {
        if(pMEM_Dst->f) {
            memcpy(pbDataDst, pMEM_Dst->pb, pMEM_Dst->cb);
            pbDataDst = pbDataDst + pMEM_Dst->cb;
            cbRead += pMEM_Dst->cb;
        }
        pMEM_Dst = pMEM_Dst + 1;
    }
    pRsp->cb = pReq->cb + cbRead;
    pRsp->qwData[0] = cMEMs;
    LeechRPC_Compress(&ctxLeechRpc.Compress, pRsp, (pReq->flags & LEECHRPC_FLAG_NOCOMPRESS));
    *pcbOut = pRsp->cbMsg;
    *ppbOut = (PBYTE)pRsp;
    LocalFree(ppMEMs);
    LocalFree(pbData);
    return 0;
fail:
    *pcbOut = 0;
    *ppbOut = NULL;
    LocalFree(pRsp);
    LocalFree(ppMEMs);
    LocalFree(pbData);
    return (error_status_t)-1;
}

error_status_t LeechRpc_CommandWriteScatter(_In_ HANDLE hLC, _In_ PLEECHRPC_MSG_BIN pReq, long *pcbOut, byte **ppbOut)
{
    PBOOL pfRsp;
    PLEECHRPC_MSG_BIN pRsp = NULL;
    PMEM_SCATTER pMEM, pMEMs;
    PPMEM_SCATTER ppMEMs = NULL;
    DWORD i, cMEMs, cbRsp;
    PBYTE pbData = NULL;
    cMEMs = (DWORD)pReq->qwData[0];
    // 1: verify and fixup incoming data 
    pMEMs = (PMEM_SCATTER)pReq->pb;
    pbData = pReq->pb + cMEMs * sizeof(MEM_SCATTER);
    if(pReq->cb != cMEMs * (sizeof(MEM_SCATTER) + 0x1000)) { goto fail; }
    if(!(ppMEMs = LocalAlloc(LMEM_ZEROINIT, cMEMs * sizeof(PMEM_SCATTER)))) { goto fail; }
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = pMEM = pMEMs + i;
        if((pMEM->cb > 0x1000) || (pMEM->iStack > MEM_SCATTER_STACK_SIZE - 4)) { goto fail; }
        pMEM->pb = pbData;
        pbData += pMEM->cb;
    }
    // 2: call & return result
    LcWriteScatter(hLC, cMEMs, ppMEMs);
    cbRsp = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(BOOL);
    if(!(pRsp = LocalAlloc(LMEM_ZEROINIT, cbRsp))) { goto fail; }
    pRsp->cbMsg = cbRsp;
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = TRUE;
    pRsp->tpMsg = LEECHRPC_MSGTYPE_WRITESCATTER_RSP;
    pRsp->cb = cMEMs * sizeof(BOOL);
    pfRsp = (PBOOL)pRsp->pb;
    for(i = 0; i < cMEMs; i++) {
        pfRsp[i] = pMEMs[i].f;
    }
    pRsp->qwData[0] = cMEMs;
    LeechRPC_Compress(&ctxLeechRpc.Compress, pRsp, (pReq->flags & LEECHRPC_FLAG_NOCOMPRESS));
    *pcbOut = pRsp->cbMsg;
    *ppbOut = (PBYTE)pRsp;
    LocalFree(ppMEMs);
    return 0;
fail:
    *pcbOut = 0;
    *ppbOut = NULL;
    LocalFree(pRsp);
    LocalFree(ppMEMs);
    return (error_status_t)-1;
}

/*
* Transfer commands/data to/from the remote service (if it exists).
* NB! USER-FREE: ppbDataOut (LocalFree)
* -- hLC
* -- phPP
* -- fOption = the command as specified by LC_CMD_AGENT_*
* -- cbDataIn
* -- pbDataIn
* -- ppbDataOut =  ptr to receive function allocated output - must be LocalFree'd by caller!
* -- pcbDataOut = ptr to receive length of *pbDataOut.
* -- return
*/
_Success_(return)
BOOL LeechRpc_CommandAgent(_In_ HANDLE hLC, _In_opt_ PHANDLE phPP, _In_ QWORD fOption, _In_ DWORD cbDataIn, _In_reads_(cbDataIn) PBYTE pbDataIn, _Out_writes_opt_(*pcbDataOut) PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    if(ppbDataOut) { *ppbDataOut = NULL; }
    if(pcbDataOut) { *pcbDataOut = 0; }
    switch(fOption & 0xffffffff'00000000) {
        case LC_CMD_AGENT_EXEC_PYTHON:
            return LeechAgent_ProcParent_ExecPy(hLC, fOption & 0xffffffff, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_EXIT_PROCESS:
            ExitProcess(fOption & 0xffffffff);
            return FALSE;   // not reached ...
        case LC_CMD_AGENT_VFS_INITIALIZE:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsInitialize(hLC, phPP, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_CONSOLE:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsConsole(hLC, phPP, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_LIST:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_LIST, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_READ:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_READ, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_WRITE:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_WRITE, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_OPT_GET:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_OPT_GET, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_VFS_OPT_SET:
            if(!phPP) { return FALSE; }
            return LeechAgent_ProcParent_VfsCMD(hLC, phPP, LEECHAGENT_PROC_CMD_VFS_OPT_SET, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        default:
            return FALSE;
    }
}

error_status_t LeechRpc_CommandOpen(_In_ PLEECHRPC_MSG_OPEN pReq, long *pcbOut, byte **ppbOut)
{
    DWORD cbRsp;
    CHAR szTime[32];
    HANDLE hLC = NULL;
    PLEECHRPC_MSG_OPEN pRsp = NULL;
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    hLC = LcCreateEx(&pReq->cfg, &pLcErrorInfo);
    if(hLC && !LeechRPC_LcHandle_New(pReq->dwRpcClientID, hLC)) {
        LcClose(hLC);
        hLC = NULL;
    }
    pReq->cfg.pfn_printf_opt = NULL;
    cbRsp = sizeof(LEECHRPC_MSG_OPEN) + (pLcErrorInfo ? (pLcErrorInfo->cbStruct - sizeof(LC_CONFIG_ERRORINFO)) : 0);
    if(!(pRsp = LocalAlloc(LMEM_ZEROINIT, cbRsp))) {
        *pcbOut = 0;
        *ppbOut = NULL;
        return (error_status_t)-1;
    }
    pRsp->cbMsg = cbRsp;
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = TRUE;
    pRsp->fValidOpen = hLC ? TRUE : FALSE;
    if(pRsp->fValidOpen) {
        LeechSvc_GetTimeStamp(szTime);
        printf("[%s] LeechAgent:  OPEN: Client ID %08X\n", szTime, pReq->dwRpcClientID);
        memcpy(&pRsp->cfg, &pReq->cfg, sizeof(LC_CONFIG));
        pRsp->cfg.fRemoteDisableCompress = pRsp->cfg.fRemoteDisableCompress || !ctxLeechRpc.Compress.fValid;
        pRsp->flags = 0;
    }
    if(pLcErrorInfo) {
        memcpy(&pRsp->errorinfo, pLcErrorInfo, pLcErrorInfo->cbStruct);
    }
    pRsp->tpMsg = LEECHRPC_MSGTYPE_OPEN_RSP;
    *pcbOut = pRsp->cbMsg;
    *ppbOut = (PBYTE)pRsp;
    LocalFree(pLcErrorInfo);
    return 0;
}

error_status_t LeechRpc_ReservedSubmitCommand(
    /* [in] */ handle_t hBinding,
    /* [in] */ long cbIn,
    /* [size_is][in] */ byte *pbIn,
    /* [out] */ long *pcbOut,
    /* [size_is][size_is][out] */ byte **ppbOut)
{
    HANDLE hLC = NULL, *phPP = NULL;
    BOOL fTMP = FALSE;
    DWORD cbTMP = 0;
    PBYTE pbTMP = NULL;
    BOOL fFreeReqBin = FALSE;
    error_status_t status = 0;
    PLEECHRPC_MSG_HDR pReq = NULL;
    PLEECHRPC_MSG_HDR pRsp = NULL;
    PLEECHRPC_MSG_OPEN pReqOpen = NULL;
    PLEECHRPC_MSG_OPEN pRspOpen = NULL;
    PLEECHRPC_MSG_DATA pReqData = NULL;
    PLEECHRPC_MSG_DATA pRspData = NULL;
    PLEECHRPC_MSG_BIN pReqBin = NULL;
    PLEECHRPC_MSG_BIN pRspBin = NULL;
    // 1: sanity checks in incoming data
    if(!ctxLeechRpc.fValid) { return status; }
    if(cbIn < sizeof(LEECHRPC_MSG_HDR)) { return status; }
    pReq = (PLEECHRPC_MSG_HDR)pbIn;
    if((pReq->dwMagic != LEECHRPC_MSGMAGIC) || (pReq->tpMsg > LEECHRPC_MSGTYPE_MAX) || (pReq->cbMsg < sizeof(LEECHRPC_MSG_HDR))) { return status; }
    hLC = LeechRPC_LcHandle_GetExisting(pReq->dwRpcClientID, &phPP);
    if(!hLC && !((pReq->tpMsg == LEECHRPC_MSGTYPE_PING_REQ) || (pReq->tpMsg == LEECHRPC_MSGTYPE_OPEN_REQ) || (pReq->tpMsg == LEECHRPC_MSGTYPE_CLOSE_REQ))) { goto fail; }
    switch(pReq->tpMsg) {
        case LEECHRPC_MSGTYPE_PING_REQ:
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
        case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_HDR)) { goto fail; }
            break;
        case LEECHRPC_MSGTYPE_OPEN_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_OPEN)) { goto fail; }
            pReqOpen = (PLEECHRPC_MSG_OPEN)pReq;
            break;
        case LEECHRPC_MSGTYPE_GETOPTION_REQ:
        case LEECHRPC_MSGTYPE_SETOPTION_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_DATA)) { goto fail; }
            pReqData = (PLEECHRPC_MSG_DATA)pReq;
            break;
        case LEECHRPC_MSGTYPE_READSCATTER_REQ:
        case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
        case LEECHRPC_MSGTYPE_COMMAND_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)pReq)->cb) { goto fail; }
            if(((PLEECHRPC_MSG_BIN)pReq)->cbDecompress) {
                if(!LeechRPC_Decompress(&ctxLeechRpc.Compress, (PLEECHRPC_MSG_BIN)pReq, &pReqBin)) { goto fail; }
                fFreeReqBin = TRUE; // data allocated by decompress function must be free'd
            } else {
                pReqBin = ((PLEECHRPC_MSG_BIN)pReq);
            }
            break;
        default:
            goto fail;
    }
    // 2: dispatch
    switch(pReq->tpMsg) {
        case LEECHRPC_MSGTYPE_PING_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            pRsp->tpMsg = LEECHRPC_MSGTYPE_PING_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            goto finish;
        case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            pRsp->tpMsg = LEECHRPC_MSGTYPE_KEEPALIVE_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            goto finish;
        case LEECHRPC_MSGTYPE_OPEN_REQ:
            if(pReqOpen) {
                LeechRpc_CommandOpen(pReqOpen, pcbOut, ppbOut);
            }
            goto finish;
        case LEECHRPC_MSGTYPE_READSCATTER_REQ:
            status = LeechRpc_CommandReadScatter(hLC, pReqBin, pcbOut, ppbOut);
            if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
            goto finish;
        case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
            status = LeechRpc_CommandWriteScatter(hLC, pReqBin, pcbOut, ppbOut);
            if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
            goto finish;
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
            LeechRPC_LcHandle_Return(hLC, pReq->dwRpcClientID);
            hLC = NULL;
            LeechRPC_LcHandle_Close(pReq->dwRpcClientID, FALSE);
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            pRsp->tpMsg = LEECHRPC_MSGTYPE_CLOSE_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            goto finish;
        case LEECHRPC_MSGTYPE_GETOPTION_REQ:
            if(!(pRspData = LocalAlloc(0, sizeof(LEECHRPC_MSG_DATA)))) { goto fail; }
            pRspData->cbMsg = sizeof(LEECHRPC_MSG_DATA);
            pRspData->dwMagic = LEECHRPC_MSGMAGIC;
            pRspData->fMsgResult = pReqData && LcGetOption(hLC, pReqData->qwData[0], &pRspData->qwData[0]);
            pRspData->tpMsg = LEECHRPC_MSGTYPE_GETOPTION_RSP;
            *pcbOut = pRspData->cbMsg;
            *ppbOut = (PBYTE)pRspData;
            goto finish;
        case LEECHRPC_MSGTYPE_SETOPTION_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = pReqData && LcSetOption(hLC, pReqData->qwData[0], pReqData->qwData[1]);
            pRsp->tpMsg = LEECHRPC_MSGTYPE_SETOPTION_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            goto finish;
        case LEECHRPC_MSGTYPE_COMMAND_REQ:
            fTMP = (pReqBin->qwData[0] >> 63) ?
                LeechRpc_CommandAgent(hLC, phPP, pReqBin->qwData[0], pReqBin->cb, pReqBin->pb, &pbTMP, &cbTMP) :
                LcCommand(hLC, pReqBin->qwData[0], pReqBin->cb, pReqBin->pb, &pbTMP, &cbTMP);
            if(!fTMP) { cbTMP = 0; }
            if(!(pRspBin = LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_MSG_BIN) + cbTMP))) {
                goto fail;
            }
            pRspBin->fMsgResult = fTMP;
            pRspBin->cb = cbTMP;
            memcpy(pRspBin->pb, pbTMP, cbTMP);
            pbTMP = LocalFree(pbTMP);
            pRspBin->tpMsg = LEECHRPC_MSGTYPE_COMMAND_RSP;
            pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
            pRspBin->cbMsg = sizeof(LEECHRPC_MSG_BIN) + pRspBin->cb;
            LeechRPC_Compress(&ctxLeechRpc.Compress, pRspBin, (pReq->flags & LEECHRPC_FLAG_NOCOMPRESS));
            *pcbOut = pRspBin->cbMsg;
            *ppbOut = (PBYTE)pRspBin;
            if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
            goto finish;
        default:
            goto fail;
    }
finish:
    if(pReq) { LeechRPC_LcHandle_Return(hLC, pReq->dwRpcClientID); }
    return status;
fail:
    LeechRPC_LcHandle_Return(hLC, pReq->dwRpcClientID);
    if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
    *pcbOut = 0;
    *ppbOut = NULL;
    return (error_status_t)-1;
}
