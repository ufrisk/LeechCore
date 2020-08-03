// leechrpc.c : implementation of RPC server-side functionality.
//
// (c) Ulf Frisk, 2018-2020
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
    HANDLE hLC;
    LEECHRPC_COMPRESS Compress;
    BOOL fLeechCoreValid;
    BOOL fHousekeeperThread;
    BOOL fHousekeeperThreadIsRunning;
    CRITICAL_SECTION LockUpdateKeepalive;
    struct {
        DWORD dwRpcClientID;
        QWORD qwLastTickCount64;
    } ClientKeepalive[LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS];
} LEECHRPC_SERVER_CONTEXT, *PLEECHRPC_SERVER_CONTEXT;

LEECHRPC_SERVER_CONTEXT ctxLeechRpc = { 0 };

/*
* Close any connection to 'LeechCore' and the embedded Python/VMM environments
* if they should exist.
*/
VOID LeechRPC_FinalConnectionCleanup()
{
    LcClose(ctxLeechRpc.hLC);
    ctxLeechRpc.hLC = NULL;
}

//-----------------------------------------------------------------------------
// CLIENT TRACK / KEEPALIVE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

DWORD LeechRPC_ClientKeepaliveRemove(_In_ DWORD dwRpcClientID)
{
    DWORD i, c;
    CHAR szTime[MAX_PATH];
    EnterCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
    for(c = 0, i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(dwRpcClientID && (dwRpcClientID == ctxLeechRpc.ClientKeepalive[i].dwRpcClientID)) {
            LeechSvc_GetTimeStamp(szTime);
            printf("[%s] LeechAgent: CLOSE: Client ID %08X\n", szTime, dwRpcClientID);
            ctxLeechRpc.ClientKeepalive[i].dwRpcClientID = 0;
        }
        if(ctxLeechRpc.ClientKeepalive[i].dwRpcClientID) {
            c++;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
    return c;
}

VOID LeechRPC_ClientKeepaliveThread(PVOID pv)
{
    DWORD i;
    CHAR szTime[MAX_PATH];
    ctxLeechRpc.fHousekeeperThread = TRUE;
    ctxLeechRpc.fHousekeeperThreadIsRunning = TRUE;
    while(ctxLeechRpc.fHousekeeperThread) {
        Sleep(100);
        EnterCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
        for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
            if(ctxLeechRpc.ClientKeepalive[i].dwRpcClientID && (ctxLeechRpc.ClientKeepalive[i].qwLastTickCount64 + LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS < GetTickCount64())) {
                if(0 == LeechRPC_ClientKeepaliveRemove(ctxLeechRpc.ClientKeepalive[i].dwRpcClientID)) {
                    LeechSvc_GetTimeStamp(szTime);
                    printf("[%s] LeechAgent: CLOSE: Last connected client timed out after %is.\n", szTime, (LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS / 1000));
                    ctxLeechRpc.fLeechCoreValid = FALSE;
                    LeechRPC_FinalConnectionCleanup();
                }
            }
        }
        LeaveCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
    }
    ctxLeechRpc.fHousekeeperThreadIsRunning = FALSE;
}

/*
* -- qwClientID
* -- return = number of clients registered after keepalive update, (DWORD)-1 on fail.
*/
DWORD LeechRPC_ClientKeepaliveUpdate(_In_ DWORD dwRpcClientID, _In_ BOOL fAdd)
{
    DWORD i, c;
    CHAR szTime[MAX_PATH];
    BOOL fUpdated = FALSE;
    if(!dwRpcClientID) { return (DWORD)-1; }
    EnterCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
    // 1: update existing entry
    for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(dwRpcClientID == ctxLeechRpc.ClientKeepalive[i].dwRpcClientID) {
            ctxLeechRpc.ClientKeepalive[i].qwLastTickCount64 = GetTickCount64();
            fUpdated = TRUE;
            break;
        }
    }
    // 2: find new entry and insert into (if needed)
    if(!fUpdated && fAdd) {
        for(i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
            if(0 == ctxLeechRpc.ClientKeepalive[i].dwRpcClientID) {
                LeechSvc_GetTimeStamp(szTime);
                printf("[%s] LeechAgent:  OPEN: Client ID %08X\n", szTime, dwRpcClientID);
                ctxLeechRpc.ClientKeepalive[i].dwRpcClientID = dwRpcClientID;
                ctxLeechRpc.ClientKeepalive[i].qwLastTickCount64 = GetTickCount64();
                fUpdated = TRUE;
                break;
            }
        }
    }
    if(!fUpdated) {
        LeaveCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
        return (DWORD)-1;
    }
    // 3: count entries
    for(c = 0, i = 0; i < LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS; i++) {
        if(ctxLeechRpc.ClientKeepalive[i].dwRpcClientID) {
            c++;
        }
    }
    LeaveCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
    return c;
}

//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRpcOnLoadInitialize()
{
    ctxLeechRpc.fLeechCoreValid = TRUE;
    LeechRPC_CompressInitialize(&ctxLeechRpc.Compress);
    InitializeCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechRPC_ClientKeepaliveThread, NULL, 0, NULL);
}

VOID LeechRpcOnUnloadClose()
{
    ctxLeechRpc.fHousekeeperThread = FALSE;
    while(ctxLeechRpc.fHousekeeperThreadIsRunning) {
        SwitchToThread();
    }
    LeechRPC_FinalConnectionCleanup();
    DeleteCriticalSection(&ctxLeechRpc.LockUpdateKeepalive);
    LeechRPC_CompressClose(&ctxLeechRpc.Compress);
    ZeroMemory(&ctxLeechRpc, sizeof(LEECHRPC_SERVER_CONTEXT));
}

error_status_t LeechRpc_CommandReadScatter(_In_ PLEECHRPC_MSG_BIN pReq, long *pcbOut, byte **ppbOut)
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
    LcReadScatter(ctxLeechRpc.hLC, cMEMs, ppMEMs);
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

error_status_t LeechRpc_CommandWriteScatter(_In_ PLEECHRPC_MSG_BIN pReq, long *pcbOut, byte **ppbOut)
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
    LcWriteScatter(ctxLeechRpc.hLC, cMEMs, ppMEMs);
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
* -- fOption = the command as specified by LC_CMD_AGENT_*
* -- cbDataIn
* -- pbDataIn
* -- ppbDataOut =  ptr to receive function allocated output - must be LocalFree'd by caller!
* -- pcbDataOut = ptr to receive length of *pbDataOut.
* -- return
*/
_Success_(return)
BOOL LeechRpc_CommandAgent(_In_ QWORD fOption, _In_ DWORD cbDataIn, _In_reads_(cbDataIn) PBYTE pbDataIn, _Out_writes_opt_(*pcbDataOut) PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    if(ppbDataOut) { *ppbDataOut = NULL; }
    if(pcbDataOut) { *pcbDataOut = 0; }
    switch(fOption & 0xffffffff'00000000) {
        case LC_CMD_AGENT_EXEC_PYTHON:
            return LeechAgent_ProcParent_ExecPy(fOption & 0xffffffff, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
        case LC_CMD_AGENT_EXIT_PROCESS:
            ExitProcess(fOption & 0xffffffff);
            return FALSE;   // not reached ...
        default:
            return FALSE;
    }
}

error_status_t LeechRpc_CommandOpen(_In_ PLEECHRPC_MSG_OPEN pReq, long *pcbOut, byte **ppbOut)
{
    HANDLE hLeechCoreExisting;
    PLEECHRPC_MSG_OPEN pRsp = NULL;
    if(!(pRsp = LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_MSG_OPEN)))) {
        *pcbOut = 0;
        *ppbOut = NULL;
        return (error_status_t)-1;
    }
    if(ctxLeechRpc.hLC) {
        strcpy_s(pReq->cfg.szDevice, MAX_PATH - 1, "existing");
        hLeechCoreExisting = LcCreate(&pReq->cfg);
        // decrement handle refcount (rpc server keeps track of refcount internally)
        if(hLeechCoreExisting) { LcClose(hLeechCoreExisting); }
    } else {
        ctxLeechRpc.hLC = LcCreate(&pReq->cfg);
    }
    pReq->cfg.pfn_printf_opt = NULL;
    pRsp->cbMsg = sizeof(LEECHRPC_MSG_OPEN);
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = ctxLeechRpc.hLC ? TRUE : FALSE;
    if(pRsp->fMsgResult) {
        ctxLeechRpc.fLeechCoreValid = TRUE;
        memcpy(&pRsp->cfg, &pReq->cfg, sizeof(LC_CONFIG));
        pRsp->cfg.fRemoteDisableCompress = pRsp->cfg.fRemoteDisableCompress || !ctxLeechRpc.Compress.fValid;
        pRsp->flags = 0;
        LeechRPC_ClientKeepaliveUpdate(pReq->dwRpcClientID, TRUE);
    }
    pRsp->tpMsg = LEECHRPC_MSGTYPE_OPEN_RSP;
    *pcbOut = pRsp->cbMsg;
    *ppbOut = (PBYTE)pRsp;
    return 0;
}

error_status_t LeechRpc_ReservedSubmitCommand(
    /* [in] */ handle_t hBinding,
    /* [in] */ long cbIn,
    /* [size_is][in] */ byte *pbIn,
    /* [out] */ long *pcbOut,
    /* [size_is][size_is][out] */ byte **ppbOut)
{
    BOOL fTMP = FALSE;
    DWORD cbTMP = 0;
    PBYTE pbTMP = NULL;
    BOOL fFreeReqBin = FALSE;
    CHAR szTime[MAX_PATH];
    error_status_t status;
    PLEECHRPC_MSG_HDR pReq = NULL;
    PLEECHRPC_MSG_HDR pRsp = NULL;
    PLEECHRPC_MSG_OPEN pReqOpen = NULL;
    PLEECHRPC_MSG_OPEN pRspOpen = NULL;
    PLEECHRPC_MSG_DATA pReqData = NULL;
    PLEECHRPC_MSG_DATA pRspData = NULL;
    PLEECHRPC_MSG_BIN pReqBin = NULL;
    PLEECHRPC_MSG_BIN pRspBin = NULL;
    // 1: sanity checks in incoming data
    if(cbIn < sizeof(LEECHRPC_MSG_HDR)) { goto fail; }
    pReq = (PLEECHRPC_MSG_HDR)pbIn;
    if((pReq->dwMagic != LEECHRPC_MSGMAGIC) || (pReq->tpMsg > LEECHRPC_MSGTYPE_MAX) || (pReq->cbMsg < sizeof(LEECHRPC_MSG_HDR))) { goto fail; }
    if(!ctxLeechRpc.fLeechCoreValid && !((pReq->tpMsg == LEECHRPC_MSGTYPE_PING_REQ) || (pReq->tpMsg == LEECHRPC_MSGTYPE_OPEN_REQ) || (pReq->tpMsg == LEECHRPC_MSGTYPE_CLOSE_REQ))) { goto fail; }
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
            return 0;
        case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            LeechRPC_ClientKeepaliveUpdate(pReq->dwRpcClientID, FALSE);
            pRsp->tpMsg = LEECHRPC_MSGTYPE_KEEPALIVE_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            return 0;
        case LEECHRPC_MSGTYPE_OPEN_REQ:
            if(pReqOpen) {
                LeechRpc_CommandOpen(pReqOpen, pcbOut, ppbOut);
            }
            return 0;
        case LEECHRPC_MSGTYPE_READSCATTER_REQ:
            status = LeechRpc_CommandReadScatter(pReqBin, pcbOut, ppbOut);
            if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
            return status;
        case LEECHRPC_MSGTYPE_WRITESCATTER_REQ:
            status = LeechRpc_CommandWriteScatter(pReqBin, pcbOut, ppbOut);
            if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
            return status;
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            if(pReq->dwRpcClientID && (0 == LeechRPC_ClientKeepaliveRemove(pReq->dwRpcClientID))) {
                LeechSvc_GetTimeStamp(szTime);
                printf("[%s] LeechAgent: CLOSE: Last connected client requested close.\n", szTime);
                ctxLeechRpc.fLeechCoreValid = FALSE;
                LeechRPC_FinalConnectionCleanup();
            }
            pRsp->tpMsg = LEECHRPC_MSGTYPE_CLOSE_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            return 0;
        case LEECHRPC_MSGTYPE_GETOPTION_REQ:
            if(!(pRspData = LocalAlloc(0, sizeof(LEECHRPC_MSG_DATA)))) { goto fail; }
            pRspData->cbMsg = sizeof(LEECHRPC_MSG_DATA);
            pRspData->dwMagic = LEECHRPC_MSGMAGIC;
            pRspData->fMsgResult = pReqData && LcGetOption(ctxLeechRpc.hLC, pReqData->qwData[0], &pRspData->qwData[0]);
            pRspData->tpMsg = LEECHRPC_MSGTYPE_GETOPTION_RSP;
            *pcbOut = pRspData->cbMsg;
            *ppbOut = (PBYTE)pRspData;
            return 0;
        case LEECHRPC_MSGTYPE_SETOPTION_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = pReqData && LcSetOption(ctxLeechRpc.hLC, pReqData->qwData[0], pReqData->qwData[1]);
            pRsp->tpMsg = LEECHRPC_MSGTYPE_SETOPTION_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            return 0;
        case LEECHRPC_MSGTYPE_COMMAND_REQ:
            fTMP = (pReqBin->qwData[0] >> 63) ?
                LeechRpc_CommandAgent(pReqBin->qwData[0], pReqBin->cb, pReqBin->pb, &pbTMP, &cbTMP) :
                LcCommand(ctxLeechRpc.hLC, pReqBin->qwData[0], pReqBin->cb, pReqBin->pb, &pbTMP, &cbTMP);
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
            return 0;
        default:
            goto fail;
    }
    return 0;
fail:
    if(fFreeReqBin) { LocalFree(pReqBin); pReqBin = NULL; } // only free locally allocated decompressed bindata
    *pcbOut = 0;
    *ppbOut = NULL;
    return (error_status_t)-1;
}
