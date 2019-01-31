// leechrpc.c : implementation of RPC server-side functionality.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechsvc.h"
#include "leechrpc.h"
#include "leechrpc_h.h"
#include <stdio.h>

typedef struct tdLEECHRPC_CONTEXT {
    BOOL fCompressDisable;
    LEECHRPC_COMPRESS Compress;
} LEECHRPC_CONTEXT, *PLEECHRPC_CONTEXT;

LEECHRPC_CONTEXT ctxLeechRpc = { 0 };

//-----------------------------------------------------------------------------
// COMPRESSION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#include <compressapi.h>

VOID LeechRPC_CompressClose()
{
    PLEECHRPC_COMPRESS ctx = (PLEECHRPC_COMPRESS)&ctxLeechRpc.Compress;
    if(ctx->fValid) {
        DeleteCriticalSection(&ctx->LockCompressor);
        DeleteCriticalSection(&ctx->LockDecompressor);
    }
    if(ctx->hCompressor) { ctx->fn.pfnCloseCompressor(ctx->hCompressor); }
    if(ctx->hDecompressor) { ctx->fn.pfnCloseCompressor(ctx->hDecompressor); }
    if(ctx->hDll) { FreeLibrary(ctx->hDll); }
    ZeroMemory(ctx, sizeof(LEECHRPC_COMPRESS));
}

VOID LeechRPC_CompressInitialize()
{
    PLEECHRPC_COMPRESS ctx = (PLEECHRPC_COMPRESS)&ctxLeechRpc.Compress;
    const LPSTR FN_LIST[] = { "CreateCompressor", "CreateDecompressor", "CloseCompressor", "CloseDecompressor", "Compress", "Decompress" };
    DWORD i;
    if(sizeof(ctx->fn) != sizeof(FN_LIST)) { return; }
    ctx->hDll = LoadLibraryA("cabinet.dll");
    if(!ctx->hDll) { return; }
    for(i = 0; i < sizeof(FN_LIST) / sizeof(LPSTR); i++) {
        if(!(*((PQWORD)&ctx->fn + i) = (QWORD)GetProcAddress(ctx->hDll, FN_LIST[i]))) { goto fail; }
    }
    ctx->fValid =
        ctx->fn.pfnCreateCompressor(3, NULL, &ctx->hCompressor) &&
        ctx->fn.pfnCreateDecompressor(3, NULL, &ctx->hDecompressor);
    if(ctx->fValid) {
        InitializeCriticalSection(&ctx->LockCompressor);
        InitializeCriticalSection(&ctx->LockDecompressor);
    }
fail:
    if(!ctx->fValid) {
        LeechRPC_CompressClose();
    }
}

/*
* Compresses data already enclosed in the pMsg contigious buffer. Existing data
* is overwritten with compressed data. (If possible and desirable).
* -- pMsg
*/
VOID LeechRPC_Compress(_Inout_ PLEECHRPC_MSG_BIN pMsg)
{
    PLEECHRPC_COMPRESS ctx = (PLEECHRPC_COMPRESS)&ctxLeechRpc.Compress;
    BOOL result;
    PBYTE pb;
    SIZE_T cb;
    if(ctx->fValid && (pMsg->cb > 0x1000) && !ctxLeechRpc.fCompressDisable) {
        if(!(pb = LocalAlloc(0, pMsg->cb))) { return; }
        EnterCriticalSection(&ctx->LockCompressor);
        result = ctx->fn.pfnCompress(ctx->hCompressor, pMsg->pb, pMsg->cb, pb, pMsg->cb, &cb);
        LeaveCriticalSection(&ctx->LockCompressor);
        if(result && (cb <= pMsg->cb)) {
            memcpy(pMsg->pb, pb, cb);
            pMsg->cbDecompress = pMsg->cb;
            pMsg->cb = (DWORD)cb;
            pMsg->cbMsg = sizeof(LEECHRPC_MSG_BIN) + (DWORD)cb;
        }
        LocalFree(pb);
    }
}

/*
* Decompresses the data in pMsg if possible. The pMsg is also de-allocated and
* must not be used after this function is called. A replacement struct will be
* returned on succcess.
* --pMsg = original pMsg to decompress and deallocate.
* -- return = replacement pMsg on success, NULL on fail.
*/
PLEECHRPC_MSG_BIN LeechRPC_Decompress(_In_ PLEECHRPC_MSG_BIN pMsg)
{
    PLEECHRPC_COMPRESS ctx = (PLEECHRPC_COMPRESS)&ctxLeechRpc.Compress;
    BOOL result;
    SIZE_T cb;
    PLEECHRPC_MSG_BIN pMsg2 = NULL;
    if(!pMsg->cbDecompress) { return pMsg; }
    if(!ctx->hDecompressor || (pMsg->cbDecompress > 0x04000000)) { goto fail; }
    if(!(pMsg2 = (PLEECHRPC_MSG_BIN)LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + pMsg->cbDecompress))) { goto fail; }
    memcpy(pMsg2, pMsg, sizeof(LEECHRPC_MSG_BIN));
    EnterCriticalSection(&ctx->LockDecompressor);
    result = ctx->fn.pfnDecompress(
        ctx->hDecompressor,
        pMsg->pb,
        pMsg->cb,
        pMsg2->pb,
        pMsg2->cbDecompress,
        &cb);
    LeaveCriticalSection(&ctx->LockDecompressor);
    if(!result || (cb != pMsg->cbDecompress)) { goto fail; }
    pMsg2->cb = (DWORD)cb;
    pMsg2->cbMsg = sizeof(LEECHRPC_MSG_BIN) + pMsg2->cb;
    pMsg2->cbDecompress = 0;
    LocalFree(pMsg);
    return pMsg2;
fail:
    LocalFree(pMsg);
    LocalFree(pMsg2);
    return NULL;
}

VOID LeechRpcOnLoadInitialize()
{
    LeechRPC_CompressInitialize();
}

VOID LeechRpcOnUnloadClose()
{
    LeechRPC_CompressClose();
}

error_status_t LeechRpc_CommandReadScatter(_In_ PLEECHRPC_MSG_BIN pReq, long *pcbOut, byte **ppbOut)
{
    BOOL fOK;
    PLEECHRPC_MSG_BIN pRsp = NULL;
    PMEM_IO_SCATTER_HEADER pMEM_Src, pMEM_Dst;
    PPMEM_IO_SCATTER_HEADER ppMEMs = NULL;
    DWORD i, cMEMs, cbMax;
    PBYTE pbData = NULL, pbDataDst;
    DWORD cbDataOffset = 0, cbRead = 0;
    DWORD cbRsp;
    cMEMs = (DWORD)pReq->qwData[0];
    cbMax = (DWORD)pReq->qwData[1];
    // 1: verify incoming result
    fOK = (pReq->cb == cMEMs * sizeof(MEM_IO_SCATTER_HEADER)) && (cMEMs <= 0x2000) && (cbMax <= (cMEMs << 12));
    if(!fOK) { goto fail; }
    // 2: allocate read data buffer, ppMEMs & prepare LeechCore call
    if(!(ppMEMs = LocalAlloc(0, cMEMs * sizeof(MEM_IO_SCATTER_HEADER)))) { goto fail; }
    if(!(pbData = LocalAlloc(0, cbMax))) { goto fail; }
    pMEM_Src = (PMEM_IO_SCATTER_HEADER)pReq->pb;
    for(i = 0; i < cMEMs; i++) {
        pMEM_Src->cb = 0;
        pMEM_Src->pb = pbData + cbDataOffset;
        cbDataOffset += pMEM_Src->cbMax;
        ppMEMs[i] = pMEM_Src;
        pMEM_Src = pMEM_Src + 1;
    }
    if(cbDataOffset > cbMax) { goto fail; }
    // 4: call & count read data
    LeechCore_ReadScatter(ppMEMs, cMEMs);
    LocalFree(ppMEMs);
    ppMEMs = NULL;
    pMEM_Src = (PMEM_IO_SCATTER_HEADER)pReq->pb;
    for(i = 0, cbRead = 0; i < cMEMs; i++) {
        cbRead += pMEM_Src->cb;
        pMEM_Src = pMEM_Src + 1;
    }
    // 5: allocate and prepare result
    cbRsp = sizeof(LEECHRPC_MSG_BIN) + cMEMs * sizeof(MEM_IO_SCATTER_HEADER) + cbRead;
    if(!(pRsp = LocalAlloc(0, cbRsp))) { goto fail; }
    ZeroMemory(pRsp, sizeof(LEECHRPC_MSG_BIN));
    pRsp->cbMsg = cbRsp;
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = TRUE;
    pRsp->tpMsg = LEECHRPC_MSGTYPE_READSCATTER_RSP;
    memcpy(pRsp->pb, pReq->pb, pReq->cb);   // all MEMs
    pbDataDst = pRsp->pb + pReq->cb;        // rsp data buffer
    pMEM_Dst = (PMEM_IO_SCATTER_HEADER)pRsp->pb;
    for(i = 0, cbRead = 0; i < cMEMs; i++) {
        if(pMEM_Dst->cb) {
            memcpy(pbDataDst, pMEM_Dst->pb, pMEM_Dst->cb);
            pbDataDst = pbDataDst + pMEM_Dst->cb;
            cbRead += pMEM_Dst->cb;
        }
        pMEM_Dst = pMEM_Dst + 1;
    }
    pRsp->cb = pReq->cb + cbRead;
    pRsp->qwData[0] = cMEMs;
    LeechRPC_Compress(pRsp);
    *pcbOut = pRsp->cbMsg;
    *ppbOut = (PBYTE)pRsp;
    LocalFree(pbData);
    return 0;
fail:
    LocalFree(pRsp);
    LocalFree(ppMEMs);
    LocalFree(pbData);
    *pcbOut = 0;
    *ppbOut = NULL;
    return (error_status_t)-1;
}

error_status_t LeechRpc_CommandOpen(_In_ PLEECHRPC_MSG_OPEN pReq, long *pcbOut, byte **ppbOut)
{
    PLEECHRPC_MSG_OPEN pRsp = NULL;
    if(!(pRsp = LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_MSG_OPEN)))) {
        *pcbOut = 0;
        *ppbOut = NULL;
        return (error_status_t)-1;
    }
    ctxLeechRpc.fCompressDisable = !ctxLeechRpc.Compress.fValid || (pReq->cfg.flags & LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS) ? TRUE : FALSE;
    pRsp->cbMsg = sizeof(LEECHRPC_MSG_OPEN);
    pRsp->dwMagic = LEECHRPC_MSGMAGIC;
    pRsp->fMsgResult = LeechCore_Open(&pReq->cfg);
    if(pRsp->fMsgResult) {
        memcpy(&pRsp->cfg, &pReq->cfg, sizeof(LEECHCORE_CONFIG));
        pRsp->cfg.flags |= ctxLeechRpc.fCompressDisable ? LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS : 0;
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
    DWORD dw;
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
    if((pReq->dwMagic != LEECHRPC_MSGMAGIC) || (pReq->tpMsg >= LEECHRPC_MSGTYPE_MAX) || (pReq->cbMsg < sizeof(LEECHRPC_MSG_HDR))) { goto fail; }
    switch(pReq->tpMsg) {
        case LEECHRPC_MSGTYPE_PING_REQ:
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
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
        case LEECHRPC_MSGTYPE_WRITE_REQ:
        case LEECHRPC_MSGTYPE_PROBE_REQ:
        case LEECHRPC_MSGTYPE_COMMANDDATA_REQ:
            if(pReq->cbMsg != sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)pReq)->cb) { goto fail; }
            pReqBin = (PLEECHRPC_MSG_BIN)pReq;
            if(pReqBin->cbDecompress) {
                pReqBin = LeechRPC_Decompress(pReqBin);
                pReq = (PLEECHRPC_MSG_HDR)pReqBin;
                if(!pReq) { goto fail; }
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
        case LEECHRPC_MSGTYPE_OPEN_REQ:
            LeechRpc_CommandOpen(pReqOpen, pcbOut, ppbOut);
            return 0;
        case LEECHRPC_MSGTYPE_READSCATTER_REQ:
            status = LeechRpc_CommandReadScatter(pReqBin, pcbOut, ppbOut);
            LocalFree(pReqBin);
            return status;
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = TRUE;
            LeechCore_Close();
            pRsp->tpMsg = LEECHRPC_MSGTYPE_CLOSE_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            return 0;
        case LEECHRPC_MSGTYPE_GETOPTION_REQ:
            if(!(pRspData = LocalAlloc(0, sizeof(LEECHRPC_MSG_DATA)))) { goto fail; }
            pRspData->cbMsg = sizeof(LEECHRPC_MSG_DATA);
            pRspData->dwMagic = LEECHRPC_MSGMAGIC;
            pRspData->fMsgResult = LeechCore_GetOption(pReqData->qwData[0], &pRspData->qwData[0]);
            pRspData->tpMsg = LEECHRPC_MSGTYPE_GETOPTION_RSP;
            *pcbOut = pRspData->cbMsg;
            *ppbOut = (PBYTE)pRspData;
            return 0;
        case LEECHRPC_MSGTYPE_SETOPTION_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = LeechCore_SetOption(pReqData->qwData[0], pReqData->qwData[1]);
            pRsp->tpMsg = LEECHRPC_MSGTYPE_SETOPTION_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            return 0;
        case LEECHRPC_MSGTYPE_WRITE_REQ:
            if(!(pRsp = LocalAlloc(0, sizeof(LEECHRPC_MSG_HDR)))) { goto fail; }
            pRsp->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRsp->dwMagic = LEECHRPC_MSGMAGIC;
            pRsp->fMsgResult = LeechCore_Write(pReqBin->qwData[0], pReqBin->pb, pReqBin->cb);
            pRsp->tpMsg = LEECHRPC_MSGTYPE_WRITE_RSP;
            *pcbOut = pRsp->cbMsg;
            *ppbOut = (PBYTE)pRsp;
            LocalFree(pReqBin);
            return 0;
        case LEECHRPC_MSGTYPE_COMMANDDATA_REQ:
            if(pReqBin->qwData[1] > 0x02000000) { goto fail; } // MAX 32MB
            if(!(pRspBin = LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + pReqBin->qwData[1]))) {
                goto fail;
            }
            pRspBin->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            pRspBin->dwMagic = LEECHRPC_MSGMAGIC;
            pRspBin->fMsgResult = LeechCore_CommandData(pReqBin->qwData[0], pReqBin->pb, pReqBin->cb, pRspBin->pb, (DWORD)pReqBin->qwData[1], &dw);
            pReqBin->qwData[0] = dw;
            pReqBin->cb = (DWORD)pReqBin->qwData[1];
            pRspBin->tpMsg = LEECHRPC_MSGTYPE_WRITE_RSP;
            LeechRPC_Compress(pRspBin);
            *pcbOut = pRspBin->cbMsg;
            *ppbOut = (PBYTE)pRspBin;
            LocalFree(pReqBin);
            return 0;
        default:
            goto fail;
    }
    return 0;
fail:
    *pcbOut = 0;
    *ppbOut = NULL;
    return (error_status_t)-1;
}
