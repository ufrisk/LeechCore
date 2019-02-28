// leechrpcclient.c : implementation of the remote procedure call (RPC) client.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechrpc.h"
#include "device.h"
#include "util.h"

#ifdef _WIN32
#include <rpc.h>
#include "leechrpc_h.h"

/*********************************************************************/
/*                MIDL allocate and free                             */
/*********************************************************************/
void __RPC_FAR * __RPC_USER midl_user_allocate(size_t len)
{
    return LocalAlloc(0, len);
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
    LocalFree(ptr);
}

//-----------------------------------------------------------------------------
// COMPRESSION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#include <compressapi.h>

VOID LeechRPC_CompressClose()
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxDeviceMain->hDevice;
    if(ctx->Compress.fValid) {
        DeleteCriticalSection(&ctx->Compress.LockCompressor);
        DeleteCriticalSection(&ctx->Compress.LockDecompressor);
    }
    if(ctx->Compress.hCompressor) { ctx->Compress.fn.pfnCloseCompressor(ctx->Compress.hCompressor); }
    if(ctx->Compress.hDecompressor) { ctx->Compress.fn.pfnCloseCompressor(ctx->Compress.hDecompressor); }
    if(ctx->Compress.hDll) { FreeLibrary(ctx->Compress.hDll); }
    ZeroMemory(&ctx->Compress, sizeof(ctx->Compress));
}

VOID LeechRPC_CompressInitialize()
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxDeviceMain->hDevice;
    const LPSTR FN_LIST[] = { "CreateCompressor", "CreateDecompressor", "CloseCompressor", "CloseDecompressor", "Compress", "Decompress" };
    DWORD i;
    if(sizeof(ctx->Compress.fn) != sizeof(FN_LIST)) { return; }
    ctx->Compress.hDll = LoadLibraryA("cabinet.dll");
    if(!ctx->Compress.hDll) { return; }
    for(i = 0; i < sizeof(FN_LIST) / sizeof(LPSTR); i++) {
        if(!(*((PQWORD)&ctx->Compress.fn + i) = (QWORD)GetProcAddress(ctx->Compress.hDll, FN_LIST[i]))) { goto fail; }
    }
    ctx->Compress.fValid =
        ctx->Compress.fn.pfnCreateCompressor(3, NULL, &ctx->Compress.hCompressor) &&
        ctx->Compress.fn.pfnCreateDecompressor(3, NULL, &ctx->Compress.hDecompressor);
    if(ctx->Compress.fValid) {
        InitializeCriticalSection(&ctx->Compress.LockCompressor);
        InitializeCriticalSection(&ctx->Compress.LockDecompressor);
    }
fail:
    if(!ctx->Compress.fValid) {
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
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxDeviceMain->hDevice;
    BOOL result;
    PBYTE pb;
    SIZE_T cb;
    if(ctx->Compress.fValid && (pMsg->cb > 0x1000) && !(ctxDeviceMain->cfg.flags & LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS)) {
        if(!(pb = LocalAlloc(0, pMsg->cb))) { return; }
        EnterCriticalSection(&ctx->Compress.LockCompressor);
        result = ctx->Compress.fn.pfnCompress(ctx->Compress.hCompressor, pMsg->pb, pMsg->cb, pb, pMsg->cb, &cb);
        LeaveCriticalSection(&ctx->Compress.LockCompressor);
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
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxDeviceMain->hDevice;
    BOOL result;
    SIZE_T cb;
    PLEECHRPC_MSG_BIN pMsg2 = NULL;
    if(!pMsg->cbDecompress) { return pMsg; }
    if(!ctx->Compress.hDecompressor || (pMsg->cbDecompress > 0x04000000)) { goto fail; }
    if(!(pMsg2 = (PLEECHRPC_MSG_BIN)LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + pMsg->cbDecompress))) { goto fail; }
    memcpy(pMsg2, pMsg, sizeof(LEECHRPC_MSG_BIN));
    EnterCriticalSection(&ctx->Compress.LockDecompressor);
    result = ctx->Compress.fn.pfnDecompress(
        ctx->Compress.hDecompressor,
        pMsg->pb,
        pMsg->cb,
        pMsg2->pb,
        pMsg2->cbDecompress,
        &cb);
    LeaveCriticalSection(&ctx->Compress.LockDecompressor);
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



//-----------------------------------------------------------------------------
// CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL LeechRPC_SubmitCommand(_In_ PLEECHRPC_MSG_HDR pMsgIn, _In_ LEECHRPC_MSGTYPE tpMsgRsp, _Out_ PPLEECHRPC_MSG_HDR ppMsgOut)
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxDeviceMain->hDevice;
    error_status_t error;
    BOOL fOK;
    DWORD cbMsgOut;
    // fill out message header given a message type
    pMsgIn->dwMagic = LEECHRPC_MSGMAGIC;
    pMsgIn->fMsgResult = TRUE;
    switch(pMsgIn->tpMsg) {
        case LEECHRPC_MSGTYPE_PING_REQ:
        case LEECHRPC_MSGTYPE_CLOSE_REQ:
        case LEECHRPC_MSGTYPE_KEEPALIVE_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_HDR);
            break;
        case LEECHRPC_MSGTYPE_OPEN_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_OPEN);
            break;
        case LEECHRPC_MSGTYPE_GETOPTION_REQ:
        case LEECHRPC_MSGTYPE_SETOPTION_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_DATA);
            break;
        case LEECHRPC_MSGTYPE_READSCATTER_REQ:
        case LEECHRPC_MSGTYPE_WRITE_REQ:
        case LEECHRPC_MSGTYPE_PROBE_REQ:
        case LEECHRPC_MSGTYPE_COMMANDDATA_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)pMsgIn)->cb;
            LeechRPC_Compress((PLEECHRPC_MSG_BIN)pMsgIn);
            break;
        default:
            return FALSE;
    }
    // submit message to RPC server.
    __try {
        pMsgIn->qwRpcClientID = ctxDeviceMain->qwRpcClientID;
        error = LeechRpc_ReservedSubmitCommand(ctx->hRPC, pMsgIn->cbMsg, (PBYTE)pMsgIn, &cbMsgOut, (PBYTE*)ppMsgOut);
    } __except(EXCEPTION_EXECUTE_HANDLER) { error = E_FAIL; }
    if(error) {
        *ppMsgOut = NULL;
        return FALSE;
    }
    // sanity check non-trusted incoming message from RPC server.
    fOK = (cbMsgOut >= sizeof(LEECHRPC_MSG_HDR)) && *ppMsgOut && ((*ppMsgOut)->dwMagic == LEECHRPC_MSGMAGIC);
    fOK = fOK && ((*ppMsgOut)->tpMsg <= LEECHRPC_MSGTYPE_MAX) && ((*ppMsgOut)->cbMsg == cbMsgOut);
    fOK = fOK && (*ppMsgOut)->fMsgResult && ((*ppMsgOut)->tpMsg == tpMsgRsp);
    if(fOK) {
        switch((*ppMsgOut)->tpMsg) {
            case LEECHRPC_MSGTYPE_PING_RSP:
            case LEECHRPC_MSGTYPE_CLOSE_RSP:
            case LEECHRPC_MSGTYPE_KEEPALIVE_RSP:
            case LEECHRPC_MSGTYPE_WRITE_RSP:
            case LEECHRPC_MSGTYPE_SETOPTION_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_HDR);
                break;
            case LEECHRPC_MSGTYPE_OPEN_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_OPEN);
                break;
            case LEECHRPC_MSGTYPE_GETOPTION_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_DATA);
                break;
            case LEECHRPC_MSGTYPE_READSCATTER_RSP:
            case LEECHRPC_MSGTYPE_PROBE_RSP:
            case LEECHRPC_MSGTYPE_COMMANDDATA_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)*ppMsgOut)->cb;
                if(fOK) {
                    *ppMsgOut = (PLEECHRPC_MSG_HDR)LeechRPC_Decompress((PLEECHRPC_MSG_BIN)*ppMsgOut);
                    if(!*ppMsgOut) { goto fail; }
                }
                break;
            default:
                LocalFree(*ppMsgOut);
                *ppMsgOut = NULL;
                return FALSE;
        }
        return TRUE;
    }
fail:
    LocalFree(*ppMsgOut);
    *ppMsgOut = NULL;
    return FALSE;
}

_Success_(return)
BOOL LeechRPC_Ping()
{
    BOOL result;
    LEECHRPC_MSG_HDR MsgReq = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_PING_REQ;
    result = LeechRPC_SubmitCommand(&MsgReq, LEECHRPC_MSGTYPE_PING_RSP, &pMsgRsp);
    LocalFree(pMsgRsp);
    return result;
}



//-----------------------------------------------------------------------------
// CLIENT TRACK / KEEPALIVE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRPC_KeepaliveThreadClient(PVOID pv)
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxDeviceMain->hDevice;
    LEECHRPC_MSG_HDR MsgReq = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    DWORD c = 0;
    ctx->fHousekeeperThread = TRUE;
    ctx->fHousekeeperThreadIsRunning = TRUE;
    while(ctx->fHousekeeperThread) {
        c++;
        if(0 == (c % (10 * 15))) { // send keepalive every 15s
            ZeroMemory(&MsgReq, sizeof(LEECHRPC_MSG_HDR));
            MsgReq.tpMsg = LEECHRPC_MSGTYPE_KEEPALIVE_REQ;
            LeechRPC_SubmitCommand(&MsgReq, LEECHRPC_MSGTYPE_KEEPALIVE_RSP, &pMsgRsp);
            LocalFree(pMsgRsp);
        }
        Sleep(100);
    }
    ctx->fHousekeeperThreadIsRunning = FALSE;
}



//-----------------------------------------------------------------------------
// OPEN/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRPC_RpcClose(PLEECHRPC_CLIENT_CONTEXT ctx)
{
    if(ctx->hRPC) { 
        RpcBindingFree(ctx->hRPC);
        ctx->hRPC = NULL;
    }
    if(ctx->szStringBinding) {
        RpcStringFreeA(&ctx->szStringBinding);
        ctx->szStringBinding = NULL;
    }
}

VOID LeechRPC_Close()
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxDeviceMain->hDevice;
    LEECHRPC_MSG_HDR Msg = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    if(!ctx) { return; }
    ctx->fHousekeeperThread = FALSE;
    Msg.tpMsg = LEECHRPC_MSGTYPE_CLOSE_REQ;
    if(LeechRPC_SubmitCommand(&Msg, LEECHRPC_MSGTYPE_CLOSE_RSP, &pMsgRsp)) {
        LocalFree(pMsgRsp);
    }
    LeechRPC_RpcClose(ctx);
    LeechRPC_CompressClose();
    LocalFree(ctx);
    ctxDeviceMain->hDevice = NULL;
}

_Success_(return)
BOOL LeechRPC_RpcInitialize(PLEECHRPC_CLIENT_CONTEXT ctx)
{
    RPC_STATUS status;
    RPC_SECURITY_QOS RpcSecurityQOS = { 0 };
    LeechRPC_RpcClose(ctx);
    status = RpcStringBindingComposeA(
        CLSID_BINDING_INTERFACE_LEECHRPC,
        "ncacn_ip_tcp",
        ctx->szTcpAddr,
        ctx->szTcpPort,
        NULL,
        &ctx->szStringBinding);
    if(status) {
        vprintf("RPC: Failed compose binding: Error code: 0x%08x\n", status);
        LeechRPC_RpcClose(ctx);
        return FALSE;
    }
    status = RpcBindingFromStringBindingA(ctx->szStringBinding, &ctx->hRPC);
    if(status) {
        vprintf("RPC: Failed create binding: Error code: 0x%08x\n", status);
        LeechRPC_RpcClose(ctx);
        return FALSE;
    }
    if(!ctx->fAllowInsecure) {
        RpcSecurityQOS.Version = 1;
        RpcSecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
        RpcSecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_DYNAMIC;
        RpcSecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IDENTIFY;
        status = RpcBindingSetAuthInfoExA(
            ctx->hRPC,
            ctx->szRemoteSPN,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_AUTHN_GSS_KERBEROS,
            NULL,
            0,
            &RpcSecurityQOS);
        if(status) {
            vprintf("RPC: Failed to set connection security: SPN: '%s', Error code: 0x%08x\n", ctx->szRemoteSPN, status);
            vprintf("     Maybe try kerberos security disable by specify SPN 'insecure' if server allows...\n");
            LeechRPC_RpcClose(ctx);
            return FALSE;
        }
    }
    vprintfv("leechrpcclient.c!LeechRPC_RpcInitialize: '%s'\n", ctx->szStringBinding);
    return TRUE;
}



//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRPC_ReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    BOOL result, fOK;
    DWORD i;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    PLEECHRPC_MSG_BIN pMsgRsp = NULL;
    DWORD cbOffset, cbTotal = 0;
    PMEM_IO_SCATTER_HEADER pMEM_Src, pMEM_Dst;
    // 1: prepare message to send
    if(!(pMsgReq = LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + cpMEMs * sizeof(MEM_IO_SCATTER_HEADER)))) { return; }
    ZeroMemory(pMsgReq, sizeof(LEECHRPC_MSG_BIN));
    pMsgReq->tpMsg = LEECHRPC_MSGTYPE_READSCATTER_REQ;
    pMsgReq->cb = cpMEMs * sizeof(MEM_IO_SCATTER_HEADER);
    pMEM_Dst = (PMEM_IO_SCATTER_HEADER)pMsgReq->pb;
    for(i = 0; i < cpMEMs; i++) {
        pMEM_Src = ppMEMs[i];
        // sanity check incoming data
        fOK = (pMEM_Src->magic == MEM_IO_SCATTER_HEADER_MAGIC) && (pMEM_Src->version == MEM_IO_SCATTER_HEADER_VERSION);
        fOK = fOK && (pMEM_Src->cbMax <= 0x1000);
        if(!fOK) { goto fail; }
        cbTotal += pMEM_Src->cbMax;
        memcpy(pMEM_Dst, pMEM_Src, sizeof(MEM_IO_SCATTER_HEADER));
        // zero out already completed MEMs - no need to ask remote system to re-read!
        if(pMEM_Dst->cb >= pMEM_Dst->cbMax) {
            pMEM_Dst->cb = 0;
            pMEM_Dst->cbMax = 0;
        }
        pMEM_Dst = pMEM_Dst + 1;
    }
    pMsgReq->qwData[0] = cpMEMs;
    pMsgReq->qwData[1] = cbTotal;
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand((PLEECHRPC_MSG_HDR)pMsgReq, LEECHRPC_MSGTYPE_READSCATTER_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    if(!result) { goto fail; }
    if(result && (pMsgRsp->qwData[0] == cpMEMs) && (pMsgRsp->cb >= cpMEMs * sizeof(MEM_IO_SCATTER_HEADER))) {
        cbOffset = cpMEMs * sizeof(MEM_IO_SCATTER_HEADER);
        pMEM_Src = (PMEM_IO_SCATTER_HEADER)pMsgRsp->pb;
        for(i = 0; i < cpMEMs; i++) {
            pMEM_Dst = ppMEMs[i];
            // sanity check
            fOK = (pMEM_Src->magic == MEM_IO_SCATTER_HEADER_MAGIC) && (pMEM_Src->version == MEM_IO_SCATTER_HEADER_VERSION);
            fOK = fOK && (pMEM_Src->qwA == pMEM_Dst->qwA) && (pMEM_Src->cb <= pMsgRsp->cb - cbOffset);
            if(!fOK) { break; }
            if((pMEM_Src->cb == 0) && (pMEM_Src->cbMax == 0)) {
                ; // skip over (already completed).
            } else if((pMEM_Src->cb == pMEM_Dst->cbMax) && (pMEM_Src->cbMax == pMEM_Dst->cbMax)) {
                pMEM_Dst->cb = pMEM_Src->cb;
                memcpy(pMEM_Dst->pb, pMsgRsp->pb + cbOffset, pMEM_Src->cb);
                cbOffset += pMEM_Src->cb;
            } else {
                pMEM_Dst->cb = 0;
            }
            pMEM_Src = pMEM_Src + 1;
        }
    }
fail:
    LocalFree(pMsgReq);
    LocalFree(pMsgRsp);
}

_Success_(return)
BOOL LeechRPC_WriteMEM(_In_ QWORD pa, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    // 1: prepare message to send
    if(!(pMsgReq = LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + cb))) { return FALSE; }
    ZeroMemory(pMsgReq, sizeof(LEECHRPC_MSG_BIN));
    pMsgReq->tpMsg = LEECHRPC_MSGTYPE_WRITE_REQ;
    pMsgReq->qwData[0] = pa;
    pMsgReq->cb = cb;
    memcpy(pMsgReq->pb, pb, cb);
    // 2: transmit
    result = LeechRPC_SubmitCommand((PLEECHRPC_MSG_HDR)pMsgReq, LEECHRPC_MSGTYPE_WRITE_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    LocalFree(pMsgReq);
    LocalFree(pMsgRsp);
    return result;
}

VOID LeechRPC_ProbeMEM(_In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_updates_bytes_(cPages) PBYTE pbResultMap)
{
    BOOL result;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    PLEECHRPC_MSG_BIN pMsgRsp = NULL;
    // 1: prepare message to send
    if(!(pMsgReq = LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + cPages))) { return; }
    ZeroMemory(pMsgReq, sizeof(LEECHRPC_MSG_BIN));
    pMsgReq->tpMsg = LEECHRPC_MSGTYPE_PROBE_REQ;
    pMsgReq->qwData[0] = qwAddr;
    pMsgReq->cb = cPages;
    memcpy(pMsgReq->pb, pbResultMap, cPages);
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand((PLEECHRPC_MSG_HDR)pMsgReq, LEECHRPC_MSGTYPE_PROBE_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    if(result && (pMsgRsp->cb == cPages)) {
        memcpy(pbResultMap, pMsgRsp->pb, cPages);
    }
    LocalFree(pMsgReq);
    LocalFree(pMsgRsp);
}

_Success_(return)
BOOL LeechRPC_GetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    BOOL result;
    LEECHRPC_MSG_DATA MsgReq = { 0 };
    PLEECHRPC_MSG_DATA pMsgRsp = NULL;
    // 1: prepare message to send
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_GETOPTION_REQ;
    MsgReq.qwData[0] = fOption;
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand((PLEECHRPC_MSG_HDR)&MsgReq, LEECHRPC_MSGTYPE_GETOPTION_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    *pqwValue = result ? pMsgRsp->qwData[0] : 0;
    LocalFree(pMsgRsp);
    return result;
}

_Success_(return)
BOOL LeechRPC_SetOption(_In_ QWORD fOption, _In_ QWORD qwValue)
{
    BOOL result;
    LEECHRPC_MSG_DATA MsgReq = { 0 };
    PLEECHRPC_MSG_HDR pMsgRsp = NULL;
    // 1: prepare message to send
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_SETOPTION_REQ;
    MsgReq.qwData[0] = fOption;
    MsgReq.qwData[1] = qwValue;
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand((PLEECHRPC_MSG_HDR)&MsgReq, LEECHRPC_MSGTYPE_SETOPTION_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    LocalFree(pMsgRsp);
    return result;
}

_Success_(return)
BOOL LeechRPC_CommandData(_In_ ULONG64 fOption, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(cbDataOut) PBYTE pbDataOut, _In_ DWORD cbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    BOOL result;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    PLEECHRPC_MSG_BIN pMsgRsp = NULL;
    // 1: prepare message to send
    if(!(pMsgReq = LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + cbDataIn))) { return FALSE; }
    ZeroMemory(pMsgReq, sizeof(LEECHRPC_MSG_BIN));
    pMsgReq->tpMsg = LEECHRPC_MSGTYPE_COMMANDDATA_REQ;
    pMsgReq->cb = cbDataIn;
    pMsgReq->qwData[0] = fOption;
    pMsgReq->qwData[1] = cbDataOut;
    memcpy(pMsgReq->pb, pbDataIn, cbDataIn);
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand((PLEECHRPC_MSG_HDR)pMsgReq, LEECHRPC_MSGTYPE_COMMANDDATA_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    if(result) {
        if(!pbDataOut && pcbDataOut) {
            *pcbDataOut = (DWORD)pMsgRsp->qwData[0];
        } else if((pMsgRsp->qwData[0] <= cbDataOut) && pbDataOut && pcbDataOut) {
            *pcbDataOut = (DWORD)pMsgRsp->qwData[0];
            memcpy(pbDataOut, pMsgRsp->pb, pMsgRsp->qwData[0]);
        } else {
            result = FALSE;
        }
    }
    if(!result && pcbDataOut) {
        *pcbDataOut = 0;
    }
    LocalFree(pMsgReq);
    LocalFree(pMsgRsp);
    return result;
}

_Success_(return)
BOOL LeechRPC_Open()
{
    PLEECHRPC_CLIENT_CONTEXT ctx;
    CHAR _szBuffer[MAX_PATH];
    LEECHRPC_MSG_OPEN MsgReq = { 0 };
    PLEECHRPC_MSG_OPEN pMsgRsp = NULL;
    BOOL fOK;
    LPSTR szArg1, szArg2;
    DWORD dwPort;
    ctx = (PLEECHRPC_CLIENT_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_CLIENT_CONTEXT));
    if(!ctx) { return FALSE; }
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    // parse arguments
    Util_Split2(ctxDeviceMain->cfg.szRemote + 6, ':', _szBuffer, &szArg1, &szArg2);
    if(!szArg1 || !szArg1[0] || !szArg2 || !szArg2[0]) { goto fail; }
    if(!_stricmp("insecure", szArg1)) {
        ctx->fAllowInsecure = TRUE;
    } else {
        strncpy_s(ctx->szRemoteSPN, _countof(ctx->szRemoteSPN), szArg1, MAX_PATH);
    }
    Util_Split2(szArg2, ':', _szBuffer, &szArg1, &szArg2);
    strncpy_s(ctx->szTcpAddr, _countof(ctx->szTcpAddr), szArg1, MAX_PATH);
    if(szArg2 && szArg2[0] && atoi(szArg2) && (0xffff >= atoi(szArg2))) {
        dwPort = atoi(szArg2);
    } else {
        dwPort = 28473; // default port
    }
    _itoa_s(dwPort, ctx->szTcpPort, 6, 10);
    // initialize rpc connection and ping
    if(!LeechRPC_RpcInitialize(ctx)) {
        vprintf("RPC: ERROR: Unable to connect to remote service '%s'\n", ctxDeviceMain->cfg.szRemote);
        goto fail;
    }
    if(!LeechRPC_Ping()) {
        vprintf("RPC: ERROR: Unable to ping remote service '%s'\n", ctxDeviceMain->cfg.szRemote);
        goto fail;
    }
    LeechRPC_CompressInitialize();
    if(!ctx->Compress.fValid) {
        ctxDeviceMain->cfg.flags = ctxDeviceMain->cfg.flags | LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS;
    }
    // call open on the remote service
    Util_GenRandom((PBYTE)&ctxDeviceMain->qwRpcClientID, sizeof(QWORD));
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_OPEN_REQ;
    memcpy(&MsgReq.cfg, &ctxDeviceMain->cfg, sizeof(LEECHCORE_CONFIG));
    ZeroMemory(MsgReq.cfg.szRemote, _countof(MsgReq.cfg.szRemote));
    MsgReq.cfg.pfn_printf_opt = 0;
    if(!LeechRPC_SubmitCommand((PLEECHRPC_MSG_HDR)&MsgReq, LEECHRPC_MSGTYPE_OPEN_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp)) {
        vprintf("RPC: ERROR: Unable to open remote device '%s'\n", ctxDeviceMain->cfg.szDevice);
        goto fail;
    }
    // sanity check positive result from remote service
    fOK = pMsgRsp->cbMsg == sizeof(LEECHRPC_MSG_OPEN);
    fOK = fOK && (pMsgRsp->cfg.magic == LEECHCORE_CONFIG_MAGIC);
    fOK = fOK && (pMsgRsp->cfg.version == LEECHCORE_CONFIG_VERSION);
    if(!fOK) {
        vprintf("RPC: ERROR: Invalid message received from remote service.\n");
        goto fail;
    }
    if(pMsgRsp->cfg.flags & LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS) {
        vprintfv("RPC: INFO: Compression disabled.\n");
    }
    // all ok - initialize this rpc device stub.
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechRPC_KeepaliveThreadClient, NULL, 0, NULL);
    memcpy(&ctxDeviceMain->cfg, &pMsgRsp->cfg, sizeof(LEECHCORE_CONFIG));
    ctxDeviceMain->cfg.fRemote = TRUE;
    ctxDeviceMain->cfg.cbMaxSizeMemIo = 0x01000000; // 16MB
    ctxDeviceMain->fDeviceMultiThread = TRUE;
    ctxDeviceMain->pfnReadScatterMEM = LeechRPC_ReadScatterMEM;
    ctxDeviceMain->pfnWriteMEM = LeechRPC_WriteMEM;
    ctxDeviceMain->pfnProbeMEM = LeechRPC_ProbeMEM;
    ctxDeviceMain->pfnClose = LeechRPC_Close;
    ctxDeviceMain->pfnGetOption = LeechRPC_GetOption;
    ctxDeviceMain->pfnSetOption = LeechRPC_SetOption;
    ctxDeviceMain->pfnCommandData = LeechRPC_CommandData;
    vprintfv("RPC: Successfully opened remote device of type: %.i\n", ctxDeviceMain->cfg.tpDevice);
    return TRUE;
fail:
    LeechRPC_Close();
    return FALSE;
}

#endif /* _WIN32 */
#ifdef LINUX

_Success_(return)
BOOL LeechRPC_Open()
{
    return FALSE;
}

#endif /* LINUX */
