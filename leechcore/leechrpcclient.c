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

//-----------------------------------------------------------------------------
// CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Send and receive data to the pipe server. First write the pMsgIn then listen
* for a pMsgOut response from the server and read it.
* NB! USER_FREE: *ppMsgOut
* -- ctx
* -- pMsgIn
* -- pcbMsgOut
* -- ppMsgOut
* -- return
*/
_Success_(return)
BOOL LeechRPC_SubmitCommand_Pipe(_In_ PLEECHRPC_CLIENT_CONTEXT ctx, _In_ PLEECHRPC_MSG_HDR pMsgIn, _Out_ PDWORD pcbMsgOut, _Out_ PPLEECHRPC_MSG_HDR ppMsgOut)
{
    DWORD cbWrite = 0;
    LEECHRPC_MSG_HDR Hdr = { 0 };
    PLEECHRPC_MSG_HDR pMsgOut;
    if(!pcbMsgOut || !ppMsgOut) { return FALSE; }
    // 1: write contents to pipe
    if(!ctx->hPipeMem_Wr) { return FALSE; }
    if(!WriteFile(ctx->hPipeMem_Wr, (PVOID)pMsgIn, pMsgIn->cbMsg, &cbWrite, NULL)) { return FALSE; }
    // 2: read resulting contents : header
    if(!Util_GetBytesPipe(ctx->hPipeMem_Rd, (PBYTE)&Hdr, sizeof(LEECHRPC_MSG_HDR))) { return FALSE; }
    if((Hdr.dwMagic != LEECHRPC_MSGMAGIC) || (Hdr.cbMsg > 0x04000000)) { return FALSE; }
    pMsgOut = (PLEECHRPC_MSG_HDR)LocalAlloc(0, Hdr.cbMsg);
    if(!pMsgOut) { return FALSE; }
    memcpy(pMsgOut, &Hdr, sizeof(LEECHRPC_MSG_HDR));
    // 3: read resulting contents : data
    if(pMsgOut->cbMsg > sizeof(LEECHRPC_MSG_HDR)) {
        if(!Util_GetBytesPipe(ctx->hPipeMem_Rd, ((PBYTE)pMsgOut) + sizeof(LEECHRPC_MSG_HDR), pMsgOut->cbMsg - sizeof(LEECHRPC_MSG_HDR))) {
            LocalFree(pMsgOut);
            return FALSE;
        }
    }
    *pcbMsgOut = pMsgOut->cbMsg;
    *ppMsgOut = pMsgOut;
    return TRUE;
}

_Success_(return)
BOOL LeechRPC_SubmitCommand(_In_ PLEECHRPC_MSG_HDR pMsgIn, _In_ LEECHRPC_MSGTYPE tpMsgRsp, _Out_ PPLEECHRPC_MSG_HDR ppMsgOut)
{
    PLEECHRPC_CLIENT_CONTEXT ctx = (PLEECHRPC_CLIENT_CONTEXT)ctxDeviceMain->hDevice;
    error_status_t error;
    BOOL fOK;
    DWORD cbMsgOut;
    PLEECHRPC_MSG_BIN pMsgOutDecompress = NULL;
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
        case LEECHRPC_MSGTYPE_COMMANDSVC_REQ:
            pMsgIn->cbMsg = sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)pMsgIn)->cb;
            LeechRPC_Compress(&ctx->Compress, (PLEECHRPC_MSG_BIN)pMsgIn, ctxDeviceMain->cfg.flags & LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS);
            break;
        default:
            return FALSE;
    }
    // submit message to RPC server or PIPE parent process.
    if(ctx->fIsRpc) {
        // RPC connection method:
        __try {
            pMsgIn->dwRpcClientID = ctxDeviceMain->dwRpcClientID;
            pMsgIn->flags = (ctxDeviceMain->cfg.flags & LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS) ? LEECHRPC_FLAG_NOCOMPRESS : 0;
            error = LeechRpc_ReservedSubmitCommand(ctx->hRPC, pMsgIn->cbMsg, (PBYTE)pMsgIn, &cbMsgOut, (PBYTE*)ppMsgOut);
        } __except(EXCEPTION_EXECUTE_HANDLER) { error = E_FAIL; }
        if(error) {
            *ppMsgOut = NULL;
            return FALSE;
        }
    } else {
        // PIPE connection method:
        pMsgIn->dwRpcClientID = ctxDeviceMain->dwRpcClientID;
        pMsgIn->flags = LEECHRPC_FLAG_NOCOMPRESS;
        if(!LeechRPC_SubmitCommand_Pipe(ctx, pMsgIn, &cbMsgOut, ppMsgOut)) {
            *ppMsgOut = NULL;
            return FALSE;
        }
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
            case LEECHRPC_MSGTYPE_COMMANDSVC_RSP:
                fOK = (*ppMsgOut)->cbMsg == sizeof(LEECHRPC_MSG_BIN) + ((PLEECHRPC_MSG_BIN)*ppMsgOut)->cb;
                if(fOK && ((PLEECHRPC_MSG_BIN)*ppMsgOut)->cbDecompress) {
                    if(!LeechRPC_Decompress(&ctx->Compress, (PLEECHRPC_MSG_BIN)*ppMsgOut, &pMsgOutDecompress)) { goto fail; }
                    LocalFree(*ppMsgOut);
                    *ppMsgOut = (PLEECHRPC_MSG_HDR)pMsgOutDecompress;
                }
                break;
            default:
                fOK = FALSE;
                break;
        }
        if(!fOK) { goto fail; }
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
            pMsgRsp = NULL;
        }
        Sleep(100);
    }
    ctx->fHousekeeperThreadIsRunning = FALSE;
}



//-----------------------------------------------------------------------------
// RPC: OPEN/CLOSE FUNCTIONALITY BELOW:
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
    if(ctx->hPipeMem_Rd) {
        CloseHandle(ctx->hPipeMem_Rd);
        ctx->hPipeMem_Rd = NULL;
    }
    if(ctx->hPipeMem_Wr) {
        CloseHandle(ctx->hPipeMem_Wr);
        ctx->hPipeMem_Wr = NULL;
    }
    LeechRPC_RpcClose(ctx);
    LeechRPC_CompressClose(&ctx->Compress);
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
    ctx->fIsRpc = TRUE;
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
            *pcbDataOut = pMsgRsp->cb;
        } else if((pMsgRsp->cb <= cbDataOut) && pbDataOut && pcbDataOut) {
            *pcbDataOut = pMsgRsp->cb;
            memcpy(pbDataOut, pMsgRsp->pb, pMsgRsp->cb);
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
DLLEXPORT BOOL LeechRPC_AgentCommand(
    _In_ ULONG64 fCommand,
    _In_ ULONG64 fDataIn,
    _In_reads_(cbDataIn) PBYTE pbDataIn,
    _In_ DWORD cbDataIn,
    _Out_writes_opt_(*pcbDataOut) PBYTE *ppbDataOut,
    _Out_opt_ PDWORD pcbDataOut
)
{
    BOOL result;
    PLEECHRPC_MSG_BIN pMsgReq = NULL;
    PLEECHRPC_MSG_BIN pMsgRsp = NULL;
    // 1: prepare message to send
    if(!(pMsgReq = LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + cbDataIn))) { return FALSE; }
    ZeroMemory(pMsgReq, sizeof(LEECHRPC_MSG_BIN));
    pMsgReq->tpMsg = LEECHRPC_MSGTYPE_COMMANDSVC_REQ;
    pMsgReq->cb = cbDataIn;
    pMsgReq->qwData[0] = fCommand;
    pMsgReq->qwData[1] = fDataIn;
    memcpy(pMsgReq->pb, pbDataIn, cbDataIn);
    // 2: transmit & get result
    result = LeechRPC_SubmitCommand((PLEECHRPC_MSG_HDR)pMsgReq, LEECHRPC_MSGTYPE_COMMANDSVC_RSP, (PPLEECHRPC_MSG_HDR)&pMsgRsp);
    if(result && (pMsgRsp->cb > 0x04000000)) { result = FALSE; } // Max 64MB
    if(pcbDataOut) { *pcbDataOut = 0; }
    if(result && ppbDataOut && pcbDataOut) {
        *ppbDataOut = LocalAlloc(0, pMsgRsp->cb);
        if(!*ppbDataOut) {
            result = FALSE;
        } else {
            *pcbDataOut = pMsgRsp->cb;
            memcpy(*ppbDataOut, pMsgRsp->pb, pMsgRsp->cb);
        }
    }
    if(!result && pcbDataOut) {
        *pcbDataOut = 0;
    }
    LocalFree(pMsgReq);
    LocalFree(pMsgRsp);
    return result;
}



//-----------------------------------------------------------------------------
// OPEN FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

_Success_(return)
BOOL LeechRPC_Open(_In_ BOOL fIsRpc)
{
    PLEECHRPC_CLIENT_CONTEXT ctx;
    CHAR _szBufferArg[MAX_PATH], _szBufferOpt[MAX_PATH];
    LEECHRPC_MSG_OPEN MsgReq = { 0 };
    PLEECHRPC_MSG_OPEN pMsgRsp = NULL;
    BOOL fOK;
    LPSTR szArg1, szArg2, szArg3;
    LPSTR szOpt[3];
    DWORD i, dwPort = 0;
    int(*pfn_printf_opt_tmp)(_In_z_ _Printf_format_string_ char const* const _Format, ...);
    ctx = (PLEECHRPC_CLIENT_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHRPC_CLIENT_CONTEXT));
    if(!ctx) { return FALSE; }
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    if(fIsRpc) {
        // RPC SPECIFIC INITIALIZATION BELOW:
        // parse arguments
        Util_Split3(ctxDeviceMain->cfg.szRemote + 6, ':', _szBufferArg, &szArg1, &szArg2, &szArg3);
        if(!szArg1 || !szArg1[0] || !szArg2 || !szArg2[0]) { goto fail; }
        // Argument1 : Kerberos SPN or "insecure".
        if(!_stricmp("insecure", szArg1)) {
            ctx->fAllowInsecure = TRUE;
        } else {
            strncpy_s(ctx->szRemoteSPN, _countof(ctx->szRemoteSPN), szArg1, MAX_PATH);
        }
        // Argument2 : Tcp Address.
        strncpy_s(ctx->szTcpAddr, _countof(ctx->szTcpAddr), szArg2, MAX_PATH);
        // Argument3 : Options.
        if(szArg3[0]) {
            Util_Split3(szArg3, ',', _szBufferOpt, &szOpt[0], &szOpt[1], &szOpt[2]);
            for(i = 0; i < 3; i++) {
                if(0 == _stricmp("nocompress", szOpt[i])) {
                    ctxDeviceMain->cfg.flags = ctxDeviceMain->cfg.flags | LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS;
                }
                if(0 == _strnicmp("port=", szOpt[i], 5)) {
                    dwPort = atoi(szOpt[i] + 5);
                }
            }
        }
        if(dwPort == 0) {
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
        if(!LeechRPC_CompressInitialize(&ctx->Compress)) {
            ctxDeviceMain->cfg.flags = ctxDeviceMain->cfg.flags | LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS;
        }
    } else {
        // PIPE SPECIFIC INITIALIZATION BELOW:
        // parse arguments
        Util_Split2(ctxDeviceMain->cfg.szRemote + 7, ':', _szBufferArg, &szArg1, &szArg2);
        if(!szArg1 || !szArg2) { goto fail; }
        ctx->hPipeMem_Rd = (HANDLE)_atoi64(szArg1);
        ctx->hPipeMem_Wr = (HANDLE)_atoi64(szArg2);
        if(!ctx->hPipeMem_Rd || !ctx->hPipeMem_Wr) { goto fail; }
        // ping parent process via the pipe
        if(!LeechRPC_Ping()) {
            vprintf("PIPE: ERROR: Unable to ping remote service '%s'\n", ctxDeviceMain->cfg.szRemote);
            goto fail;
        }
        // no compression
        ctxDeviceMain->cfg.flags = ctxDeviceMain->cfg.flags | LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS;
    }
    // call open on the remote service
    Util_GenRandom((PBYTE)&ctxDeviceMain->dwRpcClientID, sizeof(DWORD));
    MsgReq.tpMsg = LEECHRPC_MSGTYPE_OPEN_REQ;
    memcpy(&MsgReq.cfg, &ctxDeviceMain->cfg, sizeof(LEECHCORE_CONFIG));
    if(!_stricmp("existingremote", MsgReq.cfg.szDevice)) {
        strncpy_s(MsgReq.cfg.szDevice, _countof(MsgReq.cfg.szDevice), "existing", _TRUNCATE);
    }
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
    strncpy_s(pMsgRsp->cfg.szRemote, sizeof(pMsgRsp->cfg.szRemote), ctxDeviceMain->cfg.szRemote, _TRUNCATE); // ctx from remote doesn't contain remote info ...
    pfn_printf_opt_tmp = ctxDeviceMain->cfg.pfn_printf_opt;
    memcpy(&ctxDeviceMain->cfg, &pMsgRsp->cfg, sizeof(LEECHCORE_CONFIG));
    ctxDeviceMain->cfg.pfn_printf_opt = pfn_printf_opt_tmp;
    ctxDeviceMain->cfg.fRemote = TRUE;
    ctxDeviceMain->cfg.cbMaxSizeMemIo = 0x01000000;     // 16MB
    ctxDeviceMain->fDeviceMultiThread = ctx->fIsRpc;    // RPC = multi-thread, PIPE = single-thread access
    if(pMsgRsp->flags & LEECHRPC_FLAG_FNEXIST_ReadScatterMEM) {
        ctxDeviceMain->pfnReadScatterMEM = LeechRPC_ReadScatterMEM;
    }
    if(pMsgRsp->flags & LEECHRPC_FLAG_FNEXIST_WriteMEM) {
        ctxDeviceMain->pfnWriteMEM = LeechRPC_WriteMEM;
    }
    if(pMsgRsp->flags & LEECHRPC_FLAG_FNEXIST_ProbeMEM) {
        ctxDeviceMain->pfnProbeMEM = LeechRPC_ProbeMEM;
    }
    if(pMsgRsp->flags & LEECHRPC_FLAG_FNEXIST_Close) {
        ctxDeviceMain->pfnClose = LeechRPC_Close;
    }
    if(pMsgRsp->flags & LEECHRPC_FLAG_FNEXIST_GetOption) {
        ctxDeviceMain->pfnGetOption = LeechRPC_GetOption;
    }
    if(pMsgRsp->flags & LEECHRPC_FLAG_FNEXIST_SetOption) {
        ctxDeviceMain->pfnSetOption = LeechRPC_SetOption;
    }
    if(pMsgRsp->flags & LEECHRPC_FLAG_FNEXIST_CommandData) {
        ctxDeviceMain->pfnCommandData = LeechRPC_CommandData;
    }
    ctxDeviceMain->pfnAgentCommand = LeechRPC_AgentCommand;
    vprintfv("RPC: Successfully opened remote device of type: %.i\n", ctxDeviceMain->cfg.tpDevice);
    return TRUE;
fail:
    LeechRPC_Close();
    return FALSE;
}

#endif /* _WIN32 */
#ifdef LINUX

_Success_(return)
BOOL LeechRPC_Open(_In_ BOOL fIsRpc)
{
    return FALSE;
}

#endif /* LINUX */
