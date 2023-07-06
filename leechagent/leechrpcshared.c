// leechrpcshared.c : implementation of the remote procedure call (RPC) shared functionality (client/server).
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <stdio.h>
#include "leechrpc.h"

//-----------------------------------------------------------------------------
// MIDL ALLOCATE AND FREE:
//-----------------------------------------------------------------------------

_Must_inspect_result_
_Ret_maybenull_ _Post_writable_byte_size_(size)
void  * __RPC_USER MIDL_user_allocate(_In_ size_t size)
{
    return LocalAlloc(0, size);
}

void __RPC_USER MIDL_user_free(_Pre_maybenull_ _Post_invalid_ void* ptr)
{
    LocalFree(ptr);
}

//-----------------------------------------------------------------------------
// COMPRESSION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRPC_CompressClose(_Inout_ PLEECHRPC_COMPRESS ctxCompress)
{
    DWORD i;
    for(i = 0; i < LEECHRPC_COMPRESS_MAXTHREADS; i++) {
        if(ctxCompress->fValid) {
            DeleteCriticalSection(&ctxCompress->Compress[i].Lock);
            DeleteCriticalSection(&ctxCompress->Decompress[i].Lock);
        }
        if(ctxCompress->Compress[i].h) { ctxCompress->fn.pfnCloseCompressor(ctxCompress->Compress[i].h); }
        if(ctxCompress->Decompress[i].h) { ctxCompress->fn.pfnCloseCompressor(ctxCompress->Decompress[i].h); }
    }
    if(ctxCompress->hDll) { FreeLibrary(ctxCompress->hDll); }
    ZeroMemory(ctxCompress, sizeof(LEECHRPC_COMPRESS));
}

BOOL LeechRPC_CompressInitialize(_Inout_ PLEECHRPC_COMPRESS ctxCompress)
{
    const LPSTR FN_LIST[] = { "CreateCompressor", "CreateDecompressor", "CloseCompressor", "CloseDecompressor", "Compress", "Decompress" };
    DWORD i;
    LeechRPC_CompressClose(ctxCompress);
    ctxCompress->hDll = LoadLibraryA("cabinet.dll");
    if(!ctxCompress->hDll) { return FALSE; }
    for(i = 0; i < sizeof(FN_LIST) / sizeof(LPSTR); i++) {
        if(!(*((PSIZE_T)&ctxCompress->fn + i) = (SIZE_T)GetProcAddress(ctxCompress->hDll, FN_LIST[i]))) { goto fail; }
    }
    ctxCompress->fValid = TRUE;
    for(i = 0; i < LEECHRPC_COMPRESS_MAXTHREADS; i++) {
        ctxCompress->fValid =
            ctxCompress->fValid &&
            ctxCompress->fn.pfnCreateCompressor(3, NULL, &ctxCompress->Compress[i].h) &&
            ctxCompress->fn.pfnCreateDecompressor(3, NULL, &ctxCompress->Decompress[i].h);
    }
    if(ctxCompress->fValid) {
        for(i = 0; i < LEECHRPC_COMPRESS_MAXTHREADS; i++) {
            InitializeCriticalSection(&ctxCompress->Compress[i].Lock);
            InitializeCriticalSection(&ctxCompress->Decompress[i].Lock);
        }
    }
    // fall-through
fail:
    if(!ctxCompress->fValid) {
        LeechRPC_CompressClose(ctxCompress);
    }
    return ctxCompress->fValid;
}

VOID LeechRPC_Compress(_In_ PLEECHRPC_COMPRESS ctxCompress, _Inout_ PLEECHRPC_MSG_BIN pMsg, _In_ BOOL fCompressDisable)
{
    BOOL result;
    PBYTE pb;
    SIZE_T cb;
    DWORD i;
    if(ctxCompress->fValid && (pMsg->cb > 0x1800) && !fCompressDisable) {
        if(!(pb = LocalAlloc(0, pMsg->cb))) { return; }
        do {
            i = InterlockedIncrement(&ctxCompress->iCompress) % LEECHRPC_COMPRESS_MAXTHREADS;
        } while(!TryEnterCriticalSection(&ctxCompress->Compress[i].Lock));
        result = ctxCompress->fn.pfnCompress(ctxCompress->Compress[i].h, pMsg->pb, pMsg->cb, pb, pMsg->cb, &cb);
        LeaveCriticalSection(&ctxCompress->Compress[i].Lock);
        if(result && (cb <= pMsg->cb)) {
            memcpy(pMsg->pb, pb, cb);
            pMsg->cbDecompress = pMsg->cb;
            pMsg->cb = (DWORD)cb;
            pMsg->cbMsg = sizeof(LEECHRPC_MSG_BIN) + (DWORD)cb;
        }
        LocalFree(pb);
    }
}

_Success_(return)
BOOL LeechRPC_Decompress(_In_ PLEECHRPC_COMPRESS ctxCompress, _In_ PLEECHRPC_MSG_BIN pMsgIn, _Out_ PLEECHRPC_MSG_BIN *ppMsgOut)
{
    BOOL result;
    DWORD i;
    SIZE_T cb;
    PLEECHRPC_MSG_BIN pMsgOut = NULL;
    *ppMsgOut = NULL;
    if(!pMsgIn->cbDecompress) { return FALSE; }
    if(!ctxCompress->fValid || (pMsgIn->cbDecompress > 0x04000000)) { return FALSE; }
    if(!(pMsgOut = (PLEECHRPC_MSG_BIN)LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + pMsgIn->cbDecompress))) { return FALSE; }
    memcpy(pMsgOut, pMsgIn, sizeof(LEECHRPC_MSG_BIN));
    do {
        i = InterlockedIncrement(&ctxCompress->iDecompress) % LEECHRPC_COMPRESS_MAXTHREADS;
    } while(!TryEnterCriticalSection(&ctxCompress->Decompress[i].Lock));
    result = ctxCompress->fn.pfnDecompress(
        ctxCompress->Decompress[i].h,
        pMsgIn->pb,
        pMsgIn->cb,
        pMsgOut->pb,
        pMsgOut->cbDecompress,
        &cb);
    LeaveCriticalSection(&ctxCompress->Decompress[i].Lock);
    if(!result || (cb != pMsgIn->cbDecompress)) {
        LocalFree(pMsgOut);
        return FALSE;
    }
    pMsgOut->cb = (DWORD)cb;
    pMsgOut->cbMsg = sizeof(LEECHRPC_MSG_BIN) + pMsgOut->cb;
    pMsgOut->cbDecompress = 0;
    *ppMsgOut = pMsgOut;
    return TRUE;
}

//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechSvc_GetTimeStamp(_Out_writes_(32) LPSTR szTime)
{
    SYSTEMTIME time;
    GetLocalTime(&time);
    sprintf_s(
        szTime,
        32,
        "%04i-%02i-%02i %02i:%02i:%02i",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond
    );
}
