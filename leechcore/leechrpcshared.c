// leechrpcshared.c : implementation of the remote procedure call (RPC) shared functionality (client/server).
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <stdio.h>
#include "leechrpc.h"

#ifdef _WIN32

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

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_BUFFER_ALL_ZEROS          ((NTSTATUS)0x00000117L)

VOID LeechRPC_CompressClose(_Inout_ PLEECHRPC_COMPRESS ctxCompress)
{
    DWORD i;
    for(i = 0; i < LEECHRPC_COMPRESS_MAXTHREADS; i++) {
        if(ctxCompress->fValid) {
            DeleteCriticalSection(&ctxCompress->Compress[i].Lock);
            LocalFree(ctxCompress->Compress[i].pbWorkspace);
        }
    }
    if(ctxCompress->hDll) { FreeLibrary(ctxCompress->hDll); }
    ZeroMemory(ctxCompress, sizeof(LEECHRPC_COMPRESS));
}

BOOL LeechRPC_CompressInitialize(_Inout_ PLEECHRPC_COMPRESS ctxCompress)
{
    DWORD i;
    LeechRPC_CompressClose(ctxCompress);
    ctxCompress->hDll = LoadLibraryA("ntdll.dll");
    if(!ctxCompress->hDll) { return FALSE; }
    if(!(ctxCompress->fn.pfnRtlCompressBuffer = (PFN_RtlCompressBuffer*)GetProcAddress(ctxCompress->hDll, "RtlCompressBuffer"))) { goto fail; }
    if(!(ctxCompress->fn.pfnRtlDecompressBuffer = (PFN_RtlDecompressBuffer*)GetProcAddress(ctxCompress->hDll, "RtlDecompressBuffer"))) { goto fail; }
    ctxCompress->fValid = TRUE;
    for(i = 0; i < LEECHRPC_COMPRESS_MAXTHREADS; i++) {
        InitializeCriticalSection(&ctxCompress->Compress[i].Lock);
        ctxCompress->fValid = ctxCompress->fValid && (ctxCompress->Compress[i].pbWorkspace = LocalAlloc(0, 0x00100000));
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
    NTSTATUS nt;
    PBYTE pb;
    ULONG cb;
    DWORD i;
    if(ctxCompress->fValid && (pMsg->cb > 0x1800) && !fCompressDisable) {
        if(!(pb = LocalAlloc(0, pMsg->cb))) { return; }
        do {
            i = InterlockedIncrement(&ctxCompress->iCompress) % LEECHRPC_COMPRESS_MAXTHREADS;
        } while(!TryEnterCriticalSection(&ctxCompress->Compress[i].Lock));
        nt = ctxCompress->fn.pfnRtlCompressBuffer(COMPRESSION_FORMAT_XPRESS, pMsg->pb, pMsg->cb, pb, pMsg->cb, 4096, &cb, ctxCompress->Compress[i].pbWorkspace);
        LeaveCriticalSection(&ctxCompress->Compress[i].Lock);
        if(((nt == STATUS_SUCCESS) || (nt == STATUS_BUFFER_ALL_ZEROS)) && (cb <= pMsg->cb)) {
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
    NTSTATUS nt;
    ULONG cb;
    PLEECHRPC_MSG_BIN pMsgOut = NULL;
    *ppMsgOut = NULL;
    if(!pMsgIn->cbDecompress) { return FALSE; }
    if(!ctxCompress->fValid || (pMsgIn->cbDecompress > 0x04000000)) { return FALSE; }
    if(!(pMsgOut = (PLEECHRPC_MSG_BIN)LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + pMsgIn->cbDecompress))) { return FALSE; }
    memcpy(pMsgOut, pMsgIn, sizeof(LEECHRPC_MSG_BIN));
    nt = ctxCompress->fn.pfnRtlDecompressBuffer(COMPRESSION_FORMAT_XPRESS, pMsgOut->pb, pMsgOut->cbDecompress, pMsgIn->pb, pMsgIn->cb, &cb);
    if((nt != STATUS_SUCCESS) || (cb != pMsgIn->cbDecompress)) {
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

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

#include "oscompatibility.h"

//-----------------------------------------------------------------------------
// COMPRESSION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID LeechRPC_CompressClose(_Inout_ PLEECHRPC_COMPRESS ctxCompress)
{
    if(ctxCompress->lib_mscompress) {
        dlclose(ctxCompress->lib_mscompress);
        ZeroMemory(ctxCompress, sizeof(LEECHRPC_COMPRESS));
    }
}

BOOL LeechRPC_CompressInitialize(_Inout_ PLEECHRPC_COMPRESS ctxCompress)
{
    CHAR szPathLib[MAX_PATH] = { 0 };
    if(!ctxCompress->fValid) {
        Util_GetPathLib(szPathLib);
        strncat_s(szPathLib, sizeof(szPathLib), "libMSCompression"LC_LIBRARY_FILETYPE, _TRUNCATE);
        ctxCompress->lib_mscompress = dlopen(szPathLib, RTLD_NOW);
        if(ctxCompress->lib_mscompress) {
            ctxCompress->pfn_xpress_compress = (pfn_xpress_decompress)dlsym(ctxCompress->lib_mscompress, "xpress_compress");
            ctxCompress->pfn_xpress_decompress = (pfn_xpress_decompress)dlsym(ctxCompress->lib_mscompress, "xpress_decompress");
            ctxCompress->fValid = ctxCompress->pfn_xpress_compress && ctxCompress->pfn_xpress_decompress;
        }
    }
    return ctxCompress->fValid;
}

VOID LeechRPC_Compress(_In_ PLEECHRPC_COMPRESS ctxCompress, _Inout_ PLEECHRPC_MSG_BIN pMsg, _In_ BOOL fCompressDisable)
{
    int rc;
    PBYTE pb;
    SIZE_T cb;
    DWORD i;
    if(ctxCompress->fValid && (pMsg->cb > 0x1800) && !fCompressDisable) {
        if(!(pb = LocalAlloc(0, pMsg->cb))) { return; }
        cb = pMsg->cb;
        rc = ctxCompress->pfn_xpress_compress(pMsg->pb, pMsg->cb, pb, &cb);
        if((rc >= 0) && (cb <= pMsg->cb)) {
            memcpy(pMsg->pb, pb, cb);
            pMsg->cbDecompress = pMsg->cb;
            pMsg->cb = (DWORD)cb;
            pMsg->cbMsg = sizeof(LEECHRPC_MSG_BIN) + (DWORD)cb;
        }
        LocalFree(pb);
    }
}

_Success_(return)
BOOL LeechRPC_Decompress(_In_ PLEECHRPC_COMPRESS ctxCompress, _In_ PLEECHRPC_MSG_BIN pMsgIn, _Out_ PLEECHRPC_MSG_BIN * ppMsgOut)
{
    int rc;
    DWORD i;
    SIZE_T cb;
    PLEECHRPC_MSG_BIN pMsgOut = NULL;
    *ppMsgOut = NULL;
    if(!pMsgIn->cbDecompress) { return FALSE; }
    if(!ctxCompress->fValid || (pMsgIn->cbDecompress > 0x04000000)) { return FALSE; }
    if(!(pMsgOut = (PLEECHRPC_MSG_BIN)LocalAlloc(0, sizeof(LEECHRPC_MSG_BIN) + pMsgIn->cbDecompress))) { return FALSE; }
    memcpy(pMsgOut, pMsgIn, sizeof(LEECHRPC_MSG_BIN));
    cb = pMsgOut->cbDecompress;
    rc = ctxCompress->pfn_xpress_decompress(pMsgIn->pb, (SIZE_T)pMsgIn->cb, pMsgOut->pb, &cb);
    if((rc < 0) || (cb != pMsgIn->cbDecompress)) {
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
    struct tm localTime;
    time_t now = time(NULL);
    localtime_r(&now, &localTime);
    snprintf(szTime, 32, "%04i-%02i-%02i %02i:%02i:%02i",
        localTime.tm_year + 1900,
        localTime.tm_mon + 1,
        localTime.tm_mday,
        localTime.tm_hour,
        localTime.tm_min,
        localTime.tm_sec);
}

#endif /* LINUX || MACOS */
