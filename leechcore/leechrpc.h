// leechrpcclient.h : definitions related to the leech rpc service.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHRPC_H__
#define __LEECHRPC_H__
#include "leechcore.h"

#define LEECHRPC_MSGMAGIC                   0xd05a2667
#define LEECHRPC_FLAG_NOCOMPRESS                0x0010
#define LEECHRPC_FLAG_FNEXIST_ReadScatterMEM    0x0100
#define LEECHRPC_FLAG_FNEXIST_WriteScatterMEM   0x0200
#define LEECHRPC_FLAG_FNEXIST_Close             0x0800
#define LEECHRPC_FLAG_FNEXIST_GetOption         0x1000
#define LEECHRPC_FLAG_FNEXIST_SetOption         0x2000
#define LEECHRPC_FLAG_FNEXIST_Command           0x4000

#ifdef _WIN32
#include <windows.h>

#define CLSID_BINDING_INTERFACE_LEECHRPC "906B0DC2-1337-0666-0001-0000657A63DD"

#define LEECHRPC_COMPRESS_MAXTHREADS    8

typedef struct tdLEECHRPC_COMPRESS {
    BOOL fValid;
    HANDLE hDll;
    DWORD iCompress;
    DWORD iDecompress;
    struct {
        CRITICAL_SECTION Lock;
        HANDLE h;
    } Compress[LEECHRPC_COMPRESS_MAXTHREADS];
    struct {
        CRITICAL_SECTION Lock;
        HANDLE h;
    } Decompress[LEECHRPC_COMPRESS_MAXTHREADS];
    struct {
        BOOL(WINAPI *pfnCreateCompressor)(DWORD Algorithm, PVOID AllocationRoutines, PHANDLE CompressorHandle);
        BOOL(WINAPI *pfnCreateDecompressor)(DWORD Algorithm, PVOID AllocationRoutines, PHANDLE DecompressorHandle);
        BOOL(WINAPI *pfnCloseCompressor)(HANDLE CompressorHandle);
        BOOL(WINAPI *pfnCloseDecompressor)(HANDLE DecompressorHandle);
        BOOL(WINAPI *pfnCompress)(HANDLE CompressorHandle, LPCVOID UncompressedData, SIZE_T UncompressedDataSize, PVOID CompressedBuffer, SIZE_T CompressedBufferSize, PSIZE_T CompressedDataSize);
        BOOL(WINAPI *pfnDecompress)(HANDLE DecompressorHandle, LPCVOID CompressedData, SIZE_T CompressedDataSize, PVOID UncompressedBuffer, SIZE_T UncompressedBufferSize, PSIZE_T UncompressedDataSize);
    } fn;
} LEECHRPC_COMPRESS, *PLEECHRPC_COMPRESS;

typedef struct tdLEECHRPC_CLIENT_CONTEXT {
    BOOL fIsProtoRpc;               // RPC over TCP/IP.
    BOOL fIsProtoSmb;               // RPC over SMB (named pipe).
    BOOL fHousekeeperThread;
    BOOL fHousekeeperThreadIsRunning;
    // RPC functionality below:
    BOOL fIsAuthInsecure;           // No authentication (insecure connection).
    BOOL fIsAuthNTLM;               // NTLM authentication (no server validation).
    BOOL fIsAuthKerberos;           // Kerberos authentication (mutual authentication).
    BOOL fIsAuthNTLMCredPrompt;     // NTLM authentication (with credential prompt).
    CHAR szRemoteSPN[MAX_PATH];
    CHAR szTcpAddr[MAX_PATH];
    CHAR szTcpPort[6];
    RPC_BINDING_HANDLE hRPC;
    RPC_CSTR szStringBinding;
    LEECHRPC_COMPRESS Compress;
} LEECHRPC_CLIENT_CONTEXT, *PLEECHRPC_CLIENT_CONTEXT;

typedef enum {
    LEECHRPC_MSGTYPE_NA =                0,
    LEECHRPC_MSGTYPE_PING_REQ =          1,
    LEECHRPC_MSGTYPE_PING_RSP =          2,
    LEECHRPC_MSGTYPE_OPEN_REQ =          3,
    LEECHRPC_MSGTYPE_OPEN_RSP =          4,
    LEECHRPC_MSGTYPE_CLOSE_REQ =         5,
    LEECHRPC_MSGTYPE_CLOSE_RSP =         6,
    LEECHRPC_MSGTYPE_READSCATTER_REQ =   7,
    LEECHRPC_MSGTYPE_READSCATTER_RSP =   8,
    LEECHRPC_MSGTYPE_WRITESCATTER_REQ =  9,
    LEECHRPC_MSGTYPE_WRITESCATTER_RSP = 10,
    LEECHRPC_MSGTYPE_GETOPTION_REQ =    11,
    LEECHRPC_MSGTYPE_GETOPTION_RSP =    12,
    LEECHRPC_MSGTYPE_SETOPTION_REQ =    13,
    LEECHRPC_MSGTYPE_SETOPTION_RSP =    14,
    LEECHRPC_MSGTYPE_COMMAND_REQ =      15,
    LEECHRPC_MSGTYPE_COMMAND_RSP =      16,
    LEECHRPC_MSGTYPE_KEEPALIVE_REQ =    17,
    LEECHRPC_MSGTYPE_KEEPALIVE_RSP =    18,
    LEECHRPC_MSGTYPE_MAX =              18,
} LEECHRPC_MSGTYPE;

typedef struct tdLEECHRPC_MSG_HDR {
    DWORD dwMagic;
    DWORD cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    BOOL fMsgResult;
    DWORD dwRpcClientID;
    DWORD flags;
} LEECHRPC_MSG_HDR, *PLEECHRPC_MSG_HDR, **PPLEECHRPC_MSG_HDR;

typedef struct tdLEECHRPC_MSG_OPEN {
    // HDR
    DWORD dwMagic;
    DWORD cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    BOOL fMsgResult;
    DWORD dwRpcClientID;
    DWORD flags;
    // MSG
    BOOL fValidOpen;
    LC_CONFIG cfg;
    LC_CONFIG_ERRORINFO errorinfo;
} LEECHRPC_MSG_OPEN, *PLEECHRPC_MSG_OPEN;

typedef struct tdLEECHRPC_MSG_BIN {
    // HDR
    DWORD dwMagic;
    DWORD cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    BOOL fMsgResult;
    DWORD dwRpcClientID;
    DWORD flags;
    // MSG
    QWORD qwData[2];
    DWORD cbDecompress; // cb uncompressed data, 0 = no compression
    DWORD cb;
    BYTE pb[];
} LEECHRPC_MSG_BIN, *PLEECHRPC_MSG_BIN;

typedef struct tdLEECHRPC_MSG_DATA {
    // HDR
    DWORD dwMagic;
    DWORD cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    BOOL fMsgResult;
    DWORD dwRpcClientID;
    DWORD flags;
    // MSG
    QWORD qwData[2];
} LEECHRPC_MSG_DATA, *PLEECHRPC_MSG_DATA;

/*
* Initialize the compression context.
* -- ctxCompress
* -- return
*/
BOOL LeechRPC_CompressInitialize(_Inout_ PLEECHRPC_COMPRESS ctxCompress);

/*
* Close the compression context
* -- ctxCompress
*/
VOID LeechRPC_CompressClose(_Inout_ PLEECHRPC_COMPRESS ctxCompress);

/*
* Compresses data already enclosed in the pMsg contiguous buffer. Existing data
* is overwritten with compressed data. (If possible and desirable).
* -- ctxCompress
* -- pMsg
* -- fCompressDisable = do not perform compression
*/
VOID LeechRPC_Compress(_In_ PLEECHRPC_COMPRESS ctxCompress, _Inout_ PLEECHRPC_MSG_BIN pMsg, _In_ BOOL fCompressDisable);

/*
* Decompresses the data in pMsgIn if possible. The uncompressed data is allocated
* by the function and is returned in ppMsgOut. Caller must FREE.
* NB! CALLER FREE: ppMsgOut
* -- ctxCompress
* -- pMsgIn = original pMsg to decompress.
* -- ppMsgOut = function allocated decompressed data!
* -- return
*/
_Success_(return)
BOOL LeechRPC_Decompress(_In_ PLEECHRPC_COMPRESS ctxCompress, _In_ PLEECHRPC_MSG_BIN pMsgIn, _Out_ PLEECHRPC_MSG_BIN *ppMsgOut);

/*
* Utility function to retrieve a time stamp on the format 'YYYY-MM-DD HH:MM:SS'
* -- szTime = user-allocated buffer to receive result.
*/
VOID LeechSvc_GetTimeStamp(_Out_writes_(32) LPSTR szTime);

/*
* Service functions.
* (server-side only).
*/
VOID LeechRpcOnLoadInitialize();
VOID LeechRpcOnUnloadClose();

#endif /* _WIN32 */

#endif /* __LEECHRPC_H__ */
