// leechrpcclient.h : definitions related to the leech rpc service.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHRPC_H__
#define __LEECHRPC_H__
#include "leechcore.h"
#ifdef _WIN32
#include <windows.h>

#define CLSID_BINDING_INTERFACE_LEECHRPC "906B0DC2-1337-0666-0001-0000657A63DC"

typedef struct tdLEECHRPC_COMPRESS {
    BOOL fValid;
    HANDLE hDll;
    CRITICAL_SECTION LockCompressor;
    CRITICAL_SECTION LockDecompressor;
    HANDLE hCompressor;
    HANDLE hDecompressor;
    struct {
        BOOL(*pfnCreateCompressor)(DWORD Algorithm, PVOID AllocationRoutines, PHANDLE CompressorHandle);
        BOOL(*pfnCreateDecompressor)(DWORD Algorithm, PVOID AllocationRoutines, PHANDLE DecompressorHandle);
        BOOL(*pfnCloseCompressor)(HANDLE CompressorHandle);
        BOOL(*pfnCloseDecompressor)(HANDLE DecompressorHandle);
        BOOL(*pfnCompress)(HANDLE CompressorHandle, LPCVOID UncompressedData, SIZE_T UncompressedDataSize, PVOID CompressedBuffer, SIZE_T CompressedBufferSize, PSIZE_T CompressedDataSize);
        BOOL(*pfnDecompress)(HANDLE DecompressorHandle, LPCVOID CompressedData, SIZE_T CompressedDataSize, PVOID UncompressedBuffer, SIZE_T UncompressedBufferSize, PSIZE_T UncompressedDataSize);
    } fn;
} LEECHRPC_COMPRESS, *PLEECHRPC_COMPRESS;

typedef struct tdLEECHRPC_CLIENT_CONTEXT {
    BOOL fAllowInsecure;
    CHAR szRemoteSPN[MAX_PATH];
    CHAR szTcpAddr[MAX_PATH];
    CHAR szTcpPort[6];
    RPC_BINDING_HANDLE hRPC;
    RPC_CSTR szStringBinding;
    LEECHRPC_COMPRESS Compress;
} LEECHRPC_CLIENT_CONTEXT, *PLEECHRPC_CLIENT_CONTEXT;

typedef enum {
    LEECHRPC_MSGTYPE_NA = 0,
    LEECHRPC_MSGTYPE_PING_REQ = 1,
    LEECHRPC_MSGTYPE_PING_RSP = 2,
    LEECHRPC_MSGTYPE_OPEN_REQ = 3,
    LEECHRPC_MSGTYPE_OPEN_RSP = 4,
    LEECHRPC_MSGTYPE_CLOSE_REQ = 5,
    LEECHRPC_MSGTYPE_CLOSE_RSP = 6,
    LEECHRPC_MSGTYPE_READSCATTER_REQ = 7,
    LEECHRPC_MSGTYPE_READSCATTER_RSP = 8,
    LEECHRPC_MSGTYPE_WRITE_REQ = 9,
    LEECHRPC_MSGTYPE_WRITE_RSP = 10,
    LEECHRPC_MSGTYPE_PROBE_REQ = 11,
    LEECHRPC_MSGTYPE_PROBE_RSP = 12,
    LEECHRPC_MSGTYPE_GETOPTION_REQ = 13,
    LEECHRPC_MSGTYPE_GETOPTION_RSP = 14,
    LEECHRPC_MSGTYPE_SETOPTION_REQ = 15,
    LEECHRPC_MSGTYPE_SETOPTION_RSP = 16,
    LEECHRPC_MSGTYPE_COMMANDDATA_REQ = 17,
    LEECHRPC_MSGTYPE_COMMANDDATA_RSP = 18,
    LEECHRPC_MSGTYPE_MAX = 19,
} LEECHRPC_MSGTYPE;

#define LEECHRPC_MSGMAGIC       0xd05a0666

typedef struct tdLEECHRPC_MSG_HDR {
    DWORD dwMagic;
    DWORD cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    BOOL fMsgResult;
} LEECHRPC_MSG_HDR, *PLEECHRPC_MSG_HDR, **PPLEECHRPC_MSG_HDR;

typedef struct tdLEECHRPC_MSG_OPEN {
    // HDR
    DWORD dwMagic;
    DWORD cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    BOOL fMsgResult;
    // MSG
    LEECHCORE_CONFIG cfg;
} LEECHRPC_MSG_OPEN, *PLEECHRPC_MSG_OPEN;

typedef struct tdLEECHRPC_MSG_BIN {
    // HDR
    DWORD dwMagic;
    DWORD cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    BOOL fMsgResult;
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
    // MSG
    QWORD qwData[2];
} LEECHRPC_MSG_DATA, *PLEECHRPC_MSG_DATA;

/*
* Service functions.
* (server-side only).
*/
VOID LeechRpcOnLoadInitialize();
VOID LeechRpcOnUnloadClose();

#endif /* _WIN32 */

/*
* Open a "connection" to the remote RPC server.
* (client-side only).
* -- result
*/
_Success_(return)
BOOL LeechRPC_Open();

#endif /* __LEECHRPC_H__ */
