//	leechagent_proc.h : Definitions of parent/child process functionality.
//                 Child processes host execution environments such as the
//                 Python environment which allows for execution of scripts.
//                 Child processes are spawned and controlled by the main
//                 LeechAgent process.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHAGENT_PROC_H__
#define __LEECHAGENT_PROC_H__
#include "leechagent.h"

#define LEECHAGENT_PROC_CMD_MAGIC           0x20f02ab8
#define LEECHAGENT_PROC_CMD_EXITCLIENT      0x00000001
#define LEECHAGENT_PROC_CMD_INIT_VMM        0x00000002
#define LEECHAGENT_PROC_CMD_INIT_PYTHON     0x00000003
#define LEECHAGENT_PROC_CMD_EXEC_PYTHON     0x00000004
#define LEECHAGENT_PROC_CMD_VFS_LIST        0x00000005
#define LEECHAGENT_PROC_CMD_VFS_READ        0x00000006
#define LEECHAGENT_PROC_CMD_VFS_WRITE       0x00000007
#define LEECHAGENT_PROC_CMD_VFS_OPT_GET     0x00000008
#define LEECHAGENT_PROC_CMD_VFS_OPT_SET     0x00000009

typedef struct tdLEECHAGENT_PROC_CMD {
    DWORD dwMagic;
    DWORD dwCmd;
    BOOL fSuccess;
    DWORD cb;
    BYTE pb[];
} LEECHAGENT_PROC_CMD, *PLEECHAGENT_PROC_CMD;

VOID LeechAgent_ProcChild_Main(int argc, wchar_t* argv[]);

_Success_(return)
BOOL LeechAgent_ProcParent_ExecPy(_In_ HANDLE hLC, _In_ DWORD dwTimeout, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_opt_ PBYTE* ppbDataOut, _Out_opt_ PDWORD pcbDataOut);

/*
* Execute a virtual file system command towards MemProcFS / vmm.dll.
* CALLER LocalFree: *ppbDataOut
* -- hLC
* -- phPP = ptr to "ParentProcess" handle to update as required.
* -- dwCMD = LEECHAGENT_PROC_CMD_VFS_LIST | LEECHAGENT_PROC_CMD_VFS_READ | LEECHAGENT_PROC_CMD_VFS_WRITE
* -- pbDataIn
* -- cbDataIn
* -- ppbDataOut
* -- pcbDataOut
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcParent_VfsCMD(_In_ HANDLE hLC, _Inout_ PHANDLE phPP, _In_ DWORD dwCMD, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_opt_ PBYTE* ppbDataOut, _Out_opt_ PDWORD pcbDataOut);

/*
* Initialize a virtual file system handle towards MemProcFS / vmm.dll.
* CALLER LocalFree: *ppbDataOut
* -- hLC
* -- phPP = ptr to "ParentProcess" handle to update as required.
* -- pbDataIn
* -- cbDataIn
* -- ppbDataOut
* -- pcbDataOut
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcParent_VfsInitialize(_In_ HANDLE hLC, _Inout_ PHANDLE phPP, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_opt_ PBYTE * ppbDataOut, _Out_opt_ PDWORD pcbDataOut);

/*
* Retrieve console information from the child process (if any) and perform a a
* keepalive operation.
* CALLER LocalFree: *ppbDataOut
* -- hLC
* -- phPP = ptr to "ParentProcess" handle to update as required.
* -- ppbDataOut
* -- pcbDataOut
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcParent_VfsConsole(_In_ HANDLE hLC, _Inout_ PHANDLE phPP, _Out_opt_ PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut);

/*
* Close a ProcParent handle kept by the leechrpcserver.
* This is usually done on vfs close / handle close after vfs operations.
* -- hPP = handle to destroy / close.
*/
VOID LeechAgent_ProcParent_Close(_In_opt_ HANDLE hPP);

#endif /* __LEECHAGENT_PROC_H__ */
