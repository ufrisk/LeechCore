//	leechagent_procchild.c : Implementation of child process functionality.
//                 Child processes host execution environments such as the
//                 Python environment which allows for execution of scripts.
//
// (c) Ulf Frisk, 2020-2022
// Author: Ulf Frisk, pcileech@frizk.net
//
// In general, this child process is meant to be a temporary host process to
// load and execute various tasks. Communication with the parent process takes
// place via anonymous pipes inherited from the parent process.
// The child process does not do any cleanup - except for the minimum since the
// main cleanup task is left to the OS upon the termination of this temporary
// child process. As such, most cleanup code is missing.
//
// Communication between parent/child takes place via:
// -- command pipe: child reads command and responds with result.
// -- memread pipe: child request mem read (via leechcore) and parent responds with result.
// -- stdout/err redirection: child output is captured by parent process.
// The child looks until termination reading commands from the command pipe in
// function: LeechAgent_ProcChild_ReaderCmd()
//
#include "leechagent_proc.h"
#include "util.h"
#include <stdio.h>

#define VMMDLL_VFS_FILELISTBLOB_VERSION     0xf88f0001

typedef struct tdVMMDLL_VFS_FILELISTBLOB_OPAQUE {
    DWORD dwVersion;                        // VMMDLL_VFS_FILELISTBLOB_VERSION
    DWORD cbStruct;
    BYTE pbOpaque[0];
} VMMDLL_VFS_FILELISTBLOB_OPAQUE, *PVMMDLL_VFS_FILELISTBLOB_OPAQUE;

typedef struct tdPROCCHILD_CONTEXT {
    BOOL fStateRunning;
    HMODULE hDllVmm;
    HMODULE hDllPython3;
    HMODULE hDllPython3X;
    HMODULE hDllLeechCorePyC;
    BOOL(*pfnVMMDLL_Initialize)(_In_ DWORD argc, _In_ LPSTR argv[]);
    BOOL(*pfnVMMDLL_InitializePlugins)();
    BOOL(*pfnVMMDLL_Close)();
    PVMMDLL_VFS_FILELISTBLOB_OPAQUE(*pfnVMMDLL_VfsListBlobU)(LPSTR);
    DWORD(*pfnVMMDLL_VfsReadU)(_In_ LPSTR  uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
    DWORD(*pfnVMMDLL_VfsWriteU)(_In_ LPSTR  uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
    BOOL(*pfnVMMDLL_ConfigGet)(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
    BOOL(*pfnVMMDLL_ConfigSet)(_In_ ULONG64 fOption, _In_ ULONG64 qwValue);
    BOOL(*pfnLeechCorePyC_EmbPythonInitialize)(_In_ HMODULE hDllPython);
    BOOL(*pfnLeechCorePyC_EmbExecPyInMem)(_In_ LPSTR szPythonProgram);
    VOID(*pfnLeechCorePyC_EmbClose)();
    HANDLE hPipeCmd_Rd;
    HANDLE hPipeCmd_Wr;
    HANDLE hPipeMem_Rd;
    HANDLE hPipeMem_Wr;
    CHAR szDevice[MAX_PATH];
    CHAR szRemote[MAX_PATH];
} PROCCHILD_CONTEXT;

PROCCHILD_CONTEXT ctxProcChild = { 0 };

/*
* Initialize the MemProcFS / VMM.DLL
*/
_Success_(return)
BOOL LeechAgent_ProcChild_InitializeVmm()
{
    BOOL result;
    LPSTR szVMM_ARGUMENTS[] = { "", "-device", "existingremote", "-remote", "pipe://" };
    szVMM_ARGUMENTS[2] = ctxProcChild.szDevice;
    szVMM_ARGUMENTS[4] = ctxProcChild.szRemote;
    ctxProcChild.hDllVmm = LoadLibraryExA("vmm.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    if(!ctxProcChild.hDllVmm) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not locate/load MemProcFS library vmm.dll\n");
        return FALSE;
    }
    ctxProcChild.pfnVMMDLL_Initialize = (BOOL(*)(DWORD, LPSTR*))GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_Initialize");
    ctxProcChild.pfnVMMDLL_InitializePlugins = (BOOL(*)())GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_InitializePlugins");
    ctxProcChild.pfnVMMDLL_Close = (BOOL(*)())GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_Close");
    ctxProcChild.pfnVMMDLL_VfsListBlobU = (PVMMDLL_VFS_FILELISTBLOB_OPAQUE(*)(LPSTR))GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_VfsListBlobU");
    ctxProcChild.pfnVMMDLL_VfsReadU = (DWORD(*)(LPSTR, PBYTE, DWORD, PDWORD, ULONG64))GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_VfsReadU");
    ctxProcChild.pfnVMMDLL_VfsWriteU = (DWORD(*)(LPSTR, PBYTE, DWORD, PDWORD, ULONG64))GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_VfsWriteU");
    ctxProcChild.pfnVMMDLL_ConfigGet = (BOOL(*)(ULONG64, PULONG64))GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_ConfigGet");
    ctxProcChild.pfnVMMDLL_ConfigSet = (BOOL(*)(ULONG64, ULONG64))GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_ConfigSet");
    if(!ctxProcChild.pfnVMMDLL_Initialize || !ctxProcChild.pfnVMMDLL_InitializePlugins || !ctxProcChild.pfnVMMDLL_Close) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not load MemProcFS library functions.\n");
        return FALSE;
    }
    result = ctxProcChild.pfnVMMDLL_Initialize((sizeof(szVMM_ARGUMENTS) / sizeof(LPCSTR)), szVMM_ARGUMENTS);
    if(!result) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not initialize MemProcFS library.\n");
        return FALSE;
    }
    result = ctxProcChild.pfnVMMDLL_InitializePlugins();
    if(!result) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not initialize MemProcFS Plugins.\n");
        return FALSE;
    }
    return TRUE;
}

/*
* Perform a MemProcFS Virtual File System (VFS) list operation.
* CALLER LOCALFREE: *ppRsp
* -- pReq
* -- ppRsp
* -- pcbRsp
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcChild_VmmVfsList(_In_ PLC_CMD_AGENT_VFS_REQ pReq, _Out_ PLC_CMD_AGENT_VFS_RSP *ppRsp, _Out_ PDWORD pcbRsp)
{
    PLC_CMD_AGENT_VFS_RSP pRsp = 0;
    PVMMDLL_VFS_FILELISTBLOB_OPAQUE pBlob = NULL;
    pReq->uszPathFile[_countof(pReq->uszPathFile) - 1] = 0;
    if(!ctxProcChild.pfnVMMDLL_VfsListBlobU) { goto fail; }
    if(!(pBlob = ctxProcChild.pfnVMMDLL_VfsListBlobU(pReq->uszPathFile))) { goto fail; }
    if((pBlob->dwVersion != VMMDLL_VFS_FILELISTBLOB_VERSION) || (pBlob->cbStruct > 0x04000000)) { goto fail; }
    if(!(pRsp = LocalAlloc(0, sizeof(LC_CMD_AGENT_VFS_RSP) + pBlob->cbStruct))) { goto fail; }
    ZeroMemory(pRsp, sizeof(LC_CMD_AGENT_VFS_RSP));
    pRsp->dwVersion = LC_CMD_AGENT_VFS_RSP_VERSION;
    memcpy(pRsp->pb, pBlob, pBlob->cbStruct);
    pRsp->cb = pBlob->cbStruct;
    *pcbRsp = sizeof(LC_CMD_AGENT_VFS_RSP) + pRsp->cb;
    *ppRsp = pRsp;
fail:
    LocalFree(pBlob);
    return pRsp ? TRUE : FALSE;
}

/*
* Perform a MemProcFS Virtual File System (VFS) read operation.
* CALLER LOCALFREE: *ppRsp
* -- pReq
* -- ppRsp
* -- pcbRsp
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcChild_VmmVfsRead(_In_ PLC_CMD_AGENT_VFS_REQ pReq, _Out_ PLC_CMD_AGENT_VFS_RSP *ppRsp, _Out_ PDWORD pcbRsp)
{
    PLC_CMD_AGENT_VFS_RSP pRsp;
    if(!ctxProcChild.pfnVMMDLL_VfsReadU) { return FALSE; }
    pReq->uszPathFile[_countof(pReq->uszPathFile) - 1] = 0;
    if(pReq->dwLength > 0x04000000) { return FALSE; }
    if(!(pRsp = LocalAlloc(0, sizeof(LC_CMD_AGENT_VFS_RSP) + pReq->dwLength))) { return FALSE; }
    ZeroMemory(pRsp, sizeof(LC_CMD_AGENT_VFS_RSP));
    pRsp->dwVersion = LC_CMD_AGENT_VFS_RSP_VERSION;
    pRsp->dwStatus = ctxProcChild.pfnVMMDLL_VfsReadU(pReq->uszPathFile, pRsp->pb, pReq->dwLength, &pRsp->cbReadWrite, pReq->qwOffset);
    pRsp->cb = pRsp->cbReadWrite;
    *pcbRsp = sizeof(LC_CMD_AGENT_VFS_RSP) + pRsp->cb;
    *ppRsp = pRsp;
    return TRUE;
}

/*
* Perform a MemProcFS Virtual File System (VFS) write operation.
* CALLER LOCALFREE: *ppRsp
* -- pReq
* -- ppRsp
* -- pcbRsp
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcChild_VmmVfsWrite(_In_ PLC_CMD_AGENT_VFS_REQ pReq, _Out_ PLC_CMD_AGENT_VFS_RSP *ppRsp, _Out_ PDWORD pcbRsp)
{
    PLC_CMD_AGENT_VFS_RSP pRsp;
    if(!ctxProcChild.pfnVMMDLL_VfsWriteU) { return FALSE; }
    pReq->uszPathFile[_countof(pReq->uszPathFile) - 1] = 0;
    if(!(pRsp = LocalAlloc(LMEM_ZEROINIT, sizeof(LC_CMD_AGENT_VFS_RSP)))) { return FALSE; }
    pRsp->dwVersion = LC_CMD_AGENT_VFS_RSP_VERSION;
    pRsp->dwStatus = ctxProcChild.pfnVMMDLL_VfsWriteU(pReq->uszPathFile, pReq->pb, pReq->cb, &pRsp->cbReadWrite, pReq->qwOffset);
    *pcbRsp = sizeof(LC_CMD_AGENT_VFS_RSP);
    *ppRsp = pRsp;
    return TRUE;
}

/*
* Perform a MemProcFS Virtual File System (VFS) get config operation.
* CALLER LOCALFREE: *ppRsp
* -- pReq
* -- ppRsp
* -- pcbRsp
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcChild_VmmVfsConfigGet(_In_ PLC_CMD_AGENT_VFS_REQ pReq, _Out_ PLC_CMD_AGENT_VFS_RSP *ppRsp, _Out_ PDWORD pcbRsp)
{
    QWORD qwResult = 0;
    PLC_CMD_AGENT_VFS_RSP pRsp;
    if(!ctxProcChild.pfnVMMDLL_ConfigGet) { return FALSE; }
    if(!(pRsp = LocalAlloc(LMEM_ZEROINIT, sizeof(LC_CMD_AGENT_VFS_RSP) + sizeof(QWORD)))) { return FALSE; }
    pRsp->dwVersion = LC_CMD_AGENT_VFS_RSP_VERSION;
    pRsp->dwStatus = (DWORD)ctxProcChild.pfnVMMDLL_ConfigGet(pReq->fOption, (PULONG64)pRsp->pb);
    pRsp->cb = sizeof(QWORD);
    *pcbRsp = sizeof(LC_CMD_AGENT_VFS_RSP) + sizeof(QWORD);
    *ppRsp = pRsp;
    return TRUE;

}

/*
* Perform a MemProcFS Virtual File System (VFS) set config operation.
* CALLER LOCALFREE: *ppRsp
* -- pReq
* -- ppRsp
* -- pcbRsp
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcChild_VmmVfsConfigSet(_In_ PLC_CMD_AGENT_VFS_REQ pReq, _Out_ PLC_CMD_AGENT_VFS_RSP *ppRsp, _Out_ PDWORD pcbRsp)
{
    QWORD qwResult = 0;
    PLC_CMD_AGENT_VFS_RSP pRsp;
    if(!ctxProcChild.pfnVMMDLL_ConfigSet || (pReq->cb != sizeof(QWORD))) { return FALSE; }
    if(!(pRsp = LocalAlloc(LMEM_ZEROINIT, sizeof(LC_CMD_AGENT_VFS_RSP)))) { return FALSE; }
    pRsp->dwVersion = LC_CMD_AGENT_VFS_RSP_VERSION;
    pRsp->dwStatus = (DWORD)ctxProcChild.pfnVMMDLL_ConfigSet(pReq->fOption, *(PULONG64)pReq->pb);
    *pcbRsp = sizeof(LC_CMD_AGENT_VFS_RSP);
    *ppRsp = pRsp;
    return TRUE;
}

/*
* Initialize the embedded Python environment. This should happen after the
* MemProcFS has been loaded.
*/
_Success_(return)
BOOL LeechAgent_ProcChild_InitializePython()
{
    BOOL result;
    DWORD i;
    WCHAR wszPythonPath[MAX_PATH];
    LPWSTR wszPYTHON_VERSIONS_SUPPORTED[] = { L"python315.dll", L"python314.dll", L"python313.dll", L"python312.dll", L"python311.dll", L"python310.dll", L"python39.dll", L"python38.dll", L"python37.dll", L"python36.dll" };
    DWORD cszPYTHON_VERSIONS_SUPPORTED = (sizeof(wszPYTHON_VERSIONS_SUPPORTED) / sizeof(LPSTR));
    // Locate Python
    for(i = 0; i < cszPYTHON_VERSIONS_SUPPORTED; i++) {
        ZeroMemory(wszPythonPath, MAX_PATH * sizeof(WCHAR));
        Util_GetPathDllW(wszPythonPath, NULL);
        wcscat_s(wszPythonPath, MAX_PATH, L"\\Python\\");
        wcscat_s(wszPythonPath, MAX_PATH, wszPYTHON_VERSIONS_SUPPORTED[i]);
        ctxProcChild.hDllPython3X = LoadLibraryExW(wszPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
        if(ctxProcChild.hDllPython3X) { break; }
    }
    if(!ctxProcChild.hDllPython3X) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not locate/load library Python3X.dll\n");
        return FALSE;
    }
    Util_GetPathDllW(wszPythonPath, NULL);
    wcscat_s(wszPythonPath, MAX_PATH, L"\\Python\\python3.dll");
    ctxProcChild.hDllPython3 = LoadLibraryExW(wszPythonPath, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
    if(!ctxProcChild.hDllPython3) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not locate/load library Python3.dll\n");
        return FALSE;
    }
    // Locate LeechCorePyC
    ctxProcChild.hDllLeechCorePyC = LoadLibraryA("Plugins\\leechcorepyc\\leechcorepyc.pyd");
    if(!ctxProcChild.hDllLeechCorePyC) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not locate/load library leechcorepyc.pyd\n");
        return FALSE;
    }
    ctxProcChild.pfnLeechCorePyC_EmbPythonInitialize = (BOOL(*)(HMODULE))GetProcAddress(ctxProcChild.hDllLeechCorePyC, "LeechCorePyC_EmbPythonInitialize");
    ctxProcChild.pfnLeechCorePyC_EmbExecPyInMem = (BOOL(*)(LPSTR))GetProcAddress(ctxProcChild.hDllLeechCorePyC, "LeechCorePyC_EmbExecPyInMem");
    ctxProcChild.pfnLeechCorePyC_EmbClose = (VOID(*)())GetProcAddress(ctxProcChild.hDllLeechCorePyC, "LeechCorePyC_EmbClose");
    if(!ctxProcChild.pfnLeechCorePyC_EmbPythonInitialize || !ctxProcChild.pfnLeechCorePyC_EmbExecPyInMem || !ctxProcChild.pfnLeechCorePyC_EmbClose) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not load leechcorepyc.pyd library functions.\n");
        return FALSE;
    }
    // Initalize Python environment
    result = ctxProcChild.pfnLeechCorePyC_EmbPythonInitialize(ctxProcChild.hDllPython3X);
    if(!result) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not initialize Python subsystem.\n");
        return FALSE;
    }
    return TRUE;
}

VOID LeechAgent_ProcChild_Close_ForceTerminateThread(PVOID pv)
{
    Sleep(500);
    TerminateProcess(GetCurrentProcess(), 1);
}

/*
* Exit / Shut down this child process. Before shutdown an attempt to shut down
* Python (to flush remaining buffers) is made.
*/
VOID LeechAgent_ProcChild_Close()
{
    fflush(stdout);
    fflush(stderr);
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcChild_Close_ForceTerminateThread, NULL, 0, NULL);
    if(ctxProcChild.pfnLeechCorePyC_EmbClose) {
        ctxProcChild.pfnLeechCorePyC_EmbClose();
    }
    fflush(stdout);
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 0);
    Sleep(200);
    ExitProcess(0);
}

/*
* Read a command from the parent. This function will hang if there isn't an
* exact match in the number of bytes transmitted. That shouldn't happen though
* since both reader/write is trusted.
* NB! CALLER LocalFree: *ppCmd
* -- ppCmd = caller responsible for LocalFree
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcChild_CmdRead(_Out_opt_ PLEECHAGENT_PROC_CMD* ppCmd)
{
    LEECHAGENT_PROC_CMD Cmd, *pCmd;
    if(!ppCmd) { return FALSE; }
    if(!Util_GetBytesPipe(ctxProcChild.hPipeCmd_Rd, (PBYTE)&Cmd, sizeof(LEECHAGENT_PROC_CMD))) { return FALSE; }
    if(Cmd.dwMagic != LEECHAGENT_PROC_CMD_MAGIC) { return FALSE; }
    pCmd = (PLEECHAGENT_PROC_CMD)LocalAlloc(0, Cmd.cb + sizeof(LEECHAGENT_PROC_CMD));
    if(!pCmd) { return FALSE; }
    memcpy(pCmd, &Cmd, sizeof(LEECHAGENT_PROC_CMD));
    if(Cmd.cb) {
        if(!Util_GetBytesPipe(ctxProcChild.hPipeCmd_Rd, pCmd->pb, pCmd->cb)) { return FALSE; }
    }
    *ppCmd = pCmd;
    return TRUE;
}

/*
* Separate thread that reads and dispatches commands read over the CMD pipe
* from the parent process.
*/
VOID LeechAgent_ProcChild_ReaderCmd(_In_opt_ qwRemoteHLC)
{
    BOOL fResult, fResultWritePipe = TRUE;
    DWORD cbWrite, cbRspData = 0;
    PBYTE pb = NULL, pbRspData = NULL;
    LEECHAGENT_PROC_CMD CmdRsp = { 0 };
    PLEECHAGENT_PROC_CMD pCmd = NULL, pCmdRsp = NULL;
    while(LeechAgent_ProcChild_CmdRead(&pCmd) && fResultWritePipe) {
        fResult = TRUE;
        switch(pCmd->dwCmd) {
            case LEECHAGENT_PROC_CMD_EXITCLIENT:
                LeechAgent_ProcChild_Close();
                break;
            case LEECHAGENT_PROC_CMD_INIT_VMM:
                fResult = LeechAgent_ProcChild_InitializeVmm(qwRemoteHLC);
                break;
            case LEECHAGENT_PROC_CMD_INIT_PYTHON:
                fResult = LeechAgent_ProcChild_InitializePython();
                break;
            case LEECHAGENT_PROC_CMD_EXEC_PYTHON:
                fResult = FALSE;
                if(ctxProcChild.pfnLeechCorePyC_EmbExecPyInMem) {
                    pb = LocalAlloc(0, pCmd->cb + 1ULL);
                    if(pb) {
                        // null terminate buffer (just in case) and send to python for execution.
                        memcpy(pb, pCmd->pb, pCmd->cb);
                        pb[pCmd->cb] = 0;
                        fResult = ctxProcChild.pfnLeechCorePyC_EmbExecPyInMem((LPSTR)pb);
                        LocalFree(pb);
                        pb = NULL;
                    }
                }
                break;
            case LEECHAGENT_PROC_CMD_VFS_LIST:
                fResult = (pCmd->cb >= sizeof(LC_CMD_AGENT_VFS_REQ)) && (((PLC_CMD_AGENT_VFS_REQ)pCmd->pb)->cb <= pCmd->cb - sizeof(LC_CMD_AGENT_VFS_REQ));
                fResult = fResult && LeechAgent_ProcChild_VmmVfsList((PLC_CMD_AGENT_VFS_REQ)pCmd->pb, (PLC_CMD_AGENT_VFS_RSP *)&pbRspData, &cbRspData);
                break;
            case LEECHAGENT_PROC_CMD_VFS_READ:
                fResult = (pCmd->cb >= sizeof(LC_CMD_AGENT_VFS_REQ)) && (((PLC_CMD_AGENT_VFS_REQ)pCmd->pb)->cb <= pCmd->cb - sizeof(LC_CMD_AGENT_VFS_REQ));
                fResult = fResult && LeechAgent_ProcChild_VmmVfsRead((PLC_CMD_AGENT_VFS_REQ)pCmd->pb, (PLC_CMD_AGENT_VFS_RSP *)&pbRspData, &cbRspData);
                break;
            case LEECHAGENT_PROC_CMD_VFS_WRITE:
                fResult = (pCmd->cb >= sizeof(LC_CMD_AGENT_VFS_REQ)) && (((PLC_CMD_AGENT_VFS_REQ)pCmd->pb)->cb <= pCmd->cb - sizeof(LC_CMD_AGENT_VFS_REQ));
                fResult = fResult && LeechAgent_ProcChild_VmmVfsWrite((PLC_CMD_AGENT_VFS_REQ)pCmd->pb, (PLC_CMD_AGENT_VFS_RSP *)&pbRspData, &cbRspData);
                break;
            case LEECHAGENT_PROC_CMD_VFS_OPT_GET:
                fResult = (pCmd->cb >= sizeof(LC_CMD_AGENT_VFS_REQ)) && (((PLC_CMD_AGENT_VFS_REQ)pCmd->pb)->cb <= pCmd->cb - sizeof(LC_CMD_AGENT_VFS_REQ));
                fResult = fResult && LeechAgent_ProcChild_VmmVfsConfigGet((PLC_CMD_AGENT_VFS_REQ)pCmd->pb, (PLC_CMD_AGENT_VFS_RSP *)&pbRspData, &cbRspData);
                break;
            case LEECHAGENT_PROC_CMD_VFS_OPT_SET:
                fResult = (pCmd->cb >= sizeof(LC_CMD_AGENT_VFS_REQ)) && (((PLC_CMD_AGENT_VFS_REQ)pCmd->pb)->cb <= pCmd->cb - sizeof(LC_CMD_AGENT_VFS_REQ));
                fResult = fResult && LeechAgent_ProcChild_VmmVfsConfigSet((PLC_CMD_AGENT_VFS_REQ)pCmd->pb, (PLC_CMD_AGENT_VFS_RSP *)&pbRspData, &cbRspData);
                break;
            default:
                fprintf(stderr, "LeechAgent: WARN: CHILD received unknown CMD from parent. ID: 0x%08x\n", pCmd->dwCmd);
                break;
        }
        // write result to pipe
        if(fResult && cbRspData && pbRspData) {
            if((pCmdRsp = LocalAlloc(0, sizeof(LEECHAGENT_PROC_CMD) + cbRspData))) {
                ZeroMemory(pCmdRsp, sizeof(LEECHAGENT_PROC_CMD));
                memcpy(pCmdRsp->pb, pbRspData, cbRspData);
                pCmdRsp->cb = cbRspData;
            } else {
                fResult = FALSE;
            }
        }
        if(!pCmdRsp) {
            pCmdRsp = &CmdRsp;
        }
        pCmdRsp->dwMagic = LEECHAGENT_PROC_CMD_MAGIC;
        pCmdRsp->dwCmd = pCmd->dwCmd;
        pCmdRsp->fSuccess = fResult;
        fResultWritePipe = WriteFile(ctxProcChild.hPipeCmd_Wr, pCmdRsp, sizeof(LEECHAGENT_PROC_CMD) + pCmdRsp->cb, &cbWrite, NULL);
        // cleanup
        LocalFree(pCmd);
        pCmd = NULL;
        if(pCmdRsp != &CmdRsp) { LocalFree(pCmdRsp); }
        pCmdRsp = NULL;
        cbRspData = 0;
        if(pbRspData) {
            LocalFree(pbRspData);
            pbRspData = NULL;
        }
    }
    if(ctxProcChild.fStateRunning) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not read/write CMD from/to parent. Exiting.\n");
        LeechAgent_ProcChild_Close();
    }
}

/*
* Main entry point for the child process.
*/
VOID LeechAgent_ProcChild_Main(int argc, wchar_t* argv[])
{
    QWORD qwRemoteHLC = 0;
    PLEECHAGENT_PROC_CMD pCmd = NULL;
    ctxProcChild.fStateRunning = TRUE;
    if(argc <= 6) { return; }
    ctxProcChild.hPipeCmd_Rd = (HANDLE)_wtoi64(argv[2]);
    ctxProcChild.hPipeCmd_Wr = (HANDLE)_wtoi64(argv[3]);
    ctxProcChild.hPipeMem_Rd = (HANDLE)_wtoi64(argv[4]);
    ctxProcChild.hPipeMem_Wr = (HANDLE)_wtoi64(argv[5]);
    qwRemoteHLC = _wtoi64(argv[6]);
    if(!ctxProcChild.hPipeCmd_Rd || !ctxProcChild.hPipeMem_Rd || !ctxProcChild.hPipeMem_Wr) { goto fail; }
    _snprintf_s(ctxProcChild.szDevice, _countof(ctxProcChild.szDevice), _TRUNCATE, "existingremote://0x%llx", qwRemoteHLC);
    _snprintf_s(ctxProcChild.szRemote, _countof(ctxProcChild.szRemote), _TRUNCATE, "pipe://%llu:%llu", (QWORD)ctxProcChild.hPipeMem_Rd, (QWORD)ctxProcChild.hPipeMem_Wr);
    // use main thread for eternal cmd-read loop
    LeechAgent_ProcChild_ReaderCmd(qwRemoteHLC);
fail:
    LeechAgent_ProcChild_Close();
}
