//	leechagent_procchild.c : Implementation of child process functionality.
//                 Child processes host execution environments such as the
//                 Python environment which allows for execution of scripts.
//
// (c) Ulf Frisk, 2020-2025
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
#define VMMDLL_VFS_INITIALIZEBLOB_VERSION   0xfaaf0001
#define VMMDLL_VFS_INITIALIZEBLOB_MAX_ARGC  64

typedef struct tdVMM_HANDLE *VMM_HANDLE;

static VMM_HANDLE g_hVMM = NULL;

typedef struct tdVMMDLL_VFS_FILELISTBLOB_OPAQUE {
    DWORD dwVersion;                        // VMMDLL_VFS_FILELISTBLOB_VERSION
    DWORD cbStruct;
    BYTE pbOpaque[0];
} VMMDLL_VFS_FILELISTBLOB_OPAQUE, *PVMMDLL_VFS_FILELISTBLOB_OPAQUE;

typedef struct tdVMMDLL_VFS_INITIALIZEBLOB {
    DWORD dwVersion;                        // VMMDLL_VFS_INITIALIZEBLOB_VERSION
    DWORD cbStruct;
    QWORD _FutureUse1[16];
    DWORD _FutureUse2;
    DWORD argc;
    union {
        LPSTR sz;
        QWORD qw;
    } argv[0];
} VMMDLL_VFS_INITIALIZEBLOB, *PVMMDLL_VFS_INITIALIZEBLOB;

typedef _Success_(return != NULL)   VMM_HANDLE  (*PFN_VMMDLL_Initialize)(_In_ DWORD argc, _In_ LPSTR argv[]);
typedef _Success_(return)           BOOL        (*PFN_VMMDLL_InitializePlugins)(_In_ VMM_HANDLE hVMM);
typedef                             VOID        (*PFN_VMMDLL_Close)(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE hVMM);
typedef                             VOID        (*PFN_VMMDLL_MemFree)(_Frees_ptr_opt_ PVOID pvMem);
typedef _Success_(return != NULL)   PVMMDLL_VFS_FILELISTBLOB_OPAQUE(*PFN_VMMDLL_VfsListBlobU)(_In_ VMM_HANDLE hVMM, _In_ LPSTR uszPath);
typedef                             NTSTATUS    (*PFN_VMMDLL_VfsReadU)(_In_ VMM_HANDLE hVMM, _In_ LPSTR  uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
typedef                             NTSTATUS    (*PFN_VMMDLL_VfsWriteU)(_In_ VMM_HANDLE hVMM, _In_ LPSTR  uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
typedef _Success_(return)           BOOL        (*PFN_VMMDLL_ConfigGet)(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
typedef _Success_(return)           BOOL        (*PFN_VMMDLL_ConfigSet)(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _In_ ULONG64 qwValue);
typedef _Success_(return)           BOOL        (*PFN_LeechCorePyC_EmbPythonInitialize)(_In_ HMODULE hDllPython);
typedef                             BOOL        (*PFN_LeechCorePyC_EmbExecPyInMem)(_In_ LPSTR szPythonProgram);
typedef                             VOID        (*PFN_LeechCorePyC_EmbClose)();

typedef struct tdPROCCHILD_CONTEXT {
    BOOL fStateRunning;
    HMODULE hDllVmm;
    HMODULE hDllPython3;
    HMODULE hDllPython3X;
    HMODULE hDllLeechCorePyC;
    PFN_VMMDLL_Initialize pfnVMMDLL_Initialize;
    PFN_VMMDLL_InitializePlugins pfnVMMDLL_InitializePlugins;
    PFN_VMMDLL_Close pfnVMMDLL_Close;
    PFN_VMMDLL_MemFree pfnVMMDLL_MemFree;
    PFN_VMMDLL_VfsListBlobU pfnVMMDLL_VfsListBlobU;
    PFN_VMMDLL_VfsReadU pfnVMMDLL_VfsReadU;
    PFN_VMMDLL_VfsWriteU pfnVMMDLL_VfsWriteU;
    PFN_VMMDLL_ConfigGet pfnVMMDLL_ConfigGet;
    PFN_VMMDLL_ConfigSet pfnVMMDLL_ConfigSet;
    PFN_LeechCorePyC_EmbPythonInitialize pfnLeechCorePyC_EmbPythonInitialize;
    PFN_LeechCorePyC_EmbExecPyInMem pfnLeechCorePyC_EmbExecPyInMem;
    PFN_LeechCorePyC_EmbClose pfnLeechCorePyC_EmbClose;
    HANDLE hPipeCmd_Rd;
    HANDLE hPipeCmd_Wr;
    CHAR szDevice[MAX_PATH];
    CHAR szRemote[MAX_PATH];
} PROCCHILD_CONTEXT;

PROCCHILD_CONTEXT ctxProcChild = { 0 };

/*
* Initialize the MemProcFS / VMM.DLL
* -- qwRemoteHLC: remote handle to the LeechCore process
* -- pVfsInitBlob: pointer to the VFS initialization blob
*/
_Success_(return)
BOOL LeechAgent_ProcChild_InitializeVmm(_In_opt_ PVMMDLL_VFS_INITIALIZEBLOB pVfsInitBlob)
{
    DWORD i;
    BOOL f, result;
    DWORD argc = 0;
    LPSTR argv[VMMDLL_VFS_INITIALIZEBLOB_MAX_ARGC+5];
    argv[argc++] = "";
    argv[argc++] = "-device";
    argv[argc++] = ctxProcChild.szDevice;
    argv[argc++] = "-remote";
    argv[argc++] = ctxProcChild.szRemote;
    // 1: verify & fix-up init blob:
    if(pVfsInitBlob) {
        if(pVfsInitBlob->dwVersion != VMMDLL_VFS_INITIALIZEBLOB_VERSION) {
            fprintf(stderr, "LeechAgent: FAIL: CHILD VFS init blob version mismatch.\n");
            return FALSE;
        }
        if(pVfsInitBlob->argc > VMMDLL_VFS_INITIALIZEBLOB_MAX_ARGC) {
            fprintf(stderr, "LeechAgent: FAIL: Too many initialization arguments.\n");
            return FALSE;
        }
        if(pVfsInitBlob->cbStruct < sizeof(VMMDLL_VFS_INITIALIZEBLOB) + pVfsInitBlob->argc * sizeof(LPSTR)) {
            return FALSE;
        }
        for(i = 0; i < pVfsInitBlob->argc; i++) {
            if(pVfsInitBlob->argv[i].qw) {
                if(pVfsInitBlob->argv[i].qw >= pVfsInitBlob->cbStruct - 1) {
                    return FALSE;
                }
                argv[argc++] = (LPSTR)((PBYTE)pVfsInitBlob + pVfsInitBlob->argv[i].qw);
            }
        }
        ((PBYTE)pVfsInitBlob)[pVfsInitBlob->cbStruct - 1] = 0;
    }
    // 2: fetch vmm.dll library and function pointers:
    ctxProcChild.hDllVmm = LoadLibraryExA("vmm.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    if(!ctxProcChild.hDllVmm) {
        ctxProcChild.hDllVmm = LoadLibraryA("vmm.dll");
    }
    if(!ctxProcChild.hDllVmm) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not locate/load MemProcFS library vmm.dll\n");
        return FALSE;
    }
    f = (ctxProcChild.pfnVMMDLL_Initialize = (PFN_VMMDLL_Initialize)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_Initialize")) &&
        (ctxProcChild.pfnVMMDLL_InitializePlugins = (PFN_VMMDLL_InitializePlugins)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_InitializePlugins")) &&
        (ctxProcChild.pfnVMMDLL_Close = (PFN_VMMDLL_Close)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_Close")) &&
        (ctxProcChild.pfnVMMDLL_MemFree = (PFN_VMMDLL_MemFree)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_MemFree")) &&
        (ctxProcChild.pfnVMMDLL_VfsListBlobU = (PFN_VMMDLL_VfsListBlobU)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_VfsListBlobU")) &&
        (ctxProcChild.pfnVMMDLL_VfsReadU = (PFN_VMMDLL_VfsReadU)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_VfsReadU")) &&
        (ctxProcChild.pfnVMMDLL_VfsWriteU = (PFN_VMMDLL_VfsWriteU)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_VfsWriteU")) &&
        (ctxProcChild.pfnVMMDLL_ConfigGet = (PFN_VMMDLL_ConfigGet)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_ConfigGet")) &&
        (ctxProcChild.pfnVMMDLL_ConfigSet = (PFN_VMMDLL_ConfigSet)GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_ConfigSet"));
    if(!f) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not load MemProcFS library functions.\n");
        return FALSE;
    }
    // 3: initialize MemProcFS vmm.dll library:
    g_hVMM = ctxProcChild.pfnVMMDLL_Initialize(argc, argv);
    if(!g_hVMM) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not initialize MemProcFS library.\n");
        return FALSE;
    }
    result = ctxProcChild.pfnVMMDLL_InitializePlugins(g_hVMM);
    if(!result) {
        ctxProcChild.pfnVMMDLL_Close(g_hVMM);
        g_hVMM = NULL;
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
    if(!(pBlob = ctxProcChild.pfnVMMDLL_VfsListBlobU(g_hVMM, pReq->uszPathFile))) { goto fail; }
    if((pBlob->dwVersion != VMMDLL_VFS_FILELISTBLOB_VERSION) || (pBlob->cbStruct > 0x04000000)) { goto fail; }
    if(!(pRsp = LocalAlloc(0, sizeof(LC_CMD_AGENT_VFS_RSP) + pBlob->cbStruct))) { goto fail; }
    ZeroMemory(pRsp, sizeof(LC_CMD_AGENT_VFS_RSP));
    pRsp->dwVersion = LC_CMD_AGENT_VFS_RSP_VERSION;
    memcpy(pRsp->pb, pBlob, pBlob->cbStruct);
    pRsp->cb = pBlob->cbStruct;
    *pcbRsp = sizeof(LC_CMD_AGENT_VFS_RSP) + pRsp->cb;
    *ppRsp = pRsp;
fail:
    ctxProcChild.pfnVMMDLL_MemFree(pBlob);
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
    pRsp->dwStatus = ctxProcChild.pfnVMMDLL_VfsReadU(g_hVMM, pReq->uszPathFile, pRsp->pb, pReq->dwLength, &pRsp->cbReadWrite, pReq->qwOffset);
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
    pRsp->dwStatus = ctxProcChild.pfnVMMDLL_VfsWriteU(g_hVMM, pReq->uszPathFile, pReq->pb, pReq->cb, &pRsp->cbReadWrite, pReq->qwOffset);
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
    pRsp->dwStatus = (DWORD)ctxProcChild.pfnVMMDLL_ConfigGet(g_hVMM, pReq->fOption, (PULONG64)pRsp->pb);
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
    pRsp->dwStatus = (DWORD)ctxProcChild.pfnVMMDLL_ConfigSet(g_hVMM, pReq->fOption, *(PULONG64)pReq->pb);
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
    ctxProcChild.pfnLeechCorePyC_EmbPythonInitialize = (PFN_LeechCorePyC_EmbPythonInitialize)GetProcAddress(ctxProcChild.hDllLeechCorePyC, "LeechCorePyC_EmbPythonInitialize");
    ctxProcChild.pfnLeechCorePyC_EmbExecPyInMem = (PFN_LeechCorePyC_EmbExecPyInMem)GetProcAddress(ctxProcChild.hDllLeechCorePyC, "LeechCorePyC_EmbExecPyInMem");
    ctxProcChild.pfnLeechCorePyC_EmbClose = (PFN_LeechCorePyC_EmbClose)GetProcAddress(ctxProcChild.hDllLeechCorePyC, "LeechCorePyC_EmbClose");
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
* CALLER LocalFree: *ppCmd
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
VOID LeechAgent_ProcChild_ReaderCmd()
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
                fResult = ((pCmd->cb == 0) || (pCmd->cb >= sizeof(VMMDLL_VFS_INITIALIZEBLOB)));
                fResult = fResult && LeechAgent_ProcChild_InitializeVmm(pCmd->cb ? (PVMMDLL_VFS_INITIALIZEBLOB)pCmd->pb : NULL);
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
* Main entry point for the child process. (called from leechagent!wmain).
* -- argc
* -- argv
*/
VOID LeechAgent_ProcChild_Main(int argc, wchar_t* argv[])
{
    QWORD qwRemoteHLC = 0;
    PLEECHAGENT_PROC_CMD pCmd = NULL;
    ctxProcChild.fStateRunning = TRUE;
    if(argc <= 4) { return; }
    ctxProcChild.hPipeCmd_Rd = (HANDLE)_wtoi64(argv[2]);
    ctxProcChild.hPipeCmd_Wr = (HANDLE)_wtoi64(argv[3]);
    qwRemoteHLC = _wtoi64(argv[4]);
    if(!ctxProcChild.hPipeCmd_Rd || !ctxProcChild.hPipeCmd_Wr) { goto fail; }
    _snprintf_s(ctxProcChild.szDevice, _countof(ctxProcChild.szDevice), _TRUNCATE, "existingremote://0x%llx", qwRemoteHLC);
    _snprintf_s(ctxProcChild.szRemote, _countof(ctxProcChild.szRemote), _TRUNCATE, "smb://ntlm:localhost");
    // use main thread for eternal cmd-read loop
    LeechAgent_ProcChild_ReaderCmd();
fail:
    LeechAgent_ProcChild_Close();
}
