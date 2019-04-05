//	leechagent_procchild.c : Implementation of child process functionality.
//                 Child processes host execution environments such as the
//                 Python environment which allows for execution of scripts.
//
// (c) Ulf Frisk, 2019
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

typedef struct tdPROCCHILD_CONTEXT {
    BOOL fStateRunning;
    HMODULE hDllVmm;
    HMODULE hDllPython3;
    HMODULE hDllPython3X;
    HMODULE hDllLeechCorePyC;
    BOOL(*pfnVMMDLL_Initialize)(_In_ DWORD argc, _In_ LPSTR argv[]);
    BOOL(*pfnVMMDLL_Close)();
    BOOL(*pfnLeechCorePyC_EmbPythonInitialize)(_In_ HMODULE hDllPython);
    BOOL(*pfnLeechCorePyC_EmbExecPyInMem)(_In_ LPSTR szPythonProgram);
    VOID(*pfnLeechCorePyC_EmbClose)();
    HANDLE hPipeCmd_Rd;
    HANDLE hPipeCmd_Wr;
    HANDLE hPipeMem_Rd;
    HANDLE hPipeMem_Wr;
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
    LPSTR szVMM_ARGUMENTS[] = { "", "-device", "existingremote", "-remote", "" };
    szVMM_ARGUMENTS[4] = ctxProcChild.szRemote;
    ctxProcChild.hDllVmm = LoadLibraryExA("vmm.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    if(!ctxProcChild.hDllVmm) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not locate/load MemProcFS library vmm.dll\n");
        return FALSE;
    }
    ctxProcChild.pfnVMMDLL_Initialize = (BOOL(*)(DWORD, LPSTR*))GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_Initialize");
    ctxProcChild.pfnVMMDLL_Close = (BOOL(*)())GetProcAddress(ctxProcChild.hDllVmm, "VMMDLL_Close");
    if(!ctxProcChild.pfnVMMDLL_Initialize || !ctxProcChild.pfnVMMDLL_Close) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not load MemProcFS library functions.\n");
        return FALSE;
    }
    result = ctxProcChild.pfnVMMDLL_Initialize((sizeof(szVMM_ARGUMENTS) / sizeof(LPCSTR)), szVMM_ARGUMENTS);
    if(!result) {
        fprintf(stderr, "LeechAgent: FAIL: CHILD could not initialize MemProcFS library.\n");
        return FALSE;
    }
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
    LPWSTR wszPYTHON_VERSIONS_SUPPORTED[] = { L"python36.dll", L"python37.dll", L"python38.dll" };
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
    ctxProcChild.hDllLeechCorePyC = LoadLibraryA("leechcorepyc.pyd");
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
* Python (to flush remaining buffers) is made. Also the MemProcFS will be shut
* down for the memory reader to unregister from the parent process.
* All other cleaning of pipe handles and buffers are left to the OS to manage
* on process shutdown.
* If orderly shutdown takes too long a forceful process termination is requested.
*/
VOID LeechAgent_ProcChild_Close()
{
    ctxProcChild.fStateRunning = FALSE;
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcChild_Close_ForceTerminateThread, NULL, 0, NULL);
    if(ctxProcChild.pfnLeechCorePyC_EmbClose) {
        ctxProcChild.pfnLeechCorePyC_EmbClose();
    }
    fflush(stdout);
    fflush(stderr);
    if(ctxProcChild.pfnVMMDLL_Close) {
        ctxProcChild.pfnVMMDLL_Close();
    }
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
VOID LeechAgent_ProcChild_ReaderCmd()
{
    BOOL result;
    DWORD cbWrite;
    PBYTE pb = NULL;
    LEECHAGENT_PROC_CMD CmdRsp = { 0 };
    PLEECHAGENT_PROC_CMD pCmd = NULL;
    CmdRsp.dwMagic = LEECHAGENT_PROC_CMD_MAGIC;
    while(LeechAgent_ProcChild_CmdRead(&pCmd)) {
        result = TRUE;
        switch(pCmd->dwCmd) {
            case LEECHAGENT_PROC_CMD_EXITCLIENT:
                LeechAgent_ProcChild_Close();
                break;
            case LEECHAGENT_PROC_CMD_INIT_VMM:
                result = LeechAgent_ProcChild_InitializeVmm();
                break;
            case LEECHAGENT_PROC_CMD_INIT_PYTHON:
                result = LeechAgent_ProcChild_InitializePython();
                break;
            case LEECHAGENT_PROC_CMD_EXEC_PYTHON:
                result = FALSE;
                if(ctxProcChild.pfnLeechCorePyC_EmbExecPyInMem) {
                    pb = LocalAlloc(0, pCmd->cb + 1ULL);
                    if(pb) {
                        // null terminate buffer (just in case) and send to python for execution.
                        memcpy(pb, pCmd->pb, pCmd->cb);
                        pb[pCmd->cb] = 0;
                        result = ctxProcChild.pfnLeechCorePyC_EmbExecPyInMem((LPSTR)pb);
                        LocalFree(pb);
                        pb = NULL;
                    }
                }
                break;
            default:
                fprintf(stderr, "LeechAgent: WARN: CHILD received unknown CMD from parent. ID: 0x%08x\n", pCmd->dwCmd);
                break;
        }
        CmdRsp.fSuccess = result;
        CmdRsp.dwCmd = pCmd->dwCmd;
        if(!WriteFile(ctxProcChild.hPipeCmd_Wr, &CmdRsp, sizeof(LEECHAGENT_PROC_CMD), &cbWrite, NULL)) {
            break;
        }
        LocalFree(pCmd);
        pCmd = NULL;
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
    PLEECHAGENT_PROC_CMD pCmd = NULL;
    ctxProcChild.fStateRunning = TRUE;
    if(argc <= 5) { return; }
    ctxProcChild.hPipeCmd_Rd = (HANDLE)_wtoi64(argv[2]);
    ctxProcChild.hPipeCmd_Wr = (HANDLE)_wtoi64(argv[3]);
    ctxProcChild.hPipeMem_Rd = (HANDLE)_wtoi64(argv[4]);
    ctxProcChild.hPipeMem_Wr = (HANDLE)_wtoi64(argv[5]);
    if(!ctxProcChild.hPipeCmd_Rd || !ctxProcChild.hPipeMem_Rd || !ctxProcChild.hPipeMem_Wr) { goto fail; }
    _snprintf_s(ctxProcChild.szRemote, MAX_PATH - 1, _TRUNCATE, "pipe://%llu:%llu", (QWORD)ctxProcChild.hPipeMem_Rd, (QWORD)ctxProcChild.hPipeMem_Wr);
    // use main thread for eternal cmd-read loop
    LeechAgent_ProcChild_ReaderCmd();
fail:
    LeechAgent_ProcChild_Close();
}
