//	leechagent_procparent.c : Implementation of parent process functionality.
//                 Child processes host execution environments such as the
//                 Python environment which allows for execution of scripts.
//                 The Parent process controls the child processes.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent_proc.h"
#include "leechrpc.h"
#include "leechrpc_h.h"
#include "util.h"
#include <stdio.h>

#define VMMDLL_VFS_CONSOLE_RSP_VERSION                  0xf00f0001

typedef struct tdVMMDLL_VFS_CONSOLE_RSP {
    // core:
    DWORD dwVersion;                        // VMMDLL_VFS_KEEPALIVE_RSP_VERSION
    DWORD cbStruct;
    // stdout/stderr:
    union { LPSTR szStdOut; QWORD qwStdOut; };
    union { LPSTR szStdErr; QWORD qwStdErr; };
    BYTE pbBuffer[0];
} VMMDLL_VFS_CONSOLE_RSP, *PVMMDLL_VFS_CONSOLE_RSP;

#define PROCPARENT_STDOUTERR_SIZE   0x00400000      // 4MB

typedef struct tdPROCPARENT_CONTEXT_STDHND {
    SRWLOCK LockSRW;        // buffer access lock
    HANDLE hPipeStd_Rd;     // stdout or stderr
    HANDLE hThreadReader;
    DWORD cbBuffer;
    DWORD cbBufferOffset;
    BYTE pbBuffer[PROCPARENT_STDOUTERR_SIZE];
} PROCPARENT_CONTEXT_STDHND, *PPROCPARENT_CONTEXT_STDHND;

typedef struct tdPROCPARENT_CONTEXT {
    PROCESS_INFORMATION ChildProcessInfo;
    HANDLE hJobKillSubprocess;
    QWORD qwChildKillAfterTickCount64;
    struct {
        HANDLE hPipeStdOut_Wr;
        HANDLE hPipeStdErr_Wr;
        HANDLE hPipeCmd_Rd;
        HANDLE hPipeCmd_Wr;
    } ChildPipe;
    PROCPARENT_CONTEXT_STDHND StdOut;
    PROCPARENT_CONTEXT_STDHND StdErr;
    HANDLE hPipeCmd_Wr;
    HANDLE hPipeCmd_Rd;
    HANDLE hThreadChildTerminator;
} PROCPARENT_CONTEXT, *PPROCPARENT_CONTEXT;

/*
* Cleanup / Close function - only to be called when there are no active threads
* accessing the ctx anymore.
* -- ctx
*/
VOID LeechAgent_ProcParent_CloseInternal(_In_ PPROCPARENT_CONTEXT ctx)
{
    if(ctx->ChildProcessInfo.hProcess) { CloseHandle(ctx->ChildProcessInfo.hProcess); }
    if(ctx->ChildProcessInfo.hThread) { CloseHandle(ctx->ChildProcessInfo.hThread); }
    if(ctx->hPipeCmd_Rd) { CloseHandle(ctx->hPipeCmd_Rd); }
    if(ctx->hPipeCmd_Wr) { CloseHandle(ctx->hPipeCmd_Wr); }
    if(ctx->StdOut.hPipeStd_Rd) { CloseHandle(ctx->StdOut.hPipeStd_Rd); }
    if(ctx->StdErr.hPipeStd_Rd) { CloseHandle(ctx->StdErr.hPipeStd_Rd); }
    if(ctx->StdOut.hThreadReader) { CloseHandle(ctx->StdOut.hThreadReader); }
    if(ctx->StdErr.hThreadReader) { CloseHandle(ctx->StdErr.hThreadReader); }
    if(ctx->hThreadChildTerminator) { CloseHandle(ctx->hThreadChildTerminator); }
    if(ctx->hJobKillSubprocess) { CloseHandle(ctx->hJobKillSubprocess); }
    LocalFree(ctx);
}

/*
* Automatically kill the child processes on process exit. This is useful if the
* agent have child-processes containing execution jobs for python and the main
* agent process happens to exit for whatever reason.
* -- ctx
*/
VOID LeechAgent_ProcParent_KillChildOnExit(_In_ PPROCPARENT_CONTEXT ctx)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
    ctx->hJobKillSubprocess = CreateJobObject(NULL, NULL);
    if(!ctx->hJobKillSubprocess) { return; }
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(ctx->hJobKillSubprocess, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    AssignProcessToJobObject(ctx->hJobKillSubprocess, ctx->ChildProcessInfo.hProcess);
}

/*
* Kill the child process in ctx->ChildProcessInfo.hProcess if ctx->qwChildKillAfterTickCount64 is passed.
* -- ctx
*/
VOID LeechAgent_ProcParent_ChildTerminatorThread(_In_ PPROCPARENT_CONTEXT ctx)
{
    DWORD dwExitCode;
    HANDLE hChildProcess = ctx->ChildProcessInfo.hProcess;
    while((WAIT_TIMEOUT == WaitForSingleObject(hChildProcess, 100)) && (ctx->qwChildKillAfterTickCount64 > GetTickCount64())) {
        ;
    }
    if(GetExitCodeProcess(hChildProcess, &dwExitCode) && (STILL_ACTIVE == dwExitCode)) {
        TerminateProcess(hChildProcess, 1);
    }
    ctx->hThreadChildTerminator = NULL;
}

/*
* Helper function to read from a pipe into a pre-allocated buffer.
* This is done for stdin and stderr.
*/
VOID LeechAgent_ProcParent_ReaderStdOutErr(_In_ PPROCPARENT_CONTEXT_STDHND ctx)
{
    DWORD cbRead;
    BYTE bFirstRead;
    while(TRUE) {
        if(!ReadFile(ctx->hPipeStd_Rd, &bFirstRead, 1, &cbRead, NULL) || (cbRead == 0)) {
            break;
        }
        if(!PeekNamedPipe(ctx->hPipeStd_Rd, NULL, 0, NULL, &cbRead, NULL)) {
            break;
        }
        if(ctx->cbBufferOffset + cbRead + 2 >= ctx->cbBuffer) {
            break;
        }
        AcquireSRWLockExclusive(&ctx->LockSRW);
        ctx->pbBuffer[ctx->cbBufferOffset] = bFirstRead;
        if(cbRead && !ReadFile(ctx->hPipeStd_Rd, ctx->pbBuffer + ctx->cbBufferOffset + 1, cbRead, &cbRead, NULL)) {
            ReleaseSRWLockExclusive(&ctx->LockSRW);
            break;
        }
        ctx->cbBufferOffset += 1 + cbRead;
        ReleaseSRWLockExclusive(&ctx->LockSRW);
    }
    if(ctx->hThreadReader) {
        CloseHandle(ctx->hThreadReader);
        ctx->hThreadReader = NULL;
    }
}

/*
* Send a command to the child process and wait for its reply.
* NB! this function may hang until child termination if the child
* have problems. It is recommended to keep a child termination
* watchdog thread in parallel just in case ...
* CALLER LOCALFREE: *ppbRsp
* -- ctx
* -- dwCMD
* -- pbReq
* -- cbReq
* -- ppbRsp
* -- pcbRsp
* -- return
*/
_Success_(return)
BOOL LeechAgent_ProcParent_ChildSendCmd(_In_ PPROCPARENT_CONTEXT ctx, _In_ DWORD dwCMD, _In_reads_opt_(cbReq) PBYTE pbReq, _In_ DWORD cbReq, _Out_opt_ PBYTE* ppbRsp, _Out_opt_ PDWORD pcbRsp)
{
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    BOOL result;
    DWORD cbWrite;
    PBYTE pbRsp = NULL;
    LEECHAGENT_PROC_CMD CmdReqHdr, CmdRspHdr;
    AcquireSRWLockExclusive(&LockSRW);
    if(ppbRsp) { *ppbRsp = NULL; }
    if(pcbRsp) { *pcbRsp = 0; }
    // 1: send cmd to child
    CmdReqHdr.dwMagic = LEECHAGENT_PROC_CMD_MAGIC;
    CmdReqHdr.dwCmd = dwCMD;
    CmdReqHdr.fSuccess = TRUE;
    CmdReqHdr.cb = cbReq;
    result = WriteFile(ctx->hPipeCmd_Wr, &CmdReqHdr, sizeof(LEECHAGENT_PROC_CMD), &cbWrite, NULL);
    if(pbReq && cbReq) {
        result = WriteFile(ctx->hPipeCmd_Wr, pbReq, cbReq, &cbWrite, NULL) && result;
    }
    if(!result) { goto fail; }
    // 2: wait for and receive cmd result from child after child processed cmd
    //    NB! this may hang indefinitely if child mess up a command - external
    //    watchdog to kill child after X processing time is needed!
    if(!Util_GetBytesPipe(ctx->hPipeCmd_Rd, (PBYTE)&CmdRspHdr, sizeof(LEECHAGENT_PROC_CMD))) { goto fail; }
    if(CmdRspHdr.dwMagic != LEECHAGENT_PROC_CMD_MAGIC) { goto fail; }
    if(CmdRspHdr.cb || ppbRsp) {
        if(!(pbRsp = LocalAlloc(0, CmdRspHdr.cb))) { goto fail; }
    }
    if(CmdRspHdr.cb) {
        if(!Util_GetBytesPipe(ctx->hPipeCmd_Rd, pbRsp, CmdRspHdr.cb)) { goto fail; }
    }
    if(CmdRspHdr.fSuccess && ppbRsp) {
        *ppbRsp = pbRsp;
    } else if(pbRsp) {
        LocalFree(pbRsp);
    }
    if(CmdRspHdr.fSuccess && pcbRsp) {
        *pcbRsp = CmdRspHdr.cb;
    }
    ReleaseSRWLockExclusive(&LockSRW);
    return CmdRspHdr.fSuccess;
fail:
    ReleaseSRWLockExclusive(&LockSRW);
    return FALSE;
}

/*
* Execute Python code stored in buffer pb. The buffer is automatically NULL
* padded just in case by the function.
*/
BOOL LeechAgent_ProcParent_CmdExecPy(_In_ PPROCPARENT_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD cbWrite;
    PLEECHAGENT_PROC_CMD pCmd;
    cbWrite = sizeof(LEECHAGENT_PROC_CMD) + cb;
    pCmd = (PLEECHAGENT_PROC_CMD)LocalAlloc(0, cbWrite);
    if(!pCmd) { return FALSE; }
    pCmd->dwMagic = LEECHAGENT_PROC_CMD_MAGIC;
    pCmd->dwCmd = LEECHAGENT_PROC_CMD_EXEC_PYTHON;
    pCmd->fSuccess = TRUE;
    pCmd->cb = cb;
    memcpy(pCmd->pb, pb, cb);
    return WriteFile(ctx->hPipeCmd_Wr, pCmd, cbWrite, &cbWrite, NULL);
}

/*
* Read child process stdout / stderr data and clear existing data in buffers.
* -- ctx
* -- pbData
* -- cbData
* -- pcbData
* -- return
*/
BOOL LeechAgent_ProcParent_GetStdOutErrText(_In_ PPROCPARENT_CONTEXT ctx, _Out_writes_opt_(cbData) PBYTE pbData, _In_ DWORD cbData, _Out_ PDWORD pcbData)
{
    LPCSTR szERROR_OUTPUT = "\n========== ERROR OUTPUT BELOW ==========\n";
    DWORD cb, cbPos = 0;
    DWORD cbERROR_OUTOUT = (DWORD)strlen(szERROR_OUTPUT);
    BOOL fResult = FALSE;
    AcquireSRWLockExclusive(&ctx->StdOut.LockSRW);
    AcquireSRWLockExclusive(&ctx->StdErr.LockSRW);
    cb = ctx->StdOut.cbBufferOffset + 1;
    if(ctx->StdErr.cbBufferOffset) {
        cb += cbERROR_OUTOUT + ctx->StdErr.cbBufferOffset;
    }
    *pcbData = cb;
    if(!pbData) {
        fResult = TRUE;
        goto fail;
    }
    if(cbData < cb) {
        goto fail;
    }
    memcpy(pbData + cbPos, ctx->StdOut.pbBuffer, ctx->StdOut.cbBufferOffset); cbPos += ctx->StdOut.cbBufferOffset;
    if(ctx->StdErr.cbBufferOffset) {
        memcpy(pbData + cbPos, szERROR_OUTPUT, cbERROR_OUTOUT); cbPos += cbERROR_OUTOUT;
        memcpy(pbData + cbPos, ctx->StdErr.pbBuffer, ctx->StdErr.cbBufferOffset); cbPos += ctx->StdErr.cbBufferOffset;
    }
    pbData[cbPos] = '\0';
    ctx->StdOut.cbBufferOffset = 0;
    ctx->StdErr.cbBufferOffset = 0;
    fResult = TRUE;
fail:
    ReleaseSRWLockExclusive(&ctx->StdErr.LockSRW);
    ReleaseSRWLockExclusive(&ctx->StdOut.LockSRW);
    return fResult;
}

VOID LeechAgent_ProcParent_Close(_In_opt_ HANDLE hPP)
{
    PPROCPARENT_CONTEXT ctx = (PPROCPARENT_CONTEXT)hPP;
    DWORD dwExitCode;
    if(!ctx) { return; }
    // ensure child process is killed before continue.
    if(ctx->ChildProcessInfo.hProcess) {
        if(GetExitCodeProcess(ctx->ChildProcessInfo.hProcess, &dwExitCode) && (STILL_ACTIVE == dwExitCode)) {
            TerminateProcess(ctx->ChildProcessInfo.hProcess, 1);
            WaitForSingleObject(ctx->ChildProcessInfo.hProcess, 500);
        }
        Sleep(100);
    }
    // cleanup and return
    LeechAgent_ProcParent_CloseInternal(ctx);
}

/*
* Check whether the vfs is loaded and is active or not.
* -- hLC
* -- phPP
* -- return
*/
BOOL LeechAgent_ProcParent_VfsEnsure(_In_ HANDLE hLC, _Inout_ PHANDLE phPP)
{
    PPROCPARENT_CONTEXT ctx = (PPROCPARENT_CONTEXT)*phPP;
    DWORD dwExitCode;
    if(!ctx) { return FALSE; }
    if(GetExitCodeProcess(ctx->ChildProcessInfo.hProcess, &dwExitCode) && (STILL_ACTIVE != dwExitCode)) {
        *phPP = NULL;
        LeechAgent_ProcParent_Close((HANDLE)ctx);
        ctx = NULL;
        return FALSE;
    }
    ctx->qwChildKillAfterTickCount64 = GetTickCount64() + LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS;
    return TRUE;
}

_Success_(return)
BOOL LeechAgent_ProcParent_VfsCMD(_In_ HANDLE hLC, _Inout_ PHANDLE phPP, _In_ DWORD dwCMD, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_opt_ PBYTE* ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    if(!LeechAgent_ProcParent_VfsEnsure(hLC, phPP)) { return FALSE; }
    return LeechAgent_ProcParent_ChildSendCmd((PPROCPARENT_CONTEXT)*phPP, dwCMD, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
}

_Success_(return)
BOOL LeechAgent_ProcParent_VfsConsole(_In_ HANDLE hLC, _Inout_ PHANDLE phPP, _Out_opt_ PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    PPROCPARENT_CONTEXT ctx = (PPROCPARENT_CONTEXT)*phPP;
    PVMMDLL_VFS_CONSOLE_RSP pRsp;
    DWORD o = 0, cbStruct;
    if(ppbDataOut) { *ppbDataOut = NULL; }
    if(pcbDataOut) { *pcbDataOut = 0; }
    if(!LeechAgent_ProcParent_VfsEnsure(hLC, phPP)) { return FALSE; }
    if((ctx->StdOut.cbBufferOffset == 0) && (ctx->StdErr.cbBufferOffset == 0)) { return TRUE; }
    AcquireSRWLockExclusive(&ctx->StdOut.LockSRW);
    AcquireSRWLockExclusive(&ctx->StdErr.LockSRW);
    cbStruct = sizeof(VMMDLL_VFS_CONSOLE_RSP) + ctx->StdOut.cbBufferOffset + ctx->StdErr.cbBufferOffset + 2;
    pRsp = (PVMMDLL_VFS_CONSOLE_RSP)LocalAlloc(LMEM_ZEROINIT, cbStruct);
    if(!pRsp) { goto fail; }
    pRsp->dwVersion = VMMDLL_VFS_CONSOLE_RSP_VERSION;
    pRsp->cbStruct = cbStruct;
    if(ctx->StdOut.cbBufferOffset) {
        pRsp->qwStdOut = sizeof(VMMDLL_VFS_CONSOLE_RSP) + o;
        memcpy(pRsp->pbBuffer + o, ctx->StdOut.pbBuffer, ctx->StdOut.cbBufferOffset);
        o += ctx->StdOut.cbBufferOffset + 1;
        ctx->StdOut.cbBufferOffset = 0;
    }
    if(ctx->StdErr.cbBufferOffset) {
        pRsp->qwStdErr = sizeof(VMMDLL_VFS_CONSOLE_RSP) + o;
        memcpy(pRsp->pbBuffer + o, ctx->StdErr.pbBuffer, ctx->StdErr.cbBufferOffset);
        o += ctx->StdErr.cbBufferOffset + 1;
        ctx->StdErr.cbBufferOffset = 0;
    }
    if(ppbDataOut) { *ppbDataOut = (PBYTE)pRsp; }
    if(pcbDataOut) { *pcbDataOut = cbStruct; }
fail:
    ReleaseSRWLockExclusive(&ctx->StdErr.LockSRW);
    ReleaseSRWLockExclusive(&ctx->StdOut.LockSRW);
    return TRUE;
}

_Success_(return)
BOOL LeechAgent_ProcParent_VfsInitialize(_In_ HANDLE hLC, _Inout_ PHANDLE phPP, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_opt_ PBYTE* ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    PPROCPARENT_CONTEXT ctx = (PPROCPARENT_CONTEXT)*phPP;
    WCHAR wszProcessPathName[MAX_PATH] = { 0 };
    WCHAR wszProcessArgs[MAX_PATH] = { 0 };
    STARTUPINFOW StartupInfo = { 0 };
    SECURITY_ATTRIBUTES SecAttr = { 0 };
    BOOL result;
    if(ppbDataOut) { *ppbDataOut = NULL; }
    if(pcbDataOut) { *pcbDataOut = 0; }
    // 1: ensure no existing context exists:
    if(LeechAgent_ProcParent_VfsEnsure(hLC, phPP)) {
        fprintf(stderr, "LeechAgent: FAIL: Already Initialized\n");
        goto fail;
    }
    // 2: setup new context:
    if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(PROCPARENT_CONTEXT)))) {
        fprintf(stderr, "LeechAgent: FAIL: LocalAlloc()\n");
        goto fail;
    }
    ctx->StdOut.cbBuffer = sizeof(ctx->StdOut.pbBuffer);
    ctx->StdErr.cbBuffer = sizeof(ctx->StdErr.pbBuffer);
    // 3: set up redirect pipes for child stdout/stderr:
    SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    SecAttr.bInheritHandle = TRUE;
    SecAttr.lpSecurityDescriptor = NULL;
    SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    SecAttr.bInheritHandle = TRUE;
    SecAttr.lpSecurityDescriptor = NULL;
    if(!CreatePipe(&ctx->StdOut.hPipeStd_Rd, &ctx->ChildPipe.hPipeStdOut_Wr, &SecAttr, 0) || !CreatePipe(&ctx->StdErr.hPipeStd_Rd, &ctx->ChildPipe.hPipeStdErr_Wr, &SecAttr, 0)) {
        fprintf(stderr, "LeechAgent: FAIL: CreatePipe() STD\n");
    }
    // 4: set up command pipe:
    if(!CreatePipe(&ctx->hPipeCmd_Rd, &ctx->ChildPipe.hPipeCmd_Wr, &SecAttr, 0x02000000) || !CreatePipe(&ctx->ChildPipe.hPipeCmd_Rd, &ctx->hPipeCmd_Wr, &SecAttr, 0x02000000)) {
        fprintf(stderr, "LeechAgent: FAIL: CreatePipe() CMD\n");
        goto fail;
    }
    // 5: create process:
    _snwprintf_s(
        wszProcessArgs,
        MAX_PATH - 1,
        _TRUNCATE,
        L"-child -child %llu %llu %llu",
        (QWORD)ctx->ChildPipe.hPipeCmd_Rd,
        (QWORD)ctx->ChildPipe.hPipeCmd_Wr,
        (QWORD)hLC);
    GetModuleFileNameW(NULL, wszProcessPathName, MAX_PATH - 1);
    StartupInfo.cb = sizeof(STARTUPINFOW);
    StartupInfo.hStdOutput = ctx->ChildPipe.hPipeStdOut_Wr;
    StartupInfo.hStdError = ctx->ChildPipe.hPipeStdErr_Wr;
    StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    result = CreateProcessW(
        wszProcessPathName,
        wszProcessArgs,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,
        NULL,
        NULL,
        &StartupInfo,
        &ctx->ChildProcessInfo);
    if(!result) {
        fprintf(stderr, "LeechAgent: FAIL: CreateProcessW() -> %08x\n", GetLastError());
        goto fail;
    }
    LeechAgent_ProcParent_KillChildOnExit(ctx);
    ResumeThread(ctx->ChildProcessInfo.hThread);
    // 6: set up pipe readers:
    CloseHandle(ctx->ChildPipe.hPipeStdOut_Wr); ctx->ChildPipe.hPipeStdOut_Wr = NULL;
    CloseHandle(ctx->ChildPipe.hPipeStdErr_Wr); ctx->ChildPipe.hPipeStdErr_Wr = NULL;
    CloseHandle(ctx->ChildPipe.hPipeCmd_Rd); ctx->ChildPipe.hPipeCmd_Rd = NULL;
    CloseHandle(ctx->ChildPipe.hPipeCmd_Wr); ctx->ChildPipe.hPipeCmd_Wr = NULL;
    ctx->StdOut.hThreadReader = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ReaderStdOutErr, (LPVOID)&ctx->StdOut, 0, NULL);
    ctx->StdErr.hThreadReader = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ReaderStdOutErr, (LPVOID)&ctx->StdErr, 0, NULL);
    if(!ctx->StdOut.hThreadReader || !ctx->StdErr.hThreadReader) {
        fprintf(stderr, "LeechAgent: FAIL: CreateThread()\n");
        goto fail;
    }
    // 7: initialize
    if(!LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_INIT_VMM, pbDataIn, cbDataIn, NULL, NULL)) {
        fprintf(stderr, "LeechAgent: FAIL: ChildSendCmd_VmmInit()\n");
        goto fail;
    }
    // 8: set up child process auto-terminator watchdog:
    //    NB! no 'goto fail' must be made after this
    ctx->qwChildKillAfterTickCount64 = GetTickCount64() + LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS;  // kill child after time
    ctx->hThreadChildTerminator = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ChildTerminatorThread, (LPVOID)ctx, 0, NULL);
    // 9: finalize:
    *phPP = (HANDLE)ctx;
    return TRUE;
fail:
    LeechAgent_ProcParent_Close((HANDLE)ctx);
    return FALSE;
}

_Success_(return)
BOOL LeechAgent_ProcParent_ExecPy(_In_ HANDLE hLC, _In_ DWORD dwTimeout, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_opt_ PBYTE* ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    BOOL fResult;
    DWORD dwExitCode;
    PPROCPARENT_CONTEXT ctx = NULL;
    if(ppbDataOut) { *ppbDataOut = NULL; }
    // 1: create and start vmm child process:
    if(!LeechAgent_ProcParent_VfsInitialize(hLC, &ctx, NULL, 0, NULL, NULL) || !ctx) {
        goto fail;
    }
    // 2: update child auto-terminator watchdog timeout:
    if(dwTimeout && (dwTimeout < LEECHAGENT_CHILDPROCESS_TIMEOUT_MAX_MS)) {
        ctx->qwChildKillAfterTickCount64 = GetTickCount64() + dwTimeout;
    }
    // 3: send commands to child process to  load Python and execute code.
    if(LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_INIT_PYTHON, NULL, 0, NULL, NULL)) {
        LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_EXEC_PYTHON, pbDataIn, cbDataIn, NULL, NULL);
    }
    LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_EXITCLIENT, NULL, 0, NULL, NULL);
    // 4: wait for child process termination
    WaitForSingleObject(ctx->ChildProcessInfo.hProcess, INFINITE);
    while(ctx->StdOut.hThreadReader || ctx->StdErr.hThreadReader || ctx->hThreadChildTerminator) {
        SwitchToThread();
    }
    // 5: read child process stdout/stderr data
    fResult =
        ppbDataOut && pcbDataOut &&
        LeechAgent_ProcParent_GetStdOutErrText(ctx, NULL, 0, pcbDataOut) &&
        (*ppbDataOut = LocalAlloc(0, *pcbDataOut)) &&
        LeechAgent_ProcParent_GetStdOutErrText(ctx, *ppbDataOut, *pcbDataOut, pcbDataOut);
    if(!fResult) {
        fprintf(stderr, "LeechAgent: FAIL: LeechAgent_ProcParent_GetStdOutErrText()\n");
    }
    if(!fResult && ppbDataOut && *ppbDataOut) { LocalFree(*ppbDataOut); }
    LeechAgent_ProcParent_CloseInternal(ctx);
    return fResult;
fail:
    if(!ctx) { return FALSE; }
    // ensure child process is killed before continue.
    if(ctx->ChildProcessInfo.hProcess) {
        if(GetExitCodeProcess(ctx->ChildProcessInfo.hProcess, &dwExitCode) && (STILL_ACTIVE == dwExitCode)) {
            TerminateProcess(ctx->ChildProcessInfo.hProcess, 1);
            WaitForSingleObject(ctx->ChildProcessInfo.hProcess, 500);
            Sleep(100);
        }
    }
    // fetch data from client (if any)
    fResult =
        ppbDataOut && pcbDataOut &&
        LeechAgent_ProcParent_GetStdOutErrText(ctx, NULL, 0, pcbDataOut) &&
        (*ppbDataOut = LocalAlloc(0, *pcbDataOut)) &&
        LeechAgent_ProcParent_GetStdOutErrText(ctx, *ppbDataOut, *pcbDataOut, pcbDataOut);
    // cleanup and return
    if(!fResult && ppbDataOut && *ppbDataOut) { LocalFree(*ppbDataOut); }
    LeechAgent_ProcParent_CloseInternal(ctx);
    return fResult;
}
