//	leechagent_procparent.c : Implementation of parent process functionality.
//                 Child processes host execution environments such as the
//                 Python environment which allows for execution of scripts.
//                 The Parent process controls the child processes.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent_proc.h"
#include "leechrpc.h"
#include "leechrpc_h.h"
#include "util.h"
#include <stdio.h>

#define PROCPARENT_STDOUT_SIZE  0x00400000      // 4MB
#define PROCPARENT_STDERR_SIZE  0x00040000      // 256kB

typedef struct tdPROCPARENT_CONTEXT {
    PROCESS_INFORMATION ChildProcessInfo;
    HANDLE hJobKillSubprocess;
    DWORD dwChildKillAfterMilliseconds;
    struct {
        HANDLE hPipeStdOut_Wr;
        HANDLE hPipeStdErr_Wr;
        HANDLE hPipeCmd_Rd;
        HANDLE hPipeCmd_Wr;
        HANDLE hPipeMem_Rd;
        HANDLE hPipeMem_Wr;
    } ChildPipe;
    HANDLE hPipeStdOut_Rd;
    HANDLE hPipeStdErr_Rd;
    HANDLE hPipeCmd_Wr;
    HANDLE hPipeCmd_Rd;
    HANDLE hPipeMem_Rd;
    HANDLE hPipeMem_Wr;
    HANDLE hThreadReaderStdOut;
    HANDLE hThreadReaderStdErr;
    HANDLE hThreadReaderMem;
    HANDLE hThreadChildTerminator;
    DWORD cbStdOutPos;
    DWORD cbStdErrPos;
    BYTE pbStdOut[PROCPARENT_STDOUT_SIZE];
    BYTE pbStdErr[PROCPARENT_STDERR_SIZE];
} PROCPARENT_CONTEXT, *PPROCPARENT_CONTEXT;

/*
* Cleanup / Close function - only to be called when there are no active threads
* accessing the ctx anymore.
* -- ctx
*/
VOID LeechAgent_ProcParent_Close(_In_ PPROCPARENT_CONTEXT ctx)
{
    if(ctx->ChildProcessInfo.hProcess) { CloseHandle(ctx->ChildProcessInfo.hProcess); }
    if(ctx->ChildProcessInfo.hThread) { CloseHandle(ctx->ChildProcessInfo.hThread); }
    if(ctx->hPipeStdOut_Rd) { CloseHandle(ctx->hPipeStdOut_Rd); }
    if(ctx->hPipeStdErr_Rd) { CloseHandle(ctx->hPipeStdErr_Rd); }
    if(ctx->hPipeCmd_Wr) { CloseHandle(ctx->hPipeCmd_Wr); }
    if(ctx->hPipeCmd_Rd) { CloseHandle(ctx->hPipeCmd_Rd); }
    if(ctx->hPipeMem_Rd) { CloseHandle(ctx->hPipeMem_Rd); }
    if(ctx->hPipeMem_Wr) { CloseHandle(ctx->hPipeMem_Wr); }
    if(ctx->hThreadReaderStdOut) { CloseHandle(ctx->hThreadReaderStdOut); }
    if(ctx->hThreadReaderStdErr) { CloseHandle(ctx->hThreadReaderStdErr); }
    if(ctx->hThreadReaderMem) { CloseHandle(ctx->hThreadReaderMem); }
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
* Kill the child process in ctx->ChildProcessInfo.hProcess after ctx->dwChildKillAfterMilliseconds ms.
* -- ctx
*/
VOID LeechAgent_ProcParent_ChildTerminatorThread(_In_ PPROCPARENT_CONTEXT ctx)
{
    HANDLE hChildProcess = ctx->ChildProcessInfo.hProcess;
    DWORD dwMilliseconds = ctx->dwChildKillAfterMilliseconds;
    DWORD dwExitCode;
    WaitForSingleObject(hChildProcess, dwMilliseconds);
    if(GetExitCodeProcess(hChildProcess, &dwExitCode) && (STILL_ACTIVE == dwExitCode)) {
        TerminateProcess(hChildProcess, 1);
    }
    ctx->hThreadChildTerminator = NULL;
}

VOID LeechAgent_ProcParent_ReaderStdOut(PPROCPARENT_CONTEXT ctx)
{
    BOOL result = TRUE;
    DWORD cbRead = 0;
    while((ctx->cbStdOutPos + 0x1000 < PROCPARENT_STDOUT_SIZE) && ReadFile(ctx->hPipeStdOut_Rd, ctx->pbStdOut + ctx->cbStdOutPos, 0x1000, &cbRead, NULL)) {
        ctx->cbStdOutPos += cbRead;
    }
    ctx->hThreadReaderStdOut = NULL;
}

VOID LeechAgent_ProcParent_ReaderStdErr(PPROCPARENT_CONTEXT ctx)
{
    BOOL result = TRUE;
    DWORD cbRead = 0;
    while((ctx->cbStdErrPos + 0x1000 < PROCPARENT_STDERR_SIZE) && ReadFile(ctx->hPipeStdErr_Rd, ctx->pbStdErr + ctx->cbStdErrPos, 0x1000, &cbRead, NULL)) {
        ctx->cbStdErrPos += cbRead;
    }
    ctx->hThreadReaderStdErr = NULL;
}

VOID LeechAgent_ProcParent_ReaderMem(PPROCPARENT_CONTEXT ctx)
{
    error_status_t status;
    DWORD cRuns = 0, cbMsgRsp, cbWrite = 0;
    LEECHRPC_MSG_HDR Hdr;
    PLEECHRPC_MSG_HDR pMsgReq = NULL, pMsgRsp = NULL;
    while(TRUE) {
        cRuns++;
        ZeroMemory(&Hdr, sizeof(LEECHRPC_MSG_HDR));
        // 1: read incoming request : header
        if(!Util_GetBytesPipe(ctx->hPipeMem_Rd, (PBYTE)&Hdr, sizeof(LEECHRPC_MSG_HDR))) {
            goto fail;
        }
        if((Hdr.dwMagic != LEECHRPC_MSGMAGIC) || (Hdr.cbMsg > 0x04000000)) {
            goto fail;
        }
        pMsgReq = (PLEECHRPC_MSG_HDR)LocalAlloc(0, Hdr.cbMsg);
        if(!pMsgReq) {
            goto fail;
        }
        memcpy(pMsgReq, &Hdr, sizeof(LEECHRPC_MSG_HDR));
        // 2: read resulting contents : data
        if(pMsgReq->cbMsg > sizeof(LEECHRPC_MSG_HDR)) {
            if(!Util_GetBytesPipe(ctx->hPipeMem_Rd, ((PBYTE)pMsgReq) + sizeof(LEECHRPC_MSG_HDR), pMsgReq->cbMsg - sizeof(LEECHRPC_MSG_HDR))) {
                goto fail;
            }
        }
        // 3: SEND COMMAND TO ORDINARY LEECHRPC
        status = LeechRpc_ReservedSubmitCommand(NULL, pMsgReq->cbMsg, (PBYTE)pMsgReq, &cbMsgRsp, (PBYTE*)&pMsgRsp);
        LocalFree(pMsgReq);
        pMsgReq = NULL;
        if(status != RPC_S_OK) {
            pMsgRsp = NULL;
            Hdr.dwMagic = LEECHRPC_MSGMAGIC;
            Hdr.cbMsg = sizeof(LEECHRPC_MSG_HDR);
            Hdr.tpMsg = LEECHRPC_MSGTYPE_NA;
            Hdr.fMsgResult = FALSE;
            Hdr.dwRpcClientID = 0;
            Hdr.flags = 0;
            if(!WriteFile(ctx->hPipeMem_Wr, (PVOID)&Hdr, Hdr.cbMsg, &cbWrite, NULL)) {
                goto fail;
            }
        } else {
            if(!WriteFile(ctx->hPipeMem_Wr, (PVOID)pMsgRsp, pMsgRsp->cbMsg, &cbWrite, NULL)) {
                goto fail;
            }
            LocalFree(pMsgRsp);
            pMsgRsp = NULL;
        }
    }
fail:
    LocalFree(pMsgReq);
    LocalFree(pMsgRsp);
    ctx->hThreadReaderMem = NULL;
}

/*
* Send a command to the child process and wait for its reply.
* NB! this function may hang until child termination if the child
* have problems. It is recommended to keep a child termination
* watchdog thread in parallel just in case ...
*/
BOOL LeechAgent_ProcParent_ChildSendCmd(_In_ PPROCPARENT_CONTEXT ctx, _In_ DWORD dwCMD, _In_reads_opt_(cb) PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    DWORD cbWrite;
    LEECHAGENT_PROC_CMD CmdRsp;
    PLEECHAGENT_PROC_CMD pCmd;
    // 1: send cmd to child
    cbWrite = sizeof(LEECHAGENT_PROC_CMD) + cb;
    pCmd = (PLEECHAGENT_PROC_CMD)LocalAlloc(0, cbWrite);
    if(!pCmd) { return FALSE; }
    if(!pb) { cb = 0; }
    pCmd->dwMagic = LEECHAGENT_PROC_CMD_MAGIC;
    pCmd->dwCmd = dwCMD;
    pCmd->fSuccess = TRUE;
    pCmd->cb = cb;
    if(pb) {
        memcpy(pCmd->pb, pb, cb);
    }
    result = WriteFile(ctx->hPipeCmd_Wr, pCmd, cbWrite, &cbWrite, NULL);
    LocalFree(pCmd);
    if(!result) { return FALSE; }
    // 2: wait for and receive cmd result from child after child processed cmd
    //    NB! this may hang indefinitely if child mess up a command - external
    //    watchdog to kill child after X processing time is needed!
    if(!Util_GetBytesPipe(ctx->hPipeCmd_Rd, (PBYTE)& CmdRsp, sizeof(LEECHAGENT_PROC_CMD))) { return FALSE; }
    if(CmdRsp.dwMagic != LEECHAGENT_PROC_CMD_MAGIC) { return FALSE; }
    return CmdRsp.fSuccess;
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
* Read child process stdout / stderr data. When calling this function the caller
* must ensure that no additional reads may happen when executing this function.
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
    cb = ctx->cbStdOutPos + 1;
    if(ctx->cbStdErrPos) {
        cb += cbERROR_OUTOUT + ctx->cbStdErrPos;
    }
    *pcbData = cb;
    if(!pbData) { return TRUE; }
    if(cbData < cb) { return FALSE; }
    memcpy(pbData + cbPos, ctx->pbStdOut, ctx->cbStdOutPos); cbPos += ctx->cbStdOutPos;
    if(ctx->cbStdErrPos) {
        memcpy(pbData + cbPos, szERROR_OUTPUT, cbERROR_OUTOUT); cbPos += cbERROR_OUTOUT;
        memcpy(pbData + cbPos, ctx->pbStdErr, ctx->cbStdErrPos); cbPos += ctx->cbStdErrPos;
    }
    pbData[cbPos] = '\0';
    return TRUE;
}

_Success_(return)
BOOL LeechAgent_ProcParent_ExecPy(_In_ ULONG64 fDataIn, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(*pcbDataOut) PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    WCHAR wszProcessPathName[MAX_PATH] = { 0 };
    WCHAR wszProcessArgs[MAX_PATH] = { 0 };
    STARTUPINFOW StartupInfo = { 0 };
    PPROCPARENT_CONTEXT ctx = NULL;
    SECURITY_ATTRIBUTES SecAttr = { 0 };
    BOOL result, fChildInitVmmPython;
    DWORD dwExitCode;
    if(ppbDataOut) { *ppbDataOut = NULL; }
    // set up context
    ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(PROCPARENT_CONTEXT));
    if(!ctx) {
        fprintf(stderr, "LeechAgent: FAIL: LocalAlloc()\n");
        goto fail;
    }
    // set up redirect pipes for child stdout/stderr 
    SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    SecAttr.bInheritHandle = TRUE;
    SecAttr.lpSecurityDescriptor = NULL;
    if(!CreatePipe(&ctx->hPipeStdOut_Rd, &ctx->ChildPipe.hPipeStdOut_Wr, &SecAttr, 0) || !CreatePipe(&ctx->hPipeStdErr_Rd, &ctx->ChildPipe.hPipeStdErr_Wr, &SecAttr, 0)) {
        fprintf(stderr, "LeechAgent: FAIL: CreatePipe() STD\n");
        goto fail;
    }
    // set up command pipe
    if(!CreatePipe(&ctx->hPipeCmd_Rd, &ctx->ChildPipe.hPipeCmd_Wr, &SecAttr, 0) || !CreatePipe(&ctx->ChildPipe.hPipeCmd_Rd, &ctx->hPipeCmd_Wr, &SecAttr, 0)) {
        fprintf(stderr, "LeechAgent: FAIL: CreatePipe() CMD\n");
        goto fail;
    }
    // set up memory read/write pipe
    if(!CreatePipe(&ctx->hPipeMem_Rd, &ctx->ChildPipe.hPipeMem_Wr, &SecAttr, 0) || !CreatePipe(&ctx->ChildPipe.hPipeMem_Rd, &ctx->hPipeMem_Wr, &SecAttr, 0)) {
        fprintf(stderr, "LeechAgent: FAIL: CreatePipe() MEM\n");
        goto fail;
    }
    // create process
    _snwprintf_s(
        wszProcessArgs,
        MAX_PATH - 1,
        _TRUNCATE,
        L"-child -child %llu %llu %llu %llu",
        (QWORD)ctx->ChildPipe.hPipeCmd_Rd,
        (QWORD)ctx->ChildPipe.hPipeCmd_Wr,
        (QWORD)ctx->ChildPipe.hPipeMem_Rd,
        (QWORD)ctx->ChildPipe.hPipeMem_Wr);
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
    // set up pipe readers
    CloseHandle(ctx->ChildPipe.hPipeStdOut_Wr); ctx->ChildPipe.hPipeStdOut_Wr = NULL;
    CloseHandle(ctx->ChildPipe.hPipeStdErr_Wr); ctx->ChildPipe.hPipeStdErr_Wr = NULL;
    CloseHandle(ctx->ChildPipe.hPipeCmd_Rd); ctx->ChildPipe.hPipeCmd_Rd = NULL;
    CloseHandle(ctx->ChildPipe.hPipeCmd_Wr); ctx->ChildPipe.hPipeCmd_Wr = NULL;
    CloseHandle(ctx->ChildPipe.hPipeMem_Rd); ctx->ChildPipe.hPipeMem_Rd = NULL;
    CloseHandle(ctx->ChildPipe.hPipeMem_Wr); ctx->ChildPipe.hPipeMem_Wr = NULL;
    ctx->hThreadReaderStdOut = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ReaderStdOut, (LPVOID)ctx, 0, NULL);
    ctx->hThreadReaderStdErr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ReaderStdErr, (LPVOID)ctx, 0, NULL);
    ctx->hThreadReaderMem = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ReaderMem, (LPVOID)ctx, 0, NULL);
    if(!ctx->hThreadReaderStdOut || !ctx->hThreadReaderStdErr || !ctx->hThreadReaderMem) {
        fprintf(stderr, "LeechAgent: FAIL: CreateThread()\n");
        goto fail;
    }
    // set up child process auto-terminator watchdog
    // NB! no 'goto fail' must be made after this
    ctx->dwChildKillAfterMilliseconds = (fDataIn && (fDataIn < LEECHAGENT_CHILDPROCESS_TIMEOUT_MAX_MS)) ? (DWORD)fDataIn : LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS;  // kill child after time
    ctx->hThreadChildTerminator = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ChildTerminatorThread, (LPVOID)ctx, 0, NULL);
    // send commands to child process to initialize MemProcFS, Python and execute code.
    fChildInitVmmPython =
        LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_INIT_VMM, NULL, 0) &&
        LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_INIT_PYTHON, NULL, 0);
    if(fChildInitVmmPython) {
        LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_EXEC_PYTHON, pbDataIn, cbDataIn);
    }
    LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_EXITCLIENT, NULL, 0);
    // wait for child process termination
    WaitForSingleObject(ctx->ChildProcessInfo.hProcess, INFINITE);
    while(ctx->hThreadReaderStdOut || ctx->hThreadReaderStdErr || ctx->hThreadReaderMem || ctx->hThreadChildTerminator) {
        SwitchToThread();
    }
    // read child process stdout/stderr data
    result =
        ppbDataOut && pcbDataOut &&
        LeechAgent_ProcParent_GetStdOutErrText(ctx, NULL, 0, pcbDataOut) &&
        (*ppbDataOut = LocalAlloc(0, *pcbDataOut)) &&
        LeechAgent_ProcParent_GetStdOutErrText(ctx, *ppbDataOut, *pcbDataOut, pcbDataOut);
    if(!result) {
        fprintf(stderr, "LeechAgent: FAIL: LeechAgent_ProcParent_GetStdOutErrText()\n");
    }
    if(!result && ppbDataOut && *ppbDataOut) { LocalFree(*ppbDataOut); }
    LeechAgent_ProcParent_Close(ctx);
    return result;
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
    result =
        ppbDataOut && pcbDataOut&&
        LeechAgent_ProcParent_GetStdOutErrText(ctx, NULL, 0, pcbDataOut) &&
        (*ppbDataOut = LocalAlloc(0, *pcbDataOut)) &&
        LeechAgent_ProcParent_GetStdOutErrText(ctx, *ppbDataOut, *pcbDataOut, pcbDataOut);
    // cleanup and return
    if(!result && ppbDataOut && *ppbDataOut) { LocalFree(*ppbDataOut); }
    LeechAgent_ProcParent_Close(ctx);
    return result;
}
