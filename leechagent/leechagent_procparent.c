//	leechagent_procparent.c : Implementation of parent process functionality.
//                 Child processes host execution environments such as the
//                 Python environment which allows for execution of scripts.
//                 The Parent process controls the child processes.
//
// (c) Ulf Frisk, 2020-2021
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
    QWORD qwChildKillAfterTickCount64;
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
VOID LeechAgent_ProcParent_CloseInternal(_In_ PPROCPARENT_CONTEXT ctx)
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
        if(!Util_GetBytesPipe(ctx->hPipeMem_Rd, (PBYTE)&Hdr, sizeof(LEECHRPC_MSG_HDR))) { goto fail; }
        if((Hdr.dwMagic != LEECHRPC_MSGMAGIC) || (Hdr.cbMsg > 0x04000000)) { goto fail; }
        pMsgReq = (PLEECHRPC_MSG_HDR)LocalAlloc(0, Hdr.cbMsg);
        if(!pMsgReq) { goto fail; }
        memcpy(pMsgReq, &Hdr, sizeof(LEECHRPC_MSG_HDR));
        // 2: read resulting contents : data
        if(pMsgReq->cbMsg > sizeof(LEECHRPC_MSG_HDR)) {
            if(!Util_GetBytesPipe(ctx->hPipeMem_Rd, ((PBYTE)pMsgReq) + sizeof(LEECHRPC_MSG_HDR), pMsgReq->cbMsg - sizeof(LEECHRPC_MSG_HDR))) { goto fail; }
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
            if(!WriteFile(ctx->hPipeMem_Wr, (PVOID)&Hdr, Hdr.cbMsg, &cbWrite, NULL)) { goto fail; }
        } else {
            if(!WriteFile(ctx->hPipeMem_Wr, (PVOID)pMsgRsp, pMsgRsp->cbMsg, &cbWrite, NULL)) { goto fail; }
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
BOOL LeechAgent_ProcParent_ExecPy(_In_ HANDLE hLC, _In_ DWORD dwTimeout, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_opt_ PBYTE* ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
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
    if(!CreatePipe(&ctx->hPipeStdOut_Rd, &ctx->ChildPipe.hPipeStdOut_Wr, &SecAttr, 0x01000000) || !CreatePipe(&ctx->hPipeStdErr_Rd, &ctx->ChildPipe.hPipeStdErr_Wr, &SecAttr, 0x01000000)) {
        fprintf(stderr, "LeechAgent: FAIL: CreatePipe() STD\n");
        goto fail;
    }
    // set up command pipe
    if(!CreatePipe(&ctx->hPipeCmd_Rd, &ctx->ChildPipe.hPipeCmd_Wr, &SecAttr, 0x02000000) || !CreatePipe(&ctx->ChildPipe.hPipeCmd_Rd, &ctx->hPipeCmd_Wr, &SecAttr, 0x02000000)) {
        fprintf(stderr, "LeechAgent: FAIL: CreatePipe() CMD\n");
        goto fail;
    }
    // set up memory read/write pipe
    if(!CreatePipe(&ctx->hPipeMem_Rd, &ctx->ChildPipe.hPipeMem_Wr, &SecAttr, 0x04000000) || !CreatePipe(&ctx->ChildPipe.hPipeMem_Rd, &ctx->hPipeMem_Wr, &SecAttr, 0x04000000)) {
        fprintf(stderr, "LeechAgent: FAIL: CreatePipe() MEM\n");
        goto fail;
    }
    // create process
    _snwprintf_s(
        wszProcessArgs,
        MAX_PATH - 1,
        _TRUNCATE,
        L"-child -child %llu %llu %llu %llu %llu",
        (QWORD)ctx->ChildPipe.hPipeCmd_Rd,
        (QWORD)ctx->ChildPipe.hPipeCmd_Wr,
        (QWORD)ctx->ChildPipe.hPipeMem_Rd,
        (QWORD)ctx->ChildPipe.hPipeMem_Wr,
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
    ctx->qwChildKillAfterTickCount64 = GetTickCount64();
    ctx->qwChildKillAfterTickCount64 += (dwTimeout && (dwTimeout < LEECHAGENT_CHILDPROCESS_TIMEOUT_MAX_MS)) ? dwTimeout : LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS;  // kill child after time
    ctx->hThreadChildTerminator = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ChildTerminatorThread, (LPVOID)ctx, 0, NULL);
    // send commands to child process to initialize MemProcFS, Python and execute code.
    fChildInitVmmPython =
        LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_INIT_VMM, NULL, 0, NULL, NULL) &&
        LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_INIT_PYTHON, NULL, 0, NULL, NULL);
    if(fChildInitVmmPython) {
        LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_EXEC_PYTHON, pbDataIn, cbDataIn, NULL, NULL);
    }
    LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_EXITCLIENT, NULL, 0, NULL, NULL);
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
    LeechAgent_ProcParent_CloseInternal(ctx);
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
    LeechAgent_ProcParent_CloseInternal(ctx);
    return result;
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
            Sleep(100);
        }
    }
    // cleanup and return
    LeechAgent_ProcParent_CloseInternal(ctx);
}

_Success_(return)
BOOL LeechAgent_ProcParent_VfsEnsure(_In_ HANDLE hLC, _Inout_ PHANDLE phPP)
{
    PPROCPARENT_CONTEXT ctx = (PPROCPARENT_CONTEXT)*phPP;
    WCHAR wszProcessPathName[MAX_PATH] = { 0 };
    WCHAR wszProcessArgs[MAX_PATH] = { 0 };
    STARTUPINFOW StartupInfo = { 0 };
    SECURITY_ATTRIBUTES SecAttr = { 0 };
    DWORD dwExitCode;
    BOOL result;
    // 1: check pre-existing context if it's still good
    if(ctx) {
        if(GetExitCodeProcess(ctx->ChildProcessInfo.hProcess, &dwExitCode) && (STILL_ACTIVE != dwExitCode)) {
            *phPP = NULL;
            LeechAgent_ProcParent_Close((HANDLE)ctx);
            ctx = NULL;
        } else {
            ctx->qwChildKillAfterTickCount64 = GetTickCount64() + LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS;
        }
    }
    // 2: setup new context (if required)
    if(!ctx) {
        if(!(ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(PROCPARENT_CONTEXT)))) {
            fprintf(stderr, "LeechAgent: FAIL: LocalAlloc()\n");
            goto fail;
        }
        // set up redirect pipes for child stdout/stderr 
        SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        SecAttr.bInheritHandle = TRUE;
        SecAttr.lpSecurityDescriptor = NULL;
        // set up command pipe
        if(!CreatePipe(&ctx->hPipeCmd_Rd, &ctx->ChildPipe.hPipeCmd_Wr, &SecAttr, 0x02000000) || !CreatePipe(&ctx->ChildPipe.hPipeCmd_Rd, &ctx->hPipeCmd_Wr, &SecAttr, 0x02000000)) {
            fprintf(stderr, "LeechAgent: FAIL: CreatePipe() CMD\n");
            goto fail;
        }
        // set up memory read/write pipe
        if(!CreatePipe(&ctx->hPipeMem_Rd, &ctx->ChildPipe.hPipeMem_Wr, &SecAttr, 0x04000000) || !CreatePipe(&ctx->ChildPipe.hPipeMem_Rd, &ctx->hPipeMem_Wr, &SecAttr, 0x04000000)) {
            fprintf(stderr, "LeechAgent: FAIL: CreatePipe() MEM\n");
            goto fail;
        }
        // create process
        _snwprintf_s(
            wszProcessArgs,
            MAX_PATH - 1,
            _TRUNCATE,
            L"-child -child %llu %llu %llu %llu %llu",
            (QWORD)ctx->ChildPipe.hPipeCmd_Rd,
            (QWORD)ctx->ChildPipe.hPipeCmd_Wr,
            (QWORD)ctx->ChildPipe.hPipeMem_Rd,
            (QWORD)ctx->ChildPipe.hPipeMem_Wr,
            (QWORD)hLC);
        GetModuleFileNameW(NULL, wszProcessPathName, MAX_PATH - 1);
        StartupInfo.cb = sizeof(STARTUPINFOW);
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
        CloseHandle(ctx->ChildPipe.hPipeCmd_Rd); ctx->ChildPipe.hPipeCmd_Rd = NULL;
        CloseHandle(ctx->ChildPipe.hPipeCmd_Wr); ctx->ChildPipe.hPipeCmd_Wr = NULL;
        CloseHandle(ctx->ChildPipe.hPipeMem_Rd); ctx->ChildPipe.hPipeMem_Rd = NULL;
        CloseHandle(ctx->ChildPipe.hPipeMem_Wr); ctx->ChildPipe.hPipeMem_Wr = NULL;
        ctx->hThreadReaderMem = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ReaderMem, (LPVOID)ctx, 0, NULL);
        if(!ctx->hThreadReaderMem) {
            fprintf(stderr, "LeechAgent: FAIL: CreateThread()\n");
            goto fail;
        }
        // set up child process auto-terminator watchdog
        // NB! no 'goto fail' must be made after this
        ctx->qwChildKillAfterTickCount64 = GetTickCount64() + LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS;  // kill child after time
        ctx->hThreadChildTerminator = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechAgent_ProcParent_ChildTerminatorThread, (LPVOID)ctx, 0, NULL);
        // send commands to child process to initialize MemProcFS, Python and execute code.
        if(!LeechAgent_ProcParent_ChildSendCmd(ctx, LEECHAGENT_PROC_CMD_INIT_VMM, NULL, 0, NULL, NULL)) {
            fprintf(stderr, "LeechAgent: FAIL: ChildSendCmd_VmmInit()\n");
            goto fail;
        }
        *phPP = (HANDLE)ctx;
    }
    return TRUE;
fail:
    LeechAgent_ProcParent_Close((HANDLE)ctx);
    return FALSE;
}

_Success_(return)
BOOL LeechAgent_ProcParent_VfsCMD(_In_ HANDLE hLC, _Inout_ PHANDLE phPP, _In_ DWORD dwCMD, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_opt_ PBYTE* ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    if(!LeechAgent_ProcParent_VfsEnsure(hLC, phPP)) { return FALSE; }
    return LeechAgent_ProcParent_ChildSendCmd((PPROCPARENT_CONTEXT)*phPP, dwCMD, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
}
