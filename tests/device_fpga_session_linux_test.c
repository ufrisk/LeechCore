#include "../leechcore/device_fpga_session.h"

#include <stdio.h>

#define TEST_FT_TIMEOUT_STATUS 19

static int g_cFailures;

#define ASSERT_TRUE(value) \
    do { \
        if(!(value)) { \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #value); \
            g_cFailures++; \
        } \
    } while(0)

#define ASSERT_EQ(actual, expected) \
    do { \
        unsigned long long _actual = (unsigned long long)(actual); \
        unsigned long long _expected = (unsigned long long)(expected); \
        if(_actual != _expected) { \
            printf( \
                "FAIL %s:%d: %s=%llu expected %llu\n", \
                __FILE__, __LINE__, #actual, _actual, _expected); \
            g_cFailures++; \
        } \
    } while(0)

typedef struct tdWAIT_SCRIPT {
    ULONG pStatus[8];
    ULONG pTransferred[8];
    BOOL pfWaitArguments[8];
    DWORD cResults;
    DWORD iResult;
    DWORD cGetCalls;
    DWORD cSleepCalls;
    DWORD dwAdvanceOnBlockingMs;
    QWORD qwNow;
} WAIT_SCRIPT, *PWAIT_SCRIPT;

static ULONG WINAPI ScriptedGetOverlappedResult(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _Out_ PULONG pulLengthTransferred,
    _In_ BOOL fWait
)
{
    PWAIT_SCRIPT pScript = (PWAIT_SCRIPT)hFTDI;
    DWORD iResult = pScript->iResult;
    UNREFERENCED_PARAMETER(pOverlapped);
    if(pScript->cGetCalls < 8) {
        pScript->pfWaitArguments[pScript->cGetCalls] = fWait;
    }
    pScript->cGetCalls++;
    if(fWait) {
        pScript->qwNow += pScript->dwAdvanceOnBlockingMs;
    }
    if(iResult >= pScript->cResults) {
        iResult = pScript->cResults - 1;
    } else {
        pScript->iResult++;
    }
    *pulLengthTransferred = pScript->pTransferred[iResult];
    return pScript->pStatus[iResult];
}

static QWORD ScriptedTick(_In_ PVOID pvContext)
{
    return ((PWAIT_SCRIPT)pvContext)->qwNow;
}

static VOID ScriptedSleep(
    _In_ PVOID pvContext,
    _In_ DWORD dwMilliseconds
)
{
    PWAIT_SCRIPT pScript = (PWAIT_SCRIPT)pvContext;
    pScript->cSleepCalls++;
    pScript->qwNow += dwMilliseconds;
}

static DEVICE_FPGA_SESSION_WAIT_RESULT RunWait(
    _Inout_ PWAIT_SCRIPT pScript,
    _In_ BOOL fUseEventWait,
    _In_ DWORD dwTimeoutMs
)
{
    BYTE pbOverlapped[64] = { 0 };
    return DeviceFPGA_Session_WaitOverlapped(
        pScript,
        (LPOVERLAPPED)pbOverlapped,
        ScriptedGetOverlappedResult,
        fUseEventWait,
        dwTimeoutMs,
        1,
        pScript,
        ScriptedTick,
        ScriptedSleep);
}

static VOID TestWaitUsesBoundedBlockingDriverCall(VOID)
{
    WAIT_SCRIPT Script = {
        .pStatus = { DEVICE_FPGA_SESSION_FT_OK },
        .pTransferred = { 0x1234 },
        .cResults = 1
    };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = RunWait(&Script, TRUE, 1000);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_OK);
    ASSERT_EQ(Result.cbTransferred, 0x1234);
    ASSERT_EQ(Script.cGetCalls, 1);
    ASSERT_EQ(Script.cSleepCalls, 0);
    ASSERT_TRUE(Script.pfWaitArguments[0]);
}

static VOID TestBlockingIncompleteFallsBackToDeadlinePolling(VOID)
{
    WAIT_SCRIPT Script = {
        .pStatus = {
            DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE,
            DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE,
            DEVICE_FPGA_SESSION_FT_OK
        },
        .pTransferred = { 0, 0, 0x1234 },
        .cResults = 3
    };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = RunWait(&Script, TRUE, 1000);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.cbTransferred, 0x1234);
    ASSERT_EQ(Script.cGetCalls, 3);
    ASSERT_EQ(Script.cSleepCalls, 1);
    ASSERT_EQ(Script.qwNow, 1);
    ASSERT_TRUE(Script.pfWaitArguments[0]);
    ASSERT_TRUE(!Script.pfWaitArguments[1]);
    ASSERT_TRUE(!Script.pfWaitArguments[2]);
}

static VOID TestBlockingTimeoutMapsToTimedOut(VOID)
{
    WAIT_SCRIPT Script = {
        .pStatus = { TEST_FT_TIMEOUT_STATUS },
        .cResults = 1
    };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = RunWait(&Script, TRUE, 1000);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_TIMED_OUT);
    ASSERT_EQ(Result.status, TEST_FT_TIMEOUT_STATUS);
    ASSERT_EQ(Result.cbTransferred, 0);
    ASSERT_EQ(Script.cGetCalls, 1);
    ASSERT_EQ(Script.cSleepCalls, 0);
    ASSERT_TRUE(Script.pfWaitArguments[0]);
}

static VOID TestBlockingIncompleteKeepsOriginalDeadline(VOID)
{
    WAIT_SCRIPT Script = {
        .pStatus = {
            DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE,
            DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE
        },
        .cResults = 2,
        .dwAdvanceOnBlockingMs = 1000
    };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = RunWait(&Script, TRUE, 1000);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_TIMED_OUT);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE);
    ASSERT_EQ(Script.cGetCalls, 2);
    ASSERT_EQ(Script.cSleepCalls, 0);
    ASSERT_EQ(Script.qwNow, 1000);
    ASSERT_TRUE(Script.pfWaitArguments[0]);
    ASSERT_TRUE(!Script.pfWaitArguments[1]);
}

static VOID TestExplicitPollingStaysNonblocking(VOID)
{
    WAIT_SCRIPT Script = {
        .pStatus = {
            DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE,
            DEVICE_FPGA_SESSION_FT_OK
        },
        .pTransferred = { 0, 0x1234 },
        .cResults = 2
    };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = RunWait(&Script, FALSE, 1000);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.cbTransferred, 0x1234);
    ASSERT_EQ(Script.cGetCalls, 2);
    ASSERT_EQ(Script.cSleepCalls, 1);
    ASSERT_TRUE(!Script.pfWaitArguments[0]);
    ASSERT_TRUE(!Script.pfWaitArguments[1]);
}

int main(void)
{
    TestWaitUsesBoundedBlockingDriverCall();
    TestBlockingIncompleteFallsBackToDeadlinePolling();
    TestBlockingTimeoutMapsToTimedOut();
    TestBlockingIncompleteKeepsOriginalDeadline();
    TestExplicitPollingStaysNonblocking();
    if(g_cFailures) {
        printf("%d Linux wait assertion(s) failed.\n", g_cFailures);
        return 1;
    }
    printf("PASS: 5 Linux FPGA session wait cases.\n");
    return 0;
}
