#include <stdio.h>
#include <string.h>

#include "../leechcore/device_fpga_session.h"

static int g_cFailures = 0;

#define ASSERT_TRUE(value) \
    do { \
        if(!(value)) { \
            printf("FAIL %s:%d: expected true\n", __FILE__, __LINE__); \
            g_cFailures++; \
        } \
    } while(0)

#define ASSERT_FALSE(value) \
    do { \
        if(value) { \
            printf("FAIL %s:%d: expected false\n", __FILE__, __LINE__); \
            g_cFailures++; \
        } \
    } while(0)

#define ASSERT_EQ(actual, expected) \
    do { \
        if((actual) != (expected)) { \
            printf("FAIL %s:%d: expected %lu, got %lu\n", \
                __FILE__, __LINE__, \
                (unsigned long)(expected), (unsigned long)(actual)); \
            g_cFailures++; \
        } \
    } while(0)

static VOID AssertBytes(
    _In_reads_(cbActual) PBYTE pbActual,
    _In_reads_(cbActual) PBYTE pbExpected,
    _In_ DWORD cbActual,
    _In_ DWORD line
)
{
    DWORD i;
    if(!memcmp(pbActual, pbExpected, cbActual)) { return; }
    printf("FAIL %s:%lu: byte mismatch:", __FILE__, (unsigned long)line);
    for(i = 0; i < cbActual; i++) {
        printf(" %02x/%02x", pbActual[i], pbExpected[i]);
    }
    printf("\n");
    g_cFailures++;
}

#define ASSERT_BYTES(actual, expected, count) \
    AssertBytes((actual), (expected), (count), __LINE__)

static VOID TestCompleteAlignedReply(VOID)
{
    BYTE pbReply[32] = {
        0x33, 0x00, 0x00, 0xe0,
        0x00, 0x08, 0x04, 0x13,
        0x00, 0x0a, 0x04, 0x00
    };
    BYTE pbActual[3] = { 0xaa, 0xbb, 0xcc };
    BYTE pbExpected[3] = { 0x04, 0x13, 0x04 };
    ASSERT_TRUE(DeviceFPGA_Session_ParseConfigReply(
        pbReply, sizeof(pbReply), 0x0008, pbActual, sizeof(pbActual), 0x0003));
    ASSERT_BYTES(pbActual, pbExpected, sizeof(pbActual));
}

static VOID TestCompleteUnalignedReply(VOID)
{
    BYTE pbReply[32] = {
        0x03, 0x00, 0x00, 0xe0,
        0x00, 0x08, 0x04, 0x13
    };
    BYTE pbActual[1] = { 0xaa };
    BYTE pbExpected[1] = { 0x13 };
    ASSERT_TRUE(DeviceFPGA_Session_ParseConfigReply(
        pbReply, sizeof(pbReply), 0x0009, pbActual, sizeof(pbActual), 0x0003));
    ASSERT_BYTES(pbActual, pbExpected, sizeof(pbActual));
}

static VOID TestCompleteZeroValuedReply(VOID)
{
    BYTE pbReply[32] = {
        0x33, 0x00, 0x00, 0xe0,
        0x00, 0x08, 0x00, 0x00,
        0x00, 0x0a, 0x00, 0x00
    };
    BYTE pbActual[3] = { 0xaa, 0xbb, 0xcc };
    BYTE pbExpected[3] = { 0x00, 0x00, 0x00 };
    ASSERT_TRUE(DeviceFPGA_Session_ParseConfigReply(
        pbReply, sizeof(pbReply), 0x0008, pbActual, sizeof(pbActual), 0x0003));
    ASSERT_BYTES(pbActual, pbExpected, sizeof(pbActual));
}

static VOID TestEmptyReplyFailsAndClearsOutput(VOID)
{
    BYTE pbActual[3] = { 0xaa, 0xbb, 0xcc };
    BYTE pbExpected[3] = { 0x00, 0x00, 0x00 };
    ASSERT_FALSE(DeviceFPGA_Session_ParseConfigReply(
        NULL, 0, 0x0008, pbActual, sizeof(pbActual), 0x0003));
    ASSERT_BYTES(pbActual, pbExpected, sizeof(pbActual));
}

static VOID TestPartialReplyFailsAndClearsOutput(VOID)
{
    BYTE pbReply[32] = {
        0x03, 0x00, 0x00, 0xe0,
        0x00, 0x08, 0x04, 0x13
    };
    BYTE pbActual[3] = { 0xaa, 0xbb, 0xcc };
    BYTE pbExpected[3] = { 0x00, 0x00, 0x00 };
    ASSERT_FALSE(DeviceFPGA_Session_ParseConfigReply(
        pbReply, sizeof(pbReply), 0x0008, pbActual, sizeof(pbActual), 0x0003));
    ASSERT_BYTES(pbActual, pbExpected, sizeof(pbActual));
}

static VOID TestWrongSourceReplyFailsAndClearsOutput(VOID)
{
    BYTE pbReply[32] = {
        0x11, 0x00, 0x00, 0xe0,
        0x00, 0x08, 0x04, 0x13,
        0x00, 0x0a, 0x04, 0x00
    };
    BYTE pbActual[3] = { 0xaa, 0xbb, 0xcc };
    BYTE pbExpected[3] = { 0x00, 0x00, 0x00 };
    ASSERT_FALSE(DeviceFPGA_Session_ParseConfigReply(
        pbReply, sizeof(pbReply), 0x0008, pbActual, sizeof(pbActual), 0x0003));
    ASSERT_BYTES(pbActual, pbExpected, sizeof(pbActual));
}

typedef struct tdCONFIG_READ_SCRIPT {
    DWORD cCalls;
    DWORD cFailures;
    BYTE pbIdentity[3];
    BOOL fUnexpectedArguments;
} CONFIG_READ_SCRIPT, *PCONFIG_READ_SCRIPT;

static BOOL ScriptedConfigRead(
    _In_ PVOID pvContext,
    _In_ WORD wBaseAddr,
    _Out_writes_(cb) PBYTE pb,
    _In_ WORD cb,
    _In_ WORD flags
)
{
    PCONFIG_READ_SCRIPT pScript = (PCONFIG_READ_SCRIPT)pvContext;
    pScript->cCalls++;
    if((wBaseAddr != 0x0008) || (cb != 3) || (flags != 0x0003)) {
        pScript->fUnexpectedArguments = TRUE;
        return FALSE;
    }
    if(pScript->cCalls <= pScript->cFailures) {
        ZeroMemory(pb, cb);
        return FALSE;
    }
    memcpy(pb, pScript->pbIdentity, cb);
    return TRUE;
}

static VOID AssertIdentity(
    _In_ PDEVICE_FPGA_IDENTITY pIdentity,
    _In_ WORD wVersionMajor,
    _In_ WORD wVersionMinor,
    _In_ WORD wFpgaID,
    _In_ DWORD line
)
{
    if((pIdentity->wVersionMajor == wVersionMajor) &&
       (pIdentity->wVersionMinor == wVersionMinor) &&
       (pIdentity->wFpgaID == wFpgaID)) {
        return;
    }
    printf(
        "FAIL %s:%lu: expected identity %u.%u id %u, got %u.%u id %u\n",
        __FILE__,
        (unsigned long)line,
        wVersionMajor,
        wVersionMinor,
        wFpgaID,
        pIdentity->wVersionMajor,
        pIdentity->wVersionMinor,
        pIdentity->wFpgaID);
    g_cFailures++;
}

#define ASSERT_IDENTITY(identity, major, minor, id) \
    AssertIdentity(&(identity), (major), (minor), (id), __LINE__)

static VOID TestV4IdentityRetriesAndPublishesCompleteReply(VOID)
{
    CONFIG_READ_SCRIPT Script = { 0, 1, { 4, 19, 4 }, FALSE };
    DEVICE_FPGA_IDENTITY Identity = { 0xaa, 0xbb, 0xcc };
    ASSERT_TRUE(DeviceFPGA_Session_ReadV4Identity(
        &Script, ScriptedConfigRead, 0x0003, &Identity));
    ASSERT_FALSE(Script.fUnexpectedArguments);
    ASSERT_EQ(Script.cCalls, 2);
    ASSERT_IDENTITY(Identity, 4, 19, 4);
}

static VOID TestV4IdentityFailureIsBoundedAndDoesNotPublish(VOID)
{
    CONFIG_READ_SCRIPT Script = { 0, 10, { 4, 19, 4 }, FALSE };
    DEVICE_FPGA_IDENTITY Identity = { 0xaa, 0xbb, 0xcc };
    ASSERT_FALSE(DeviceFPGA_Session_ReadV4Identity(
        &Script, ScriptedConfigRead, 0x0003, &Identity));
    ASSERT_FALSE(Script.fUnexpectedArguments);
    ASSERT_EQ(Script.cCalls, 5);
    ASSERT_IDENTITY(Identity, 0xaa, 0xbb, 0xcc);
}

static VOID TestV4IdentityAcceptsExplicitZeroFpgaId(VOID)
{
    CONFIG_READ_SCRIPT Script = { 0, 0, { 4, 19, 0 }, FALSE };
    DEVICE_FPGA_IDENTITY Identity = { 0xaa, 0xbb, 0xcc };
    ASSERT_TRUE(DeviceFPGA_Session_ReadV4Identity(
        &Script, ScriptedConfigRead, 0x0003, &Identity));
    ASSERT_IDENTITY(Identity, 4, 19, 0);
}

static VOID TestV4IdentityRejectsLegacyMajorWithoutPublishing(VOID)
{
    CONFIG_READ_SCRIPT Script = { 0, 0, { 3, 7, 4 }, FALSE };
    DEVICE_FPGA_IDENTITY Identity = { 0xaa, 0xbb, 0xcc };
    ASSERT_FALSE(DeviceFPGA_Session_ReadV4Identity(
        &Script, ScriptedConfigRead, 0x0003, &Identity));
    ASSERT_EQ(Script.cCalls, 1);
    ASSERT_IDENTITY(Identity, 0xaa, 0xbb, 0xcc);
}

static VOID TestV3IdentityRequiresEveryIdentityCommand(VOID)
{
    BYTE pbReply[32] = {
        0x33, 0x00, 0x00, 0xe0,
        0x04, 0x00, 0x00, 0x01,
        0x13, 0x00, 0x00, 0x05
    };
    DEVICE_FPGA_IDENTITY Identity = { 0xaa, 0xbb, 0xcc };
    WORD wPcieDeviceId = 0xdddd;
    ASSERT_FALSE(DeviceFPGA_Session_ParseV3Identity(
        pbReply, sizeof(pbReply), &Identity, &wPcieDeviceId));
    ASSERT_IDENTITY(Identity, 0xaa, 0xbb, 0xcc);
    ASSERT_EQ(wPcieDeviceId, 0xdddd);
}

static VOID TestV3IdentityPublishesCompleteReply(VOID)
{
    BYTE pbReply[32] = {
        0x33, 0x03, 0x00, 0xe0,
        0x04, 0x00, 0x00, 0x01,
        0x13, 0x00, 0x00, 0x05,
        0x04, 0x00, 0x00, 0x03
    };
    DEVICE_FPGA_IDENTITY Identity = { 0xaa, 0xbb, 0xcc };
    WORD wPcieDeviceId = 0xdddd;
    ASSERT_TRUE(DeviceFPGA_Session_ParseV3Identity(
        pbReply, sizeof(pbReply), &Identity, &wPcieDeviceId));
    ASSERT_IDENTITY(Identity, 4, 19, 4);
    ASSERT_EQ(wPcieDeviceId, 0);
}

static VOID TestV3IdentityAcceptsExplicitZeroFpgaId(VOID)
{
    BYTE pbReply[32] = {
        0x33, 0x03, 0x00, 0xe0,
        0x04, 0x00, 0x00, 0x01,
        0x13, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x00, 0x03
    };
    DEVICE_FPGA_IDENTITY Identity = { 0xaa, 0xbb, 0xcc };
    WORD wPcieDeviceId = 0xdddd;
    ASSERT_TRUE(DeviceFPGA_Session_ParseV3Identity(
        pbReply, sizeof(pbReply), &Identity, &wPcieDeviceId));
    ASSERT_IDENTITY(Identity, 4, 19, 0);
}

typedef struct tdWAIT_SCRIPT {
    ULONG pStatus[8];
    ULONG pTransferred[8];
    DWORD cResults;
    DWORD iResult;
    DWORD cGetCalls;
    DWORD cSleepCalls;
    QWORD qwNow;
    BOOL fWaitArgument;
} WAIT_SCRIPT, *PWAIT_SCRIPT;

static ULONG WINAPI ScriptedWaitGetOverlappedResult(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _Out_ PULONG pulLengthTransferred,
    _In_ BOOL fWait
)
{
    PWAIT_SCRIPT pScript = (PWAIT_SCRIPT)hFTDI;
    DWORD iResult;
    UNREFERENCED_PARAMETER(pOverlapped);
    pScript->cGetCalls++;
    pScript->fWaitArgument = fWait;
    iResult = pScript->iResult;
    if(iResult >= pScript->cResults) {
        iResult = pScript->cResults - 1;
    } else {
        pScript->iResult++;
    }
    *pulLengthTransferred = pScript->pTransferred[iResult];
    return pScript->pStatus[iResult];
}

static QWORD ScriptedWaitTick(_In_ PVOID pvContext)
{
    return ((PWAIT_SCRIPT)pvContext)->qwNow;
}

static VOID ScriptedWaitSleep(_In_ PVOID pvContext, _In_ DWORD dwMilliseconds)
{
    PWAIT_SCRIPT pScript = (PWAIT_SCRIPT)pvContext;
    pScript->cSleepCalls++;
    pScript->qwNow += dwMilliseconds;
}

static VOID TestWaitCompletesWithoutBlockingDriverCall(VOID)
{
    WAIT_SCRIPT Script = {
        { DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE, DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE, DEVICE_FPGA_SESSION_FT_OK },
        { 0, 0, 0x1234 },
        3,
        0,
        0,
        0,
        0,
        FALSE
    };
    OVERLAPPED Overlapped = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = DeviceFPGA_Session_WaitOverlapped(
        &Script,
        &Overlapped,
        ScriptedWaitGetOverlappedResult,
        1000,
        1,
        &Script,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_OK);
    ASSERT_EQ(Result.cbTransferred, 0x1234);
    ASSERT_EQ(Script.cGetCalls, 3);
    ASSERT_EQ(Script.cSleepCalls, 2);
    ASSERT_FALSE(Script.fWaitArgument);
}

static VOID TestWaitPendingForeverTimesOutAtDeadline(VOID)
{
    WAIT_SCRIPT Script = {
        { DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE },
        { 0 },
        1,
        0,
        0,
        0,
        0,
        FALSE
    };
    OVERLAPPED Overlapped = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = DeviceFPGA_Session_WaitOverlapped(
        &Script,
        &Overlapped,
        ScriptedWaitGetOverlappedResult,
        5,
        1,
        &Script,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_TIMED_OUT);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE);
    ASSERT_EQ(Result.cbTransferred, 0);
    ASSERT_EQ(Script.qwNow, 5);
    ASSERT_EQ(Script.cGetCalls, 6);
    ASSERT_EQ(Script.cSleepCalls, 5);
    ASSERT_FALSE(Script.fWaitArgument);
}

static VOID TestWaitReturnsDriverErrorWithoutRetry(VOID)
{
    WAIT_SCRIPT Script = {
        { 0x20 },
        { 0x9999 },
        1,
        0,
        0,
        0,
        0,
        FALSE
    };
    OVERLAPPED Overlapped = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = DeviceFPGA_Session_WaitOverlapped(
        &Script,
        &Overlapped,
        ScriptedWaitGetOverlappedResult,
        1000,
        1,
        &Script,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_DRIVER_ERROR);
    ASSERT_EQ(Result.status, 0x20);
    ASSERT_EQ(Result.cbTransferred, 0);
    ASSERT_EQ(Script.cGetCalls, 1);
    ASSERT_EQ(Script.cSleepCalls, 0);
    ASSERT_FALSE(Script.fWaitArgument);
}

typedef struct tdCLOSE_SCRIPT {
    BYTE pbEvents[4];
    DWORD cEvents;
    DWORD cGetCalls;
    DWORD cReleaseCalls;
    DWORD cSleepCalls;
    QWORD qwNow;
    ULONG ulRxAbortStatus;
    ULONG ulTxAbortStatus;
    ULONG ulGetStatus;
    ULONG ulReleaseStatus;
    BOOL fRxAborted;
    BOOL fTxAborted;
    BOOL fWaitedBeforeAbort;
    BOOL fSawWaitArgument;
} CLOSE_SCRIPT, *PCLOSE_SCRIPT;

#define EVENT_GET_OVERLAPPED    0xf1
#define EVENT_RELEASE           0xf2

static ULONG WINAPI ScriptedAbortPipe(_In_ HANDLE hFTDI, _In_ UCHAR ucPipeID)
{
    PCLOSE_SCRIPT pScript = (PCLOSE_SCRIPT)hFTDI;
    if(pScript->cEvents < sizeof(pScript->pbEvents)) {
        pScript->pbEvents[pScript->cEvents++] = ucPipeID;
    }
    if(ucPipeID == 0x82) { pScript->fRxAborted = TRUE; }
    if(ucPipeID == 0x02) { pScript->fTxAborted = TRUE; }
    return (ucPipeID == 0x82) ?
        pScript->ulRxAbortStatus :
        pScript->ulTxAbortStatus;
}

static ULONG WINAPI ScriptedGetOverlappedResult(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _Out_ PULONG pulLengthTransferred,
    _In_ BOOL fWait
)
{
    PCLOSE_SCRIPT pScript = (PCLOSE_SCRIPT)hFTDI;
    UNREFERENCED_PARAMETER(pOverlapped);
    *pulLengthTransferred = 0;
    pScript->cGetCalls++;
    pScript->fWaitedBeforeAbort = !pScript->fRxAborted;
    pScript->fSawWaitArgument |= fWait;
    if(pScript->cEvents < sizeof(pScript->pbEvents)) {
        pScript->pbEvents[pScript->cEvents++] = EVENT_GET_OVERLAPPED;
    }
    return pScript->fWaitedBeforeAbort ? 1 : pScript->ulGetStatus;
}

static ULONG WINAPI ScriptedReleaseOverlapped(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped
)
{
    PCLOSE_SCRIPT pScript = (PCLOSE_SCRIPT)hFTDI;
    UNREFERENCED_PARAMETER(pOverlapped);
    pScript->cReleaseCalls++;
    if(pScript->cEvents < sizeof(pScript->pbEvents)) {
        pScript->pbEvents[pScript->cEvents++] = EVENT_RELEASE;
    }
    return pScript->ulReleaseStatus;
}

static QWORD ScriptedCloseTick(_In_ PVOID pvContext)
{
    return ((PCLOSE_SCRIPT)pvContext)->qwNow;
}

static VOID ScriptedCloseSleep(_In_ PVOID pvContext, _In_ DWORD dwMilliseconds)
{
    PCLOSE_SCRIPT pScript = (PCLOSE_SCRIPT)pvContext;
    pScript->cSleepCalls++;
    pScript->qwNow += dwMilliseconds;
}

static VOID TestCloseCancelsReadPipeBeforeWaiting(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BYTE pbExpected[] = { 0x82, EVENT_GET_OVERLAPPED, EVENT_RELEASE };
    ASSERT_TRUE(DeviceFPGA_Session_CloseOverlapped(
        &Script,
        &Overlapped,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep));
    ASSERT_FALSE(Script.fWaitedBeforeAbort);
    ASSERT_FALSE(Script.fSawWaitArgument);
    ASSERT_TRUE(Script.fRxAborted);
    ASSERT_FALSE(Script.fTxAborted);
    ASSERT_EQ(Script.cEvents, sizeof(pbExpected));
    ASSERT_BYTES(Script.pbEvents, pbExpected, sizeof(pbExpected));
}

static VOID TestClosePendingForeverIsBoundedAndStillReleases(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    Script.ulGetStatus = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    ASSERT_FALSE(DeviceFPGA_Session_CloseOverlapped(
        &Script,
        &Overlapped,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep));
    ASSERT_FALSE(Script.fSawWaitArgument);
    ASSERT_EQ(Script.qwNow, DEVICE_FPGA_SESSION_CANCEL_TIMEOUT_MS);
    ASSERT_EQ(Script.cGetCalls, DEVICE_FPGA_SESSION_CANCEL_TIMEOUT_MS + 1);
    ASSERT_EQ(Script.cReleaseCalls, 1);
}

static VOID TestCloseReportsAbortErrorAfterAttemptingCleanup(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    Script.ulRxAbortStatus = 1;
    ASSERT_FALSE(DeviceFPGA_Session_CloseOverlapped(
        &Script,
        &Overlapped,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep));
    ASSERT_TRUE(Script.fRxAborted);
    ASSERT_FALSE(Script.fTxAborted);
    ASSERT_EQ(Script.cGetCalls, 1);
    ASSERT_EQ(Script.cReleaseCalls, 1);
}

typedef struct tdPIPE_TIMEOUT_SCRIPT {
    BYTE pbPipe[2];
    ULONG pulTimeout[2];
    DWORD cCalls;
    ULONG ulRxStatus;
    ULONG ulTxStatus;
} PIPE_TIMEOUT_SCRIPT, *PPIPE_TIMEOUT_SCRIPT;

static ULONG WINAPI ScriptedSetPipeTimeout(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _In_ ULONG ulTimeoutInMs
)
{
    PPIPE_TIMEOUT_SCRIPT pScript = (PPIPE_TIMEOUT_SCRIPT)hFTDI;
    DWORD i = pScript->cCalls++;
    if(i < 2) {
        pScript->pbPipe[i] = ucPipeID;
        pScript->pulTimeout[i] = ulTimeoutInMs;
    }
    return (ucPipeID == 0x82) ? pScript->ulRxStatus : pScript->ulTxStatus;
}

static VOID TestConfigurePipeTimeoutsConfiguresBothDirections(VOID)
{
    PIPE_TIMEOUT_SCRIPT Script = { 0 };
    ASSERT_TRUE(DeviceFPGA_Session_ConfigurePipeTimeouts(
        &Script,
        DEVICE_FPGA_SESSION_WAIT_TIMEOUT_MS,
        ScriptedSetPipeTimeout));
    ASSERT_EQ(Script.cCalls, 2);
    ASSERT_EQ(Script.pbPipe[0], 0x82);
    ASSERT_EQ(Script.pbPipe[1], 0x02);
    ASSERT_EQ(Script.pulTimeout[0], DEVICE_FPGA_SESSION_WAIT_TIMEOUT_MS);
    ASSERT_EQ(Script.pulTimeout[1], DEVICE_FPGA_SESSION_WAIT_TIMEOUT_MS);
}

static VOID TestConfigurePipeTimeoutsReportsEitherFailure(VOID)
{
    PIPE_TIMEOUT_SCRIPT RxFailure = { { 0 }, { 0 }, 0, 1, 0 };
    PIPE_TIMEOUT_SCRIPT TxFailure = { { 0 }, { 0 }, 0, 0, 1 };
    ASSERT_FALSE(DeviceFPGA_Session_ConfigurePipeTimeouts(
        &RxFailure,
        DEVICE_FPGA_SESSION_WAIT_TIMEOUT_MS,
        ScriptedSetPipeTimeout));
    ASSERT_EQ(RxFailure.cCalls, 2);
    ASSERT_FALSE(DeviceFPGA_Session_ConfigurePipeTimeouts(
        &TxFailure,
        DEVICE_FPGA_SESSION_WAIT_TIMEOUT_MS,
        ScriptedSetPipeTimeout));
    ASSERT_EQ(TxFailure.cCalls, 2);
}

int main(void)
{
    TestCompleteAlignedReply();
    TestCompleteUnalignedReply();
    TestCompleteZeroValuedReply();
    TestEmptyReplyFailsAndClearsOutput();
    TestPartialReplyFailsAndClearsOutput();
    TestWrongSourceReplyFailsAndClearsOutput();
    TestV4IdentityRetriesAndPublishesCompleteReply();
    TestV4IdentityFailureIsBoundedAndDoesNotPublish();
    TestV4IdentityAcceptsExplicitZeroFpgaId();
    TestV4IdentityRejectsLegacyMajorWithoutPublishing();
    TestV3IdentityRequiresEveryIdentityCommand();
    TestV3IdentityPublishesCompleteReply();
    TestV3IdentityAcceptsExplicitZeroFpgaId();
    TestWaitCompletesWithoutBlockingDriverCall();
    TestWaitPendingForeverTimesOutAtDeadline();
    TestWaitReturnsDriverErrorWithoutRetry();
    TestCloseCancelsReadPipeBeforeWaiting();
    TestClosePendingForeverIsBoundedAndStillReleases();
    TestCloseReportsAbortErrorAfterAttemptingCleanup();
    TestConfigurePipeTimeoutsConfiguresBothDirections();
    TestConfigurePipeTimeoutsReportsEitherFailure();
    if(g_cFailures) {
        printf("%d test assertion(s) failed.\n", g_cFailures);
        return 1;
    }
    printf("PASS: 21 FPGA session protocol cases.\n");
    return 0;
}
