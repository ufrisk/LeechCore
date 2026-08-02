#include <stdio.h>
#include <string.h>

#include "../leechcore/device_fpga_session.h"

static int g_cFailures = 0;
static int g_cTests = 0;

#define RUN_TEST(test) \
    do { \
        (test)(); \
        g_cTests++; \
    } while(0)

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

static VOID TestTlpFrameIgnoresContinuationUntilFirst(VOID)
{
    DEVICE_FPGA_SESSION_TLP_FRAME_STATE State = { TRUE, FALSE, 0 };
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x00, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_IGNORE);
    ASSERT_FALSE(State.fInTlp);
    ASSERT_EQ(State.cdwTlp, 0);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x04, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_IGNORE);
    ASSERT_FALSE(State.fInTlp);
    ASSERT_EQ(State.cdwTlp, 0);
}

static VOID TestTlpFrameCompletesAfterExplicitFirst(VOID)
{
    DEVICE_FPGA_SESSION_TLP_FRAME_STATE State = { TRUE, FALSE, 0 };
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x08, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_APPEND);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x00, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_APPEND);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x04, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_COMPLETE);
    ASSERT_FALSE(State.fInTlp);
    ASSERT_EQ(State.cdwTlp, 3);
}

static VOID TestTlpFrameRestartsAtNewFirst(VOID)
{
    DEVICE_FPGA_SESSION_TLP_FRAME_STATE State = { TRUE, FALSE, 0 };
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x08, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_APPEND);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x00, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_APPEND);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x08, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_RESTART);
    ASSERT_TRUE(State.fInTlp);
    ASSERT_EQ(State.cdwTlp, 1);
}

static VOID TestTlpFrameRejectsShortAndOversizePackets(VOID)
{
    DEVICE_FPGA_SESSION_TLP_FRAME_STATE State = { TRUE, FALSE, 0 };
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x0c, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED);
    ASSERT_FALSE(State.fInTlp);
    ASSERT_EQ(State.cdwTlp, 0);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x08, 1),
        DEVICE_FPGA_SESSION_TLP_FRAME_APPEND);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x00, 1),
        DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED);
    ASSERT_FALSE(State.fInTlp);
    ASSERT_EQ(State.cdwTlp, 0);
}

static VOID TestTlpFrameAcceptsLegacyStreamWithoutFirst(VOID)
{
    DEVICE_FPGA_SESSION_TLP_FRAME_STATE State = { FALSE, FALSE, 0 };
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x00, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_APPEND);
    ASSERT_TRUE(State.fInTlp);
    ASSERT_EQ(State.cdwTlp, 1);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x00, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_APPEND);
    ASSERT_EQ(
        DeviceFPGA_Session_TlpFrameStep(&State, 0x04, 260),
        DEVICE_FPGA_SESSION_TLP_FRAME_COMPLETE);
    ASSERT_FALSE(State.fInTlp);
    ASSERT_EQ(State.cdwTlp, 3);
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
    BOOL fResultTracksEvent;
    HANDLE hFirstQueryEvent;
} WAIT_SCRIPT, *PWAIT_SCRIPT;

typedef struct tdREAD_PIPE_SCRIPT {
    WAIT_SCRIPT Wait;
    ULONG ulReadStatus;
    ULONG cbImmediate;
    DWORD cReadCalls;
    UCHAR ucPipeID;
    ULONG cbBuffer;
    PUCHAR pbBuffer;
    LPOVERLAPPED pOverlapped;
} READ_PIPE_SCRIPT, *PREAD_PIPE_SCRIPT;

static ULONG WINAPI ScriptedReadPipe(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbTransferred,
    _In_ LPOVERLAPPED pOverlapped
)
{
    PREAD_PIPE_SCRIPT pScript = (PREAD_PIPE_SCRIPT)hFTDI;
    pScript->cReadCalls++;
    pScript->ucPipeID = ucPipeID;
    pScript->cbBuffer = cbBuffer;
    pScript->pbBuffer = pbBuffer;
    pScript->pOverlapped = pOverlapped;
    *pcbTransferred = pScript->cbImmediate;
    return pScript->ulReadStatus;
}

static VOID TestOverlappedReadSubmissionTracksOnlyPendingStatus(VOID)
{
    READ_PIPE_SCRIPT Script = { 0 };
    BYTE pbBuffer[64] = { 0 };
    DWORD cbRead = 0;
    OVERLAPPED Overlapped = { 0 };
    BOOL fReadPending = FALSE;
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_IO_PENDING;
    ASSERT_EQ(DeviceFPGA_Session_StartOverlappedRead(
        &Script,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        &Overlapped,
        ScriptedReadPipe,
        &fReadPending), DEVICE_FPGA_SESSION_FT_IO_PENDING);
    ASSERT_TRUE(fReadPending);
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_OK;
    fReadPending = TRUE;
    ASSERT_EQ(DeviceFPGA_Session_StartOverlappedRead(
        &Script,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        &Overlapped,
        ScriptedReadPipe,
        &fReadPending), DEVICE_FPGA_SESSION_FT_OK);
    ASSERT_FALSE(fReadPending);
    Script.ulReadStatus = 0x20;
    fReadPending = TRUE;
    ASSERT_EQ(DeviceFPGA_Session_StartOverlappedRead(
        &Script,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        &Overlapped,
        ScriptedReadPipe,
        &fReadPending), 0x20);
    ASSERT_FALSE(fReadPending);
    ASSERT_EQ(Script.cReadCalls, 3);
}

static ULONG WINAPI ScriptedWaitGetOverlappedResult(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _Out_ PULONG pulLengthTransferred,
    _In_ BOOL fWait
)
{
    PWAIT_SCRIPT pScript = (PWAIT_SCRIPT)hFTDI;
    DWORD iResult;
    pScript->cGetCalls++;
    pScript->fWaitArgument = fWait;
    if(pScript->fResultTracksEvent) {
        if(WaitForSingleObject(pOverlapped->hEvent, 0) == WAIT_OBJECT_0) {
            *pulLengthTransferred = 0x1234;
            return DEVICE_FPGA_SESSION_FT_OK;
        }
        if(pScript->hFirstQueryEvent) {
            SetEvent(pScript->hFirstQueryEvent);
        }
        *pulLengthTransferred = 0;
        return DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    }
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

static VOID ScriptedWaitRealSleep(
    _In_ PVOID pvContext,
    _In_ DWORD dwMilliseconds
)
{
    ScriptedWaitSleep(pvContext, dwMilliseconds);
    Sleep(dwMilliseconds);
}

typedef struct tdWAIT_EVENT_SIGNAL {
    HANDLE hFirstQueryEvent;
    HANDLE hCompletionEvent;
} WAIT_EVENT_SIGNAL, *PWAIT_EVENT_SIGNAL;

static DWORD WINAPI SignalWaitEventAfterFirstQuery(_In_ PVOID pvContext)
{
    PWAIT_EVENT_SIGNAL pSignal = (PWAIT_EVENT_SIGNAL)pvContext;
    if(WaitForSingleObject(pSignal->hFirstQueryEvent, 1000) == WAIT_OBJECT_0) {
        Sleep(10);
        SetEvent(pSignal->hCompletionEvent);
    }
    return 0;
}

static VOID TestWaitUsesEventWithoutPolling(VOID)
{
    WAIT_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    HANDLE hSignalThread;
    WAIT_EVENT_SIGNAL Signal;
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
    Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    Script.hFirstQueryEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ASSERT_TRUE(Overlapped.hEvent != NULL);
    ASSERT_TRUE(Script.hFirstQueryEvent != NULL);
    if(!Overlapped.hEvent || !Script.hFirstQueryEvent) {
        if(Script.hFirstQueryEvent) { CloseHandle(Script.hFirstQueryEvent); }
        if(Overlapped.hEvent) { CloseHandle(Overlapped.hEvent); }
        return;
    }
    Script.fResultTracksEvent = TRUE;
    Signal.hFirstQueryEvent = Script.hFirstQueryEvent;
    Signal.hCompletionEvent = Overlapped.hEvent;
    hSignalThread = CreateThread(
        NULL,
        0,
        SignalWaitEventAfterFirstQuery,
        &Signal,
        0,
        NULL);
    ASSERT_TRUE(hSignalThread != NULL);
    if(!hSignalThread) {
        CloseHandle(Script.hFirstQueryEvent);
        CloseHandle(Overlapped.hEvent);
        return;
    }
    SetEvent(Script.hFirstQueryEvent);
    Result = DeviceFPGA_Session_WaitOverlapped(
        &Script,
        &Overlapped,
        ScriptedWaitGetOverlappedResult,
        TRUE,
        1000,
        1,
        &Script,
        ScriptedWaitTick,
        ScriptedWaitRealSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_OK);
    ASSERT_EQ(Result.cbTransferred, 0x1234);
    ASSERT_EQ(Script.cGetCalls, 1);
    ASSERT_EQ(Script.cSleepCalls, 0);
    ASSERT_FALSE(Script.fWaitArgument);
    ASSERT_EQ(WaitForSingleObject(hSignalThread, 1000), WAIT_OBJECT_0);
    CloseHandle(hSignalThread);
    CloseHandle(Script.hFirstQueryEvent);
    CloseHandle(Overlapped.hEvent);
}

static VOID TestWaitFallsBackToPollingAfterEarlyEvent(VOID)
{
    WAIT_SCRIPT Script = {
        {
            DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE,
            DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE,
            DEVICE_FPGA_SESSION_FT_OK
        },
        { 0, 0, 0x1234 },
        3,
        0,
        0,
        0,
        0,
        FALSE
    };
    OVERLAPPED Overlapped = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
    Overlapped.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    ASSERT_TRUE(Overlapped.hEvent != NULL);
    if(!Overlapped.hEvent) { return; }
    Result = DeviceFPGA_Session_WaitOverlapped(
        &Script,
        &Overlapped,
        ScriptedWaitGetOverlappedResult,
        TRUE,
        1000,
        1,
        &Script,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_OK);
    ASSERT_EQ(Result.cbTransferred, 0x1234);
    ASSERT_EQ(Script.cGetCalls, 3);
    ASSERT_EQ(Script.cSleepCalls, 1);
    ASSERT_EQ(Script.qwNow, 1);
    ASSERT_FALSE(Script.fWaitArgument);
    CloseHandle(Overlapped.hEvent);
}

static VOID TestWaitCanBypassSignaledEventForPolling(VOID)
{
    WAIT_SCRIPT Script = {
        {
            DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE,
            DEVICE_FPGA_SESSION_FT_OK
        },
        { 0, 0x1234 },
        2,
        0,
        0,
        0,
        0,
        FALSE
    };
    OVERLAPPED Overlapped = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
    Overlapped.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    ASSERT_TRUE(Overlapped.hEvent != NULL);
    if(!Overlapped.hEvent) { return; }
    Result = DeviceFPGA_Session_WaitOverlapped(
        &Script,
        &Overlapped,
        ScriptedWaitGetOverlappedResult,
        FALSE,
        1000,
        1,
        &Script,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_OK);
    ASSERT_EQ(Result.cbTransferred, 0x1234);
    ASSERT_EQ(Script.cGetCalls, 2);
    ASSERT_EQ(Script.cSleepCalls, 1);
    ASSERT_EQ(Script.qwNow, 1);
    ASSERT_FALSE(Script.fWaitArgument);
    CloseHandle(Overlapped.hEvent);
}

static VOID TestWaitEventTimeoutDoesNotPoll(VOID)
{
    WAIT_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
    Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ASSERT_TRUE(Overlapped.hEvent != NULL);
    if(!Overlapped.hEvent) { return; }
    Script.fResultTracksEvent = TRUE;
    Result = DeviceFPGA_Session_WaitOverlapped(
        &Script,
        &Overlapped,
        ScriptedWaitGetOverlappedResult,
        TRUE,
        5,
        1,
        &Script,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_TIMED_OUT);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE);
    ASSERT_EQ(Result.cbTransferred, 0);
    ASSERT_EQ(Script.cGetCalls, 0);
    ASSERT_EQ(Script.cSleepCalls, 0);
    ASSERT_FALSE(Script.fWaitArgument);
    CloseHandle(Overlapped.hEvent);
}

static VOID TestBoundedReadReturnsImmediateCompletion(VOID)
{
    BYTE pbBuffer[0x4000];
    OVERLAPPED Overlapped = { 0 };
    READ_PIPE_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
    BOOL fReadPending = TRUE;
    Script.cbImmediate = 0x2345;
    Result = DeviceFPGA_Session_ReadPipeBounded(
        &Script,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &Overlapped,
        ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult,
        &fReadPending,
        TRUE,
        1000,
        1,
        &Script.Wait,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_OK);
    ASSERT_EQ(Result.cbTransferred, 0x2345);
    ASSERT_EQ(Script.cReadCalls, 1);
    ASSERT_EQ(Script.Wait.cGetCalls, 0);
    ASSERT_EQ(Script.Wait.cSleepCalls, 0);
    ASSERT_FALSE(fReadPending);
    ASSERT_EQ(Script.ucPipeID, 0x82);
    ASSERT_EQ(Script.cbBuffer, sizeof(pbBuffer));
    ASSERT_TRUE(Script.pbBuffer == pbBuffer);
    ASSERT_TRUE(Script.pOverlapped == &Overlapped);
}

static VOID TestBoundedReadWaitsForPendingCompletion(VOID)
{
    BYTE pbBuffer[0x4000];
    OVERLAPPED Overlapped = { 0 };
    READ_PIPE_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
    BOOL fReadPending = FALSE;
    HANDLE hSignalThread;
    WAIT_EVENT_SIGNAL Signal;
    Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    Script.Wait.hFirstQueryEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ASSERT_TRUE(Overlapped.hEvent != NULL);
    ASSERT_TRUE(Script.Wait.hFirstQueryEvent != NULL);
    if(!Overlapped.hEvent || !Script.Wait.hFirstQueryEvent) {
        if(Script.Wait.hFirstQueryEvent) {
            CloseHandle(Script.Wait.hFirstQueryEvent);
        }
        if(Overlapped.hEvent) { CloseHandle(Overlapped.hEvent); }
        return;
    }
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_IO_PENDING;
    Script.cbImmediate = 0x9999;
    Script.Wait.fResultTracksEvent = TRUE;
    Signal.hFirstQueryEvent = Script.Wait.hFirstQueryEvent;
    Signal.hCompletionEvent = Overlapped.hEvent;
    hSignalThread = CreateThread(
        NULL,
        0,
        SignalWaitEventAfterFirstQuery,
        &Signal,
        0,
        NULL);
    ASSERT_TRUE(hSignalThread != NULL);
    if(!hSignalThread) {
        CloseHandle(Script.Wait.hFirstQueryEvent);
        CloseHandle(Overlapped.hEvent);
        return;
    }
    SetEvent(Script.Wait.hFirstQueryEvent);
    Result = DeviceFPGA_Session_ReadPipeBounded(
        &Script,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &Overlapped,
        ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult,
        &fReadPending,
        TRUE,
        1000,
        1,
        &Script.Wait,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_COMPLETED);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_OK);
    ASSERT_EQ(Result.cbTransferred, 0x1234);
    ASSERT_EQ(Script.cReadCalls, 1);
    ASSERT_EQ(Script.Wait.cGetCalls, 1);
    ASSERT_EQ(Script.Wait.cSleepCalls, 0);
    ASSERT_FALSE(Script.Wait.fWaitArgument);
    ASSERT_FALSE(fReadPending);
    ASSERT_TRUE(Script.pOverlapped == &Overlapped);
    ASSERT_EQ(WaitForSingleObject(hSignalThread, 1000), WAIT_OBJECT_0);
    CloseHandle(hSignalThread);
    CloseHandle(Script.Wait.hFirstQueryEvent);
    CloseHandle(Overlapped.hEvent);
}

static VOID TestBoundedReadPendingForeverTimesOut(VOID)
{
    BYTE pbBuffer[0x4000];
    OVERLAPPED Overlapped = { 0 };
    READ_PIPE_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
    BOOL fReadPending = FALSE;
    Overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ASSERT_TRUE(Overlapped.hEvent != NULL);
    if(!Overlapped.hEvent) { return; }
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_IO_PENDING;
    Script.cbImmediate = 0x9999;
    Result = DeviceFPGA_Session_ReadPipeBounded(
        &Script,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &Overlapped,
        ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult,
        &fReadPending,
        TRUE,
        5,
        1,
        &Script.Wait,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_TIMED_OUT);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE);
    ASSERT_EQ(Result.cbTransferred, 0);
    ASSERT_EQ(Script.cReadCalls, 1);
    ASSERT_EQ(Script.Wait.qwNow, 0);
    ASSERT_EQ(Script.Wait.cGetCalls, 0);
    ASSERT_EQ(Script.Wait.cSleepCalls, 0);
    ASSERT_FALSE(Script.Wait.fWaitArgument);
    ASSERT_TRUE(fReadPending);
    CloseHandle(Overlapped.hEvent);
}

static VOID TestBoundedReadReturnsSubmissionErrorWithoutPolling(VOID)
{
    BYTE pbBuffer[0x4000];
    OVERLAPPED Overlapped = { 0 };
    READ_PIPE_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
    BOOL fReadPending = TRUE;
    Script.ulReadStatus = 0x20;
    Script.cbImmediate = 0x9999;
    Result = DeviceFPGA_Session_ReadPipeBounded(
        &Script,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &Overlapped,
        ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult,
        &fReadPending,
        TRUE,
        1000,
        1,
        &Script.Wait,
        ScriptedWaitTick,
        ScriptedWaitSleep);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_WAIT_DRIVER_ERROR);
    ASSERT_EQ(Result.status, 0x20);
    ASSERT_EQ(Result.cbTransferred, 0);
    ASSERT_EQ(Script.cReadCalls, 1);
    ASSERT_EQ(Script.Wait.cGetCalls, 0);
    ASSERT_EQ(Script.Wait.cSleepCalls, 0);
    ASSERT_FALSE(fReadPending);
}

static VOID TestBoundedReadRejectsInvalidArguments(VOID)
{
    BYTE pbBuffer[0x100];
    OVERLAPPED Overlapped = { 0 };
    READ_PIPE_SCRIPT Script = { 0 };
#define ASSERT_INVALID_BOUNDED_READ(handle, buffer, size, overlapped, read, get, pending, tick, sleep) \
    ASSERT_EQ( \
        DeviceFPGA_Session_ReadPipeBounded( \
            (handle), 0x82, (buffer), (size), (overlapped), (read), (get), \
            (pending), TRUE, 1000, 1, &Script.Wait, (tick), (sleep)).outcome, \
        DEVICE_FPGA_SESSION_WAIT_DRIVER_ERROR)
    BOOL fReadPending = TRUE;
    ASSERT_INVALID_BOUNDED_READ(
        NULL, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, &fReadPending,
        ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, NULL, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, &fReadPending,
        ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, 0, &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, &fReadPending,
        ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), NULL, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, &fReadPending,
        ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, NULL,
        ScriptedWaitGetOverlappedResult, &fReadPending,
        ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        NULL, &fReadPending, ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, NULL,
        ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, &fReadPending,
        NULL, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, &fReadPending,
        ScriptedWaitTick, NULL);
#undef ASSERT_INVALID_BOUNDED_READ
    ASSERT_EQ(Script.cReadCalls, 0);
    ASSERT_EQ(Script.Wait.cGetCalls, 0);
    ASSERT_EQ(Script.Wait.cSleepCalls, 0);
}

typedef struct tdOPPORTUNISTIC_READ_SCRIPT {
    WAIT_SCRIPT Wait;
    ULONG ulReadStatus;
    ULONG cbImmediate;
    ULONG ulAbortStatus;
    ULONG ulReleaseStatus;
    ULONG ulInitializeStatus;
    DWORD cReadCalls;
    DWORD cAbortCalls;
    DWORD cReleaseCalls;
    DWORD cInitializeCalls;
} OPPORTUNISTIC_READ_SCRIPT, *POPPORTUNISTIC_READ_SCRIPT;

static ULONG WINAPI ScriptedOpportunisticRead(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbTransferred,
    _In_ LPOVERLAPPED pOverlapped
)
{
    POPPORTUNISTIC_READ_SCRIPT pScript =
        (POPPORTUNISTIC_READ_SCRIPT)hFTDI;
    UNREFERENCED_PARAMETER(ucPipeID);
    UNREFERENCED_PARAMETER(pbBuffer);
    UNREFERENCED_PARAMETER(cbBuffer);
    UNREFERENCED_PARAMETER(pOverlapped);
    pScript->cReadCalls++;
    *pcbTransferred = pScript->cbImmediate;
    return pScript->ulReadStatus;
}

static ULONG WINAPI ScriptedOpportunisticAbort(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID
)
{
    POPPORTUNISTIC_READ_SCRIPT pScript =
        (POPPORTUNISTIC_READ_SCRIPT)hFTDI;
    ASSERT_EQ(ucPipeID, 0x82);
    pScript->cAbortCalls++;
    return pScript->ulAbortStatus;
}

static ULONG WINAPI ScriptedOpportunisticRelease(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped
)
{
    POPPORTUNISTIC_READ_SCRIPT pScript =
        (POPPORTUNISTIC_READ_SCRIPT)hFTDI;
    UNREFERENCED_PARAMETER(pOverlapped);
    pScript->cReleaseCalls++;
    return pScript->ulReleaseStatus;
}

static ULONG WINAPI ScriptedOpportunisticInitialize(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped
)
{
    POPPORTUNISTIC_READ_SCRIPT pScript =
        (POPPORTUNISTIC_READ_SCRIPT)hFTDI;
    UNREFERENCED_PARAMETER(pOverlapped);
    pScript->cInitializeCalls++;
    return pScript->ulInitializeStatus;
}

static DEVICE_FPGA_SESSION_READ_RESULT RunOpportunisticRead(
    _Inout_ POPPORTUNISTIC_READ_SCRIPT pScript,
    _Inout_ PBOOL pfOverlappedInitialized,
    _Inout_ PBOOL pfReadPending
)
{
    BYTE pbBuffer[64] = { 0 };
    OVERLAPPED Overlapped = { 0 };
    return DeviceFPGA_Session_ReadPipeOpportunistic(
        pScript,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &Overlapped,
        ScriptedOpportunisticRead,
        ScriptedWaitGetOverlappedResult,
        ScriptedOpportunisticAbort,
        ScriptedOpportunisticRelease,
        ScriptedOpportunisticInitialize,
        3,
        1,
        &pScript->Wait,
        ScriptedWaitTick,
        ScriptedWaitSleep,
        pfOverlappedInitialized,
        pfReadPending);
}

static VOID TestOpportunisticReadReturnsDelayedDataWithoutCancelling(VOID)
{
    OPPORTUNISTIC_READ_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_READ_RESULT Result;
    BOOL fOverlappedInitialized = TRUE, fReadPending = FALSE;
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_IO_PENDING;
    Script.Wait.pStatus[0] = DEVICE_FPGA_SESSION_FT_OK;
    Script.Wait.pTransferred[0] = 32;
    Script.Wait.cResults = 1;
    Result = RunOpportunisticRead(
        &Script, &fOverlappedInitialized, &fReadPending);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_READ_DATA);
    ASSERT_EQ(Result.cbTransferred, 32);
    ASSERT_FALSE(fReadPending);
    ASSERT_TRUE(fOverlappedInitialized);
    ASSERT_EQ(Script.cAbortCalls, 0);
    ASSERT_EQ(Script.cReleaseCalls, 0);
    ASSERT_EQ(Script.cInitializeCalls, 0);
}

static VOID TestOpportunisticReadTreatsCancelledSilenceAsQuiet(VOID)
{
    OPPORTUNISTIC_READ_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_READ_RESULT Result;
    BOOL fOverlappedInitialized = TRUE, fReadPending = FALSE;
    DWORD i;
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_IO_PENDING;
    for(i = 0; i < 5; i++) {
        Script.Wait.pStatus[i] = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    }
    Script.Wait.pStatus[5] = DEVICE_FPGA_SESSION_FT_OK;
    Script.Wait.cResults = 6;
    Result = RunOpportunisticRead(
        &Script, &fOverlappedInitialized, &fReadPending);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_READ_QUIET);
    ASSERT_EQ(Result.cbTransferred, 0);
    ASSERT_FALSE(fReadPending);
    ASSERT_TRUE(fOverlappedInitialized);
    ASSERT_EQ(Script.cAbortCalls, 1);
    ASSERT_EQ(Script.cReleaseCalls, 1);
    ASSERT_EQ(Script.cInitializeCalls, 1);
}

static VOID TestOpportunisticReadPreservesCompletionThatRacesTimeout(VOID)
{
    OPPORTUNISTIC_READ_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_READ_RESULT Result;
    BOOL fOverlappedInitialized = TRUE, fReadPending = FALSE;
    DWORD i;
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_IO_PENDING;
    for(i = 0; i < 4; i++) {
        Script.Wait.pStatus[i] = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    }
    Script.Wait.pStatus[4] = DEVICE_FPGA_SESSION_FT_OK;
    Script.Wait.pTransferred[4] = 32;
    Script.Wait.cResults = 5;
    Result = RunOpportunisticRead(
        &Script, &fOverlappedInitialized, &fReadPending);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_READ_DATA);
    ASSERT_EQ(Result.cbTransferred, 32);
    ASSERT_FALSE(fReadPending);
    ASSERT_TRUE(fOverlappedInitialized);
    ASSERT_EQ(Script.cAbortCalls, 0);
    ASSERT_EQ(Script.cReleaseCalls, 0);
    ASSERT_EQ(Script.cInitializeCalls, 0);
}

static VOID TestOpportunisticReadKeepsPendingObjectWhenCancelTimesOut(VOID)
{
    OPPORTUNISTIC_READ_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_READ_RESULT Result;
    BOOL fOverlappedInitialized = TRUE, fReadPending = FALSE;
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_IO_PENDING;
    Script.Wait.pStatus[0] = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    Script.Wait.cResults = 1;
    Result = RunOpportunisticRead(
        &Script, &fOverlappedInitialized, &fReadPending);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_READ_DRIVER_ERROR);
    ASSERT_EQ(Result.status, DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE);
    ASSERT_TRUE(fReadPending);
    ASSERT_TRUE(fOverlappedInitialized);
    ASSERT_EQ(Script.cAbortCalls, 1);
    ASSERT_EQ(Script.cReleaseCalls, 0);
    ASSERT_EQ(Script.cInitializeCalls, 0);
}

static VOID TestOpportunisticReadReportsAbortFailure(VOID)
{
    OPPORTUNISTIC_READ_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_READ_RESULT Result;
    BOOL fOverlappedInitialized = TRUE, fReadPending = FALSE;
    DWORD i;
    Script.ulReadStatus = DEVICE_FPGA_SESSION_FT_IO_PENDING;
    Script.ulAbortStatus = 0x20;
    for(i = 0; i < 5; i++) {
        Script.Wait.pStatus[i] = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    }
    Script.Wait.pStatus[5] = DEVICE_FPGA_SESSION_FT_OK;
    Script.Wait.cResults = 6;
    Result = RunOpportunisticRead(
        &Script, &fOverlappedInitialized, &fReadPending);
    ASSERT_EQ(Result.outcome, DEVICE_FPGA_SESSION_READ_DRIVER_ERROR);
    ASSERT_EQ(Result.status, 0x20);
    ASSERT_FALSE(fReadPending);
    ASSERT_TRUE(fOverlappedInitialized);
    ASSERT_EQ(Script.cAbortCalls, 1);
    ASSERT_EQ(Script.cReleaseCalls, 1);
    ASSERT_EQ(Script.cInitializeCalls, 1);
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
        TRUE,
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
        TRUE,
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
        TRUE,
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
    ULONG ulPreAbortGetStatus;
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
    BOOL fBeforeAbort = !pScript->fRxAborted;
    UNREFERENCED_PARAMETER(pOverlapped);
    *pulLengthTransferred = 0;
    pScript->cGetCalls++;
    pScript->fWaitedBeforeAbort |= fBeforeAbort;
    pScript->fSawWaitArgument |= fWait;
    if(pScript->cEvents < sizeof(pScript->pbEvents)) {
        pScript->pbEvents[pScript->cEvents++] = EVENT_GET_OVERLAPPED;
    }
    return fBeforeAbort ?
        pScript->ulPreAbortGetStatus :
        pScript->ulGetStatus;
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

static VOID TestTrackedCloseReleasesIdleReadWithoutCancelling(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BOOL fReleased = FALSE;
    BYTE pbExpected[] = { EVENT_RELEASE };
    ASSERT_TRUE(DeviceFPGA_Session_TeardownOverlapped(
        &Script,
        &Overlapped,
        FALSE,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep,
        &fReleased));
    ASSERT_TRUE(fReleased);
    ASSERT_FALSE(Script.fRxAborted);
    ASSERT_FALSE(Script.fTxAborted);
    ASSERT_EQ(Script.cGetCalls, 0);
    ASSERT_EQ(Script.cSleepCalls, 0);
    ASSERT_EQ(Script.cReleaseCalls, 1);
    ASSERT_EQ(Script.cEvents, sizeof(pbExpected));
    ASSERT_BYTES(Script.pbEvents, pbExpected, sizeof(pbExpected));
}

static VOID TestTrackedCloseCancelsPendingReadBeforeRelease(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BOOL fReleased = FALSE;
    BYTE pbExpected[] = {
        EVENT_GET_OVERLAPPED, 0x82, EVENT_GET_OVERLAPPED, EVENT_RELEASE
    };
    Script.ulPreAbortGetStatus = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    ASSERT_TRUE(DeviceFPGA_Session_TeardownOverlapped(
        &Script,
        &Overlapped,
        TRUE,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep,
        &fReleased));
    ASSERT_TRUE(fReleased);
    ASSERT_TRUE(Script.fRxAborted);
    ASSERT_FALSE(Script.fTxAborted);
    ASSERT_TRUE(Script.fWaitedBeforeAbort);
    ASSERT_EQ(Script.cEvents, sizeof(pbExpected));
    ASSERT_BYTES(Script.pbEvents, pbExpected, sizeof(pbExpected));
}

static VOID TestTrackedCloseReleasesCompletedReadWithoutCancelling(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BOOL fReleased = FALSE;
    BYTE pbExpected[] = { EVENT_GET_OVERLAPPED, EVENT_RELEASE };
    ASSERT_TRUE(DeviceFPGA_Session_TeardownOverlapped(
        &Script,
        &Overlapped,
        TRUE,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep,
        &fReleased));
    ASSERT_TRUE(fReleased);
    ASSERT_FALSE(Script.fRxAborted);
    ASSERT_FALSE(Script.fTxAborted);
    ASSERT_TRUE(Script.fWaitedBeforeAbort);
    ASSERT_EQ(Script.cGetCalls, 1);
    ASSERT_EQ(Script.cReleaseCalls, 1);
    ASSERT_EQ(Script.cEvents, sizeof(pbExpected));
    ASSERT_BYTES(Script.pbEvents, pbExpected, sizeof(pbExpected));
}

static VOID TestOverlappedReadLifecycleAndCloseOrdering(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BOOL fReleased = FALSE;
    BYTE pbExpected[] = {
        EVENT_GET_OVERLAPPED, 0x82, EVENT_GET_OVERLAPPED, EVENT_RELEASE
    };

    RUN_TEST(TestOverlappedReadSubmissionTracksOnlyPendingStatus);
    RUN_TEST(TestTrackedCloseReleasesIdleReadWithoutCancelling);
    RUN_TEST(TestTrackedCloseReleasesCompletedReadWithoutCancelling);
    RUN_TEST(TestTrackedCloseCancelsPendingReadBeforeRelease);

    Script.ulPreAbortGetStatus = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    ASSERT_TRUE(DeviceFPGA_Session_CloseOverlapped(
        &Script,
        &Overlapped,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep,
        &fReleased));
    ASSERT_TRUE(fReleased);
    ASSERT_TRUE(Script.fWaitedBeforeAbort);
    ASSERT_FALSE(Script.fSawWaitArgument);
    ASSERT_TRUE(Script.fRxAborted);
    ASSERT_FALSE(Script.fTxAborted);
    ASSERT_EQ(Script.cEvents, sizeof(pbExpected));
    ASSERT_BYTES(Script.pbEvents, pbExpected, sizeof(pbExpected));
}

static VOID TestClosePendingForeverIsBoundedAndDoesNotRelease(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BOOL fReleased = TRUE;
    Script.ulPreAbortGetStatus = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    Script.ulGetStatus = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    ASSERT_FALSE(DeviceFPGA_Session_CloseOverlapped(
        &Script,
        &Overlapped,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep,
        &fReleased));
    ASSERT_FALSE(fReleased);
    ASSERT_FALSE(Script.fSawWaitArgument);
    ASSERT_EQ(Script.qwNow, DEVICE_FPGA_SESSION_CANCEL_TIMEOUT_MS);
    ASSERT_EQ(Script.cGetCalls, DEVICE_FPGA_SESSION_CANCEL_TIMEOUT_MS + 2);
    ASSERT_EQ(Script.cReleaseCalls, 0);
}

static VOID TestCloseReportsAbortErrorAfterAttemptingCleanup(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BOOL fReleased = FALSE;
    Script.ulPreAbortGetStatus = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
    Script.ulRxAbortStatus = 1;
    ASSERT_FALSE(DeviceFPGA_Session_CloseOverlapped(
        &Script,
        &Overlapped,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep,
        &fReleased));
    ASSERT_TRUE(fReleased);
    ASSERT_TRUE(Script.fRxAborted);
    ASSERT_FALSE(Script.fTxAborted);
    ASSERT_EQ(Script.cGetCalls, 2);
    ASSERT_EQ(Script.cReleaseCalls, 1);
}

static VOID TestCloseUnexpectedQueryErrorStillAbortsAndReleases(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BOOL fReleased = FALSE;
    BYTE pbExpected[] = {
        EVENT_GET_OVERLAPPED, 0x82, EVENT_GET_OVERLAPPED, EVENT_RELEASE
    };
    Script.ulPreAbortGetStatus = 1;
    ASSERT_TRUE(DeviceFPGA_Session_CloseOverlapped(
        &Script,
        &Overlapped,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep,
        &fReleased));
    ASSERT_TRUE(fReleased);
    ASSERT_TRUE(Script.fRxAborted);
    ASSERT_FALSE(Script.fTxAborted);
    ASSERT_EQ(Script.cEvents, sizeof(pbExpected));
    ASSERT_BYTES(Script.pbEvents, pbExpected, sizeof(pbExpected));
}

static VOID TestCloseReleaseFailureKeepsHandleOwnership(VOID)
{
    CLOSE_SCRIPT Script = { 0 };
    OVERLAPPED Overlapped = { 0 };
    BOOL fReleased = TRUE;
    Script.ulReleaseStatus = 1;
    ASSERT_FALSE(DeviceFPGA_Session_CloseOverlapped(
        &Script,
        &Overlapped,
        ScriptedAbortPipe,
        ScriptedGetOverlappedResult,
        ScriptedReleaseOverlapped,
        &Script,
        ScriptedCloseTick,
        ScriptedCloseSleep,
        &fReleased));
    ASSERT_FALSE(fReleased);
    ASSERT_FALSE(Script.fRxAborted);
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

#define RECOVERY_EVENT_QUIESCE      1
#define RECOVERY_EVENT_REOPEN       2
#define RECOVERY_EVENT_INITIALIZE   3
#define RECOVERY_EVENT_INVALIDATE   4
#define RECOVERY_EVENT_DRAIN        5
#define RECOVERY_EVENT_IDENTITY     6

typedef struct tdRECOVERY_SCRIPT {
    BYTE pbEvents[6];
    DWORD cEvents;
    BYTE bFailEvent;
} RECOVERY_SCRIPT, *PRECOVERY_SCRIPT;

static BOOL RecoveryRecordStep(_Inout_ PVOID pvContext, _In_ BYTE bEvent)
{
    PRECOVERY_SCRIPT pScript = (PRECOVERY_SCRIPT)pvContext;
    pScript->pbEvents[pScript->cEvents++] = bEvent;
    return pScript->bFailEvent != bEvent;
}

static BOOL RecoveryQuiesce(_Inout_ PVOID pvContext)
{
    return RecoveryRecordStep(pvContext, RECOVERY_EVENT_QUIESCE);
}

static BOOL RecoveryReopen(_Inout_ PVOID pvContext)
{
    return RecoveryRecordStep(pvContext, RECOVERY_EVENT_REOPEN);
}

static BOOL RecoveryInitialize(_Inout_ PVOID pvContext)
{
    return RecoveryRecordStep(pvContext, RECOVERY_EVENT_INITIALIZE);
}

static VOID RecoveryInvalidate(_Inout_ PVOID pvContext)
{
    PRECOVERY_SCRIPT pScript = (PRECOVERY_SCRIPT)pvContext;
    pScript->pbEvents[pScript->cEvents++] = RECOVERY_EVENT_INVALIDATE;
}

static BOOL RecoveryDrain(_Inout_ PVOID pvContext)
{
    return RecoveryRecordStep(pvContext, RECOVERY_EVENT_DRAIN);
}

static BOOL RecoveryIdentity(_Inout_ PVOID pvContext)
{
    return RecoveryRecordStep(pvContext, RECOVERY_EVENT_IDENTITY);
}

static DEVICE_FPGA_SESSION_RECOVERY_OPS g_RecoveryOps = {
    RecoveryQuiesce,
    RecoveryReopen,
    RecoveryInitialize,
    RecoveryInvalidate,
    RecoveryDrain,
    RecoveryIdentity
};

static VOID TestRecoveryCoordinatorExecutesOneOrderedAttempt(VOID)
{
    RECOVERY_SCRIPT Script = { 0 };
    BYTE pbExpected[] = {
        RECOVERY_EVENT_QUIESCE,
        RECOVERY_EVENT_REOPEN,
        RECOVERY_EVENT_INITIALIZE,
        RECOVERY_EVENT_INVALIDATE,
        RECOVERY_EVENT_DRAIN,
        RECOVERY_EVENT_IDENTITY
    };
    ASSERT_EQ(
        DeviceFPGA_Session_Recover(&Script, &g_RecoveryOps),
        DEVICE_FPGA_SESSION_RECOVERY_READY);
    ASSERT_EQ(Script.cEvents, sizeof(pbExpected));
    ASSERT_BYTES(Script.pbEvents, pbExpected, sizeof(pbExpected));
}

static VOID TestRecoveryCoordinatorStopsAtEachFailedStage(VOID)
{
    static const BYTE pbFailEvents[] = {
        RECOVERY_EVENT_QUIESCE,
        RECOVERY_EVENT_REOPEN,
        RECOVERY_EVENT_INITIALIZE,
        RECOVERY_EVENT_DRAIN,
        RECOVERY_EVENT_IDENTITY
    };
    static const DEVICE_FPGA_SESSION_RECOVERY_STAGE pExpectedStages[] = {
        DEVICE_FPGA_SESSION_RECOVERY_QUIESCE_FAILED,
        DEVICE_FPGA_SESSION_RECOVERY_REOPEN_FAILED,
        DEVICE_FPGA_SESSION_RECOVERY_INITIALIZE_FAILED,
        DEVICE_FPGA_SESSION_RECOVERY_DRAIN_FAILED,
        DEVICE_FPGA_SESSION_RECOVERY_IDENTITY_FAILED
    };
    DWORD i;
    for(i = 0; i < sizeof(pbFailEvents); i++) {
        RECOVERY_SCRIPT Script = { 0 };
        Script.bFailEvent = pbFailEvents[i];
        ASSERT_EQ(
            DeviceFPGA_Session_Recover(&Script, &g_RecoveryOps),
            pExpectedStages[i]);
        ASSERT_EQ(
            Script.pbEvents[Script.cEvents - 1],
            pbFailEvents[i]);
        ASSERT_EQ(
            Script.cEvents,
            pbFailEvents[i]);
    }
}

static VOID TestRecoveryCoordinatorRejectsIncompleteOpsBeforeStarting(VOID)
{
    RECOVERY_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_RECOVERY_OPS Ops = g_RecoveryOps;
    Ops.pfnDrainStaleTraffic = NULL;
    ASSERT_EQ(
        DeviceFPGA_Session_Recover(&Script, &Ops),
        DEVICE_FPGA_SESSION_RECOVERY_QUIESCE_FAILED);
    ASSERT_EQ(Script.cEvents, 0);
}

static VOID TestFillerClassificationRequiresCompleteFillerWords(VOID)
{
    BYTE pbOneWord[] = { 0x66, 0x66, 0x55, 0x55 };
    BYTE pbRepeated[] = {
        0x66, 0x66, 0x55, 0x55,
        0x66, 0x66, 0x55, 0x55,
        0x66, 0x66, 0x55, 0x55,
        0x66, 0x66, 0x55, 0x55,
        0x66, 0x66, 0x55, 0x55
    };
    BYTE pbFramed[] = {
        0x66, 0x66, 0x55, 0x55,
        0x00, 0x00, 0x00, 0xe0
    };
    BYTE pbTruncated[] = { 0x66, 0x66 };
    ASSERT_TRUE(DeviceFPGA_Session_IsFillerOnly(NULL, 0));
    ASSERT_TRUE(DeviceFPGA_Session_IsFillerOnly(
        pbOneWord, sizeof(pbOneWord)));
    ASSERT_TRUE(DeviceFPGA_Session_IsFillerOnly(
        pbRepeated, sizeof(pbRepeated)));
    ASSERT_FALSE(DeviceFPGA_Session_IsFillerOnly(
        pbFramed, sizeof(pbFramed)));
    ASSERT_FALSE(DeviceFPGA_Session_IsFillerOnly(
        pbTruncated, sizeof(pbTruncated)));
}

typedef struct tdDRAIN_SCRIPT {
    DWORD cCalls;
    DWORD cSleepCalls;
    DWORD iFailCall;
    DWORD iOversizeCall;
    DWORD iNonFillerCall;
    DWORD cbNonFiller;
    DWORD dwReadDelayMs;
    DWORD dwFirstReadTimeoutMs;
    DWORD dwLastReadTimeoutMs;
    QWORD qwNow;
    BOOL fAlwaysNonFiller;
    BOOL fUseFiller;
    BOOL fWrongSleep;
} DRAIN_SCRIPT, *PDRAIN_SCRIPT;

static BOOL ScriptedDrainRead(
    _Inout_ PVOID pvContext,
    _Out_writes_(cbBuffer) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _In_ DWORD dwTimeoutMs,
    _Out_ PDWORD pcbRead
)
{
    PDRAIN_SCRIPT pScript = (PDRAIN_SCRIPT)pvContext;
    DWORD iCall = ++pScript->cCalls;
    if(iCall == 1) {
        pScript->dwFirstReadTimeoutMs = dwTimeoutMs;
    }
    pScript->dwLastReadTimeoutMs = dwTimeoutMs;
    pScript->qwNow += pScript->dwReadDelayMs;
    if(iCall == pScript->iFailCall) {
        *pcbRead = 0;
        return FALSE;
    }
    if(iCall == pScript->iOversizeCall) {
        *pcbRead = cbBuffer + 1;
        return TRUE;
    }
    if(pScript->fAlwaysNonFiller ||
       (iCall == pScript->iNonFillerCall)) {
        if(cbBuffer < pScript->cbNonFiller) { return FALSE; }
        memset(pbBuffer, 0xa5, pScript->cbNonFiller);
        *pcbRead = pScript->cbNonFiller;
        return TRUE;
    }
    if(pScript->fUseFiller) {
        DWORD dwFiller = 0x55556666;
        if(cbBuffer < sizeof(DWORD)) { return FALSE; }
        memcpy(pbBuffer, &dwFiller, sizeof(dwFiller));
        *pcbRead = sizeof(DWORD);
        return TRUE;
    }
    *pcbRead = 0;
    return TRUE;
}

static QWORD ScriptedDrainTick(_In_ PVOID pvContext)
{
    return ((PDRAIN_SCRIPT)pvContext)->qwNow;
}

static VOID ScriptedDrainSleep(
    _In_ PVOID pvContext,
    _In_ DWORD dwMilliseconds
)
{
    PDRAIN_SCRIPT pScript = (PDRAIN_SCRIPT)pvContext;
    pScript->cSleepCalls++;
    pScript->fWrongSleep |= dwMilliseconds != 10;
    pScript->qwNow += dwMilliseconds;
}

static DEVICE_FPGA_SESSION_DRAIN_OUTCOME RunScriptedDrain(
    _Inout_ PDRAIN_SCRIPT pScript,
    _Out_writes_(cbBuffer) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _In_ DWORD cbMaxNonFiller
)
{
    return DeviceFPGA_Session_Drain(
        pScript,
        ScriptedDrainRead,
        pbBuffer,
        cbBuffer,
        cbMaxNonFiller,
        2000,
        5000,
        10,
        pScript,
        ScriptedDrainTick,
        ScriptedDrainSleep);
}

static VOID TestDrainRequiresSustainedQuiescence(VOID)
{
    BYTE pbBuffer[64];
    DRAIN_SCRIPT Filler = { 0 };
    DRAIN_SCRIPT Empty = { 0 };
    Filler.fUseFiller = TRUE;
    ASSERT_EQ(
        RunScriptedDrain(
            &Filler, pbBuffer, sizeof(pbBuffer), 1),
        DEVICE_FPGA_SESSION_DRAIN_CLEAN);
    ASSERT_EQ(Filler.qwNow, 2000);
    ASSERT_EQ(Filler.cCalls, 201);
    ASSERT_EQ(Filler.cSleepCalls, 200);
    ASSERT_FALSE(Filler.fWrongSleep);
    ASSERT_EQ(
        RunScriptedDrain(
            &Empty, pbBuffer, sizeof(pbBuffer), 1),
        DEVICE_FPGA_SESSION_DRAIN_CLEAN);
    ASSERT_EQ(Empty.qwNow, 2000);
    ASSERT_EQ(Empty.cCalls, 201);
    ASSERT_EQ(Empty.cSleepCalls, 200);
    ASSERT_FALSE(Empty.fWrongSleep);
}

static VOID TestDrainResetsQuietWindowAfterTraffic(VOID)
{
    BYTE pbBuffer[64];
    DRAIN_SCRIPT Script = { 0 };
    Script.iNonFillerCall = 101;
    Script.cbNonFiller = 32;
    Script.fUseFiller = TRUE;
    ASSERT_EQ(
        RunScriptedDrain(
            &Script, pbBuffer, sizeof(pbBuffer), 0x100000),
        DEVICE_FPGA_SESSION_DRAIN_CLEAN);
    ASSERT_EQ(Script.qwNow, 3000);
    ASSERT_EQ(Script.cCalls, 301);
    ASSERT_EQ(Script.cSleepCalls, 300);
    ASSERT_FALSE(Script.fWrongSleep);
}

static VOID TestDrainReportsReadErrorWithoutRetry(VOID)
{
    BYTE pbBuffer[64];
    DRAIN_SCRIPT Script = { 0 };
    Script.iFailCall = 1;
    ASSERT_EQ(
        RunScriptedDrain(
            &Script, pbBuffer, sizeof(pbBuffer), 0x100000),
        DEVICE_FPGA_SESSION_DRAIN_READ_ERROR);
    ASSERT_EQ(Script.cCalls, 1);
    ASSERT_EQ(Script.cSleepCalls, 0);
}

static VOID TestDrainRejectsOversizedRead(VOID)
{
    BYTE pbBuffer[64];
    DRAIN_SCRIPT Script = { 0 };
    Script.iOversizeCall = 1;
    ASSERT_EQ(
        RunScriptedDrain(
            &Script, pbBuffer, sizeof(pbBuffer), 0x100000),
        DEVICE_FPGA_SESSION_DRAIN_READ_ERROR);
    ASSERT_EQ(Script.cCalls, 1);
    ASSERT_EQ(Script.cSleepCalls, 0);
}

static VOID TestDrainEnforcesNonFillerByteLimit(VOID)
{
    static BYTE pbBuffer[0x10000];
    DRAIN_SCRIPT Script = { 0 };
    Script.cbNonFiller = sizeof(pbBuffer);
    Script.fAlwaysNonFiller = TRUE;
    ASSERT_EQ(
        RunScriptedDrain(
            &Script, pbBuffer, sizeof(pbBuffer), 0x100000),
        DEVICE_FPGA_SESSION_DRAIN_BYTE_LIMIT);
    ASSERT_EQ(Script.cCalls, 16);
    ASSERT_EQ(Script.cSleepCalls, 15);
}

static VOID TestDrainEnforcesOverallDeadline(VOID)
{
    BYTE pbBuffer[64];
    DRAIN_SCRIPT Script = { 0 };
    Script.cbNonFiller = sizeof(DWORD);
    Script.fAlwaysNonFiller = TRUE;
    ASSERT_EQ(
        RunScriptedDrain(
            &Script, pbBuffer, sizeof(pbBuffer), 0x100000),
        DEVICE_FPGA_SESSION_DRAIN_TIME_LIMIT);
    ASSERT_EQ(Script.qwNow, 5000);
    ASSERT_EQ(Script.cCalls, 500);
    ASSERT_EQ(Script.cSleepCalls, 500);
    ASSERT_FALSE(Script.fWrongSleep);
}

static VOID TestDrainDeadlineWinsAfterSlowRead(VOID)
{
    BYTE pbBuffer[64];
    DRAIN_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_DRAIN_OUTCOME Outcome;
    Script.dwReadDelayMs = 5000;
    Outcome = RunScriptedDrain(
        &Script, pbBuffer, sizeof(pbBuffer), 0x100000);
    ASSERT_EQ(Outcome, DEVICE_FPGA_SESSION_DRAIN_TIME_LIMIT);
    ASSERT_EQ(Script.qwNow, 5000);
    ASSERT_EQ(Script.cCalls, 1);
    ASSERT_EQ(Script.cSleepCalls, 0);
}

static VOID TestDrainPassesRemainingDeadlineToReads(VOID)
{
    BYTE pbBuffer[64];
    DRAIN_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_DRAIN_OUTCOME Outcome;
    Script.cbNonFiller = sizeof(DWORD);
    Script.dwReadDelayMs = 1000;
    Script.fAlwaysNonFiller = TRUE;
    Outcome = RunScriptedDrain(
        &Script, pbBuffer, sizeof(pbBuffer), 0x100000);
    ASSERT_EQ(Outcome, DEVICE_FPGA_SESSION_DRAIN_TIME_LIMIT);
    ASSERT_EQ(Script.dwFirstReadTimeoutMs, 5000);
    ASSERT_EQ(Script.dwLastReadTimeoutMs, 960);
    ASSERT_EQ(Script.cCalls, 5);
    ASSERT_EQ(Script.cSleepCalls, 4);
}

static VOID TestDrainRejectsInvalidPolicy(VOID)
{
    BYTE pbBuffer[64];
    DRAIN_SCRIPT Script = { 0 };
    ASSERT_EQ(
        DeviceFPGA_Session_Drain(
            &Script,
            ScriptedDrainRead,
            pbBuffer,
            sizeof(pbBuffer),
            0x100000,
            0,
            5000,
            10,
            &Script,
            ScriptedDrainTick,
            ScriptedDrainSleep),
        DEVICE_FPGA_SESSION_DRAIN_READ_ERROR);
    ASSERT_EQ(Script.cCalls, 0);
}

int main(void)
{
    RUN_TEST(TestCompleteAlignedReply);
    RUN_TEST(TestCompleteUnalignedReply);
    RUN_TEST(TestCompleteZeroValuedReply);
    RUN_TEST(TestEmptyReplyFailsAndClearsOutput);
    RUN_TEST(TestPartialReplyFailsAndClearsOutput);
    RUN_TEST(TestWrongSourceReplyFailsAndClearsOutput);
    RUN_TEST(TestV4IdentityRetriesAndPublishesCompleteReply);
    RUN_TEST(TestV4IdentityFailureIsBoundedAndDoesNotPublish);
    RUN_TEST(TestV4IdentityAcceptsExplicitZeroFpgaId);
    RUN_TEST(TestV4IdentityRejectsLegacyMajorWithoutPublishing);
    RUN_TEST(TestV3IdentityRequiresEveryIdentityCommand);
    RUN_TEST(TestV3IdentityPublishesCompleteReply);
    RUN_TEST(TestV3IdentityAcceptsExplicitZeroFpgaId);
    RUN_TEST(TestTlpFrameIgnoresContinuationUntilFirst);
    RUN_TEST(TestTlpFrameCompletesAfterExplicitFirst);
    RUN_TEST(TestTlpFrameRestartsAtNewFirst);
    RUN_TEST(TestTlpFrameRejectsShortAndOversizePackets);
    RUN_TEST(TestTlpFrameAcceptsLegacyStreamWithoutFirst);
    RUN_TEST(TestBoundedReadReturnsImmediateCompletion);
    RUN_TEST(TestBoundedReadWaitsForPendingCompletion);
    RUN_TEST(TestBoundedReadPendingForeverTimesOut);
    RUN_TEST(TestBoundedReadReturnsSubmissionErrorWithoutPolling);
    RUN_TEST(TestBoundedReadRejectsInvalidArguments);
    RUN_TEST(TestOpportunisticReadReturnsDelayedDataWithoutCancelling);
    RUN_TEST(TestOpportunisticReadTreatsCancelledSilenceAsQuiet);
    RUN_TEST(TestOpportunisticReadPreservesCompletionThatRacesTimeout);
    RUN_TEST(TestOpportunisticReadKeepsPendingObjectWhenCancelTimesOut);
    RUN_TEST(TestOpportunisticReadReportsAbortFailure);
    RUN_TEST(TestWaitUsesEventWithoutPolling);
    RUN_TEST(TestWaitFallsBackToPollingAfterEarlyEvent);
    RUN_TEST(TestWaitCanBypassSignaledEventForPolling);
    RUN_TEST(TestWaitEventTimeoutDoesNotPoll);
    RUN_TEST(TestWaitCompletesWithoutBlockingDriverCall);
    RUN_TEST(TestWaitPendingForeverTimesOutAtDeadline);
    RUN_TEST(TestWaitReturnsDriverErrorWithoutRetry);
    RUN_TEST(TestOverlappedReadLifecycleAndCloseOrdering);
    RUN_TEST(TestClosePendingForeverIsBoundedAndDoesNotRelease);
    RUN_TEST(TestCloseReportsAbortErrorAfterAttemptingCleanup);
    RUN_TEST(TestCloseUnexpectedQueryErrorStillAbortsAndReleases);
    RUN_TEST(TestCloseReleaseFailureKeepsHandleOwnership);
    RUN_TEST(TestConfigurePipeTimeoutsConfiguresBothDirections);
    RUN_TEST(TestConfigurePipeTimeoutsReportsEitherFailure);
    RUN_TEST(TestRecoveryCoordinatorExecutesOneOrderedAttempt);
    RUN_TEST(TestRecoveryCoordinatorStopsAtEachFailedStage);
    RUN_TEST(TestRecoveryCoordinatorRejectsIncompleteOpsBeforeStarting);
    RUN_TEST(TestFillerClassificationRequiresCompleteFillerWords);
    RUN_TEST(TestDrainRequiresSustainedQuiescence);
    RUN_TEST(TestDrainResetsQuietWindowAfterTraffic);
    RUN_TEST(TestDrainReportsReadErrorWithoutRetry);
    RUN_TEST(TestDrainRejectsOversizedRead);
    RUN_TEST(TestDrainEnforcesNonFillerByteLimit);
    RUN_TEST(TestDrainEnforcesOverallDeadline);
    RUN_TEST(TestDrainDeadlineWinsAfterSlowRead);
    RUN_TEST(TestDrainPassesRemainingDeadlineToReads);
    RUN_TEST(TestDrainRejectsInvalidPolicy);
    if(g_cFailures) {
        printf("%d test assertion(s) failed.\n", g_cFailures);
        return 1;
    }
    printf("PASS: %d FPGA session protocol cases.\n", g_cTests);
    return 0;
}
