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

static VOID TestCompleteReplyAcceptsTrailingFiller(VOID)
{
    BYTE pbReply[64] = {
        0x33, 0x00, 0x00, 0xe0,
        0x00, 0x08, 0x04, 0x13,
        0x00, 0x0a, 0x04, 0x00
    };
    BYTE pbActual[3] = { 0xaa, 0xbb, 0xcc };
    BYTE pbExpected[3] = { 0x04, 0x13, 0x04 };
    DWORD i, dwFiller = 0x55556666;
    for(i = 32; i < sizeof(pbReply); i += sizeof(dwFiller)) {
        memcpy(pbReply + i, &dwFiller, sizeof(dwFiller));
    }
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

static VOID BuildPCIeConfigReplyRecord(
    _Out_writes_(32) PBYTE pbRecord,
    _In_ DWORD dwData
)
{
    DWORD dwStatus = 0xe0000001;
    ZeroMemory(pbRecord, 32);
    memcpy(pbRecord, &dwStatus, sizeof(dwStatus));
    memcpy(pbRecord + sizeof(dwStatus), &dwData, sizeof(dwData));
}

static VOID TestPCIeConfigParserPlacesOneDwordAndMarksCoverage(VOID)
{
    BYTE pbReply[100];
    BYTE pbResult[0x200] = { 0 };
    BYTE pbCoverage[0x200] = { 0 };
    DWORD dwFiller = 0x55556666;
    memcpy(pbReply, &dwFiller, sizeof(dwFiller));
    BuildPCIeConfigReplyRecord(pbReply + 4, 0x08042a00);
    BuildPCIeConfigReplyRecord(pbReply + 36, 0x22112c00);
    BuildPCIeConfigReplyRecord(pbReply + 68, 0x44332e00);
    ASSERT_TRUE(DeviceFPGA_Session_ParsePCIeConfigReply(
        pbReply, sizeof(pbReply), pbResult, pbCoverage));
    ASSERT_EQ(pbResult[0x10], 0x11);
    ASSERT_EQ(pbResult[0x11], 0x22);
    ASSERT_EQ(pbResult[0x12], 0x33);
    ASSERT_EQ(pbResult[0x13], 0x44);
    ASSERT_EQ(pbCoverage[0x10], 1);
    ASSERT_EQ(pbCoverage[0x11], 1);
    ASSERT_EQ(pbCoverage[0x12], 1);
    ASSERT_EQ(pbCoverage[0x13], 1);
    ASSERT_EQ(pbCoverage[0x0f], 0);
    ASSERT_EQ(pbCoverage[0x14], 0);
}

static VOID TestPCIeConfigParserAcceptsCompleteSpaceCoverage(VOID)
{
    BYTE pbReply[32 * 3 * 128];
    BYTE pbResult[0x200] = { 0 };
    BYTE pbCoverage[0x200] = { 0 };
    DWORD i;
    for(i = 0; i < 0x200; i += 4) {
        BuildPCIeConfigReplyRecord(
            pbReply + ((i >> 2) * 96) + 0,
            0x08002a00 | ((i >> 2) << 16));
        BuildPCIeConfigReplyRecord(
            pbReply + ((i >> 2) * 96) + 32,
            (((i + 1) & 0xff) << 24) | ((i & 0xff) << 16) | 0x2c00);
        BuildPCIeConfigReplyRecord(
            pbReply + ((i >> 2) * 96) + 64,
            (((i + 3) & 0xff) << 24) | (((i + 2) & 0xff) << 16) | 0x2e00);
    }
    ASSERT_TRUE(DeviceFPGA_Session_ParsePCIeConfigReply(
        pbReply, sizeof(pbReply), pbResult, pbCoverage));
    ASSERT_TRUE(DeviceFPGA_Session_IsPCIeConfigComplete(pbCoverage, 0));
    for(i = 0; i < 0x200; i++) {
        ASSERT_EQ(pbResult[i], i & 0xff);
        ASSERT_EQ(pbCoverage[i], 1);
    }
}

static VOID TestPCIeConfigCoverageRejectsOneMissingByte(VOID)
{
    BYTE pbCoverage[0x200];
    memset(pbCoverage, 1, sizeof(pbCoverage));
    pbCoverage[0x17] = 0;
    ASSERT_FALSE(DeviceFPGA_Session_IsPCIeConfigComplete(pbCoverage, 0));
}

static VOID TestPCIeConfigCoverageAcceptsRequestedSingleDword(VOID)
{
    BYTE pbCoverage[0x200] = { 0 };
    memset(pbCoverage + 0x1fc, 1, sizeof(DWORD));
    ASSERT_TRUE(DeviceFPGA_Session_IsPCIeConfigComplete(
        pbCoverage, 0x80000000 | 0x7f));
}

static VOID TestPCIeConfigCoverageRejectsIncompleteSingleDword(VOID)
{
    BYTE pbCoverage[0x200] = { 0 };
    memset(pbCoverage + 0x40, 1, sizeof(DWORD));
    pbCoverage[0x42] = 0;
    ASSERT_FALSE(DeviceFPGA_Session_IsPCIeConfigComplete(
        pbCoverage, 0x80000000 | 0x10));
}

static VOID TestPCIeConfigCoverageRejectsOutOfRangeSingleDword(VOID)
{
    BYTE pbCoverage[0x200];
    memset(pbCoverage, 1, sizeof(pbCoverage));
    ASSERT_FALSE(DeviceFPGA_Session_IsPCIeConfigComplete(
        pbCoverage, 0x80000000 | 0x80));
}

static VOID TestPCIeConfigParserRejectsTruncatedAndFillerOnlyReply(VOID)
{
    BYTE pbFillerOnly[4] = { 0x66, 0x66, 0x55, 0x55 };
    BYTE pbTruncated[31] = { 0 };
    BYTE pbResult[0x200] = { 0 };
    BYTE pbCoverage[0x200] = { 0 };
    ASSERT_FALSE(DeviceFPGA_Session_ParsePCIeConfigReply(
        pbFillerOnly, sizeof(pbFillerOnly), pbResult, pbCoverage));
    ASSERT_FALSE(DeviceFPGA_Session_ParsePCIeConfigReply(
        pbTruncated, sizeof(pbTruncated), pbResult, pbCoverage));
}

static VOID TestPCIeConfigParserDoesNotCoverDataBeforeMetadata(VOID)
{
    BYTE pbReply[32];
    BYTE pbResult[0x200] = { 0 };
    BYTE pbCoverage[0x200] = { 0 };
    BuildPCIeConfigReplyRecord(pbReply, 0x22112c00);
    ASSERT_TRUE(DeviceFPGA_Session_ParsePCIeConfigReply(
        pbReply, sizeof(pbReply), pbResult, pbCoverage));
    ASSERT_EQ(pbResult[0], 0);
    ASSERT_EQ(pbCoverage[0], 0);
    ASSERT_FALSE(DeviceFPGA_Session_IsPCIeConfigComplete(pbCoverage, 0));
}

static VOID TestPCIeConfigBatchSizingBoundsRepliesBelowTransportBoundary(VOID)
{
    ASSERT_EQ(DeviceFPGA_Session_GetPCIeConfigBatchDWords(0, 0), 16);
    ASSERT_EQ(DeviceFPGA_Session_GetPCIeConfigBatchDWords(112, 0), 16);
    ASSERT_EQ(DeviceFPGA_Session_GetPCIeConfigBatchDWords(127, 0), 1);
    ASSERT_EQ(DeviceFPGA_Session_GetPCIeConfigBatchDWords(128, 0), 0);
    ASSERT_EQ(DeviceFPGA_Session_GetPCIeConfigBatchDWords(
        0, 0x80000000 | 0x7f), 1);
    ASSERT_EQ(DeviceFPGA_Session_GetPCIeConfigBatchDWords(
        0, 0x80000000 | 0x80), 0);
}

static VOID AssertPCIeConfigBatchAddresses(
    _In_reads_(cbBatch) PBYTE pbBatch,
    _In_ DWORD cbBatch,
    _In_ DWORD iStartDWord,
    _In_ DWORD cDWords
)
{
    DWORD i, iAddress = 0, iExpected;
    for(i = 0; i + 8 <= cbBatch; i += 8) {
        if((pbBatch[i + 4] != 0x80) ||
           (pbBatch[i + 5] != 0x14) ||
           (pbBatch[i + 6] != 0x21) ||
           (pbBatch[i + 7] != 0x77)) {
            continue;
        }
        iExpected = iStartDWord + (iAddress ? iAddress - 1 : 0);
        ASSERT_EQ(pbBatch[i], iExpected & 0xff);
        ASSERT_EQ(pbBatch[i + 1], (iExpected >> 8) & 0x03);
        iAddress++;
    }
    ASSERT_EQ(iAddress, cDWords + 1);
}

static VOID TestPCIeConfigBatchBuilderKeepsRealRequestsBelowBoundary(VOID)
{
    BYTE pbBatch[0x1000];
    DWORD cbBatch, cBatchDWords, cBatches = 0, iDWord = 0;
    while((cBatchDWords = DeviceFPGA_Session_GetPCIeConfigBatchDWords(
        iDWord, 0))) {
        memset(pbBatch, 0xcc, sizeof(pbBatch));
        cbBatch = 0;
        ASSERT_TRUE(DeviceFPGA_Session_BuildPCIeConfigBatch(
            pbBatch, sizeof(pbBatch), &cbBatch, iDWord, 0));
        ASSERT_EQ(cBatchDWords, 16);
        ASSERT_EQ(cbBatch, 912);
        ASSERT_TRUE(cbBatch < 1024);
        ASSERT_TRUE(20 + (cBatchDWords * 32) < 1024);
        AssertPCIeConfigBatchAddresses(
            pbBatch, cbBatch, iDWord, cBatchDWords);
        iDWord += cBatchDWords;
        cBatches++;
    }
    ASSERT_EQ(iDWord, 128);
    ASSERT_EQ(cBatches, 8);
}

static VOID TestPCIeConfigBatchBuilderPreservesSingleDwordRequest(VOID)
{
    BYTE pbBatch[0x1000];
    DWORD cbBatch = 0;
    ASSERT_TRUE(DeviceFPGA_Session_BuildPCIeConfigBatch(
        pbBatch,
        sizeof(pbBatch),
        &cbBatch,
        0,
        0x80000000 | 0x7f));
    ASSERT_EQ(cbBatch, 72);
    AssertPCIeConfigBatchAddresses(pbBatch, cbBatch, 0x7f, 1);
    cbBatch = 0xaa;
    ASSERT_FALSE(DeviceFPGA_Session_BuildPCIeConfigBatch(
        pbBatch, 71, &cbBatch, 0, 0x80000000 | 0x7f));
    ASSERT_EQ(cbBatch, 0);
    ASSERT_FALSE(DeviceFPGA_Session_BuildPCIeConfigBatch(
        pbBatch,
        sizeof(pbBatch),
        &cbBatch,
        0,
        0x80000000 | 0x80));
    ASSERT_EQ(cbBatch, 0);
}

#define PCIE_CONFIG_BATCH_REPLY_SIZE \
    (DEVICE_FPGA_SESSION_PCIE_CONFIG_BATCH_DWORDS * 32)

typedef struct tdPCIE_CONFIG_BATCH_REPLY_SCRIPT {
    BYTE apbReply[9][PCIE_CONFIG_BATCH_REPLY_SIZE];
    DWORD acbReply[9];
    DWORD cReplies;
    DWORD cCalls;
} PCIE_CONFIG_BATCH_REPLY_SCRIPT, *PPCIE_CONFIG_BATCH_REPLY_SCRIPT;

static VOID BuildPCIeConfigBatchReply(
    _Out_writes_(PCIE_CONFIG_BATCH_REPLY_SIZE) PBYTE pbReply,
    _In_ DWORD iStartDWord,
    _In_ BYTE bOverride
)
{
    DWORD i, oByte, dwStatus = 0xe0000111;
    DWORD dwMeta, dwDataLo, dwDataHi;
    for(i = 0; i < DEVICE_FPGA_SESSION_PCIE_CONFIG_BATCH_DWORDS; i++) {
        oByte = (iStartDWord + i) * sizeof(DWORD);
        dwMeta = 0x08002a00 | ((iStartDWord + i) << 16);
        dwDataLo =
            ((DWORD)(bOverride ? bOverride : ((oByte + 1) & 0xff)) << 24) |
            ((DWORD)(bOverride ? bOverride : (oByte & 0xff)) << 16) |
            0x2c00;
        dwDataHi =
            ((DWORD)(bOverride ? bOverride : ((oByte + 3) & 0xff)) << 24) |
            ((DWORD)(bOverride ? bOverride : ((oByte + 2) & 0xff)) << 16) |
            0x2e00;
        ZeroMemory(pbReply + (i * 32), 32);
        memcpy(pbReply + (i * 32), &dwStatus, sizeof(dwStatus));
        memcpy(pbReply + (i * 32) + 4, &dwMeta, sizeof(dwMeta));
        memcpy(pbReply + (i * 32) + 8, &dwDataLo, sizeof(dwDataLo));
        memcpy(pbReply + (i * 32) + 12, &dwDataHi, sizeof(dwDataHi));
    }
}

static ULONG WINAPI ScriptedPCIeConfigBatchRead(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbTransferred,
    _In_opt_ LPOVERLAPPED pOverlapped
)
{
    PPCIE_CONFIG_BATCH_REPLY_SCRIPT pScript =
        (PPCIE_CONFIG_BATCH_REPLY_SCRIPT)hFTDI;
    DWORD cbReply;
    UNREFERENCED_PARAMETER(pOverlapped);
    cbReply = (pScript->cCalls < pScript->cReplies) &&
        pScript->acbReply[pScript->cCalls] ?
        pScript->acbReply[pScript->cCalls] :
        PCIE_CONFIG_BATCH_REPLY_SIZE;
    if((ucPipeID != 0x82) || (cbBuffer < cbReply)) {
        *pcbTransferred = 0;
        return 1;
    }
    if(pScript->cCalls >= pScript->cReplies) {
        *pcbTransferred = 0;
        return 0;
    }
    memcpy(pbBuffer, pScript->apbReply[pScript->cCalls],
        cbReply);
    pScript->cCalls++;
    *pcbTransferred = cbReply;
    return 0;
}

static VOID TestPCIeConfigBatchReadDoesNotAdvanceOnShiftedStaleReply(VOID)
{
    PCIE_CONFIG_BATCH_REPLY_SCRIPT Script = { 0 };
    BYTE pbBuffer[0x1000] = { 0 };
    BYTE pbResult[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE] = { 0 };
    BYTE pbCoverage[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE] = { 0 };
    DWORD i, iBatch, cbRead;
    BuildPCIeConfigBatchReply(Script.apbReply[0], 112, 0xee);
    for(iBatch = 0; iBatch < 8; iBatch++) {
        BuildPCIeConfigBatchReply(
            Script.apbReply[iBatch + 1], iBatch * 16, 0);
    }
    Script.cReplies = 9;
    for(iBatch = 0; iBatch < 8; iBatch++) {
        cbRead = 0;
        ASSERT_TRUE(DeviceFPGA_Session_ReadPCIeConfigBatchMatching(
            &Script,
            pbBuffer,
            sizeof(pbBuffer),
            &cbRead,
            ScriptedPCIeConfigBatchRead,
            iBatch * 16,
            16,
            pbResult,
            pbCoverage,
            DEVICE_FPGA_SESSION_CONFIG_REPLY_TIMEOUT_MS,
            NULL,
            NULL));
    }
    ASSERT_EQ(Script.cCalls, 9);
    ASSERT_TRUE(DeviceFPGA_Session_IsPCIeConfigComplete(pbCoverage, 0));
    for(i = 0; i < sizeof(pbResult); i++) {
        ASSERT_EQ(pbResult[i], i & 0xff);
    }
}

static VOID TestPCIeConfigBatchReadRejectsStaleFutureCoverageAfterMissingReply(VOID)
{
    PCIE_CONFIG_BATCH_REPLY_SCRIPT Script = { 0 };
    BYTE pbBuffer[0x1000] = { 0 };
    BYTE pbResult[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE] = { 0 };
    BYTE pbCoverage[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE] = { 0 };
    DWORD i, iBatch, cbRead = 0xaa;
    BuildPCIeConfigBatchReply(Script.apbReply[0], 112, 0xee);
    for(iBatch = 0; iBatch < 7; iBatch++) {
        BuildPCIeConfigBatchReply(
            Script.apbReply[iBatch + 1], iBatch * 16, 0);
    }
    BuildPCIeConfigReplyRecord(Script.apbReply[8], 0x44332211);
    Script.acbReply[8] = 32;
    Script.cReplies = 9;
    for(iBatch = 0; iBatch < 7; iBatch++) {
        cbRead = 0;
        ASSERT_TRUE(DeviceFPGA_Session_ReadPCIeConfigBatchMatching(
            &Script,
            pbBuffer,
            sizeof(pbBuffer),
            &cbRead,
            ScriptedPCIeConfigBatchRead,
            iBatch * 16,
            16,
            pbResult,
            pbCoverage,
            DEVICE_FPGA_SESSION_CONFIG_REPLY_TIMEOUT_MS,
            NULL,
            NULL));
    }
    cbRead = 0xaa;
    ASSERT_FALSE(DeviceFPGA_Session_ReadPCIeConfigBatchMatching(
        &Script,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        ScriptedPCIeConfigBatchRead,
        112,
        16,
        pbResult,
        pbCoverage,
        DEVICE_FPGA_SESSION_CONFIG_REPLY_TIMEOUT_MS,
        NULL,
        NULL));
    ASSERT_EQ(cbRead, 0);
    ASSERT_EQ(Script.cCalls, 9);
    for(i = 0; i < 112 * sizeof(DWORD); i++) {
        ASSERT_EQ(pbResult[i], i & 0xff);
        ASSERT_EQ(pbCoverage[i], 1);
    }
    for(; i < sizeof(pbResult); i++) {
        ASSERT_EQ(pbResult[i], 0);
        ASSERT_EQ(pbCoverage[i], 0);
    }
}

typedef struct tdPCIE_CONFIG_READ_SCRIPT {
    BOOL afSuccess[2];
    BYTE abWrite[2];
    DWORD cCalls;
    BOOL fSecondOutputWasCleared;
} PCIE_CONFIG_READ_SCRIPT, *PPCIE_CONFIG_READ_SCRIPT;

static BOOL ScriptedPCIeConfigReadAttempt(
    _Inout_ PVOID pvContext,
    _Out_writes_(DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE) PBYTE pbResult
)
{
    PPCIE_CONFIG_READ_SCRIPT pScript = (PPCIE_CONFIG_READ_SCRIPT)pvContext;
    DWORD i, iAttempt = pScript->cCalls++;
    if(iAttempt >= 2) { return FALSE; }
    if(iAttempt == 1) {
        for(i = 0; i < DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE; i++) {
            if(pbResult[i]) {
                pScript->fSecondOutputWasCleared = FALSE;
                break;
            }
        }
    }
    memset(pbResult, pScript->abWrite[iAttempt],
        DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE);
    return pScript->afSuccess[iAttempt];
}

static VOID TestPCIeConfigRetryReturnsFirstAttemptSuccess(VOID)
{
    PCIE_CONFIG_READ_SCRIPT Script = { { TRUE, FALSE }, { 0x11, 0x00 }, 0, TRUE };
    BYTE pbResult[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE];
    memset(pbResult, 0xaa, sizeof(pbResult));
    ASSERT_TRUE(DeviceFPGA_Session_ReadPCIeConfigWithRetry(
        &Script, ScriptedPCIeConfigReadAttempt, pbResult, 0));
    ASSERT_EQ(Script.cCalls, 1);
    ASSERT_EQ(pbResult[0], 0x11);
}

static VOID TestPCIeConfigRetryClearsOutputBeforeSecondAttempt(VOID)
{
    PCIE_CONFIG_READ_SCRIPT Script = { { FALSE, TRUE }, { 0xaa, 0x22 }, 0, TRUE };
    BYTE pbResult[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE];
    memset(pbResult, 0xff, sizeof(pbResult));
    ASSERT_TRUE(DeviceFPGA_Session_ReadPCIeConfigWithRetry(
        &Script, ScriptedPCIeConfigReadAttempt, pbResult, 0));
    ASSERT_EQ(Script.cCalls, 2);
    ASSERT_TRUE(Script.fSecondOutputWasCleared);
    ASSERT_EQ(pbResult[0], 0x22);
}

static VOID TestPCIeConfigRetryStopsAfterTwoFailures(VOID)
{
    PCIE_CONFIG_READ_SCRIPT Script = { { FALSE, FALSE }, { 0xaa, 0x22 }, 0, TRUE };
    BYTE pbResult[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE];
    BYTE pbExpected[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE] = { 0 };
    memset(pbResult, 0xff, sizeof(pbResult));
    ASSERT_FALSE(DeviceFPGA_Session_ReadPCIeConfigWithRetry(
        &Script, ScriptedPCIeConfigReadAttempt, pbResult, 0));
    ASSERT_EQ(Script.cCalls, 2);
    ASSERT_TRUE(Script.fSecondOutputWasCleared);
    ASSERT_BYTES(pbResult, pbExpected, sizeof(pbResult));
}

static VOID TestPCIeConfigRetryRejectsOutOfRangeRequestWithoutAttempt(VOID)
{
    PCIE_CONFIG_READ_SCRIPT Script = { { TRUE, TRUE }, { 0x11, 0x22 }, 0, TRUE };
    BYTE pbResult[DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE];
    memset(pbResult, 0xff, sizeof(pbResult));
    ASSERT_FALSE(DeviceFPGA_Session_ReadPCIeConfigWithRetry(
        &Script,
        ScriptedPCIeConfigReadAttempt,
        pbResult,
        0x80000000 | 0x80));
    ASSERT_EQ(Script.cCalls, 0);
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

static VOID TestV3IdentityAcceptsTrailingFiller(VOID)
{
    BYTE pbReply[64] = {
        0x33, 0x03, 0x00, 0xe0,
        0x04, 0x00, 0x00, 0x01,
        0x13, 0x00, 0x00, 0x05,
        0x04, 0x00, 0x00, 0x03
    };
    DEVICE_FPGA_IDENTITY Identity = { 0xaa, 0xbb, 0xcc };
    WORD wPcieDeviceId = 0xdddd;
    DWORD i, dwFiller = 0x55556666;
    for(i = 32; i < sizeof(pbReply); i += sizeof(dwFiller)) {
        memcpy(pbReply + i, &dwFiller, sizeof(dwFiller));
    }
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
    Script.cbImmediate = 0x2345;
    Result = DeviceFPGA_Session_ReadPipeBounded(
        &Script,
        0x82,
        pbBuffer,
        sizeof(pbBuffer),
        &Overlapped,
        ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult,
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
    CloseHandle(Overlapped.hEvent);
}

static VOID TestBoundedReadReturnsSubmissionErrorWithoutPolling(VOID)
{
    BYTE pbBuffer[0x4000];
    OVERLAPPED Overlapped = { 0 };
    READ_PIPE_SCRIPT Script = { 0 };
    DEVICE_FPGA_SESSION_WAIT_RESULT Result;
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
}

static VOID TestBoundedReadRejectsInvalidArguments(VOID)
{
    BYTE pbBuffer[0x100];
    OVERLAPPED Overlapped = { 0 };
    READ_PIPE_SCRIPT Script = { 0 };
#define ASSERT_INVALID_BOUNDED_READ(handle, buffer, size, overlapped, read, get, tick, sleep) \
    ASSERT_EQ( \
        DeviceFPGA_Session_ReadPipeBounded( \
            (handle), 0x82, (buffer), (size), (overlapped), (read), (get), \
            TRUE, 1000, 1, &Script.Wait, (tick), (sleep)).outcome, \
        DEVICE_FPGA_SESSION_WAIT_DRIVER_ERROR)
    ASSERT_INVALID_BOUNDED_READ(
        NULL, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, NULL, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, 0, &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), NULL, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, NULL,
        ScriptedWaitGetOverlappedResult, ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        NULL, ScriptedWaitTick, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, NULL, ScriptedWaitSleep);
    ASSERT_INVALID_BOUNDED_READ(
        &Script, pbBuffer, sizeof(pbBuffer), &Overlapped, ScriptedReadPipe,
        ScriptedWaitGetOverlappedResult, ScriptedWaitTick, NULL);
#undef ASSERT_INVALID_BOUNDED_READ
    ASSERT_EQ(Script.cReadCalls, 0);
    ASSERT_EQ(Script.Wait.cGetCalls, 0);
    ASSERT_EQ(Script.Wait.cSleepCalls, 0);
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

typedef struct tdCONFIG_REPLY_READ_SCRIPT {
    BYTE pbReply[2][32];
    DWORD pcbReply[2];
    DWORD cCalls;
    DWORD dwReadDelayMs;
    QWORD qwNow;
} CONFIG_REPLY_READ_SCRIPT, *PCONFIG_REPLY_READ_SCRIPT;

static ULONG WINAPI ScriptedConfigReplyRead(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbTransferred,
    _In_ LPOVERLAPPED pOverlapped
)
{
    PCONFIG_REPLY_READ_SCRIPT pScript =
        (PCONFIG_REPLY_READ_SCRIPT)hFTDI;
    DWORD iCall = pScript->cCalls++;
    UNREFERENCED_PARAMETER(ucPipeID);
    UNREFERENCED_PARAMETER(pOverlapped);
    pScript->qwNow += pScript->dwReadDelayMs;
    if(iCall >= 2 || pScript->pcbReply[iCall] > cbBuffer) {
        *pcbTransferred = 0;
        return 1;
    }
    memcpy(pbBuffer, pScript->pbReply[iCall], pScript->pcbReply[iCall]);
    *pcbTransferred = pScript->pcbReply[iCall];
    return 0;
}

static QWORD ScriptedConfigReplyTick(_In_opt_ PVOID pvContext)
{
    return ((PCONFIG_REPLY_READ_SCRIPT)pvContext)->qwNow;
}

static VOID SetConfigReplyFiller(
    _Out_writes_(20) PBYTE pb,
    _Out_ PDWORD pcb
)
{
    DWORD i;
    DWORD dwFiller = 0x55556666;
    for(i = 0; i < 20; i += sizeof(dwFiller)) {
        memcpy(pb + i, &dwFiller, sizeof(dwFiller));
    }
    *pcb = 20;
}

static VOID SetConfigReplyRecord(
    _Out_writes_(32) PBYTE pb,
    _Out_ PDWORD pcb
)
{
    static const BYTE pbRecord[32] = {
        0x33, 0x00, 0x00, 0xe0,
        0x00, 0x08, 0x04, 0x13,
        0x00, 0x0a, 0x04, 0x00
    };
    memcpy(pb, pbRecord, sizeof(pbRecord));
    *pcb = sizeof(pbRecord);
}

typedef struct tdMATCHING_CONFIG_REPLY_SCRIPT {
    DWORD cCalls;
    DWORD cWrongReplies;
    BOOL fNeverMatch;
    BOOL fSplitReply;
    BOOL fTrailingFiller;
} MATCHING_CONFIG_REPLY_SCRIPT, *PMATCHING_CONFIG_REPLY_SCRIPT;

static ULONG WINAPI ScriptedMatchingConfigReplyRead(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbTransferred,
    _In_ LPOVERLAPPED pOverlapped
)
{
    PMATCHING_CONFIG_REPLY_SCRIPT pScript =
        (PMATCHING_CONFIG_REPLY_SCRIPT)hFTDI;
    BYTE pbReply[64];
    DWORD cbReply, i, dwFiller = 0x55556666;
    UNREFERENCED_PARAMETER(ucPipeID);
    UNREFERENCED_PARAMETER(pOverlapped);
    SetConfigReplyRecord(pbReply, &cbReply);
    if(pScript->fSplitReply) {
        if((pScript->cCalls >= 2) || (cbBuffer < 16)) {
            *pcbTransferred = 0;
            return 1;
        }
        memcpy(pbBuffer, pbReply + (pScript->cCalls * 16), 16);
        pScript->cCalls++;
        *pcbTransferred = 16;
        return 0;
    }
    if(pScript->fTrailingFiller) {
        for(i = cbReply; i < sizeof(pbReply); i += sizeof(dwFiller)) {
            memcpy(pbReply + i, &dwFiller, sizeof(dwFiller));
        }
        cbReply = sizeof(pbReply);
    }
    if(cbBuffer < cbReply) {
        *pcbTransferred = 0;
        return 1;
    }
    if(pScript->fNeverMatch ||
       (pScript->cCalls < pScript->cWrongReplies)) {
        pbReply[5] = 0x20;
        pbReply[9] = 0x22;
    }
    memcpy(pbBuffer, pbReply, cbReply);
    pScript->cCalls++;
    *pcbTransferred = cbReply;
    return 0;
}

static VOID TestConfigReplyReadSkipsUnrelatedNonFillerReplies(VOID)
{
    MATCHING_CONFIG_REPLY_SCRIPT Script = { 0 };
    BYTE pbBuffer[128] = { 0 };
    BYTE pbResult[3] = { 0 };
    BYTE pbExpected[3] = { 0x04, 0x13, 0x04 };
    DWORD cbRead = 0;
    Script.cWrongReplies = 2;
    ASSERT_TRUE(DeviceFPGA_Session_ReadConfigReplyMatching(
        &Script,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        ScriptedMatchingConfigReplyRead,
        0x0008,
        pbResult,
        sizeof(pbResult),
        0x0003,
        DEVICE_FPGA_SESSION_CONFIG_REPLY_TIMEOUT_MS,
        NULL,
        NULL));
    ASSERT_EQ(Script.cCalls, 3);
    ASSERT_EQ(cbRead, 96);
    ASSERT_BYTES(pbResult, pbExpected, sizeof(pbExpected));
}

static VOID TestConfigReplyReadBoundsUnrelatedNonFillerReplies(VOID)
{
    MATCHING_CONFIG_REPLY_SCRIPT Script = { 0 };
    BYTE pbBuffer[
        DEVICE_FPGA_SESSION_CONFIG_REPLY_MAX_READS * 32] = { 0 };
    BYTE pbResult[3] = { 0 };
    DWORD cbRead = 0xaa;
    Script.fNeverMatch = TRUE;
    ASSERT_FALSE(DeviceFPGA_Session_ReadConfigReplyMatching(
        &Script,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        ScriptedMatchingConfigReplyRead,
        0x0008,
        pbResult,
        sizeof(pbResult),
        0x0003,
        DEVICE_FPGA_SESSION_CONFIG_REPLY_TIMEOUT_MS,
        NULL,
        NULL));
    ASSERT_EQ(Script.cCalls, DEVICE_FPGA_SESSION_CONFIG_REPLY_MAX_READS);
    ASSERT_EQ(cbRead, 0);
}

static VOID TestMatchingConfigReplyReadRejectsZeroTransferImmediately(VOID)
{
    CONFIG_REPLY_READ_SCRIPT Script = { 0 };
    BYTE pbBuffer[64] = { 0 };
    BYTE pbResult[3] = { 0 };
    DWORD cbRead = 0xaa;
    ASSERT_FALSE(DeviceFPGA_Session_ReadConfigReplyMatching(
        &Script,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        ScriptedConfigReplyRead,
        0x0008,
        pbResult,
        sizeof(pbResult),
        0x0003,
        DEVICE_FPGA_SESSION_CONFIG_REPLY_TIMEOUT_MS,
        NULL,
        NULL));
    ASSERT_EQ(Script.cCalls, 1);
    ASSERT_EQ(cbRead, 0);
}

static VOID TestMatchingConfigReplyReadStopsAtOverallDeadline(VOID)
{
    CONFIG_REPLY_READ_SCRIPT Script = { 0 };
    BYTE pbBuffer[64] = { 0 };
    BYTE pbResult[3] = { 0 };
    DWORD cbRead = 0xaa;
    Script.dwReadDelayMs = 100;
    SetConfigReplyFiller(Script.pbReply[0], &Script.pcbReply[0]);
    SetConfigReplyRecord(Script.pbReply[1], &Script.pcbReply[1]);
    ASSERT_FALSE(DeviceFPGA_Session_ReadConfigReplyMatching(
        &Script,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        ScriptedConfigReplyRead,
        0x0008,
        pbResult,
        sizeof(pbResult),
        0x0003,
        100,
        &Script,
        ScriptedConfigReplyTick));
    ASSERT_EQ(Script.cCalls, 1);
    ASSERT_EQ(cbRead, 0);
}

static VOID TestConfigReplyReadAccumulatesSplitReply(VOID)
{
    MATCHING_CONFIG_REPLY_SCRIPT Script = { 0 };
    BYTE pbBuffer[64] = { 0 };
    BYTE pbResult[3] = { 0 };
    BYTE pbExpected[3] = { 0x04, 0x13, 0x04 };
    DWORD cbRead = 0;
    Script.fSplitReply = TRUE;
    ASSERT_TRUE(DeviceFPGA_Session_ReadConfigReplyMatching(
        &Script,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        ScriptedMatchingConfigReplyRead,
        0x0008,
        pbResult,
        sizeof(pbResult),
        0x0003,
        DEVICE_FPGA_SESSION_CONFIG_REPLY_TIMEOUT_MS,
        NULL,
        NULL));
    ASSERT_EQ(Script.cCalls, 2);
    ASSERT_EQ(cbRead, 32);
    ASSERT_BYTES(pbResult, pbExpected, sizeof(pbExpected));
}

static VOID TestConfigReplyReadAcceptsTrailingFillerWithoutAnotherRead(VOID)
{
    MATCHING_CONFIG_REPLY_SCRIPT Script = { 0 };
    BYTE pbBuffer[64] = { 0 };
    BYTE pbResult[3] = { 0 };
    BYTE pbExpected[3] = { 0x04, 0x13, 0x04 };
    DWORD cbRead = 0;
    Script.fTrailingFiller = TRUE;
    ASSERT_TRUE(DeviceFPGA_Session_ReadConfigReplyMatching(
        &Script,
        pbBuffer,
        sizeof(pbBuffer),
        &cbRead,
        ScriptedMatchingConfigReplyRead,
        0x0008,
        pbResult,
        sizeof(pbResult),
        0x0003,
        DEVICE_FPGA_SESSION_CONFIG_REPLY_TIMEOUT_MS,
        NULL,
        NULL));
    ASSERT_EQ(Script.cCalls, 1);
    ASSERT_EQ(cbRead, sizeof(pbBuffer));
    ASSERT_BYTES(pbResult, pbExpected, sizeof(pbExpected));
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

static VOID AssertPCIeLinkInfo(
    _In_ BOOL fPhySupported,
    _In_ BYTE bRate,
    _In_ BYTE bWidthIndex,
    _In_ BOOL fExpected,
    _In_ BYTE bExpectedGen,
    _In_ BYTE bExpectedWidth
)
{
    BYTE bGen = 0xaa;
    BYTE bWidth = 0xbb;
    ASSERT_EQ(
        DeviceFPGA_Session_GetPCIeLinkInfo(
            fPhySupported,
            bRate,
            bWidthIndex,
            &bGen,
            &bWidth),
        fExpected);
    ASSERT_EQ(bGen, bExpectedGen);
    ASSERT_EQ(bWidth, bExpectedWidth);
}

static VOID TestPCIeLinkInfoRejectsUnavailableAndOutOfRangeState(VOID)
{
    BYTE bGen = 0xaa;
    BYTE bWidth = 0xbb;
    AssertPCIeLinkInfo(FALSE, 0, 0, FALSE, 0, 0);
    AssertPCIeLinkInfo(TRUE, 2, 0, FALSE, 0, 0);
    AssertPCIeLinkInfo(TRUE, 0, 4, FALSE, 0, 0);
    ASSERT_FALSE(DeviceFPGA_Session_GetPCIeLinkInfo(
        TRUE, 0, 0, NULL, &bWidth));
    ASSERT_EQ(bWidth, 0);
    ASSERT_FALSE(DeviceFPGA_Session_GetPCIeLinkInfo(
        TRUE, 0, 0, &bGen, NULL));
    ASSERT_EQ(bGen, 0);
    ASSERT_FALSE(DeviceFPGA_Session_GetPCIeLinkInfo(
        TRUE, 0, 0, NULL, NULL));
}

static VOID TestPCIeLinkInfoMapsSupportedRateAndWidthIndexes(VOID)
{
    AssertPCIeLinkInfo(TRUE, 0, 0, TRUE, 1, 1);
    AssertPCIeLinkInfo(TRUE, 0, 1, TRUE, 1, 2);
    AssertPCIeLinkInfo(TRUE, 0, 2, TRUE, 1, 4);
    AssertPCIeLinkInfo(TRUE, 0, 3, TRUE, 1, 8);
    AssertPCIeLinkInfo(TRUE, 1, 0, TRUE, 2, 1);
    AssertPCIeLinkInfo(TRUE, 1, 1, TRUE, 2, 2);
    AssertPCIeLinkInfo(TRUE, 1, 2, TRUE, 2, 4);
    AssertPCIeLinkInfo(TRUE, 1, 3, TRUE, 2, 8);
}

static VOID TestCustomPCIeConfigRequiresSuccessfulNonDefaultRead(VOID)
{
    ASSERT_FALSE(DeviceFPGA_Session_IsCustomPCIeConfig(
        FALSE, 0x12345678));
    ASSERT_FALSE(DeviceFPGA_Session_IsCustomPCIeConfig(TRUE, 0));
    ASSERT_FALSE(DeviceFPGA_Session_IsCustomPCIeConfig(
        TRUE, 0x066610ee));
    ASSERT_TRUE(DeviceFPGA_Session_IsCustomPCIeConfig(
        TRUE, 0x12345678));
}

int main(void)
{
    RUN_TEST(TestCompleteAlignedReply);
    RUN_TEST(TestCompleteReplyAcceptsTrailingFiller);
    RUN_TEST(TestCompleteUnalignedReply);
    RUN_TEST(TestCompleteZeroValuedReply);
    RUN_TEST(TestEmptyReplyFailsAndClearsOutput);
    RUN_TEST(TestPartialReplyFailsAndClearsOutput);
    RUN_TEST(TestWrongSourceReplyFailsAndClearsOutput);
    RUN_TEST(TestPCIeConfigParserPlacesOneDwordAndMarksCoverage);
    RUN_TEST(TestPCIeConfigParserAcceptsCompleteSpaceCoverage);
    RUN_TEST(TestPCIeConfigCoverageRejectsOneMissingByte);
    RUN_TEST(TestPCIeConfigCoverageAcceptsRequestedSingleDword);
    RUN_TEST(TestPCIeConfigCoverageRejectsIncompleteSingleDword);
    RUN_TEST(TestPCIeConfigCoverageRejectsOutOfRangeSingleDword);
    RUN_TEST(TestPCIeConfigParserRejectsTruncatedAndFillerOnlyReply);
    RUN_TEST(TestPCIeConfigParserDoesNotCoverDataBeforeMetadata);
    RUN_TEST(TestPCIeConfigBatchSizingBoundsRepliesBelowTransportBoundary);
    RUN_TEST(TestPCIeConfigBatchBuilderKeepsRealRequestsBelowBoundary);
    RUN_TEST(TestPCIeConfigBatchBuilderPreservesSingleDwordRequest);
    RUN_TEST(TestPCIeConfigBatchReadDoesNotAdvanceOnShiftedStaleReply);
    RUN_TEST(TestPCIeConfigBatchReadRejectsStaleFutureCoverageAfterMissingReply);
    RUN_TEST(TestPCIeConfigRetryReturnsFirstAttemptSuccess);
    RUN_TEST(TestPCIeConfigRetryClearsOutputBeforeSecondAttempt);
    RUN_TEST(TestPCIeConfigRetryStopsAfterTwoFailures);
    RUN_TEST(TestPCIeConfigRetryRejectsOutOfRangeRequestWithoutAttempt);
    RUN_TEST(TestV4IdentityRetriesAndPublishesCompleteReply);
    RUN_TEST(TestV4IdentityFailureIsBoundedAndDoesNotPublish);
    RUN_TEST(TestV4IdentityAcceptsExplicitZeroFpgaId);
    RUN_TEST(TestV4IdentityRejectsLegacyMajorWithoutPublishing);
    RUN_TEST(TestV3IdentityRequiresEveryIdentityCommand);
    RUN_TEST(TestV3IdentityPublishesCompleteReply);
    RUN_TEST(TestV3IdentityAcceptsTrailingFiller);
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
    RUN_TEST(TestWaitUsesEventWithoutPolling);
    RUN_TEST(TestWaitFallsBackToPollingAfterEarlyEvent);
    RUN_TEST(TestWaitCanBypassSignaledEventForPolling);
    RUN_TEST(TestWaitEventTimeoutDoesNotPoll);
    RUN_TEST(TestWaitCompletesWithoutBlockingDriverCall);
    RUN_TEST(TestWaitPendingForeverTimesOutAtDeadline);
    RUN_TEST(TestWaitReturnsDriverErrorWithoutRetry);
    RUN_TEST(TestCloseCancelsReadPipeBeforeWaiting);
    RUN_TEST(TestClosePendingForeverIsBoundedAndStillReleases);
    RUN_TEST(TestCloseReportsAbortErrorAfterAttemptingCleanup);
    RUN_TEST(TestConfigurePipeTimeoutsConfiguresBothDirections);
    RUN_TEST(TestConfigurePipeTimeoutsReportsEitherFailure);
    RUN_TEST(TestRecoveryCoordinatorExecutesOneOrderedAttempt);
    RUN_TEST(TestRecoveryCoordinatorStopsAtEachFailedStage);
    RUN_TEST(TestRecoveryCoordinatorRejectsIncompleteOpsBeforeStarting);
    RUN_TEST(TestFillerClassificationRequiresCompleteFillerWords);
    RUN_TEST(TestConfigReplyReadSkipsUnrelatedNonFillerReplies);
    RUN_TEST(TestConfigReplyReadBoundsUnrelatedNonFillerReplies);
    RUN_TEST(TestMatchingConfigReplyReadRejectsZeroTransferImmediately);
    RUN_TEST(TestMatchingConfigReplyReadStopsAtOverallDeadline);
    RUN_TEST(TestConfigReplyReadAccumulatesSplitReply);
    RUN_TEST(TestConfigReplyReadAcceptsTrailingFillerWithoutAnotherRead);
    RUN_TEST(TestDrainRequiresSustainedQuiescence);
    RUN_TEST(TestDrainResetsQuietWindowAfterTraffic);
    RUN_TEST(TestDrainReportsReadErrorWithoutRetry);
    RUN_TEST(TestDrainRejectsOversizedRead);
    RUN_TEST(TestDrainEnforcesNonFillerByteLimit);
    RUN_TEST(TestDrainEnforcesOverallDeadline);
    RUN_TEST(TestDrainDeadlineWinsAfterSlowRead);
    RUN_TEST(TestDrainPassesRemainingDeadlineToReads);
    RUN_TEST(TestDrainRejectsInvalidPolicy);
    RUN_TEST(TestPCIeLinkInfoRejectsUnavailableAndOutOfRangeState);
    RUN_TEST(TestPCIeLinkInfoMapsSupportedRateAndWidthIndexes);
    RUN_TEST(TestCustomPCIeConfigRequiresSuccessfulNonDefaultRead);
    if(g_cFailures) {
        printf("%d test assertion(s) failed.\n", g_cFailures);
        return 1;
    }
    printf("PASS: %d FPGA session protocol cases.\n", g_cTests);
    return 0;
}
