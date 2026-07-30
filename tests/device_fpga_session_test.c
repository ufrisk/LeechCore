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
    if(g_cFailures) {
        printf("%d test assertion(s) failed.\n", g_cFailures);
        return 1;
    }
    printf("PASS: 13 FPGA identity protocol cases.\n");
    return 0;
}
