// device_fpga_session.c : internal FPGA session protocol helpers.
//
#include "device_fpga_session.h"

#include <string.h>

#define DEVICE_FPGA_CMD_VERSION_MAJOR       0x01
#define DEVICE_FPGA_CMD_DEVICE_ID           0x03
#define DEVICE_FPGA_CMD_VERSION_MINOR       0x05
#define DEVICE_FPGA_V4_IDENTITY_ATTEMPTS    5

static DWORD DeviceFPGA_Session_ReadDWORD(_In_reads_(sizeof(DWORD)) PBYTE pb)
{
    DWORD dw;
    memcpy(&dw, pb, sizeof(dw));
    return dw;
}

DEVICE_FPGA_SESSION_WAIT_RESULT DeviceFPGA_Session_WaitOverlapped(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _In_ DWORD dwTimeoutMs,
    _In_ DWORD dwPollMs,
    _In_ PVOID pvTimingContext,
    _In_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep
)
{
    QWORD qwStart;
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = {
        DEVICE_FPGA_SESSION_WAIT_DRIVER_ERROR,
        (ULONG)-1,
        0
    };
    if(!hFTDI || !pOverlapped || !pfnGetOverlappedResult ||
       !dwTimeoutMs || !dwPollMs || !pfnTick || !pfnSleep) {
        return Result;
    }
    qwStart = pfnTick(pvTimingContext);
    for(;;) {
        Result.cbTransferred = 0;
        Result.status = pfnGetOverlappedResult(
            hFTDI,
            pOverlapped,
            &Result.cbTransferred,
            FALSE);
        if(Result.status == DEVICE_FPGA_SESSION_FT_OK) {
            Result.outcome = DEVICE_FPGA_SESSION_WAIT_COMPLETED;
            return Result;
        }
        Result.cbTransferred = 0;
        if(Result.status != DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE) {
            return Result;
        }
        if(pfnTick(pvTimingContext) - qwStart >= dwTimeoutMs) {
            Result.outcome = DEVICE_FPGA_SESSION_WAIT_TIMED_OUT;
            return Result;
        }
        pfnSleep(pvTimingContext, dwPollMs);
    }
}

_Success_(return)
BOOL DeviceFPGA_Session_ParseConfigReply(
    _In_reads_(cbReply) PBYTE pbReply,
    _In_ DWORD cbReply,
    _In_ WORD wBaseAddr,
    _Out_writes_(cbResult) PBYTE pbResult,
    _In_ WORD cbResult,
    _In_ WORD flags
)
{
    BOOL fSourceMatch;
    BYTE pbStaged[0x1000] = { 0 };
    BYTE pbCovered[0x1000] = { 0 };
    DWORD i, j, dwStatus, dwData;
    WORD wAddr;
    if(!pbResult || !cbResult || (wBaseAddr + cbResult > 0x1000)) { return FALSE; }
    ZeroMemory(pbResult, cbResult);
    if(!pbReply || (cbReply < 32)) { return FALSE; }
    for(i = 0; i + 32 <= cbReply; i += 32) {
        while((i + sizeof(DWORD) <= cbReply) &&
              (DeviceFPGA_Session_ReadDWORD(pbReply + i) == 0x55556666)) {
            i += sizeof(DWORD);
        }
        if(i + 32 > cbReply) { return FALSE; }
        dwStatus = DeviceFPGA_Session_ReadDWORD(pbReply + i);
        if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
        for(j = 0; j < 7; j++) {
            fSourceMatch = (dwStatus & 0x0f) == (DWORD)(flags & 0x03);
            dwData = DeviceFPGA_Session_ReadDWORD(pbReply + i + 4 + (j * 4));
            dwStatus >>= 4;
            if(!fSourceMatch) { continue; }
            wAddr = _byteswap_ushort((WORD)dwData);
            wAddr -= (flags & 0xC000) + wBaseAddr;
            if(wAddr == 0xffff) {
                pbStaged[0] = (BYTE)(dwData >> 24);
                pbCovered[0] = TRUE;
                continue;
            }
            if(wAddr >= cbResult) { continue; }
            pbStaged[wAddr] = (BYTE)(dwData >> 16);
            pbCovered[wAddr] = TRUE;
            if(wAddr < cbResult - 1) {
                pbStaged[wAddr + 1] = (BYTE)(dwData >> 24);
                pbCovered[wAddr + 1] = TRUE;
            }
        }
    }
    for(i = 0; i < cbResult; i++) {
        if(!pbCovered[i]) { return FALSE; }
    }
    memcpy(pbResult, pbStaged, cbResult);
    return TRUE;
}

_Success_(return)
BOOL DeviceFPGA_Session_ReadV4Identity(
    _In_ PVOID pvContext,
    _In_ PFN_DEVICE_FPGA_SESSION_CONFIG_READ pfnConfigRead,
    _In_ WORD flags,
    _Out_ PDEVICE_FPGA_IDENTITY pIdentity
)
{
    BYTE pbIdentity[3];
    DWORD i;
    DEVICE_FPGA_IDENTITY Identity;
    if(!pfnConfigRead || !pIdentity) { return FALSE; }
    for(i = 0; i < DEVICE_FPGA_V4_IDENTITY_ATTEMPTS; i++) {
        ZeroMemory(pbIdentity, sizeof(pbIdentity));
        if(!pfnConfigRead(pvContext, 0x0008, pbIdentity, sizeof(pbIdentity), flags)) {
            continue;
        }
        if(pbIdentity[0] < 4) { return FALSE; }
        Identity.wVersionMajor = pbIdentity[0];
        Identity.wVersionMinor = pbIdentity[1];
        Identity.wFpgaID = pbIdentity[2];
        *pIdentity = Identity;
        return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL DeviceFPGA_Session_ParseV3Identity(
    _In_reads_(cbReply) PBYTE pbReply,
    _In_ DWORD cbReply,
    _Out_ PDEVICE_FPGA_IDENTITY pIdentity,
    _Out_ PWORD pwPcieDeviceId
)
{
    BOOL fMajor = FALSE, fMinor = FALSE, fFpgaID = FALSE;
    DWORD i, j, dwStatus, dwData, cdwCfg = 0;
    WORD wPcieDeviceId = 0;
    DEVICE_FPGA_IDENTITY Identity = { 0 };
    if(!pbReply || !pIdentity || !pwPcieDeviceId || (cbReply < 32)) { return FALSE; }
    for(i = 0; i + 32 <= cbReply; i += 32) {
        while((i + sizeof(DWORD) <= cbReply) &&
              (DeviceFPGA_Session_ReadDWORD(pbReply + i) == 0x55556666)) {
            i += sizeof(DWORD);
        }
        if(i + 32 > cbReply) { return FALSE; }
        dwStatus = DeviceFPGA_Session_ReadDWORD(pbReply + i);
        if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
        for(j = 0; j < 7; j++) {
            dwData = DeviceFPGA_Session_ReadDWORD(pbReply + i + 4 + (j * 4));
            if((dwStatus & 0x03) == 0x03) {
                switch(dwData >> 24) {
                    case DEVICE_FPGA_CMD_VERSION_MAJOR:
                        Identity.wVersionMajor = (WORD)dwData;
                        fMajor = TRUE;
                        break;
                    case DEVICE_FPGA_CMD_VERSION_MINOR:
                        Identity.wVersionMinor = (WORD)dwData;
                        fMinor = TRUE;
                        break;
                    case DEVICE_FPGA_CMD_DEVICE_ID:
                        Identity.wFpgaID = (WORD)dwData;
                        fFpgaID = TRUE;
                        break;
                }
            }
            if((dwStatus & 0x03) == 0x01) {
                if(((++cdwCfg % 2) == 0) && (WORD)dwData) {
                    wPcieDeviceId = (WORD)dwData;
                }
            }
            dwStatus >>= 4;
        }
    }
    if(!fMajor || !fMinor || !fFpgaID) { return FALSE; }
    *pIdentity = Identity;
    *pwPcieDeviceId = wPcieDeviceId;
    return TRUE;
}

BOOL DeviceFPGA_Session_ConfigurePipeTimeouts(
    _In_ HANDLE hFTDI,
    _In_ ULONG ulTimeoutInMs,
    _In_ PFN_DEVICE_FPGA_SESSION_SET_PIPE_TIMEOUT pfnSetPipeTimeout
)
{
    ULONG ulRxStatus, ulTxStatus;
    if(!hFTDI || !ulTimeoutInMs || !pfnSetPipeTimeout) { return FALSE; }
    ulRxStatus = pfnSetPipeTimeout(hFTDI, 0x82, ulTimeoutInMs);
    ulTxStatus = pfnSetPipeTimeout(hFTDI, 0x02, ulTimeoutInMs);
    return
        (ulRxStatus == DEVICE_FPGA_SESSION_FT_OK) &&
        (ulTxStatus == DEVICE_FPGA_SESSION_FT_OK);
}

static QWORD DeviceFPGA_Session_DefaultTick(_In_ PVOID pvContext)
{
    UNREFERENCED_PARAMETER(pvContext);
    return GetTickCount64();
}

static VOID DeviceFPGA_Session_DefaultSleep(
    _In_ PVOID pvContext,
    _In_ DWORD dwMilliseconds
)
{
    UNREFERENCED_PARAMETER(pvContext);
    Sleep(dwMilliseconds);
}

BOOL DeviceFPGA_Session_CloseOverlapped(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_ABORT_PIPE pfnAbortPipe,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _In_ PFN_DEVICE_FPGA_SESSION_RELEASE_OVERLAPPED pfnReleaseOverlapped,
    _In_opt_ PVOID pvTimingContext,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep
)
{
    BOOL fResult = TRUE;
    DEVICE_FPGA_SESSION_WAIT_RESULT WaitResult;
    if(!hFTDI || !pOverlapped) { return TRUE; }
    if(!pfnAbortPipe || !pfnGetOverlappedResult || !pfnReleaseOverlapped) {
        return FALSE;
    }
    if(!pfnTick) { pfnTick = DeviceFPGA_Session_DefaultTick; }
    if(!pfnSleep) { pfnSleep = DeviceFPGA_Session_DefaultSleep; }
    // RX only: some callers don't hold the TX fast-write lock, and aborting TX here could cancel an in-flight write on that path.
    fResult &= pfnAbortPipe(hFTDI, 0x82) == DEVICE_FPGA_SESSION_FT_OK;
    WaitResult = DeviceFPGA_Session_WaitOverlapped(
        hFTDI,
        pOverlapped,
        pfnGetOverlappedResult,
        DEVICE_FPGA_SESSION_CANCEL_TIMEOUT_MS,
        DEVICE_FPGA_SESSION_WAIT_POLL_MS,
        pvTimingContext,
        pfnTick,
        pfnSleep);
    fResult &= WaitResult.outcome == DEVICE_FPGA_SESSION_WAIT_COMPLETED;
    fResult &= pfnReleaseOverlapped(hFTDI, pOverlapped) ==
        DEVICE_FPGA_SESSION_FT_OK;
    return fResult;
}
