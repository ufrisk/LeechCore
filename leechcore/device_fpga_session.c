// device_fpga_session.c : internal FPGA session protocol helpers.
//
#include "device_fpga_session.h"

#include <string.h>

#define DEVICE_FPGA_CMD_VERSION_MAJOR       0x01
#define DEVICE_FPGA_CMD_DEVICE_ID           0x03
#define DEVICE_FPGA_CMD_VERSION_MINOR       0x05
#define DEVICE_FPGA_V4_IDENTITY_ATTEMPTS    5

static QWORD DeviceFPGA_Session_DefaultTick(_In_ PVOID pvContext);

static DWORD DeviceFPGA_Session_ReadDWORD(_In_reads_(sizeof(DWORD)) PBYTE pb)
{
    DWORD dw;
    memcpy(&dw, pb, sizeof(dw));
    return dw;
}

BOOL DeviceFPGA_Session_GetPCIeLinkInfo(
    _In_ BOOL fPhySupported,
    _In_ BYTE bRate,
    _In_ BYTE bWidthIndex,
    _Out_opt_ PBYTE pbGen,
    _Out_opt_ PBYTE pbWidth
)
{
    const BYTE pbLinkWidth[4] = { 1, 2, 4, 8 };
    if(pbGen) { *pbGen = 0; }
    if(pbWidth) { *pbWidth = 0; }
    if(!fPhySupported || !pbGen || !pbWidth || (bRate > 1) ||
       (bWidthIndex > 3)) {
        return FALSE;
    }
    *pbGen = 1 + bRate;
    *pbWidth = pbLinkWidth[bWidthIndex];
    return TRUE;
}

BOOL DeviceFPGA_Session_IsCustomPCIeConfig(
    _In_ BOOL fReadSuccess,
    _In_ DWORD dwVIDPID
)
{
    return fReadSuccess && dwVIDPID && (dwVIDPID != 0x066610ee);
}

#ifndef LINUX
DEVICE_FPGA_SESSION_TLP_FRAME_ACTION DeviceFPGA_Session_TlpFrameStep(
    _Inout_ PDEVICE_FPGA_SESSION_TLP_FRAME_STATE pState,
    _In_ BYTE bStatus,
    _In_ DWORD cdwMax
)
{
    DEVICE_FPGA_SESSION_TLP_FRAME_ACTION Action;
    if(!pState || !cdwMax) {
        return DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED;
    }
    bStatus &= 0x0f;
    if(bStatus & 0x03) {
        return DEVICE_FPGA_SESSION_TLP_FRAME_IGNORE;
    }
    if(bStatus & 0x08) {
        Action = pState->fInTlp ?
            DEVICE_FPGA_SESSION_TLP_FRAME_RESTART :
            DEVICE_FPGA_SESSION_TLP_FRAME_APPEND;
        pState->fInTlp = TRUE;
        pState->cdwTlp = 0;
    } else {
        if(!pState->fInTlp) {
            if(pState->fRequireFirst) {
                return DEVICE_FPGA_SESSION_TLP_FRAME_IGNORE;
            }
            pState->fInTlp = TRUE;
            pState->cdwTlp = 0;
        }
        Action = DEVICE_FPGA_SESSION_TLP_FRAME_APPEND;
    }
    if(pState->cdwTlp >= cdwMax) {
        pState->fInTlp = FALSE;
        pState->cdwTlp = 0;
        return DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED;
    }
    pState->cdwTlp++;
    if(bStatus & 0x04) {
        pState->fInTlp = FALSE;
        if(pState->cdwTlp < 3) {
            pState->cdwTlp = 0;
            return DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED;
        }
        return DEVICE_FPGA_SESSION_TLP_FRAME_COMPLETE;
    }
    return Action;
}
#endif /* LINUX */

DEVICE_FPGA_SESSION_WAIT_RESULT DeviceFPGA_Session_WaitOverlapped(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _In_ BOOL fUseEventWait,
    _In_ DWORD dwTimeoutMs,
    _In_ DWORD dwPollMs,
    _In_opt_ PVOID pvTimingContext,
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
#ifdef WIN32
    if(fUseEventWait && pOverlapped->hEvent) {
        DWORD dwWaitResult;
        Result.status = DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE;
        dwWaitResult = WaitForSingleObject(
            pOverlapped->hEvent,
            dwTimeoutMs);
        if(dwWaitResult == WAIT_TIMEOUT) {
            Result.outcome = DEVICE_FPGA_SESSION_WAIT_TIMED_OUT;
            return Result;
        }
        if(dwWaitResult != WAIT_OBJECT_0) {
            Result.status = (ULONG)-1;
            return Result;
        }
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
    }
#endif /* WIN32 */
#ifdef LINUX
    if(fUseEventWait) {
        Result.status = pfnGetOverlappedResult(
            hFTDI,
            pOverlapped,
            &Result.cbTransferred,
            TRUE);
        if(Result.status == DEVICE_FPGA_SESSION_FT_OK) {
            Result.outcome = DEVICE_FPGA_SESSION_WAIT_COMPLETED;
            return Result;
        }
        Result.cbTransferred = 0;
        if(Result.status == DEVICE_FPGA_SESSION_FT_TIMEOUT) {
            Result.outcome = DEVICE_FPGA_SESSION_WAIT_TIMED_OUT;
            return Result;
        }
        if(Result.status != DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE) {
            return Result;
        }
    }
#endif /* LINUX */
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

DEVICE_FPGA_SESSION_WAIT_RESULT DeviceFPGA_Session_ReadPipeBounded(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_READ_PIPE pfnReadPipe,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _In_ BOOL fUseEventWait,
    _In_ DWORD dwTimeoutMs,
    _In_ DWORD dwPollMs,
    _In_opt_ PVOID pvTimingContext,
    _In_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep
)
{
    DEVICE_FPGA_SESSION_WAIT_RESULT Result = {
        DEVICE_FPGA_SESSION_WAIT_DRIVER_ERROR,
        (ULONG)-1,
        0
    };
    if(!hFTDI || !pbBuffer || !cbBuffer || !pOverlapped || !pfnReadPipe ||
       !pfnGetOverlappedResult || !dwTimeoutMs || !dwPollMs ||
       !pfnTick || !pfnSleep) {
        return Result;
    }
    Result.status = pfnReadPipe(
        hFTDI,
        ucPipeID,
        pbBuffer,
        cbBuffer,
        &Result.cbTransferred,
        pOverlapped);
    if(Result.status == DEVICE_FPGA_SESSION_FT_OK) {
        Result.outcome = DEVICE_FPGA_SESSION_WAIT_COMPLETED;
        return Result;
    }
    Result.cbTransferred = 0;
    if(Result.status != DEVICE_FPGA_SESSION_FT_IO_PENDING) {
        return Result;
    }
    return DeviceFPGA_Session_WaitOverlapped(
        hFTDI,
        pOverlapped,
        pfnGetOverlappedResult,
        fUseEventWait,
        dwTimeoutMs,
        dwPollMs,
        pvTimingContext,
        pfnTick,
        pfnSleep);
}

DEVICE_FPGA_SESSION_RECOVERY_STAGE DeviceFPGA_Session_Recover(
    _Inout_ PVOID pvContext,
    _In_ PDEVICE_FPGA_SESSION_RECOVERY_OPS pOps
)
{
    if(!pvContext || !pOps ||
       !pOps->pfnQuiesceOldHandle ||
       !pOps->pfnReopenHandle ||
       !pOps->pfnInitializeOverlapped ||
       !pOps->pfnInvalidateState ||
       !pOps->pfnDrainStaleTraffic ||
       !pOps->pfnValidateIdentity) {
        return DEVICE_FPGA_SESSION_RECOVERY_QUIESCE_FAILED;
    }
    if(!pOps->pfnQuiesceOldHandle(pvContext)) {
        return DEVICE_FPGA_SESSION_RECOVERY_QUIESCE_FAILED;
    }
    if(!pOps->pfnReopenHandle(pvContext)) {
        return DEVICE_FPGA_SESSION_RECOVERY_REOPEN_FAILED;
    }
    if(!pOps->pfnInitializeOverlapped(pvContext)) {
        return DEVICE_FPGA_SESSION_RECOVERY_INITIALIZE_FAILED;
    }
    pOps->pfnInvalidateState(pvContext);
    if(!pOps->pfnDrainStaleTraffic(pvContext)) {
        return DEVICE_FPGA_SESSION_RECOVERY_DRAIN_FAILED;
    }
    if(!pOps->pfnValidateIdentity(pvContext)) {
        return DEVICE_FPGA_SESSION_RECOVERY_IDENTITY_FAILED;
    }
    return DEVICE_FPGA_SESSION_RECOVERY_READY;
}

BOOL DeviceFPGA_Session_IsFillerOnly(
    _In_reads_(cb) PBYTE pb,
    _In_ DWORD cb
)
{
    DWORD i, dw;
    if(!cb) { return TRUE; }
    if(!pb || (cb % sizeof(DWORD))) { return FALSE; }
    for(i = 0; i < cb; i += sizeof(DWORD)) {
        memcpy(&dw, pb + i, sizeof(dw));
        if(dw != 0x55556666) { return FALSE; }
    }
    return TRUE;
}

/*
* A fresh FT601 session may return one already-queued idle filler burst before
* the configuration reply. Consume that boundary without replaying the request.
*/
_Success_(return)
BOOL DeviceFPGA_Session_ReadConfigReply(
    _In_ HANDLE hFTDI,
    _Out_writes_to_(cbBuffer, *pcbRead) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PDWORD pcbRead,
    _In_ PFN_DEVICE_FPGA_SESSION_READ_PIPE pfnReadPipe,
    _In_ DWORD dwTimeoutMs,
    _In_opt_ PVOID pvTimingContext,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick
)
{
    DWORD i;
    QWORD qwStart;
    ULONG cbRead;
    if(!pcbRead) { return FALSE; }
    *pcbRead = 0;
    if(!hFTDI || !pbBuffer || !cbBuffer || !pfnReadPipe || !dwTimeoutMs) {
        return FALSE;
    }
    // A synchronous read retains the driver's in-flight timeout; this budget
    // bounds repeated reads before and after each driver call.
    if(!pfnTick) { pfnTick = DeviceFPGA_Session_DefaultTick; }
    qwStart = pfnTick(pvTimingContext);
    for(i = 0; i < 2; i++) {
        if(pfnTick(pvTimingContext) - qwStart >= dwTimeoutMs) {
            return FALSE;
        }
        cbRead = 0;
        if(pfnReadPipe(
            hFTDI,
            0x82,
            pbBuffer,
            cbBuffer,
            &cbRead,
            NULL) ||
           (cbRead > cbBuffer)) {
            return FALSE;
        }
        if(!cbRead) { return FALSE; }
        if(pfnTick(pvTimingContext) - qwStart >= dwTimeoutMs) {
            return FALSE;
        }
        if(!DeviceFPGA_Session_IsFillerOnly(pbBuffer, cbRead)) {
            *pcbRead = cbRead;
            return TRUE;
        }
    }
    return FALSE;
}

/*
* Configuration replies may be preceded by framed responses from earlier
* requests or split across receives. Accumulate a bounded sequence and return
* only after the requested register range has complete source/address coverage.
*/
_Success_(return)
BOOL DeviceFPGA_Session_ReadConfigReplyMatching(
    _In_ HANDLE hFTDI,
    _Out_writes_to_(cbBuffer, *pcbRead) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PDWORD pcbRead,
    _In_ PFN_DEVICE_FPGA_SESSION_READ_PIPE pfnReadPipe,
    _In_ WORD wBaseAddr,
    _Out_writes_(cbResult) PBYTE pbResult,
    _In_ WORD cbResult,
    _In_ WORD flags,
    _In_ DWORD dwTimeoutMs,
    _In_opt_ PVOID pvTimingContext,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick
)
{
    DWORD i, cbAccumulated = 0, cbReadMax;
    QWORD qwStart;
    ULONG cbRead;
    if(!pcbRead) { return FALSE; }
    *pcbRead = 0;
    if(!hFTDI || !pbBuffer || !cbBuffer || !pfnReadPipe ||
       !pbResult || !cbResult || !dwTimeoutMs) {
        return FALSE;
    }
    // A synchronous read retains the driver's in-flight timeout; this budget
    // bounds repeated reads before and after each driver call.
    if(!pfnTick) { pfnTick = DeviceFPGA_Session_DefaultTick; }
    qwStart = pfnTick(pvTimingContext);
    for(i = 0; i < DEVICE_FPGA_SESSION_CONFIG_REPLY_MAX_READS; i++) {
        if(pfnTick(pvTimingContext) - qwStart >= dwTimeoutMs) {
            return FALSE;
        }
        if(cbAccumulated >= cbBuffer) { return FALSE; }
        cbReadMax = cbBuffer - cbAccumulated;
        cbRead = 0;
        if(pfnReadPipe(
            hFTDI,
            0x82,
            pbBuffer + cbAccumulated,
            cbReadMax,
            &cbRead,
            NULL) ||
           (cbRead > cbReadMax)) {
            return FALSE;
        }
        if(!cbRead) { return FALSE; }
        if(pfnTick(pvTimingContext) - qwStart >= dwTimeoutMs) {
            return FALSE;
        }
        if(DeviceFPGA_Session_IsFillerOnly(
            pbBuffer + cbAccumulated, cbRead)) {
            continue;
        }
        cbAccumulated += cbRead;
        if(DeviceFPGA_Session_ParseConfigReply(
            pbBuffer,
            cbAccumulated,
            wBaseAddr,
            pbResult,
            cbResult,
            flags)) {
            *pcbRead = cbAccumulated;
            return TRUE;
        }
    }
    return FALSE;
}

DEVICE_FPGA_SESSION_DRAIN_OUTCOME DeviceFPGA_Session_Drain(
    _Inout_ PVOID pvContext,
    _In_ PFN_DEVICE_FPGA_SESSION_DRAIN_READ pfnRead,
    _Out_writes_(cbBuffer) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _In_ DWORD cbMaxNonFiller,
    _In_ DWORD dwQuietMs,
    _In_ DWORD dwTimeoutMs,
    _In_ DWORD dwPollMs,
    _In_ PVOID pvTimingContext,
    _In_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep
)
{
    DWORD cbRead, cbNonFiller = 0, dwReadTimeoutMs, dwSleepMs;
    QWORD qwNow, qwStart, qwLastNonFiller;
    if(!pfnRead || !pbBuffer || !cbBuffer || !cbMaxNonFiller ||
       !dwQuietMs || !dwTimeoutMs || !dwPollMs || !pfnTick || !pfnSleep) {
        return DEVICE_FPGA_SESSION_DRAIN_READ_ERROR;
    }
    qwStart = pfnTick(pvTimingContext);
    qwLastNonFiller = qwStart;
    for(;;) {
        qwNow = pfnTick(pvTimingContext);
        if(qwNow - qwStart >= dwTimeoutMs) {
            return DEVICE_FPGA_SESSION_DRAIN_TIME_LIMIT;
        }
        // Bound the read itself, not just the loop: a single slow read must not run past the deadline.
        dwReadTimeoutMs = (DWORD)(dwTimeoutMs - (qwNow - qwStart));
        cbRead = 0;
        if(!pfnRead(
            pvContext,
            pbBuffer,
            cbBuffer,
            dwReadTimeoutMs,
            &cbRead) ||
           (cbRead > cbBuffer)) {
            return DEVICE_FPGA_SESSION_DRAIN_READ_ERROR;
        }
        qwNow = pfnTick(pvTimingContext);
        if(qwNow - qwStart >= dwTimeoutMs) {
            return DEVICE_FPGA_SESSION_DRAIN_TIME_LIMIT;
        }
        if(DeviceFPGA_Session_IsFillerOnly(pbBuffer, cbRead)) {
            if(qwNow - qwLastNonFiller >= dwQuietMs) {
                return DEVICE_FPGA_SESSION_DRAIN_CLEAN;
            }
        } else {
            if(cbRead >= cbMaxNonFiller - cbNonFiller) {
                return DEVICE_FPGA_SESSION_DRAIN_BYTE_LIMIT;
            }
            cbNonFiller += cbRead;
            qwLastNonFiller = qwNow;
        }
        dwSleepMs = min(
            dwPollMs,
            (DWORD)(dwTimeoutMs - (qwNow - qwStart)));
        pfnSleep(pvTimingContext, dwSleepMs);
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
        if(i == cbReply) { break; }
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
BOOL DeviceFPGA_Session_ParsePCIeConfigReply(
    _In_reads_(cbReply) PBYTE pbReply,
    _In_ DWORD cbReply,
    _Inout_updates_(DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE) PBYTE pbResult,
    _Inout_updates_(DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE) PBYTE pbCoverage
)
{
    BOOL fHaveAddress = FALSE, fSawRecord = FALSE;
    BYTE oAddress;
    DWORD i = 0, j, dwStatus, dwData, dwAddress = 0;
    if(!pbReply || !cbReply || !pbResult || !pbCoverage) { return FALSE; }
    while(i < cbReply) {
        if(i + sizeof(DWORD) > cbReply) { return FALSE; }
        while((i + sizeof(DWORD) <= cbReply) &&
              (DeviceFPGA_Session_ReadDWORD(pbReply + i) == 0x55556666)) {
            i += sizeof(DWORD);
        }
        if(i == cbReply) { return fSawRecord; }
        if(i + 32 > cbReply) { return FALSE; }
        dwStatus = DeviceFPGA_Session_ReadDWORD(pbReply + i);
        fSawRecord = TRUE;
        if((dwStatus & 0xf0000000) == 0xe0000000) {
            for(j = 0; j < 7; j++) {
                dwData = DeviceFPGA_Session_ReadDWORD(
                    pbReply + i + sizeof(DWORD) + (j * sizeof(DWORD)));
                if((dwStatus & 0x0f) == 0x01) {
                    if((dwData & 0x0800ffff) == 0x08002a00) {
                        dwAddress = ((dwData >> 16) & 0x03ff) << 2;
                        fHaveAddress = TRUE;
                    } else if(fHaveAddress) {
                        oAddress = (BYTE)(dwData >> 8);
                        if(((oAddress == 0x2c) || (oAddress == 0x2e)) &&
                           (dwAddress + (oAddress - 0x2c) + 1 <
                            DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE)) {
                            oAddress -= 0x2c;
                            pbResult[dwAddress + oAddress] = (BYTE)(dwData >> 16);
                            pbResult[dwAddress + oAddress + 1] = (BYTE)(dwData >> 24);
                            pbCoverage[dwAddress + oAddress] = TRUE;
                            pbCoverage[dwAddress + oAddress + 1] = TRUE;
                        }
                    }
                }
                dwStatus >>= 4;
            }
        }
        i += 32;
    }
    return fSawRecord;
}

static BOOL DeviceFPGA_Session_IsPCIeConfigBatchComplete(
    _In_reads_(DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE) PBYTE pbCoverage,
    _In_ DWORD iDWord,
    _In_ DWORD cDWords
)
{
    DWORD i, iLimit;
    if(!pbCoverage || !cDWords ||
       (iDWord >= DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE / sizeof(DWORD)) ||
       (cDWords >
        (DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE / sizeof(DWORD)) - iDWord)) {
        return FALSE;
    }
    i = iDWord * sizeof(DWORD);
    iLimit = i + (cDWords * sizeof(DWORD));
    for(; i < iLimit; i++) {
        if(!pbCoverage[i]) { return FALSE; }
    }
    return TRUE;
}

_Success_(return)
BOOL DeviceFPGA_Session_ReadPCIeConfigBatchMatching(
    _In_ HANDLE hFTDI,
    _Out_writes_to_(cbBuffer, *pcbRead) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PDWORD pcbRead,
    _In_ PFN_DEVICE_FPGA_SESSION_READ_PIPE pfnReadPipe,
    _In_ DWORD iDWord,
    _In_ DWORD cDWords,
    _Inout_updates_(DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE) PBYTE pbResult,
    _Inout_updates_(DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE) PBYTE pbCoverage,
    _In_ DWORD dwTimeoutMs,
    _In_opt_ PVOID pvTimingContext,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick
)
{
    DWORD i, cbAccumulated = 0, cbReadMax;
    QWORD qwStart;
    ULONG cbRead;
    if(!pcbRead) { return FALSE; }
    *pcbRead = 0;
    if(!hFTDI || !pbBuffer || !cbBuffer || !pfnReadPipe ||
       !pbResult || !pbCoverage || !dwTimeoutMs || !cDWords ||
       (iDWord >= DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE / sizeof(DWORD)) ||
       (cDWords >
        (DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE / sizeof(DWORD)) - iDWord)) {
        return FALSE;
    }
    if(!pfnTick) { pfnTick = DeviceFPGA_Session_DefaultTick; }
    qwStart = pfnTick(pvTimingContext);
    for(i = 0; i < DEVICE_FPGA_SESSION_CONFIG_REPLY_MAX_READS; i++) {
        if(pfnTick(pvTimingContext) - qwStart >= dwTimeoutMs) {
            return FALSE;
        }
        if(cbAccumulated >= cbBuffer) { return FALSE; }
        cbReadMax = cbBuffer - cbAccumulated;
        cbRead = 0;
        if(pfnReadPipe(
            hFTDI,
            0x82,
            pbBuffer + cbAccumulated,
            cbReadMax,
            &cbRead,
            NULL) ||
           (cbRead > cbReadMax)) {
            return FALSE;
        }
        if(!cbRead) { return FALSE; }
        if(pfnTick(pvTimingContext) - qwStart >= dwTimeoutMs) {
            return FALSE;
        }
        if(DeviceFPGA_Session_IsFillerOnly(
            pbBuffer + cbAccumulated, cbRead)) {
            continue;
        }
        cbAccumulated += cbRead;
        if(!DeviceFPGA_Session_ParsePCIeConfigReply(
            pbBuffer, cbAccumulated, pbResult, pbCoverage)) {
            continue;
        }
        if(DeviceFPGA_Session_IsPCIeConfigBatchComplete(
            pbCoverage, iDWord, cDWords)) {
            *pcbRead = cbAccumulated;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL DeviceFPGA_Session_IsPCIeConfigRequestValid(_In_opt_ DWORD raSingleDW)
{
    return !raSingleDW ||
        ((raSingleDW & 0x80000000) &&
         ((raSingleDW & 0x7fffffff) <
          (DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE / sizeof(DWORD))));
}

DWORD DeviceFPGA_Session_GetPCIeConfigBatchDWords(
    _In_ DWORD iDWord,
    _In_opt_ DWORD raSingleDW
)
{
    DWORD cRemaining;
    if(!DeviceFPGA_Session_IsPCIeConfigRequestValid(raSingleDW) ||
       (iDWord >= DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE / sizeof(DWORD))) {
        return 0;
    }
    if(raSingleDW) { return 1; }
    cRemaining =
        (DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE / sizeof(DWORD)) - iDWord;
    return (cRemaining < DEVICE_FPGA_SESSION_PCIE_CONFIG_BATCH_DWORDS) ?
        cRemaining : DEVICE_FPGA_SESSION_PCIE_CONFIG_BATCH_DWORDS;
}

_Success_(return)
BOOL DeviceFPGA_Session_BuildPCIeConfigBatch(
    _Out_writes_to_(cbBuffer, *pcbBatch) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _Out_ PDWORD pcbBatch,
    _In_ DWORD iDWord,
    _In_opt_ DWORD raSingleDW
)
{
    BYTE pbTxLockEnable[]   = { 0x04, 0x00, 0x04, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxLockDisable[]  = { 0x00, 0x00, 0x04, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxReadEnable[]   = { 0x01, 0x00, 0x01, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxAddress[]      = { 0x00, 0x00, 0xff, 0x03, 0x80, 0x14, 0x21, 0x77 };
    BYTE pbTxResultMeta[]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x11, 0x77 };
    BYTE pbTxResultDataLo[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x11, 0x77 };
    BYTE pbTxResultDataHi[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x11, 0x77 };
    DWORD cDWords, cbRequired, cbBatch = 0, i, iAddress, oDWord;
    if(!pcbBatch) { return FALSE; }
    *pcbBatch = 0;
    cDWords = DeviceFPGA_Session_GetPCIeConfigBatchDWords(
        iDWord, raSingleDW);
    cbRequired = cDWords * 56 + 16;
    if(!pbBuffer || !cDWords || (cbBuffer < cbRequired)) { return FALSE; }
    for(oDWord = 0; oDWord < cDWords; oDWord++) {
        memcpy(pbBuffer + cbBatch, pbTxLockEnable, 8); cbBatch += 8;
        iAddress = raSingleDW ?
            (raSingleDW & 0x7fffffff) : (iDWord + oDWord);
        pbTxAddress[0] = (BYTE)iAddress;
        pbTxAddress[1] = (BYTE)((iAddress >> 8) & 0x03);
        // The first DWORD is read twice to clear lingering result-register data.
        for(i = 0; i < (oDWord ? 1U : 2U); i++) {
            memcpy(pbBuffer + cbBatch, pbTxAddress, 8); cbBatch += 8;
            memcpy(pbBuffer + cbBatch, pbTxReadEnable, 8); cbBatch += 8;
        }
        memcpy(pbBuffer + cbBatch, pbTxResultMeta, 8); cbBatch += 8;
        memcpy(pbBuffer + cbBatch, pbTxResultDataLo, 8); cbBatch += 8;
        memcpy(pbBuffer + cbBatch, pbTxResultDataHi, 8); cbBatch += 8;
        memcpy(pbBuffer + cbBatch, pbTxLockDisable, 8); cbBatch += 8;
    }
    *pcbBatch = cbBatch;
    return cbBatch == cbRequired;
}

BOOL DeviceFPGA_Session_IsPCIeConfigComplete(
    _In_reads_(DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE) PBYTE pbCoverage,
    _In_opt_ DWORD raSingleDW
)
{
    DWORD i, iLimit;
    if(!pbCoverage ||
       !DeviceFPGA_Session_IsPCIeConfigRequestValid(raSingleDW)) {
        return FALSE;
    }
    if(raSingleDW) {
        i = raSingleDW & 0x7fffffff;
        i *= sizeof(DWORD);
        iLimit = i + sizeof(DWORD);
    } else {
        i = 0;
        iLimit = DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE;
    }
    for(; i < iLimit; i++) {
        if(!pbCoverage[i]) { return FALSE; }
    }
    return TRUE;
}

_Success_(return)
BOOL DeviceFPGA_Session_ReadPCIeConfigWithRetry(
    _Inout_ PVOID pvContext,
    _In_ PFN_DEVICE_FPGA_SESSION_PCIE_CONFIG_READ_ATTEMPT pfnAttempt,
    _Out_writes_(DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE) PBYTE pbResult,
    _In_opt_ DWORD raSingleDW
)
{
    DWORD i;
    if(!pfnAttempt || !pbResult ||
       !DeviceFPGA_Session_IsPCIeConfigRequestValid(raSingleDW)) {
        return FALSE;
    }
    for(i = 0; i < 2; i++) {
        ZeroMemory(pbResult, DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE);
        if(pfnAttempt(pvContext, pbResult)) {
            return TRUE;
        }
    }
    ZeroMemory(pbResult, DEVICE_FPGA_SESSION_PCIE_CONFIG_SIZE);
    return FALSE;
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
        if(i == cbReply) { break; }
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

_Success_(return)
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
    ULONG ftStatus;
    DEVICE_FPGA_SESSION_WAIT_RESULT WaitResult;
    if(!hFTDI || !pOverlapped) { return TRUE; }
    if(!pfnAbortPipe || !pfnGetOverlappedResult || !pfnReleaseOverlapped) {
        return FALSE;
    }
    if(!pfnTick) { pfnTick = DeviceFPGA_Session_DefaultTick; }
    if(!pfnSleep) { pfnSleep = DeviceFPGA_Session_DefaultSleep; }
    // RX only: some callers don't hold the TX fast-write lock, and aborting TX here could cancel an in-flight write on that path.
    ftStatus = pfnAbortPipe(hFTDI, 0x82);
    fResult &= ftStatus == DEVICE_FPGA_SESSION_FT_OK;
    WaitResult = DeviceFPGA_Session_WaitOverlapped(
        hFTDI,
        pOverlapped,
        pfnGetOverlappedResult,
        TRUE,
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
