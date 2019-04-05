// vmmdevice.c : implementation of the device control layer responsible for
// keeping track of devices, reading and writing physical memory.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "device.h"
#include "oscompatibility.h"
#include "memmap.h"
#include "device_usb3380.h"
#include "device_file.h"
#include "device_fpga.h"
#include "device_pmem.h"
#include "device_sp605tcp.h"
#include "device_tmd.h"
#include "device_hvsavedstate.h"
#include "device_rawtcp.h"
#include "leechrpc.h"
#include "version.h"

// ----------------------------------------------------------------------------
// DLL housekeeping functionality below - incl. global context variable setup:
// ----------------------------------------------------------------------------

#ifdef _WIN32
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH) {
        ctxDeviceMain = NULL;
    }
    if(fdwReason == DLL_PROCESS_DETACH) {
        LeechCore_Close();
    }
    return TRUE;
}
#endif /* _WIN32 */
#ifdef LINUX
__attribute__((constructor)) VOID DllMain_PROCESS_ATTACH()
{
    ctxDeviceMain = NULL;
}

__attribute__((destructor)) VOID DllMain_PROCESS_DETACH()
{
    LeechCore_Close();
}
#endif /* LINUX */

// ----------------------------------------------------------------------------
// CORE DEVICE FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

VOID LeechCore_LockAcquire()
{
    if(!ctxDeviceMain->fDeviceMultiThread) {
        EnterCriticalSection(&ctxDeviceMain->DeviceLock);
    }
}

VOID LeechCore_LockRelease()
{
    if(!ctxDeviceMain->fDeviceMultiThread) {
        LeaveCriticalSection(&ctxDeviceMain->DeviceLock);
    }
}

QWORD LeechCore_StatisticsCallStart()
{
    QWORD tmNow;
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    return tmNow;
}

VOID LeechCore_StatisticsCallEnd(_In_ DWORD fId, QWORD tmCallStart)
{
    QWORD tmNow;
    if(!ctxDeviceMain) { return; }
    if(!ctxDeviceMain || !tmCallStart || (fId > LEECHCORE_STATISTICS_ID_MAX)) { return; }
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    InterlockedIncrement64(&ctxDeviceMain->Statistics.Call[fId].c);
    InterlockedAdd64(&ctxDeviceMain->Statistics.Call[fId].tm, tmNow - tmCallStart);
}

_Success_(return)
DLLEXPORT BOOL LeechCore_AllocScatterEmpty(_In_ DWORD cMEMs, _Out_ PPMEM_IO_SCATTER_HEADER *pppMEMs)
{
    DWORD i;
    PBYTE pbBuffer, pbData;
    PMEM_IO_SCATTER_HEADER *ppMEMs, pMEMs, pMEM;
    *pppMEMs = NULL;
    pbBuffer = LocalAlloc(0, cMEMs * (sizeof(PMEM_IO_SCATTER_HEADER) + sizeof(MEM_IO_SCATTER_HEADER) + 0x1000));
    if(!pbBuffer) { return FALSE; }
    ZeroMemory(pbBuffer, cMEMs * (sizeof(PMEM_IO_SCATTER_HEADER) + sizeof(MEM_IO_SCATTER_HEADER)));
    ppMEMs = (PPMEM_IO_SCATTER_HEADER)pbBuffer;
    pMEMs = (PMEM_IO_SCATTER_HEADER)(pbBuffer + cMEMs * sizeof(PMEM_IO_SCATTER_HEADER));
    pbData = pbBuffer + cMEMs * (sizeof(PMEM_IO_SCATTER_HEADER) + sizeof(MEM_IO_SCATTER_HEADER));
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i] = pMEMs + i;
        pMEM->magic = MEM_IO_SCATTER_HEADER_MAGIC;
        pMEM->version = MEM_IO_SCATTER_HEADER_VERSION;
        pMEM->qwA = (QWORD)-1;
        pMEM->cbMax = 0x1000;
        pMEM->pb = pbData + ((QWORD)i << 12);
    }
    *pppMEMs = ppMEMs;
    return TRUE;
}

DLLEXPORT VOID LeechCore_ReadScatter(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    QWORD tmCallStart;
    if(!ctxDeviceMain || !ctxDeviceMain->hDevice || !ctxDeviceMain->pfnReadScatterMEM) { return; }
    tmCallStart = LeechCore_StatisticsCallStart();
    LeechCore_LockAcquire();
    ctxDeviceMain->pfnReadScatterMEM(ppMEMs, cpMEMs);
    LeechCore_LockRelease();
    LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_READSCATTER, tmCallStart);
}

_Success_(return)
DLLEXPORT BOOL LeechCore_Write(_In_ ULONG64 pa, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    QWORD paDevice, tmCallStart;
    if(!ctxDeviceMain || !ctxDeviceMain->hDevice || !ctxDeviceMain->pfnWriteMEM) { return FALSE; }
    if(!MemMap_VerifyTranslateRange(pa, cb, &paDevice)) { return FALSE; }
    tmCallStart = LeechCore_StatisticsCallStart();
    LeechCore_LockAcquire();
    result = ctxDeviceMain->pfnWriteMEM(paDevice, pb, cb);
    LeechCore_LockRelease();
    LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_WRITE, tmCallStart);
    return result;
}

_Success_(return)
DLLEXPORT BOOL LeechCore_WriteEx(_In_ ULONG64 pa, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD flags)
{
    BOOL result;
    PBYTE pbRead;
    result = LeechCore_Write(pa, pb, cb) ||
        ((flags & LEECHCORE_FLAG_WRITE_RETRY) && LeechCore_Write(pa, pb, cb));
    if(result && (flags & LEECHCORE_FLAG_WRITE_VERIFY)) {
        if(!(pbRead = LocalAlloc(0, cb))) { return FALSE; }
        LeechCore_Read(pa, pbRead, cb);
        result = !memcmp(pb, pbRead, cb);
        LocalFree(pbRead);
    }
    return result;
}

_Success_(return)
DLLEXPORT BOOL LeechCore_Probe(_In_ QWORD pa, _In_ DWORD cPages, _Inout_updates_bytes_(cPages) PBYTE pbResultMap)
{
    QWORD tmCallStart;
    if(!ctxDeviceMain || !ctxDeviceMain->hDevice || !ctxDeviceMain->pfnProbeMEM) { return FALSE; }
    tmCallStart = LeechCore_StatisticsCallStart();
    LeechCore_LockAcquire();
    ctxDeviceMain->pfnProbeMEM(pa, cPages, pbResultMap);
    LeechCore_LockRelease();
    LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_PROBE, tmCallStart);
    return TRUE;
}

/*
* Auto-identifies the maximum address by starting to try to read memory at 4GB
* and then by moving upwards. Reads should be minimized - but if "bad" hardware
* this may still (in very rare occurances) freeze the target computer if DMA
* device is used. Should only be called whenever needed - i.e. when the native
* device does not report a valid value in combination with the absence of user
* defined max address.
*/
QWORD LeechCore_AutoIdentifyMaxAddress()
{
    QWORD i, qwCurrentAddress = 0x100000000, qwChunkSize = 0x100000000;
    MEM_IO_SCATTER_HEADER pMEM[1], *ppMEM[1];
    BYTE pbDummy[0x1000];
    DWORD dwOFFSETS[] = { 0x0, 0x1000, 0x2000, 0x3000, 0x00010000, 0x00100000, 0x01000000, 0x10000000 };
    DWORD cOFFSETS = sizeof(dwOFFSETS) / sizeof(DWORD);
    // 1: set up
    ZeroMemory(pMEM, sizeof(MEM_IO_SCATTER_HEADER));
    pMEM->magic = MEM_IO_SCATTER_HEADER_MAGIC;
    pMEM->version = MEM_IO_SCATTER_HEADER_VERSION;
    pMEM->pb = pbDummy;
    pMEM->cbMax = 0x1000;
    *ppMEM = pMEM;
    // 2: loop until fail on smallest chunk size (0x1000)
    while(TRUE) {
        pMEM->cb = 0;
        for(i = 0; i < cOFFSETS; i++) {
            pMEM->cb = 0;
            pMEM->qwA = qwCurrentAddress + qwChunkSize + dwOFFSETS[i];
            LeechCore_ReadScatter(ppMEM, 1);
            if(pMEM->cb) {
                qwCurrentAddress += qwChunkSize;
                break;
            }
        }
        if(pMEM->cb) { continue; }
        if(qwChunkSize == 0x1000) {
            return qwCurrentAddress + ((qwCurrentAddress == 0x100000000) ? 0 : 0xfff);
        }
        qwChunkSize >>= 1; // half chunk size
    }
}

_Success_(return)
BOOL LeechCore_GetOption_Core(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    QWORD v = 0;
    *pqwValue = 0;
    switch(fOption) {
        case LEECHCORE_OPT_CORE_PRINTF_ENABLE:
            *pqwValue = ctxDeviceMain->fPrintfEnable ? 1 : 0;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERBOSE:
            *pqwValue = ctxDeviceMain->fVerbose ? 1 : 0;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERBOSE_EXTRA:
            *pqwValue = ctxDeviceMain->fVerboseExtra ? 1 : 0;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERBOSE_EXTRA_TLP:
            *pqwValue = ctxDeviceMain->fVerboseExtraTlp ? 1 : 0;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERSION_MAJOR:
            *pqwValue = VERSION_MAJOR;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERSION_MINOR:
            *pqwValue = VERSION_MINOR;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERSION_REVISION:
            *pqwValue = VERSION_REVISION;
            return TRUE;
        case LEECHCORE_OPT_CORE_FLAG_BACKEND_FUNCTIONS:
            if(ctxDeviceMain) {
                v |= (ctxDeviceMain->cfg.flags & LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS) ? LEECHRPC_FLAG_NOCOMPRESS : 0;
                v |= ctxDeviceMain->pfnReadScatterMEM ? LEECHRPC_FLAG_FNEXIST_ReadScatterMEM : 0;
                v |= ctxDeviceMain->pfnWriteMEM ? LEECHRPC_FLAG_FNEXIST_WriteMEM : 0;
                v |= ctxDeviceMain->pfnProbeMEM ? LEECHRPC_FLAG_FNEXIST_ProbeMEM : 0;
                v |= ctxDeviceMain->pfnClose ? LEECHRPC_FLAG_FNEXIST_Close : 0;
                v |= ctxDeviceMain->pfnGetOption ? LEECHRPC_FLAG_FNEXIST_GetOption : 0;
                v |= ctxDeviceMain->pfnSetOption ? LEECHRPC_FLAG_FNEXIST_SetOption : 0;
                v |= ctxDeviceMain->pfnCommandData ? LEECHRPC_FLAG_FNEXIST_CommandData : 0;
                *pqwValue = v;
            }
            return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL LeechCore_SetOption_Core(_In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    switch(fOption) {
        case LEECHCORE_OPT_CORE_PRINTF_ENABLE:
            ctxDeviceMain->fPrintfEnable = qwValue ? TRUE : FALSE;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERBOSE:
            ctxDeviceMain->fVerbose = qwValue ? TRUE : FALSE;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERBOSE_EXTRA:
            ctxDeviceMain->fVerboseExtra = qwValue ? TRUE : FALSE;
            return TRUE;
        case LEECHCORE_OPT_CORE_VERBOSE_EXTRA_TLP:
            ctxDeviceMain->fVerboseExtraTlp = qwValue ? TRUE : FALSE;
            return TRUE;
    }
    return FALSE;
}

_Success_(return)
DLLEXPORT BOOL LeechCore_GetOption(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    BOOL result;
    QWORD tmCallStart;
    if(!ctxDeviceMain) { return FALSE; }
    if(fOption & 0x81000000) {
        tmCallStart = LeechCore_StatisticsCallStart();
        result = LeechCore_GetOption_Core(fOption, pqwValue);
        LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_GETOPTION, tmCallStart);
    } else {
        if(!ctxDeviceMain->hDevice || !ctxDeviceMain->pfnSetOption) { return FALSE; }
        tmCallStart = LeechCore_StatisticsCallStart();
        LeechCore_LockAcquire();
        result = ctxDeviceMain->pfnGetOption(fOption, pqwValue);
        LeechCore_LockRelease();
        LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_GETOPTION, tmCallStart);
    }
    return result;
}

_Success_(return)
DLLEXPORT BOOL LeechCore_SetOption(_In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    BOOL result;
    QWORD tmCallStart;
    if(!ctxDeviceMain) { return FALSE; }
    if(fOption & 0x81000000) {
        tmCallStart = LeechCore_StatisticsCallStart();
        result = LeechCore_SetOption_Core(fOption, qwValue);
        LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_SETOPTION, tmCallStart);
    } else {
        if(!ctxDeviceMain->hDevice || !ctxDeviceMain->pfnSetOption) { return FALSE; }
        tmCallStart = LeechCore_StatisticsCallStart();
        LeechCore_LockAcquire();
        result = ctxDeviceMain->pfnSetOption(fOption, qwValue);
        LeechCore_LockRelease();
        LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_SETOPTION, tmCallStart);
    }
    return result;
}

_Success_(return)
BOOL LeechCore_CommandData_Core(_In_ ULONG64 fOption, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(cbDataOut) PBYTE pbDataOut, _In_ DWORD cbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    switch(fOption) {
        case LEECHCORE_COMMANDDATA_STATISTICS_GET:
            if(!pcbDataOut) { return FALSE; }
            if(!pbDataOut) { 
                *pcbDataOut = sizeof(LEECHCORE_STATISTICS);
                return TRUE;
            }
            if(cbDataOut < sizeof(LEECHCORE_STATISTICS)) { return FALSE; }
            memcpy(pbDataOut, &ctxDeviceMain->Statistics, sizeof(LEECHCORE_STATISTICS));
            *pcbDataOut = sizeof(LEECHCORE_STATISTICS);
            return TRUE;
    }
    return FALSE;
}

_Success_(return)
DLLEXPORT BOOL LeechCore_CommandData(_In_ ULONG64 fOption, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(cbDataOut) PBYTE pbDataOut, _In_ DWORD cbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    BOOL result = FALSE;
    QWORD tmCallStart;
    if(pcbDataOut) { *pcbDataOut = 0; }
    if(!ctxDeviceMain) { return FALSE; }
    tmCallStart = LeechCore_StatisticsCallStart();
    if(fOption & 0x80000000) {
        result = LeechCore_CommandData_Core(fOption, pbDataIn, cbDataIn, pbDataOut, cbDataOut, pcbDataOut);
    } else if(ctxDeviceMain->hDevice && ctxDeviceMain->pfnCommandData) {
        LeechCore_LockAcquire();
        result = ctxDeviceMain->pfnCommandData(fOption, pbDataIn, cbDataIn, pbDataOut, cbDataOut, pcbDataOut);
        LeechCore_LockRelease();
    }
    LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_COMMANDDATA, tmCallStart);
    return result;
}

_Success_(return)
DWORD LeechCore_Read_DoWork_Scatter(_In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_opt_ PLEECHCORE_PAGESTAT_MINIMAL pPageStat)
{
    PBYTE pbBuffer;
    PMEM_IO_SCATTER_HEADER pDMAs, *ppDMAs;
    DWORD i, o, cDMAs, cbReadTotal = 0;
    cDMAs = (cb + 0xfff) >> 12;
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cDMAs * (sizeof(PMEM_IO_SCATTER_HEADER) + sizeof(MEM_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return 0; }
    ppDMAs = (PMEM_IO_SCATTER_HEADER*)pbBuffer;
    pDMAs = (PMEM_IO_SCATTER_HEADER)(pbBuffer + cDMAs * sizeof(PMEM_IO_SCATTER_HEADER));
    for(i = 0, o = 0; i < cDMAs; i++, o += 0x1000) {
        ppDMAs[i] = pDMAs + i;
        pDMAs[i].magic = MEM_IO_SCATTER_HEADER_MAGIC;
        pDMAs[i].version = MEM_IO_SCATTER_HEADER_VERSION;
        pDMAs[i].qwA = qwAddr + o;
        pDMAs[i].cbMax = min(0x1000, cb - o);
        pDMAs[i].pb = pb + o;
    }
    LeechCore_ReadScatter(ppDMAs, cDMAs);
    for(i = 0; i < cDMAs; i++) {
        if(pDMAs[i].cb == pDMAs[i].cbMax) {
            if(pPageStat && (pDMAs[i].cbMax == 0x1000)) {
                pPageStat->pfnPageStatUpdate(pPageStat->h, pDMAs[i].qwA + 0x1000, 1, 0);
            }
            cbReadTotal += pDMAs[i].cbMax;
        } else {
            if(pPageStat && (pDMAs[i].cbMax == 0x1000)) {
                pPageStat->pfnPageStatUpdate(pPageStat->h, pDMAs[i].qwA + 0x1000, 0, 1);
            }
            ZeroMemory(pDMAs[i].pb, pDMAs[i].cbMax);
        }
    }
    LocalFree(pbBuffer);
    return cbReadTotal;
}

DWORD LeechCore_Read_DoWork(_In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_opt_ PLEECHCORE_PAGESTAT_MINIMAL pPageStat, _In_ DWORD cbMaxSizeIo)
{
    DWORD cbRd, cbRdOff;
    DWORD cbChunk, cChunkTotal, cChunkSuccess = 0;
    DWORD i, cbSuccess = 0;
    // calculate current chunk sizes
    cbChunk = ~0xfff & min(cb + 0xfff, cbMaxSizeIo);
    cChunkTotal = (cb / cbChunk) + ((cb % cbChunk) ? 1 : 0);
    // try read memory
    memset(pb, 0, cb);
    for(i = 0; i < cChunkTotal; i++) {
        cbRdOff = i * cbChunk;
        cbRd = ((i == cChunkTotal - 1) && (cb % cbChunk)) ? (cb % cbChunk) : cbChunk; // (last chunk may be smaller)
        cbSuccess += LeechCore_Read_DoWork_Scatter(qwAddr + cbRdOff, pb + cbRdOff, cbRd, pPageStat);
    }
    return cbSuccess;
}

DLLEXPORT DWORD LeechCore_ReadEx(_In_ ULONG64 pa, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD flags, _In_opt_ PLEECHCORE_PAGESTAT_MINIMAL pPageStat)
{
    BYTE pbWorkaround[4096];
    DWORD cbDataRead;
    if(!pb || !cb) { return 0; }
    // read memory (with strange workaround for 1-page reads...)
    if(cb > 0x1000) {
        cbDataRead = LeechCore_Read_DoWork(pa, pb, cb, pPageStat, (DWORD)ctxDeviceMain->cfg.cbMaxSizeMemIo);
    } else {
        // why is this working ??? if not here console is screwed up... (threading issue?)
        cbDataRead = LeechCore_Read_DoWork(pa, pbWorkaround, cb, pPageStat, (DWORD)ctxDeviceMain->cfg.cbMaxSizeMemIo);
        memcpy(pb, pbWorkaround, cb);
    }
    if((flags & LEECHCORE_FLAG_READ_RETRY) && (cb != cbDataRead)) {
        return LeechCore_ReadEx(pa, pb, cb, (flags & ~LEECHCORE_FLAG_READ_RETRY), pPageStat);
    }
    return cbDataRead;
}

DLLEXPORT DWORD LeechCore_Read(_In_ ULONG64 pa, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb)
{
    return LeechCore_ReadEx(pa, pb, cb, 0, NULL);
}

_Success_(return)
DLLEXPORT BOOL LeechCore_AgentCommand(
    _In_ ULONG64 fCommand,
    _In_ ULONG64 fDataIn,
    _In_reads_(cbDataIn) PBYTE pbDataIn,
    _In_ DWORD cbDataIn,
    _Out_writes_opt_(*pcbDataOut) PBYTE *ppbDataOut,
    _Out_opt_ PDWORD pcbDataOut
)
{
    BOOL result = FALSE;
    QWORD tmCallStart;
    if(pcbDataOut) { *pcbDataOut = 0; }
    if(ppbDataOut) { *ppbDataOut = NULL; }
    if(!ctxDeviceMain || !ctxDeviceMain->pfnAgentCommand) { return FALSE; }
    tmCallStart = LeechCore_StatisticsCallStart();
    LeechCore_LockAcquire();
    result = ctxDeviceMain->pfnAgentCommand(fCommand, fDataIn, pbDataIn, cbDataIn, ppbDataOut, pcbDataOut);
    LeechCore_LockRelease();
    LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_COMMANDSVC, tmCallStart);
    return result;
}



// ----------------------------------------------------------------------------
// INTIALIZATION / CLEANUP FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

DLLEXPORT VOID LeechCore_Close()
{
    if(ctxDeviceMain && ctxDeviceMain->pfnClose) { ctxDeviceMain->pfnClose(); }
    if(ctxDeviceMain && ctxDeviceMain->fDeviceLock) { DeleteCriticalSection(&ctxDeviceMain->DeviceLock); }
    LocalFree(ctxDeviceMain);
    ctxDeviceMain = NULL;
}

_Success_(return)
DLLEXPORT BOOL LeechCore_Open(_Inout_ PLEECHCORE_CONFIG pConfig)
{
    BOOL result = FALSE;
    QWORD tmCallStart;
    tmCallStart = LeechCore_StatisticsCallStart();
    if(!pConfig || (pConfig->magic != LEECHCORE_CONFIG_MAGIC) || (pConfig->version != LEECHCORE_CONFIG_VERSION)) { return FALSE; }
    if(0 == _strnicmp("existing", pConfig->szDevice, 9)) {
        if(!ctxDeviceMain) { return FALSE; }
        memcpy(pConfig, &ctxDeviceMain->cfg, sizeof(LEECHCORE_CONFIG));
        return TRUE;
    }
    if(ctxDeviceMain) {
        vprintf("Failed loading LeechCore - already initialized.\n");
        return FALSE;
    }
    ctxDeviceMain = (PLEECHCORE_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(LEECHCORE_CONTEXT));
    if(!ctxDeviceMain) { return FALSE; }
    memcpy(&ctxDeviceMain->cfg, pConfig, sizeof(LEECHCORE_CONFIG));
    ctxDeviceMain->cfg.VersionMajor = VERSION_MAJOR;
    ctxDeviceMain->cfg.VersionMinor = VERSION_MINOR;
    ctxDeviceMain->cfg.VersionRevision = VERSION_REVISION;
    ctxDeviceMain->fPrintfEnable = (ctxDeviceMain->cfg.flags & LEECHCORE_CONFIG_FLAG_PRINTF) ? TRUE : FALSE;
    ctxDeviceMain->fVerbose = (ctxDeviceMain->cfg.flags & LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_1) ? TRUE : FALSE;
    ctxDeviceMain->fVerboseExtra = (ctxDeviceMain->cfg.flags & LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_2) ? TRUE : FALSE;
    ctxDeviceMain->fVerboseExtraTlp = (ctxDeviceMain->cfg.flags & LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_3) ? TRUE : FALSE;
    ctxDeviceMain->cfg.paMax = ctxDeviceMain->cfg.paMax ? min(ctxDeviceMain->cfg.paMax, 0x0000ffffffffffff) : 0x0000ffffffffffff;
    ctxDeviceMain->paMaxUserInput = ctxDeviceMain->cfg.paMax;
    if(ctxDeviceMain->cfg.szRemote[0]) {
        if(0 == _strnicmp("rpc://", ctxDeviceMain->cfg.szRemote, 6)) {
            result = LeechRPC_Open(TRUE);
        }
        if(0 == _strnicmp("pipe://", ctxDeviceMain->cfg.szRemote, 7)) {
            result = LeechRPC_Open(FALSE);
        }
    } else if(0 == _strnicmp("fpga", ctxDeviceMain->cfg.szDevice, 4)) {
        result = DeviceFPGA_Open();
    } else if(0 == _strnicmp("usb3380", ctxDeviceMain->cfg.szDevice, 7)) {
        result = Device3380_Open();
    } else if(0 == _strnicmp("sp605tcp://", ctxDeviceMain->cfg.szDevice, 11)) {
        result = Device605_TCP_Open();
    } else if(0 == _strnicmp("rawtcp://", ctxDeviceMain->cfg.szDevice, 9)) {
        result = DeviceRawTCP_Open();
    } else if(0 == _strnicmp("HvSavedState://", ctxDeviceMain->cfg.szDevice, 15)) {
        result = DeviceHvSavedState_Open();
    } else if(0 == _stricmp("totalmeltdown", ctxDeviceMain->cfg.szDevice)) {
        result = DeviceTMD_Open();
    } else if(0 == _strnicmp("pmem", ctxDeviceMain->cfg.szDevice, 4)) {
        result = DevicePMEM_Open();
    } else {
        result = DeviceFile_Open();
    }
    if(result) {
        ctxDeviceMain->fDeviceLock = TRUE;
        InitializeCriticalSection(&ctxDeviceMain->DeviceLock);
        if((ctxDeviceMain->cfg.paMax >= 0x0000ffffffffffff) && (ctxDeviceMain->cfg.paMaxNative >= 0x0000ffffffffffff)) {
            // probe for max address - if needed and not already user supplied
            ctxDeviceMain->cfg.paMaxNative = LeechCore_AutoIdentifyMaxAddress();
        }
        ctxDeviceMain->cfg.paMax = min(ctxDeviceMain->cfg.paMax, ctxDeviceMain->cfg.paMaxNative);
        ctxDeviceMain->cfg.fWritable = ctxDeviceMain->pfnWriteMEM != NULL;
        // FPGA devices do not initialize proper memory map since max address
        // is usually unknown at initialization time - so let's do it for them!
        if(!MemMap_IsInitialized()) {
            MemMap_Initialize(ctxDeviceMain->cfg.paMax);
        }
        memcpy(pConfig, &ctxDeviceMain->cfg, sizeof(LEECHCORE_CONFIG));
        ctxDeviceMain->Statistics.magic = LEECHCORE_STATISTICS_MAGIC;
        ctxDeviceMain->Statistics.version = LEECHCORE_STATISTICS_VERSION;
        QueryPerformanceFrequency((PLARGE_INTEGER)&ctxDeviceMain->Statistics.qwFreq);
        vprintfvv("Successfully loaded LeechCore v%i.%i.%i Device %i\n", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION, ctxDeviceMain->cfg.tpDevice);
    } else {
        LeechCore_Close();
        if(pConfig->flags & LEECHCORE_CONFIG_FLAG_PRINTF) {
            vprintf("Failed loading LeechCore v%i.%i.%i\n", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);
        }
    }
    LeechCore_StatisticsCallEnd(LEECHCORE_STATISTICS_ID_OPEN, tmCallStart);
    return result;
}
