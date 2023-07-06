// leechcore.c : core implementation of the the LeechCore physical memory acquisition library.
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
#include "oscompatibility.h"
#include "util.h"
#include "version.h"

//-----------------------------------------------------------------------------
// Global Context and DLL Attach/Detach:
//-----------------------------------------------------------------------------

typedef struct tdLC_MAIN_CONTEXT {
    CRITICAL_SECTION Lock;
    HANDLE FLink;
} LC_MAIN_CONTEXT, *PLC_MAIN_CONTEXT;

LC_MAIN_CONTEXT g_ctx = { 0 };

_Success_(return) BOOL Device3380_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
_Success_(return) BOOL DeviceFile_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
_Success_(return) BOOL DeviceFPGA_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
_Success_(return) BOOL DevicePMEM_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
_Success_(return) BOOL DeviceVMM_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
_Success_(return) BOOL DeviceVMWare_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
_Success_(return) BOOL DeviceTMD_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);
_Success_(return) BOOL LeechRpc_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo);

VOID LcCloseAll();
_Success_(return) BOOL LcReadContigious_Initialize(_In_ PLC_CONTEXT ctxLC);
VOID LcReadContigious_Close(_In_ PLC_CONTEXT ctxLC);

#ifdef _WIN32
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ PVOID lpvReserved)
{
    if(fdwReason == DLL_PROCESS_ATTACH) {
        ZeroMemory(&g_ctx, sizeof(LC_MAIN_CONTEXT));
        InitializeCriticalSection(&g_ctx.Lock);
    }
    if(fdwReason == DLL_PROCESS_DETACH) {
        LcCloseAll();
        DeleteCriticalSection(&g_ctx.Lock);
        ZeroMemory(&g_ctx, sizeof(LC_MAIN_CONTEXT));
    }
    return TRUE;
}
#endif /* _WIN32 */
#ifdef LINUX
__attribute__((constructor)) VOID LcAttach()
{
    ZeroMemory(&g_ctx, sizeof(LC_MAIN_CONTEXT));
    InitializeCriticalSection(&g_ctx.Lock);
}

__attribute__((destructor)) VOID LcDetach()
{
    LcCloseAll();
    DeleteCriticalSection(&g_ctx.Lock);
    ZeroMemory(&g_ctx, sizeof(LC_MAIN_CONTEXT));
}
#endif /* LINUX */



//-----------------------------------------------------------------------------
// Initialize / Close / Core functionality:
//-----------------------------------------------------------------------------

VOID LcLockAcquire(_In_ PLC_CONTEXT ctxLC)
{
    if(!ctxLC->fMultiThread) { EnterCriticalSection(&ctxLC->Lock); }
}

VOID LcLockRelease(_In_ PLC_CONTEXT ctxLC)
{
    if(!ctxLC->fMultiThread) { LeaveCriticalSection(&ctxLC->Lock); }
}

QWORD LcCallStart()
{
    QWORD tmNow;
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    return tmNow;
}

VOID LcCallEnd(_In_ PLC_CONTEXT ctxLC, _In_ DWORD fId, _In_ QWORD tmCallStart)
{
    QWORD tmNow;
    QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
    InterlockedIncrement64(&ctxLC->CallStat.Call[fId].c);
    InterlockedAdd64(&ctxLC->CallStat.Call[fId].tm, tmNow - tmCallStart);
}

/*
* Close a LeechCore handle and free any resources no longer needed.
*/
EXPORTED_FUNCTION VOID LcClose(_In_opt_ _Post_ptr_invalid_ HANDLE hLC)
{
    PLC_CONTEXT ctxParent;
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    if(!ctxLC || (ctxLC->version != LC_CONTEXT_VERSION)) { return; }
    EnterCriticalSection(&g_ctx.Lock);
    if(0 == --ctxLC->dwHandleCount) {
        // detach from handles list
        if(g_ctx.FLink == ctxLC) {
            g_ctx.FLink = ctxLC->FLink;
        } else {
            ctxParent = (PLC_CONTEXT)g_ctx.FLink;
            while(ctxParent) {
                if(ctxParent->FLink == ctxLC) {
                    ctxParent->FLink = ctxLC->FLink;
                    break;
                }
                ctxParent = (PLC_CONTEXT)ctxParent->FLink;
            }
        }
        LcLockAcquire(ctxLC);
        LcReadContigious_Close(ctxLC);
        if(ctxLC->pfnClose) { ctxLC->pfnClose(ctxLC); }
        LcLockRelease(ctxLC);
        ctxLC->version = 0;
        DeleteCriticalSection(&ctxLC->Lock);
        if(ctxLC->hDeviceModule) { FreeLibrary(ctxLC->hDeviceModule); }
        LocalFree(ctxLC->pMemMap);
        LocalFree(ctxLC);
    }
    LeaveCriticalSection(&g_ctx.Lock);
}

/*
* Close all LeechCore devices and contexts. This is done on DLL unload.
*/
VOID LcCloseAll()
{
    EnterCriticalSection(&g_ctx.Lock);
    while(g_ctx.FLink) {
        LcClose(g_ctx.FLink);
    }
    LeaveCriticalSection(&g_ctx.Lock);
}

/*
* Create helper function to parse optional device configuration parameters.
* -- ctxLC
*/
VOID LcCreate_FetchDeviceParameter(_Inout_ PLC_CONTEXT ctxLC)
{
    PLC_DEVICE_PARAMETER_ENTRY pe;
    CHAR szDevice[MAX_PATH] = { 0 };
    LPSTR szDelim, szParameters, szToken, szTokenContext = NULL;
    memcpy(szDevice, ctxLC->Config.szDevice, _countof(szDevice));
    if(!(szParameters = strstr(szDevice, "://"))) { return; }
    szParameters += 3;
    while((szToken = strtok_s(szParameters, ",;", &szTokenContext)) && (ctxLC->cDeviceParameter < LC_DEVICE_PARAMETER_MAX_ENTRIES)) {
        szParameters = NULL;
        if(!(szDelim = strstr(szToken, "="))) { continue; }
        pe = &ctxLC->pDeviceParameter[ctxLC->cDeviceParameter];
        strncpy_s(pe->szName, _countof(pe->szName), szToken, szDelim - szToken);
        strncpy_s(pe->szValue, _countof(pe->szValue), szDelim + 1, _TRUNCATE);
        pe->qwValue = Util_GetNumericA(pe->szValue);
        if((0 == pe->qwValue) && !_stricmp(pe->szValue, "true")) {
            pe->qwValue = 1;
        }
        ctxLC->cDeviceParameter++;
    }
}

/*
* Retrieve a device parameter by its name (if exists).
* -- ctxLc
* -- szName
* -- return
*/
EXPORTED_FUNCTION PLC_DEVICE_PARAMETER_ENTRY LcDeviceParameterGet(_In_ PLC_CONTEXT ctxLC, _In_ LPSTR szName)
{
    for(DWORD i = 0; i < ctxLC->cDeviceParameter; i++) {
        if(!_stricmp(szName, ctxLC->pDeviceParameter[i].szName)) {
            return &ctxLC->pDeviceParameter[i];
        }
    }
    return NULL;
}

/*
* Retrieve the numeric value of a device parameter (if exists).
* -- ctxLc
* -- szName
* -- return = the numeric value of the device parameter - 0 on fail.
*/
EXPORTED_FUNCTION QWORD LcDeviceParameterGetNumeric(_In_ PLC_CONTEXT ctxLC, _In_ LPSTR szName)
{
    PLC_DEVICE_PARAMETER_ENTRY p = LcDeviceParameterGet(ctxLC, szName);
    return p ? p->qwValue : 0;
}

/*
* Create helper function to fetch the correct device (and its create function).
* -- ctxLC
*/
VOID LcCreate_FetchDevice(_Inout_ PLC_CONTEXT ctx)
{
    CHAR c, szModule[2 * MAX_PATH] = { 0 };
    DWORD cszDevice = 0;
    // 1: check against built-in devices:
    if(0 == _strnicmp("rpc://", ctx->Config.szRemote, 6)) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "rpc", _TRUNCATE);
        ctx->pfnCreate = LeechRpc_Open;
        return;
    }
    if(0 == _strnicmp("smb://", ctx->Config.szRemote, 6)) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "smb", _TRUNCATE);
        ctx->pfnCreate = LeechRpc_Open;
        return;
    }
    if(ctx->Config.szRemote[0]) { return; }
    if((0 == _strnicmp("file", ctx->Config.szDevice, 4)) || (0 == _strnicmp("livekd", ctx->Config.szDevice, 6)) || (0 == _strnicmp("dumpit", ctx->Config.szDevice, 6))) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "file", _TRUNCATE);
        ctx->pfnCreate = DeviceFile_Open;
        return;
    }
    if((0 == _strnicmp("fpga", ctx->Config.szDevice, 4)) || (0 == _strnicmp("rawudp://", ctx->Config.szDevice, 9))) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "fpga", _TRUNCATE);
        ctx->pfnCreate = DeviceFPGA_Open;
        return;
    }
    if(0 == _strnicmp("usb3380", ctx->Config.szDevice, 7)) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "usb3380", _TRUNCATE);
        ctx->pfnCreate = Device3380_Open;
        return;
    }
    if(0 == _stricmp("totalmeltdown", ctx->Config.szDevice)) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "totalmeltdown", _TRUNCATE);
        ctx->pfnCreate = DeviceTMD_Open;
        return;
    }
    if(0 == _strnicmp("pmem", ctx->Config.szDevice, 4)) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "pmem", _TRUNCATE);
        ctx->pfnCreate = DevicePMEM_Open;
        return;
    }
    if(0 == _strnicmp("vmm://", ctx->Config.szDevice, 6)) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "vmm", _TRUNCATE);
        ctx->pfnCreate = DeviceVMM_Open;
        return;
    }
    if(0 == _strnicmp("vmware", ctx->Config.szDevice, 4)) {
        strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "vmware", _TRUNCATE);
        ctx->pfnCreate = DeviceVMWare_Open;
        return;
    }
    // 2: check against separate device modules:
    // 2.1: count device name length (and 'sanitize' againt disallowed chars).
    while((c = ctx->Config.szDevice[cszDevice]) && (c != ':')) {
        if(((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9'))) {
            cszDevice++;
        } else {
            cszDevice = 0;
            break;
        }
    }
    // 2.2: try load module:
    if(cszDevice && (cszDevice < 16)) {
        Util_GetPathLib(szModule);
        strcat_s(szModule, sizeof(szModule), "leechcore_device_");
        strncat_s(szModule, sizeof(szModule), ctx->Config.szDevice, cszDevice);
        strcat_s(szModule, sizeof(szModule), LC_LIBRARY_FILETYPE);
        if((ctx->hDeviceModule = LoadLibraryA(szModule))) {
            if((ctx->pfnCreate = (BOOL(*)(PLC_CONTEXT, PPLC_CONFIG_ERRORINFO))GetProcAddress(ctx->hDeviceModule, "LcPluginCreate"))) {
                strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), ctx->Config.szDevice, cszDevice);
                return;
            } else {
                FreeLibrary(ctx->hDeviceModule);
                ctx->hDeviceModule = NULL;
            }
        }
    }
    // 3: assume file is to be opened if no match for device name is found:
    strncpy_s(ctx->Config.szDeviceName, sizeof(ctx->Config.szDeviceName), "file", _TRUNCATE);
    ctx->pfnCreate = DeviceFile_Open;
}

#define ADDRDETECT_MAX      0x10

VOID LcCreate_MemMapInitAddressDetect_AddDefaultRange(_Inout_ PLC_CONTEXT ctxLC, _In_ QWORD paMax)
{
    paMax = (paMax + 0xfff) & ~0xfff;
    if(ctxLC->Config.fVolatile) {
        LcMemMap_AddRange(ctxLC, 0, min(paMax, 0x000a0000), 0);
        if(paMax > 0x00100000) {
            LcMemMap_AddRange(ctxLC, 0x00100000, paMax - 0x00100000, 0x00100000);
        }
    } else {
        LcMemMap_AddRange(ctxLC, 0, paMax, 0);
    }
}

/*
* Create helper function to initialize memory map and auto-detect max address.
* -- ctxLC
*/
VOID LcCreate_MemMapInitAddressDetect(_Inout_ PLC_CONTEXT ctxLC)
{
    BOOL fFPGA, fCheckTiny = FALSE;
    PPMEM_SCATTER ppMEMs;
    QWORD i, paCurrent = 0x100000000, cbChunk = 0x100000000;
    if(LcMemMap_IsInitialized(ctxLC)) { return; }
    if(ctxLC->Config.paMax) {
        if(ctxLC->Config.paMax > 0x000000fffffff000) {
            ctxLC->Config.paMax = 0x000000fffffff000;
        }
        LcCreate_MemMapInitAddressDetect_AddDefaultRange(ctxLC, ctxLC->Config.paMax);
        return;
    }
    if(!LcAllocScatter1(ADDRDETECT_MAX + 1, &ppMEMs)) { return; }
    // 1: detect topmost 4GB aligned address in 64GB scatter reads
    while(TRUE) {
        for(i = 0; i < ADDRDETECT_MAX; i++) {
            ppMEMs[i]->qwA = paCurrent + i * cbChunk;
            ppMEMs[i]->f = FALSE;
            ppMEMs[i]->cb = 0x8;
        }
        LcReadScatter(ctxLC, ADDRDETECT_MAX, ppMEMs);
        for(i = 0; i < ADDRDETECT_MAX; i++) {
            if(ppMEMs[i]->f) {
                paCurrent = ppMEMs[i]->qwA;
            }
        }
        if(!ppMEMs[ADDRDETECT_MAX - 1]->f) {
            break;
        }
    }
    // 2: detect exact topmost address in progressively smaller scatter reads
    fFPGA = (0 == _stricmp("fpga", ctxLC->Config.szDeviceName));
    while(cbChunk > 0x1000) {
        cbChunk = cbChunk >> 4;
        if(fFPGA && (cbChunk == 0x1000)) {
            // detect need for "tiny" PCIe algorithm of 128 bytes TLP.
            ppMEMs[ADDRDETECT_MAX]->qwA = paCurrent;
            fCheckTiny = TRUE;
        }
        for(i = 0; i < ADDRDETECT_MAX; i++) {
            ppMEMs[i]->qwA = paCurrent + i * cbChunk;
            ppMEMs[i]->f = FALSE;
        }
        LcReadScatter(ctxLC, ADDRDETECT_MAX + (fCheckTiny ? 0 : 1), ppMEMs);
        for(i = 0; i < ADDRDETECT_MAX; i++) {
            if(ppMEMs[i]->f) {
                paCurrent = ppMEMs[i]->qwA;
            }
        }
        if(fCheckTiny && !ppMEMs[ADDRDETECT_MAX]->f) {
            ctxLC->pfnSetOption(ctxLC, LC_OPT_FPGA_ALGO_TINY, 1);
            lcprintfv(ctxLC, "FPGA: TINY PCIe TLP algrithm auto-selected!\n");
        }
    }
    // 3: finish
    if(paCurrent == 0x100000000) { paCurrent -= 0x1000; }
    LcCreate_MemMapInitAddressDetect_AddDefaultRange(ctxLC, paCurrent + 0x1000);
    LocalFree(ppMEMs);
}

/*
* Create a new LeechCore device according to the supplied configuration.
* CALLER LcMemFree: ppLcCreateErrorInfo
* -- pLcCreateConfig
* -- ppLcCreateErrorInfo = ptr to receive function allocated struct with error
*       information upon function failure. This info may contain a user message
*       requesting user action as an example.
* -- return
*/
_Success_(return != NULL)
EXPORTED_FUNCTION HANDLE LcCreateEx(_Inout_ PLC_CONFIG pLcCreateConfig, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    PLC_CONTEXT ctxLC = NULL;
    QWORD qwExistingHandle = 0, tmStart = LcCallStart();
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    if(!pLcCreateConfig || (pLcCreateConfig->dwVersion != LC_CONFIG_VERSION)) { return NULL; }
    // check if open existing (primary) device:
    if(!pLcCreateConfig->szRemote[0] && (0 == _strnicmp("existing", pLcCreateConfig->szDevice, 8))) {
        if(0 == _strnicmp("existing://", pLcCreateConfig->szDevice, 11)) {
            qwExistingHandle = Util_GetNumericA(pLcCreateConfig->szDevice + 11);
        }
        EnterCriticalSection(&g_ctx.Lock);
        ctxLC = (PLC_CONTEXT)g_ctx.FLink;
        while(qwExistingHandle && ctxLC && (qwExistingHandle != (QWORD)ctxLC)) {
            ctxLC = ctxLC->FLink;
        }
        if(qwExistingHandle && (qwExistingHandle != (QWORD)ctxLC)) {
            ctxLC = NULL;
        }
        if(ctxLC) {
            memcpy(pLcCreateConfig, &ctxLC->Config, sizeof(LC_CONFIG));
            InterlockedIncrement(&ctxLC->dwHandleCount);
        }
        LeaveCriticalSection(&g_ctx.Lock);
        return ctxLC;
    }
    // initialize new leechcore context:
    if(!(ctxLC = LocalAlloc(LMEM_ZEROINIT, sizeof(LC_CONTEXT)))) { return NULL; }
    pLcCreateConfig->fRemote = FALSE;
    memcpy(&ctxLC->Config, pLcCreateConfig, sizeof(LC_CONFIG));
    InitializeCriticalSection(&ctxLC->Lock);
    ctxLC->version = LC_CONTEXT_VERSION;
    ctxLC->dwHandleCount = 1;
    ctxLC->cMemMapMax = 0x20;
    ctxLC->pMemMap = LocalAlloc(LMEM_ZEROINIT, ctxLC->cMemMapMax * sizeof(LC_MEMMAP_ENTRY));
    ctxLC->fPrintf[0] = (ctxLC->Config.dwPrintfVerbosity & LC_CONFIG_PRINTF_ENABLED) ? TRUE : FALSE;
    ctxLC->fPrintf[1] = (ctxLC->Config.dwPrintfVerbosity & LC_CONFIG_PRINTF_V) ? TRUE : FALSE;
    ctxLC->fPrintf[2] = (ctxLC->Config.dwPrintfVerbosity & LC_CONFIG_PRINTF_VV) ? TRUE : FALSE;
    ctxLC->fPrintf[3] = (ctxLC->Config.dwPrintfVerbosity & LC_CONFIG_PRINTF_VVV) ? TRUE : FALSE;
    LcCreate_FetchDeviceParameter(ctxLC);
    LcCreate_FetchDevice(ctxLC);
    if(!ctxLC->pfnCreate || !ctxLC->pfnCreate(ctxLC, ppLcCreateErrorInfo) || !LcReadContigious_Initialize(ctxLC)) {
        LcClose(ctxLC);
        return NULL;
    }
    if(!ctxLC->Config.fRemote) {
        LcCreate_MemMapInitAddressDetect(ctxLC);
        ctxLC->Config.paMax = LcMemMap_GetMaxAddress(ctxLC);
        ctxLC->Config.fWritable = (ctxLC->pfnWriteScatter != NULL) || (ctxLC->pfnWriteContigious != NULL);
    }
    ctxLC->CallStat.dwVersion = LC_STATISTICS_VERSION;
    QueryPerformanceFrequency((PLARGE_INTEGER)&ctxLC->CallStat.qwFreq);
    memcpy(pLcCreateConfig, &ctxLC->Config, sizeof(LC_CONFIG));
    lcprintfvv(ctxLC, "LeechCore v%i.%i.%i: Open Device: %s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION, ctxLC->Config.szDeviceName);
    // add new leechcore context to global list and return:
    EnterCriticalSection(&g_ctx.Lock);
    ctxLC->FLink = g_ctx.FLink;
    g_ctx.FLink = ctxLC;
    LeaveCriticalSection(&g_ctx.Lock);
    LcCallEnd(ctxLC, LC_STATISTICS_ID_OPEN, tmStart);
    return ctxLC;
}

_Success_(return != NULL)
EXPORTED_FUNCTION HANDLE LcCreate(_Inout_ PLC_CONFIG pLcCreateConfig)
{
    return LcCreateEx(pLcCreateConfig, NULL);
}



//-----------------------------------------------------------------------------
// Allocate/Free MEM_SCATTER:
//-----------------------------------------------------------------------------

/*
* Free LeechCore allocated memory such as memory allocated by the
* LcAllocScatter functions.
* -- pv
*/
EXPORTED_FUNCTION VOID LcMemFree(_Frees_ptr_opt_ PVOID pv)
{
    LocalFree(pv);
}

/*
* Allocate and pre-initialize empty MEMs including a 0x1000 buffer for each
* pMEM. The result should be freed by LcFree when its no longer needed.
* -- cMEMs
* -- pppMEMs = pointer to receive ppMEMs
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcAllocScatter1(_In_ DWORD cMEMs, _Out_ PPMEM_SCATTER *pppMEMs)
{
    DWORD i, o = 0;
    PBYTE pb, pbData;
    PMEM_SCATTER pMEMs, *ppMEMs;
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(PMEM_SCATTER) + sizeof(MEM_SCATTER) + 0x1000)))) { return FALSE; }
    ppMEMs = (PPMEM_SCATTER)pb;
    pMEMs = (PMEM_SCATTER)(pb + cMEMs * (sizeof(PMEM_SCATTER)));
    pbData = pb + cMEMs * (sizeof(PMEM_SCATTER) + sizeof(MEM_SCATTER));
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = pMEMs + i;
        pMEMs[i].version = MEM_SCATTER_VERSION;
        pMEMs[i].cb = 0x1000;
        pMEMs[i].pb = pbData + o;
        o += 0x1000;
    }
    *pppMEMs = ppMEMs;
    return TRUE;
}

/*
* Allocate and pre-initialize empty MEMs excluding the 0x1000 buffer which
* will be accounted towards the pbData buffer in a contiguous way.
* The result should be freed by LcFree when its no longer needed.
* -- cbData = size of pbData (must be cMEMs * 0x1000)
* -- pbData = buffer used for MEM.pb
* -- cMEMs
* -- pppMEMs = pointer to receive ppMEMs
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcAllocScatter2(_In_ DWORD cbData, _Inout_updates_opt_(cbData) PBYTE pbData, _In_ DWORD cMEMs, _Out_ PPMEM_SCATTER *pppMEMs)
{
    DWORD i, o = 0;
    PBYTE pb;
    PMEM_SCATTER pMEMs, *ppMEMs;
    if(cbData > (cMEMs << 12)) { return FALSE; }
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(PMEM_SCATTER) + sizeof(MEM_SCATTER))))) { return FALSE; }
    ppMEMs = (PPMEM_SCATTER)pb;
    pMEMs = (PMEM_SCATTER)(pb + cMEMs * (sizeof(PMEM_SCATTER)));
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = pMEMs + i;
        pMEMs[i].version = MEM_SCATTER_VERSION;
        pMEMs[i].cb = 0x1000;
        pMEMs[i].pb = pbData + o;
        o += 0x1000;
    }
    *pppMEMs = ppMEMs;
    return TRUE;
}

/*
* Allocate and pre-initialize empty MEMs excluding the 0x1000 buffer which
* will be accounted towards the pbData buffer in a contiguous way.
* -- pbDataFirstPage = optional buffer of first page
* -- pbDataLastPage = optional buffer of last page
* -- cbData = size of pbData
* -- pbData = buffer used for MEM.pb except first/last if exists
* -- cMEMs
* -- pppMEMs = pointer to receive ppMEMs
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcAllocScatter3(_Inout_updates_opt_(0x1000) PBYTE pbDataFirstPage, _Inout_updates_opt_(0x1000) PBYTE pbDataLastPage, _In_ DWORD cbData, _Inout_updates_opt_(cbData) PBYTE pbData, _In_ DWORD cMEMs, _Out_ PPMEM_SCATTER *pppMEMs)
{
    DWORD i, o = 0;
    PBYTE pb;
    PMEM_SCATTER pMEMs, *ppMEMs;
    if(pbDataFirstPage) { cbData += 0x1000; }
    if(pbDataLastPage) { cbData += 0x1000; }
    if(cbData > (cMEMs << 12)) { return FALSE; }
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(PMEM_SCATTER) + sizeof(MEM_SCATTER))))) { return FALSE; }
    ppMEMs = (PPMEM_SCATTER)pb;
    pMEMs = (PMEM_SCATTER)(pb + cMEMs * (sizeof(PMEM_SCATTER)));
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i] = pMEMs + i;
        pMEMs[i].version = MEM_SCATTER_VERSION;
        pMEMs[i].cb = 0x1000;
        if(pbDataFirstPage && (i == 0)) {
            pMEMs[i].pb = pbDataFirstPage;
        } else if(pbDataLastPage && (i == cMEMs - 1)) {
            pMEMs[i].pb = pbDataLastPage;
        } else {
            pMEMs[i].pb = pbData + o;
            o += 0x1000;
        }
    }
    *pppMEMs = ppMEMs;
    return TRUE;
}



// ----------------------------------------------------------------------------
// READ CONTIGIOUS FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Perform a contigious read from an underlying device instance.
* -- ctxRC
*/
VOID LcReadContigious_DeviceRead(PLC_READ_CONTIGIOUS_CONTEXT ctxRC)
{
    DWORD i, o, cbRead;
    PMEM_SCATTER pMEM;
    ctxRC->ctxLC->pfnReadContigious(ctxRC);
    cbRead = ctxRC->cbRead;
    for(i = 0, o = 0; ((i < ctxRC->cMEMs) && (cbRead >= ctxRC->ppMEMs[i]->cb)); i++) {
        pMEM = ctxRC->ppMEMs[i];
        memcpy(pMEM->pb, ctxRC->pb + o, pMEM->cb);
        pMEM->f = TRUE;
        o += pMEM->cb;
        cbRead -= pMEM->cb;
    }
}

/*
* Main thread loop for multi-chunked/threaded linear reads.
* -- ctxRC
* -- return
*/
DWORD LcReadContigious_ThreadProc(PLC_READ_CONTIGIOUS_CONTEXT ctxRC)
{
    while(ctxRC->ctxLC->RC.fActive) {
        WaitForSingleObject(ctxRC->hEventWakeup, INFINITE);
        if(!ctxRC->ctxLC->RC.fActive) { break; }
        LcReadContigious_DeviceRead(ctxRC);
        SetEvent(ctxRC->hEventFinish);
    }
    SetEvent(ctxRC->hEventFinish);
    return 0;
}

/*
* Perform a read of the linear memory specified onto the supplied MEMs.
* -- ctxLC
* -- cMEMs
* -- ppMEMs
* -- paBase
* -- cb
* -- fSingleThreaded
*/
VOID LcReadContigious_Read(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs, _In_ QWORD paBase, _In_ DWORD cb, _In_ BOOL fSingleThreaded)
{
    DWORD i;
    PLC_READ_CONTIGIOUS_CONTEXT ctxRC;
    if(!ctxLC->RC.fActive) { return; }
    if(fSingleThreaded) {
        ctxRC = ctxLC->RC.ctx[0];
    } else {
        i = WaitForMultipleObjects(ctxLC->ReadContigious.cThread, ctxLC->RC.hEventFinish, FALSE, INFINITE) - WAIT_OBJECT_0;
        if(!ctxLC->RC.fActive || (i >= ctxLC->ReadContigious.cThread)) { return; }
        ctxRC = ctxLC->RC.ctx[i];
        ResetEvent(ctxRC->hEventFinish);
    }
    ctxRC->cbRead = 0;
    ctxRC->cMEMs = cMEMs;
    ctxRC->ppMEMs = ppMEMs;
    ctxRC->paBase = paBase;
    ctxRC->cb = cb;
    if(fSingleThreaded) {
        LcReadContigious_DeviceRead(ctxRC);
    } else {
        SetEvent(ctxRC->hEventWakeup);
    }
}

/*
* Condense scattered MEMs into as large linear read-chunks as possible and
* schedule these chunks for reading using either single-threaded read or
* multi-threaded read - as configured and as optimal.
* MEMs are assumed to have their memory map translation/validation completed.
* NB! MUST BE CALLED SINGLE THREADED (per device instance).
* -- ctxLC
* -- cMEMs
* -- ppMEMs
*/
VOID LcReadContigious_ReadScatterGather(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PMEM_SCATTER pMEM;
    QWORD i, iBase = 0, paBase = 0;
    DWORD cbChunkSizeLimit, c = 0, cbCurrent = 0;
    BOOL fSingleThreaded, fFirst = TRUE;
    fSingleThreaded = (ctxLC->ReadContigious.cThread == 1);
    cbChunkSizeLimit = ctxLC->ReadContigious.cbChunkSize;
    if((ctxLC->ReadContigious.cThread > 1) && ctxLC->ReadContigious.fLoadBalance) {
        cbChunkSizeLimit = min(cbChunkSizeLimit, max(0x00010000, 0x1000 * (cMEMs / ctxLC->ReadContigious.cThread)));
    }
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(!MEM_SCATTER_ADDR_ISVALID(pMEM)) { continue; }
        if(c == 0) {
            if(pMEM->cb && !pMEM->f) {
                c = 1;
                iBase = i;
                paBase = pMEM->qwA;
                cbCurrent = pMEM->cb;
            }
        } else if((paBase + cbCurrent == pMEM->qwA) && (cbCurrent < cbChunkSizeLimit)) {
            c++;
            cbCurrent += pMEM->cb;
        } else {
            fFirst = FALSE;
            LcReadContigious_Read(ctxLC, c, ppMEMs + iBase, paBase, cbCurrent, fSingleThreaded);
            c = 0;
            if(pMEM->cb && !pMEM->f) {
                c = 1;
                iBase = i;
                paBase = pMEM->qwA;
                cbCurrent = pMEM->cb;
            }
        }
    }
    fSingleThreaded = fSingleThreaded || fFirst;
    if(c) {
        LcReadContigious_Read(ctxLC, c, ppMEMs + iBase, paBase, cbCurrent, fSingleThreaded);
    }
    if(!fSingleThreaded && ctxLC->RC.fActive) {
        WaitForMultipleObjects(ctxLC->ReadContigious.cThread, ctxLC->RC.hEventFinish, TRUE, INFINITE);
    }
}

/*
* Try closing the ReadContigious sub-system for a specific device instance.
* -- ctxLC
*/
VOID LcReadContigious_Close(_In_ PLC_CONTEXT ctxLC)
{
    DWORD i;
    PLC_READ_CONTIGIOUS_CONTEXT ctxRC;
    ctxLC->RC.fActive = FALSE;
    for(i = 0; i < ctxLC->ReadContigious.cThread; i++) {
        if(!ctxLC->RC.ctx[i] || !ctxLC->RC.ctx[i]->hEventWakeup) { break; }
        SetEvent(ctxLC->RC.ctx[i]->hEventWakeup);
    }
    for(i = 0; i < ctxLC->ReadContigious.cThread; i++) {
        if(!ctxLC->RC.ctx[i]) { break; }
        ctxRC = ctxLC->RC.ctx[i];
        ctxLC->RC.ctx[i] = NULL;
        if(ctxRC->hEventWakeup) { SetEvent(ctxRC->hEventWakeup); }
        if(ctxRC->hEventFinish) { WaitForSingleObject(ctxRC->hEventFinish, INFINITE); }
        if(ctxRC->hEventFinish) { CloseHandle(ctxRC->hEventFinish); }
        if(ctxRC->hEventWakeup) { CloseHandle(ctxRC->hEventWakeup); }
        if(ctxRC->hThread) { CloseHandle(ctxRC->hThread); }
        LocalFree(ctxRC);
    }
}

/*
* Initialize the ReadContigious sub-system for a specific device instance.
* -- ctxLC
* -- return
*/
_Success_(return)
BOOL LcReadContigious_Initialize(_In_ PLC_CONTEXT ctxLC)
{
    DWORD i;
    PLC_READ_CONTIGIOUS_CONTEXT ctxRC;
    if(!ctxLC->pfnReadContigious) { return TRUE; }
    if(!ctxLC->ReadContigious.cThread) { ctxLC->ReadContigious.cThread = 1; }                   // default: single-threaded.
    if(!ctxLC->ReadContigious.cbChunkSize) { ctxLC->ReadContigious.cbChunkSize = 0x01000000; }  // default: 16MB buffer / thread.
    ctxLC->ReadContigious.cThread = min(8, ctxLC->ReadContigious.cThread);                      // max 8 threads in parallel.
    ctxLC->ReadContigious.cbChunkSize = min(0x01000000, ctxLC->ReadContigious.cbChunkSize);     // max 16MB buffer / thread.
    ctxLC->RC.fActive = TRUE;
    for(i = 0; i < ctxLC->ReadContigious.cThread; i++) {
        if(!(ctxRC = ctxLC->RC.ctx[i] = LocalAlloc(0, sizeof(LC_READ_CONTIGIOUS_CONTEXT) + ctxLC->ReadContigious.cbChunkSize + 0x1000))) { goto fail; }
        ZeroMemory(ctxRC, sizeof(LC_READ_CONTIGIOUS_CONTEXT));
        ctxRC->ctxLC = ctxLC;
        if(ctxLC->ReadContigious.cThread > 1) {
            ctxRC->iRL = i;
            if(!(ctxRC->hEventWakeup = CreateEvent(NULL, FALSE, FALSE, FALSE))) { goto fail; }
            if(!(ctxRC->hEventFinish = ctxLC->RC.hEventFinish[i] = CreateEvent(NULL, TRUE, TRUE, FALSE))) { goto fail; }
            if(!(ctxRC->hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LcReadContigious_ThreadProc, ctxRC, 0, NULL))) { goto fail; }
        }
    }
    return TRUE;
fail:
    LcReadContigious_Close(ctxLC);
    return FALSE;
}



// ----------------------------------------------------------------------------
// READ / WRITE FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Read memory in a scattered non-contiguous way. This is recommended for reads.
* -- hLC
* -- cMEMs
* -- ppMEMs
*/
EXPORTED_FUNCTION VOID LcReadScatter(_In_ HANDLE hLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    QWORD i, tmStart = LcCallStart();
    if(!ctxLC || ctxLC->version != LC_CONTEXT_VERSION) { return; }
    if(ctxLC->Config.fRemote && ctxLC->pfnReadScatter) {
        // REMOTE
        ctxLC->pfnReadScatter(ctxLC, cMEMs, ppMEMs);
    } else {
        // LOCAL LEECHCORE
        // 1: TRANSLATE
        for(i = 0; i < cMEMs; i++) {
            MEM_SCATTER_STACK_PUSH(ppMEMs[i], ppMEMs[i]->qwA);
        }
        LcMemMap_TranslateMEMs(ctxLC, cMEMs, ppMEMs);
        // 2: FETCH
        LcLockAcquire(ctxLC);
        if(ctxLC->pfnReadScatter) {
            ctxLC->pfnReadScatter(ctxLC, cMEMs, ppMEMs);
        } else if(ctxLC->RC.fActive) {
            LcReadContigious_ReadScatterGather(ctxLC, cMEMs, ppMEMs);
        }
        LcLockRelease(ctxLC);
        // 3: RESTORE
        for(i = 0; i < cMEMs; i++) {
            ppMEMs[i]->qwA = MEM_SCATTER_STACK_POP(ppMEMs[i]);
        }
    }
    LcCallEnd(ctxLC, LC_STATISTICS_ID_READSCATTER, tmStart);
}

/*
* Read memory in a contiguous way. Note that if multiple memory segments are
* to be read LcReadScatter() may be more efficient.
* -- hLC,
* -- pa
* -- cb
* -- pb
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcRead(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb)
{
    QWORD i, o, paBase, cMEMs;
    PPMEM_SCATTER ppMEMs = NULL;
    BOOL fFirst, fLast, f, fResult = FALSE;
    BYTE pbFirst[0x1000] = { 0 }, pbLast[0x1000] = { 0 };
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    QWORD tmStart = LcCallStart();
    if(!ctxLC || ctxLC->version != LC_CONTEXT_VERSION) { return FALSE; }
    if(cb == 0) { return TRUE; }
    cMEMs = ((pa & 0xfff) + cb + 0xfff) >> 12;
    if(cMEMs == 0) { return FALSE; }
    fFirst = (pa & 0xfff) || (cb < 0x1000);
    fLast = (cMEMs > 1) && ((pa + cb) & 0xfff);
    f = LcAllocScatter3(
        fFirst ? pbFirst : NULL,
        fLast ? pbLast : NULL,
        cb - (fFirst ? 0x1000 - (pa & 0xfff) : 0) - (fLast ? (pa + cb) & 0xfff : 0),
        pb + ((pa & 0xfff) ? 0x1000 - (pa & 0xfff) : 0),
        (DWORD)cMEMs,
        &ppMEMs
    );
    if(!f) { goto fail; }
    paBase = pa & ~0xfff;
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i]->qwA = paBase + (i << 12);
    }
    LcReadScatter(hLC, (DWORD)cMEMs, ppMEMs);
    for(i = 0; i < cMEMs; i++) {
        if(!ppMEMs[i]->f) { goto fail; }
    }
    if(fFirst) {
        o = pa & 0xfff;
        memcpy(pb, ppMEMs[0]->pb + o, min(cb, 0x1000 - (SIZE_T)o));
    }
    if(fLast) {
        o = ppMEMs[cMEMs - 1]->qwA;
        memcpy(pb + (SIZE_T)(o - pa), ppMEMs[cMEMs - 1]->pb, (SIZE_T)(pa + cb - o));
    }
    fResult = TRUE;
fail:
    LocalFree(ppMEMs);
    LcCallEnd(ctxLC, LC_STATISTICS_ID_READ, tmStart);
    return fResult;
}

/*
* Write scatter memory in a contigious way - helper function for LcWriteScatter_GatherContigious().
* -- ctxLC
* -- cMEMs
* -- ppMEMs
* -- cbWrite
*/
VOID LcWriteScatter_GatherContigious2(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs, _In_ DWORD cbWrite)
{
    DWORD i;
    if(ctxLC->pfnWriteContigious(ctxLC, ppMEMs[0]->qwA, cbWrite, ppMEMs[0]->pb)) {
        for(i = 0; i < cMEMs; i++) {
            ppMEMs[i]->f = TRUE;
        }
    }
}

/*
* Write scatter memory in a contigious way.
* -- ctxLC
* -- cMEMs
* -- ppMEMs
*/
VOID LcWriteScatter_GatherContigious(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    DWORD c = 0, cbCurrent;
    QWORD i, iBase = 0, paBase;
    PMEM_SCATTER pMEM;
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f || !MEM_SCATTER_ADDR_ISVALID(pMEM)) { continue; }
        if(c == 0) {
            c = 1;
            iBase = i;
            paBase = pMEM->qwA;
            cbCurrent = pMEM->cb;
        } else if(paBase + cbCurrent == pMEM->qwA) {
            c++;
            cbCurrent += pMEM->cb;
        } else {
            LcWriteScatter_GatherContigious2(ctxLC, c, ppMEMs + iBase, cbCurrent);
            c = 1;
            iBase = i;
            paBase = pMEM->qwA;
            cbCurrent = pMEM->cb;
        }
    }
    if(c) {
        LcWriteScatter_GatherContigious2(ctxLC, c, ppMEMs + iBase, cbCurrent);
    }
}

/*
* Write memory in a scattered non-contiguous way.
* -- hLC
* -- cMEMs
* -- ppMEMs
*/
EXPORTED_FUNCTION VOID LcWriteScatter(_In_ HANDLE hLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    QWORD i, tmStart = LcCallStart();
    if(!ctxLC || ctxLC->version != LC_CONTEXT_VERSION) { return; }
    if(!ctxLC->pfnWriteScatter && !ctxLC->pfnWriteContigious) { return; }
    if(!cMEMs) { return; }
    if(ctxLC->Config.fRemote && ctxLC->pfnWriteScatter) {
        // REMOTE
        ctxLC->pfnWriteScatter(ctxLC, cMEMs, ppMEMs);
    } else {
        // LOCAL LEECHCORE
        // 1: TRANSLATE
        for(i = 0; i < cMEMs; i++) {
            MEM_SCATTER_STACK_PUSH(ppMEMs[i], ppMEMs[i]->qwA);
        }
        LcMemMap_TranslateMEMs(ctxLC, cMEMs, ppMEMs);
        // 2: FETCH
        LcLockAcquire(ctxLC);
        if(ctxLC->pfnWriteScatter) {
            ctxLC->pfnWriteScatter(ctxLC, cMEMs, ppMEMs);
        } else {
            LcWriteScatter_GatherContigious(ctxLC, cMEMs, ppMEMs);
        }
        LcLockRelease(ctxLC);
        // 3: RESTORE
        for(i = 0; i < cMEMs; i++) {
            ppMEMs[i]->qwA = MEM_SCATTER_STACK_POP(ppMEMs[i]);
        }
    }
    LcCallEnd(ctxLC, LC_STATISTICS_ID_WRITESCATTER, tmStart);
}

/*
* Write memory in a contiguous way.
* -- hLC
* -- pa
* -- cb
* -- pb
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcWrite(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _In_reads_(cb) PBYTE pb)
{
    BOOL fResult = FALSE;
    PBYTE pbBuffer = NULL;
    DWORD i = 0, oA = 0, cbP, cMEMs;
    PMEM_SCATTER pMEM, pMEMs, *ppMEMs;
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    QWORD tmStart = LcCallStart();
    if(!ctxLC || ctxLC->version != LC_CONTEXT_VERSION) { goto fail; }
    // allocate
    cMEMs = (DWORD)(((pa & 0xfff) + cb + 0xfff) >> 12);
    if(!(pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cMEMs * (sizeof(MEM_SCATTER) + sizeof(PMEM_SCATTER))))) { goto fail; }
    pMEMs = (PMEM_SCATTER)pbBuffer;
    ppMEMs = (PPMEM_SCATTER)(pbBuffer + cMEMs * sizeof(MEM_SCATTER));
    // prepare pages
    while(oA < cb) {
        cbP = 0x1000 - ((pa + oA) & 0xfff);
        cbP = min(cbP, cb - oA);
        ppMEMs[i] = pMEM = pMEMs + i;
        pMEM->version = MEM_SCATTER_VERSION;
        pMEM->qwA = pa + oA;
        pMEM->cb = cbP;
        pMEM->pb = pb + oA;
        oA += cbP;
        i++;
    }
    // write and verify result
    LcWriteScatter(hLC, cMEMs, ppMEMs);
    for(i = 0; i < cMEMs; i++) {
        if(!ppMEMs[i]->f) {
            break;
        }
    }
    fResult = TRUE;
fail:
    LocalFree(pbBuffer);
    LcCallEnd(ctxLC, LC_STATISTICS_ID_WRITE, tmStart);
    return fResult;
}



// ----------------------------------------------------------------------------
// GET / SET / COMMAND FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Helper function for LcGetOption.
*/
_Success_(return)
BOOL LcGetOption_DoWork(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    *pqwValue = 0;
    switch(fOption & 0xffffffff00000000) {
        case LC_OPT_CORE_PRINTF_ENABLE:
            *pqwValue = ctxLC->fPrintf[LC_PRINTF_ENABLE] ? 1 : 0;
            return TRUE;
        case LC_OPT_CORE_VERBOSE:
            *pqwValue = ctxLC->fPrintf[LC_PRINTF_V] ? 1 : 0;
            return TRUE;
        case LC_OPT_CORE_VERBOSE_EXTRA:
            *pqwValue = ctxLC->fPrintf[LC_PRINTF_VV] ? 1 : 0;
            return TRUE;
        case LC_OPT_CORE_VERBOSE_EXTRA_TLP:
            *pqwValue = ctxLC->fPrintf[LC_PRINTF_VVV] ? 1 : 0;
            return TRUE;
        case LC_OPT_CORE_VERSION_MAJOR:
            *pqwValue = VERSION_MAJOR;
            return TRUE;
        case LC_OPT_CORE_VERSION_MINOR:
            *pqwValue = VERSION_MINOR;
            return TRUE;
        case LC_OPT_CORE_VERSION_REVISION:
            *pqwValue = VERSION_REVISION;
            return TRUE;
        case LC_OPT_CORE_ADDR_MAX:
            *pqwValue = LcMemMap_GetMaxAddress(ctxLC);
            return TRUE;
        case LC_OPT_CORE_STATISTICS_CALL_COUNT:
            if((DWORD)fOption > LC_STATISTICS_ID_MAX) { return FALSE; }
            *pqwValue = ctxLC->CallStat.Call[(DWORD)fOption].c;
            return TRUE;
        case LC_OPT_CORE_STATISTICS_CALL_TIME:
            if((DWORD)fOption > LC_STATISTICS_ID_MAX) { return FALSE; }
            *pqwValue = ctxLC->CallStat.Call[(DWORD)fOption].tm;
            return TRUE;
        case LC_OPT_CORE_VOLATILE:
            *pqwValue = ctxLC->Config.fVolatile ? 1 : 0;
            return TRUE;
        case LC_OPT_CORE_READONLY:
            *pqwValue = ctxLC->Config.fWritable ? 0 : 1;
            return TRUE;
    }
    if(ctxLC->pfnGetOption) {
        return ctxLC->pfnGetOption(ctxLC, fOption, pqwValue);
    }
    return FALSE;
}

/*
* Set an option as defined by LC_OPT_*.  (R option).
* -- hLC
* -- fOption
* -- cbData
* -- pbData
* -- pcbData
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcGetOption(_In_ HANDLE hLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    QWORD tmStart = LcCallStart();
    BOOL fResult;
    if(!ctxLC || ctxLC->version != LC_CONTEXT_VERSION) { return FALSE; }
    LcLockAcquire(ctxLC);
    fResult = ctxLC->Config.fRemote ?
        ctxLC->pfnGetOption(ctxLC, fOption, pqwValue) :
        LcGetOption_DoWork(ctxLC, fOption, pqwValue);
    LcLockRelease(ctxLC);
    LcCallEnd(ctxLC, LC_STATISTICS_ID_GETOPTION, tmStart);
    return fResult;
}

/*
* Helper function for LcSetOption.
*/
_Success_(return)
BOOL LcSetOption_DoWork(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _In_ QWORD qwValue)
{
    switch(fOption) {
        case LC_OPT_CORE_PRINTF_ENABLE:
            ctxLC->fPrintf[LC_PRINTF_ENABLE] = qwValue ? TRUE : FALSE;
            return TRUE;
        case LC_OPT_CORE_VERBOSE:
            ctxLC->fPrintf[LC_PRINTF_V] = qwValue ? TRUE : FALSE;
            return TRUE;
        case LC_OPT_CORE_VERBOSE_EXTRA:
            ctxLC->fPrintf[LC_PRINTF_VV] = qwValue ? TRUE : FALSE;
            return TRUE;
        case LC_OPT_CORE_VERBOSE_EXTRA_TLP:
            ctxLC->fPrintf[LC_PRINTF_VVV] = qwValue ? TRUE : FALSE;
            return TRUE;
    }
    if(ctxLC->pfnSetOption) {
        return ctxLC->pfnSetOption(ctxLC, fOption, qwValue);
    }
    return FALSE;
}

/*
* Get an option as defined by LC_OPT_*.  (W option).
* -- hLC
* -- fOption
* -- cbData
* -- pbData
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcSetOption(_In_ HANDLE hLC, _In_ QWORD fOption, _In_ QWORD qwValue)
{
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    QWORD tmStart = LcCallStart();
    BOOL fResult;
    if(!ctxLC || ctxLC->version != LC_CONTEXT_VERSION) { return FALSE; }
    LcLockAcquire(ctxLC);
    fResult = ctxLC->Config.fRemote ?
        ctxLC->pfnSetOption(ctxLC, fOption, qwValue) :
        LcSetOption_DoWork(ctxLC, fOption, qwValue);
    LcLockRelease(ctxLC);
    LcCallEnd(ctxLC, LC_STATISTICS_ID_SETOPTION, tmStart);
    return fResult;
}

/*
* Helper function for LcCommand.
*/
_Success_(return)
BOOL LcCommand_DoWork(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _In_ DWORD cbDataIn, _In_reads_opt_(cbDataIn) PBYTE pbDataIn, _Out_opt_ PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    if(ppbDataOut) { *ppbDataOut = NULL; }
    if(pcbDataOut) { *pcbDataOut = 0; }
    switch(fOption) {
        case LC_CMD_STATISTICS_GET:
            if(!ppbDataOut) { return FALSE; }
            if(!(*ppbDataOut = LocalAlloc(0, sizeof(LC_STATISTICS)))) { return FALSE; }
            if(pcbDataOut) { *pcbDataOut = sizeof(LC_STATISTICS); }
            memcpy(*ppbDataOut, &ctxLC->CallStat, sizeof(LC_STATISTICS));
            return TRUE;
        case LC_CMD_MEMMAP_GET_STRUCT:
            if(!ppbDataOut) { return FALSE; }
            return LcMemMap_GetRangesAsStruct(ctxLC, ppbDataOut, pcbDataOut);
        case LC_CMD_MEMMAP_SET_STRUCT:
            if(!cbDataIn || !pbDataIn) { return FALSE; }
            return LcMemMap_SetRangesFromStruct(ctxLC, (PLC_MEMMAP_ENTRY)pbDataIn, cbDataIn / sizeof(LC_MEMMAP_ENTRY));
        case LC_CMD_MEMMAP_GET:
            if(!ppbDataOut) { return FALSE; }
            return LcMemMap_GetRangesAsText(ctxLC, ppbDataOut, pcbDataOut);
        case LC_CMD_MEMMAP_SET:
            if(!pbDataIn || !cbDataIn) { return FALSE; }
            return LcMemMap_SetRangesFromText(ctxLC, pbDataIn, cbDataIn);
    }
    if(ctxLC->pfnCommand) {
        return ctxLC->pfnCommand(ctxLC, fOption, cbDataIn, pbDataIn, ppbDataOut, pcbDataOut);
    }
    return FALSE;
}

/*
* Execute a command and retrieve a result (if any) at the same time.
* NB! If *ppbDataOut contains a memory allocation on exit this should be free'd
*     by calling LcMemFree().
* CALLER LcFreeMem: *ppbDataOut
* -- hLC
* -- fCommand
* -- cbDataIn
* -- pbDataIn
* -- ppbDataOut
* -- pcbDataOut
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcCommand(_In_ HANDLE hLC, _In_ QWORD fCommand, _In_ DWORD cbDataIn, _In_reads_opt_(cbDataIn) PBYTE pbDataIn, _Out_opt_ PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    PLC_CONTEXT ctxLC = (PLC_CONTEXT)hLC;
    QWORD tmStart = LcCallStart();
    BOOL fResult;
    if(!ctxLC || ctxLC->version != LC_CONTEXT_VERSION) { return FALSE; }
    LcLockAcquire(ctxLC);
    fResult = ctxLC->Config.fRemote ?
        ctxLC->pfnCommand(ctxLC, fCommand, cbDataIn, pbDataIn, ppbDataOut, pcbDataOut) :
        LcCommand_DoWork(ctxLC, fCommand, cbDataIn, pbDataIn, ppbDataOut, pcbDataOut);
    LcLockRelease(ctxLC);
    LcCallEnd(ctxLC, LC_STATISTICS_ID_COMMAND, tmStart);
    return fResult;
}
