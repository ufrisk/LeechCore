// device_pmem.c : implementation of the rekall winpmem memory acquisition device.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
#include "util.h"
#ifdef _WIN32

DWORD g_cDevicePMEM = 0;

//-----------------------------------------------------------------------------
// MEMORY INFO STRUCT FROM WINPMEM HEADER BELOW:
// https://github.com/Velocidex/WinPmem/blob/master/kernel/userspace_interface/winpmem_shared.h
//-----------------------------------------------------------------------------

#pragma pack(push, 2)

#define PMEM_MODE_IOSPACE   0
#define PMEM_MODE_PHYSICAL  1
#define PMEM_MODE_PTE       2
#define PMEM_MODE_AUTO      99

#define NUMBER_OF_RUNS      (100)

#define PMEM_CTRL_IOCTRL CTL_CODE(0x22, 0x101, 3, 3)
#define PMEM_WRITE_ENABLE CTL_CODE(0x22, 0x102, 3, 3)
#define PMEM_INFO_IOCTRL CTL_CODE(0x22, 0x103, 3, 3)

typedef struct tdPHYSICAL_MEMORY_RANGE {
    __int64 start;
    __int64 length;
} PHYSICAL_MEMORY_RANGE;

struct PmemMemoryInfo {
    LARGE_INTEGER CR3;
    LARGE_INTEGER NtBuildNumber;
    LARGE_INTEGER KernBase;
    LARGE_INTEGER KDBG;
#ifdef _WIN64
    LARGE_INTEGER KPCR[64];
#else
    LARGE_INTEGER KPCR[32];
#endif
    LARGE_INTEGER PfnDataBase;
    LARGE_INTEGER PsLoadedModuleList;
    LARGE_INTEGER PsActiveProcessHead;
    LARGE_INTEGER NtBuildNumberAddr;
    LARGE_INTEGER Padding[0xfe];
    LARGE_INTEGER NumberOfRuns;
    PHYSICAL_MEMORY_RANGE Run[NUMBER_OF_RUNS];
};

#pragma pack(pop)

//-----------------------------------------------------------------------------
// OTHER (NON WINPMEM) TYPEDEFS AND DEFINES BELOW:
//-----------------------------------------------------------------------------

#define DEVICEPMEM_SERVICENAME      "pmem"
#define DEVICEPMEM_MEMORYFILE       "\\\\.\\pmem"
LPCSTR szDEVICEPMEM_DRIVERFILE[2][1] = {
    {"winpmem_x86.sys"},
    {"winpmem_x64.sys"}
};

typedef struct tdDEVICE_CONTEXT_PMEM {
    HANDLE hFile;
    QWORD paMax;
    struct PmemMemoryInfo MemoryInfo;
} DEVICE_CONTEXT_PMEM, *PDEVICE_CONTEXT_PMEM;

//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DevicePMEM_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    DWORD i, cbRead;
    PMEM_SCATTER pMEM;
    LARGE_INTEGER qwA_LI;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM)) { continue; }
        qwA_LI.QuadPart = pMEM->qwA;
        SetFilePointerEx(ctx->hFile, qwA_LI, NULL, FILE_BEGIN);
        pMEM->f = ReadFile(ctx->hFile, pMEM->pb, pMEM->cb, &cbRead, NULL);
        if(pMEM->f) {
            if(ctxLC->fPrintf[LC_PRINTF_VVV]) {
                lcprintf_fn(
                    ctxLC,
                    "READ:\n        offset=%016llx req_len=%08x\n",
                    pMEM->qwA,
                    pMEM->cb
                );
                Util_PrintHexAscii(ctxLC, pMEM->pb, pMEM->cb, 0);
            }
        } else {
            lcprintfvvv_fn(ctxLC, "READ FAILED:\n        offset=%016llx req_len=%08x\n", pMEM->qwA, pMEM->cb);
        }
    }
}

/*
* Unload the winpmem kernel driver and also delete the driver-loading service.
*/
VOID DevicePMEM_SvcClose()
{
    SC_HANDLE hSCM, hSvcPMem;
    SERVICE_STATUS SvcStatus;
    // 1: shut down and delete service.
    if((hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE))) {
        hSvcPMem = OpenServiceA(hSCM, DEVICEPMEM_SERVICENAME, SERVICE_ALL_ACCESS);
        if(hSvcPMem) {
            ControlService(hSvcPMem, SERVICE_CONTROL_STOP, &SvcStatus);
        };
        if(hSvcPMem) { DeleteService(hSvcPMem); }
        if(hSvcPMem) { CloseServiceHandle(hSvcPMem); }
        CloseServiceHandle(hSCM);
    }
}

/*
* Is pmem service running (kernel driver loaded).
*/
BOOL DevicePMEM_SvcStatusRunning(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    BOOL fResult = FALSE;
    SC_HANDLE hSCM, hSvcPMem;
    // 1: check if driver is already loaded
    if((hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE))) {
        if((hSvcPMem = OpenServiceA(hSCM, DEVICEPMEM_SERVICENAME, SERVICE_ALL_ACCESS))) {
            if(hSvcPMem) { CloseServiceHandle(hSvcPMem); }
            fResult = TRUE;
        }
        CloseServiceHandle(hSCM);
    }
    // 2: on success - open file handle to driver
    if(fResult) {
        ctx->hFile = CreateFileA(
            DEVICEPMEM_MEMORYFILE,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        fResult = ctx->hFile ? TRUE : FALSE;
    }
    return fResult;
}

/*
* Create the winpmem kernel driver loader service and load the kernel driver
* into the kernel. Upon fail it's guaranteed that no lingering service exists.
*/
_Success_(return)
BOOL DevicePMEM_SvcStart(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    DWORD i, dwWinErr;
    CHAR szDriverFile[MAX_PATH] = { 0 };
    FILE *pDriverFile = NULL;
    SC_HANDLE hSCM = 0, hSvcPMem = 0;
    BOOL f64;
    // 1: verify that driver file exists.
    if(!_strnicmp("pmem://", ctxLC->Config.szDevice, 7)) {
        strcat_s(szDriverFile, _countof(szDriverFile), ctxLC->Config.szDevice + 7);
    } else {
        // NB! defaults to locating driver .sys file relative to the loaded
        // 'leechcore.dll' - if unable to locate library (for whatever reason)
        // defaults will be to try to loade relative to executable (NULL).
        f64 = Util_IsPlatformBitness64();
        for(i = 0; i < (sizeof(szDEVICEPMEM_DRIVERFILE[f64 ? 1 : 0]) / sizeof(LPCSTR)); i++) {
            Util_GetPathLib(szDriverFile);
            strcat_s(szDriverFile, _countof(szDriverFile), szDEVICEPMEM_DRIVERFILE[f64 ? 1 : 0][i]);
            if(!fopen_s(&pDriverFile, szDriverFile, "rb") && pDriverFile) {
                fclose(pDriverFile);
                pDriverFile = NULL;
                break;
            }
            ZeroMemory(szDriverFile, _countof(szDriverFile));
        }
    }
    if(fopen_s(&pDriverFile, szDriverFile, "rb") || !pDriverFile) {
        lcprintf(ctxLC,
            "DEVICE: ERROR: unable to locate the winpmem driver file '%s'.\n",
            szDriverFile);
        return FALSE;
    }
    fclose(pDriverFile);
    // 2: create and start service to load driver into kernel.
    if(!(hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE))) {
        lcprintf(ctxLC, "DEVICE: ERROR: unable to load driver - not running as elevated administrator?\n");
        return FALSE;
    }
    hSvcPMem = CreateServiceA(
        hSCM,
        DEVICEPMEM_SERVICENAME,
        DEVICEPMEM_SERVICENAME,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        szDriverFile,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if(!hSvcPMem) {
        if((dwWinErr = GetLastError()) == ERROR_SERVICE_EXISTS) {
            hSvcPMem = OpenServiceA(hSCM, DEVICEPMEM_SERVICENAME, SERVICE_ALL_ACCESS);
        } else {
            lcprintf(ctxLC,
                "DEVICE: ERROR: Unable create service required to load driver.\n"
                "Is project executable running from the C:\\ drive ?\n");
            lcprintfv(ctxLC, "DEVICE: ERROR: LastError: 0x%08x\n", dwWinErr);
            CloseServiceHandle(hSCM);
            return FALSE;
        }
    }
    if(!StartServiceA(hSvcPMem, 0, NULL) && ((dwWinErr = GetLastError()) != ERROR_SERVICE_ALREADY_RUNNING)) {
        lcprintf(ctxLC,
            "DEVICE: ERROR: Unable to load driver into kernel.\n"
            "Is project executable running from the C:\\ drive ?\n");
        lcprintfv(ctxLC, "DEVICE: ERROR: LastError: 0x%08x\n", dwWinErr);
        CloseServiceHandle(hSvcPMem);
        CloseServiceHandle(hSCM);
        DevicePMEM_SvcClose();
        return FALSE;
    }
    CloseServiceHandle(hSvcPMem);
    CloseServiceHandle(hSCM);
    // 3: open file handle
    ctx->hFile = CreateFileA(
        DEVICEPMEM_MEMORYFILE,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if(!ctx->hFile) {
        DevicePMEM_SvcClose();
        return FALSE;
    }
    return TRUE;
}

/*
* Close the PMEM device and clean up both context and any kernel drivers.
*/
VOID DevicePMEM_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    if(0 == --g_cDevicePMEM) {
        DevicePMEM_SvcClose();
    }
    if(ctx) {
        CloseHandle(ctx->hFile);
        LocalFree(ctx);
    }
    ctxLC->hDevice = 0;
}

_Success_(return)
BOOL DevicePMEM_GetMemoryInformation(_Inout_ PLC_CONTEXT ctxLC, _In_ BOOL fFirst)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    DWORD i, cbRead, dwMode = PMEM_MODE_PTE;
    // 1: retrieve information from kernel driver
    if(!DeviceIoControl(ctx->hFile, PMEM_INFO_IOCTRL, NULL, 0, &ctx->MemoryInfo, sizeof(ctx->MemoryInfo), &cbRead, NULL)) {
        if(!fFirst) {
            lcprintf(ctxLC, "DEVICE: ERROR: Unable to communicate with winpmem driver.\n");
        }
        return FALSE;
    }
    // 2: sanity checks
    if((ctx->MemoryInfo.NumberOfRuns.QuadPart == 0) || (ctx->MemoryInfo.NumberOfRuns.QuadPart > 100)) {
        if(!fFirst) {
            lcprintf(ctxLC, "DEVICE: ERROR: too few/many memory segments reported from winpmem driver. (%lli)\n", ctx->MemoryInfo.NumberOfRuns.QuadPart);
        }
        return FALSE;
    }
    // 3: parse memory ranges
    for(i = 0; i < ctx->MemoryInfo.NumberOfRuns.QuadPart; i++) {
        if(!LcMemMap_AddRange(ctxLC, ctx->MemoryInfo.Run[i].start, ctx->MemoryInfo.Run[i].length, ctx->MemoryInfo.Run[i].start)) {
            if(!fFirst) {
                lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", ctx->MemoryInfo.Run[i].start, ctx->MemoryInfo.Run[i].length, ctx->MemoryInfo.Run[i].start);
            }
            return FALSE;
        }
    }
    // 4: set acquisition mode to PTE (this seems to be working with VSM).
    if(!DeviceIoControl(ctx->hFile, PMEM_CTRL_IOCTRL, &dwMode, sizeof(DWORD), NULL, 0, &cbRead, NULL)) {
        return FALSE;
    }
    return TRUE;
}

_Success_(return)
BOOL DevicePMEM_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxLC->hDevice;
    if(fOption == LC_OPT_MEMORYINFO_VALID) {
        *pqwValue = 1;
        return TRUE;
    }
    switch(fOption) {
        case LC_OPT_MEMORYINFO_FLAG_32BIT:
            *pqwValue = 0; // only 64-bit supported currently
            return TRUE;
        case LC_OPT_MEMORYINFO_FLAG_PAE:
            *pqwValue = 0;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_VERSION_MINOR:
            *pqwValue = ctx->MemoryInfo.NtBuildNumber.HighPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_VERSION_MAJOR:
            *pqwValue = ctx->MemoryInfo.NtBuildNumber.LowPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_DTB:
            *pqwValue = ctx->MemoryInfo.CR3.QuadPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PFN:
            *pqwValue = ctx->MemoryInfo.PfnDataBase.QuadPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PsLoadedModuleList:
            *pqwValue = ctx->MemoryInfo.PsLoadedModuleList.QuadPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PsActiveProcessHead:
            *pqwValue = ctx->MemoryInfo.PsActiveProcessHead.QuadPart;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP:
            *pqwValue = 0x8664; // only 64-bit supported currently
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_KERNELBASE:
            *pqwValue = ctx->MemoryInfo.KernBase.QuadPart;
            return TRUE;
    }
    *pqwValue = 0;
    return FALSE;
}

_Success_(return)
BOOL DevicePMEM_Open2(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo, _In_ BOOL fFirst)
{
    BOOL result;
    PDEVICE_CONTEXT_PMEM ctx;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    // 1: initialize core context.
    ctx = (PDEVICE_CONTEXT_PMEM)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_PMEM));
    if(!ctx) { return FALSE; }
    ctxLC->hDevice = (HANDLE)ctx;
    // set callback functions and fix up config
    ctxLC->Config.fVolatile = TRUE;
    ctxLC->pfnClose = DevicePMEM_Close;
    ctxLC->pfnReadScatter = DevicePMEM_ReadScatter;
    ctxLC->pfnGetOption = DevicePMEM_GetOption;
    // 2: load winpmem kernel driver.
    g_cDevicePMEM++;
    result = DevicePMEM_SvcStatusRunning(ctxLC) || DevicePMEM_SvcStart(ctxLC);
    // 3: retrieve memory map.
    result = result && DevicePMEM_GetMemoryInformation(ctxLC, fFirst);
    if(!result) {
        DevicePMEM_Close(ctxLC);
        return FALSE;
    }
    lcprintfv(ctxLC, "DEVICE: Successfully loaded winpmem memory acquisition driver.\n");
    return TRUE;
}

_Success_(return)
BOOL DevicePMEM_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    // Sometimes communication with PMEM driver will fail even though the driver
    // is loaded. It's unknown why this is happening. But it always helps trying
    // again so wrap the open function to perform a retry if there is a fail.
    if(DevicePMEM_Open2(ctxLC, ppLcCreateErrorInfo, TRUE)) { return TRUE; }
    Sleep(100);
    return DevicePMEM_Open2(ctxLC, ppLcCreateErrorInfo, FALSE);
}

#endif /* _WIN32 */
#ifdef LINUX

_Success_(return)
BOOL DevicePMEM_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    lcprintfv(ctxLC, "DEVICE: FAIL: 'pmem' memory acquisition only supported on Windows.\n");
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    return FALSE;
}

#endif /* LINUX */
