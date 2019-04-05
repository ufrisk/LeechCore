// device_pmem.c : implementation of the rekall winpmem memory acquisition device.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef _WIN32
#include "device.h"
#include "memmap.h"
#include "util.h"

//-----------------------------------------------------------------------------
// MEMORY INFO STRUCT FROM WINPMEM HEADER BELOW:
// https://github.com/google/rekall/blob/master/tools/windows/winpmem/executable/winpmem.h
//-----------------------------------------------------------------------------

#pragma pack(push, 2)

#define PMEM_MODE_IOSPACE 0
#define PMEM_MODE_PHYSICAL 1
#define PMEM_MODE_PTE 2
#define PMEM_MODE_PTE_PCI 3
#define PMEM_MODE_AUTO 99

#define PMEM_CTRL_IOCTRL CTL_CODE(0x22, 0x101, 0, 3)
#define PMEM_WRITE_ENABLE CTL_CODE(0x22, 0x102, 0, 3)
#define PMEM_INFO_IOCTRL CTL_CODE(0x22, 0x103, 0, 3)

typedef struct pmem_info_runs {
    __int64 start;
    __int64 length;
} PHYSICAL_MEMORY_RANGE;

struct PmemMemoryInfo {
    LARGE_INTEGER CR3;
    LARGE_INTEGER NtBuildNumber;
    LARGE_INTEGER KernBase;
    LARGE_INTEGER KDBG;
    LARGE_INTEGER KPCR[32];
    LARGE_INTEGER PfnDataBase;
    LARGE_INTEGER PsLoadedModuleList;
    LARGE_INTEGER PsActiveProcessHead;
    LARGE_INTEGER NtBuildNumberAddr;
    LARGE_INTEGER Padding[0xfe];
    LARGE_INTEGER NumberOfRuns;
    PHYSICAL_MEMORY_RANGE Run[100];
};

#pragma pack(pop)

//-----------------------------------------------------------------------------
// OTHER (NON WINPMEM) TYPEDEFS AND DEFINES BELOW:
//-----------------------------------------------------------------------------

#define DEVICEPMEM_SERVICENAME      "pmem"
#define DEVICEPMEM_MEMORYFILE       "\\\\.\\pmem"
LPCSTR szDEVICEPMEM_DRIVERFILE[2][3] = {
    {"att_winpmem_32.sys", "winpmem_32.sys", "winpmem_x86.sys"},
    {"att_winpmem_64.sys", "winpmem_64.sys", "winpmem_x64.sys"}
};

typedef struct tdDEVICE_CONTEXT_PMEM {
    HANDLE hFile;
    QWORD paMax;
    struct PmemMemoryInfo MemoryInfo;
} DEVICE_CONTEXT_PMEM, *PDEVICE_CONTEXT_PMEM;

//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DevicePMEM_ReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxDeviceMain->hDevice;
    DWORD i, cbToRead;
    PMEM_IO_SCATTER_HEADER pMEM;
    LARGE_INTEGER qwA_LI;
    BOOL fResultRead;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->cb == pMEM->cbMax) { continue; }
        if(!MemMap_VerifyTranslateMEM(pMEM, NULL)) {
            if(pMEM->cbMax && (pMEM->cb < pMEM->cbMax)) {
                vprintfvvv("device_pmem.c!DevicePMEM_ReadScatterMEM: FAILED: no memory at address %016llx\n", pMEM->qwA);
            }
            continue;
        }
        if(pMEM->qwA >= ctx->paMax) { continue; }
        cbToRead = (DWORD)min(pMEM->cb, ctx->paMax - pMEM->qwA);
        qwA_LI.QuadPart = pMEM->qwA;
        SetFilePointerEx(ctx->hFile, qwA_LI, NULL, FILE_BEGIN);
        fResultRead = ReadFile(ctx->hFile, pMEM->pb, pMEM->cbMax, &pMEM->cb, NULL);
        if(fResultRead) {
            if(ctxDeviceMain->fVerboseExtraTlp) {
                vprintf_fn(
                    "READ:\n        offset=%016llx req_len=%08x rsp_len=%08x\n",
                    pMEM->qwA,
                    pMEM->cbMax,
                    pMEM->cb
                );
                Util_PrintHexAscii(pMEM->pb, pMEM->cb, 0);
            }
        } else {
            vprintfvvv_fn("READ FAILED:\n        offset=%016llx req_len=%08x\n", pMEM->qwA, pMEM->cbMax);
        }
    }
}

BOOL DevicePMEM_GetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxDeviceMain->hDevice;
    if(fOption == LEECHCORE_OPT_MEMORYINFO_VALID) {
        *pqwValue = 1;
        return TRUE;
    }
    switch(fOption) {
        case LEECHCORE_OPT_MEMORYINFO_ADDR_MAX:
            *pqwValue = ctx->paMax;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_FLAG_32BIT:
            *pqwValue = 0; // only 64-bit supported currently
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_FLAG_PAE:
            *pqwValue = 0;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_VERSION_MINOR:
            *pqwValue = ctx->MemoryInfo.NtBuildNumber.HighPart;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_VERSION_MAJOR:
            *pqwValue = ctx->MemoryInfo.NtBuildNumber.LowPart;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_DTB:
            *pqwValue = ctx->MemoryInfo.CR3.QuadPart;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PFN:
            *pqwValue = ctx->MemoryInfo.PfnDataBase.QuadPart;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PsLoadedModuleList:
            *pqwValue = ctx->MemoryInfo.PsLoadedModuleList.QuadPart;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PsActiveProcessHead:
            *pqwValue = ctx->MemoryInfo.PsActiveProcessHead.QuadPart;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP:
            *pqwValue = 0x8664; // only 64-bit supported currently
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_KERNELBASE:
            *pqwValue = ctx->MemoryInfo.KernBase.QuadPart;
            return TRUE;
    }
    *pqwValue = 0;
    return FALSE;
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
* Create the winpmem kernel driver loader service and load the kernel driver
* into the kernel. Upon fail it's guaranteed that no lingering service exists.
*/
BOOL DevicePMEM_SvcStart()
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxDeviceMain->hDevice;
    DWORD i, dwWinErr;
    CHAR szDriverFile[MAX_PATH] = { 0 };
    FILE *pDriverFile = NULL;
    HMODULE hModuleLeechCore;
    SC_HANDLE hSCM = 0, hSvcPMem = 0;
    BOOL f64;
    // 1: verify that driver file exists.
    if(!_strnicmp("pmem://", ctxDeviceMain->cfg.szDevice, 7)) {
        strcat_s(szDriverFile, _countof(szDriverFile), ctxDeviceMain->cfg.szDevice + 7);
    } else {
        // NB! defaults to locating driver .sys file relative to the loaded
        // 'leechcore.dll' - if unable to locate library (for whatever reason)
        // defaults will be to try to loade relative to executable (NULL).
        f64 = Util_IsPlatformBitness64();
        for(i = 0; i < (sizeof(szDEVICEPMEM_DRIVERFILE[f64 ? 1 : 0]) / sizeof(LPCSTR)); i++) {
            hModuleLeechCore = LoadLibraryA("leechcore.dll");
            Util_GetPathDll(szDriverFile, hModuleLeechCore);
            if(hModuleLeechCore) { FreeLibrary(hModuleLeechCore); }
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
        vprintf(
            "DEVICE: ERROR: unable to locate the winpmem driver file '%s'.\n",
            szDriverFile);
        return FALSE;
    }
    fclose(pDriverFile);
    // 2: create and start service to load driver into kernel.
    if(!(hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE))) {
        vprintf("DEVICE: ERROR: unable to load driver - not running as elevated administrator?\n");
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
            vprintf(
                "DEVICE: ERROR: Unable create service required to load driver.\n"
                "Is project executable running from the C:\\ drive ?\n");
            vprintfv("DEVICE: ERROR: LastError: 0x%08x\n", dwWinErr);
            CloseServiceHandle(hSCM);
            return FALSE;
        }
    }
    if(!StartServiceA(hSvcPMem, 0, NULL) && ((dwWinErr = GetLastError()) != ERROR_SERVICE_ALREADY_RUNNING)) {
        vprintf(
            "DEVICE: ERROR: Unable to load driver into kernel.\n"
            "Is project executable running from the C:\\ drive ?\n");
        vprintfv("DEVICE: ERROR: LastError: 0x%08x\n", dwWinErr);
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
VOID DevicePMEM_Close()
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxDeviceMain->hDevice;
    DevicePMEM_SvcClose();
    if(ctx) {
        CloseHandle(ctx->hFile);
        MemMap_Close();
        LocalFree(ctx);
    }
    ctxDeviceMain->hDevice = 0;
}

BOOL DevicePMEM_GetMemoryInformation()
{
    PDEVICE_CONTEXT_PMEM ctx = (PDEVICE_CONTEXT_PMEM)ctxDeviceMain->hDevice;
    DWORD i, cbRead;
    // 1: retrieve information from kernel driver
    if(!DeviceIoControl(ctx->hFile, PMEM_INFO_IOCTRL, NULL, 0, &ctx->MemoryInfo, sizeof(ctx->MemoryInfo), &cbRead, NULL)) {
        vprintf("DEVICE: ERROR: Unable to communicate with winpmem driver.\n");
        return FALSE;
    }
    // 2: sanity checks
    if(ctx->MemoryInfo.NumberOfRuns.QuadPart > 100) {
        vprintf("DEVICE: ERROR: too many memory segments reported from winpmem driver. (%lli)\n", ctx->MemoryInfo.NumberOfRuns.QuadPart);
        return FALSE;
    }
    // 3: parse memory ranges
    MemMap_Initialize(0x0000ffffffffffff);
    for(i = 0; i < ctx->MemoryInfo.NumberOfRuns.QuadPart; i++) {
        if(!MemMap_AddRange(ctx->MemoryInfo.Run[i].start, ctx->MemoryInfo.Run[i].length, ctx->MemoryInfo.Run[i].start)) {
            vprintf("DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", ctx->MemoryInfo.Run[i].start, ctx->MemoryInfo.Run[i].length, ctx->MemoryInfo.Run[i].start);
            return FALSE;
        }
    }
    MemMap_GetMaxAddress(&ctx->paMax);
    return TRUE;
}

BOOL DevicePMEM_Open()
{
    BOOL result;
    PDEVICE_CONTEXT_PMEM ctx;
    // 1: terminate any lingering winpmem service.
    DevicePMEM_SvcClose();
    // 2: initialize core context.
    ctx = (PDEVICE_CONTEXT_PMEM)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_PMEM));
    if(!ctx) { return FALSE; }
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    // set callback functions and fix up config
    ctxDeviceMain->cfg.tpDevice = LEECHCORE_DEVICE_PMEM;
    ctxDeviceMain->cfg.fVolatile = TRUE;
    ctxDeviceMain->cfg.cbMaxSizeMemIo = ctxDeviceMain->cfg.cbMaxSizeMemIo ? min(ctxDeviceMain->cfg.cbMaxSizeMemIo, 0x01000000) : 0x01000000; // 16MB (or lower user-value)
    ctxDeviceMain->pfnClose = DevicePMEM_Close;
    ctxDeviceMain->pfnReadScatterMEM = DevicePMEM_ReadScatterMEM;
    ctxDeviceMain->pfnGetOption = DevicePMEM_GetOption;
    // 3: load winpmem kernel driver.
    result = DevicePMEM_SvcStart();
    // 4: retrieve memory map.
    result = result && DevicePMEM_GetMemoryInformation();
    if(!result) {
        DevicePMEM_Close();
        return FALSE;
    }
    ctxDeviceMain->cfg.paMaxNative = ctx->paMax;
    vprintfv("DEVICE: Successfully loaded winpmem memory acquisition driver.\n");
    return TRUE;
}

#endif /* _WIN32 */
#if defined(LINUX) || defined(ANDROID)
#include "device.h"

BOOL DevicePMEM_Open()
{
    vprintfv("DEVICE: FAIL: 'pmem' memory acquisition only supported on Windows.\n");
    return FALSE;
}

#endif /* LINUX || ANDROID */
