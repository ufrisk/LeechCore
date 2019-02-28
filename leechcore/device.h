// device.h : internal header file containing device-common defines.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_H__
#define __DEVICE_H__
#include <stdio.h>
#include "leechcore.h"
#include "oscompatibility.h"

#define DEVICE_PHYSMEMMAP_MAX_ENTRIES   0x100

typedef struct tdDEVICE_PHYSMEMMAP_ENTRY {
    QWORD paBase;
    QWORD cbSize;
    QWORD paRemapBase;
} DEVICE_PHYSMEMMAP_ENTRY, *PDEVICE_PHYSMEMMAP_ENTRY;

typedef struct tdDEVICE_PHYSMEMMAP {
    BOOL fValid;
    QWORD paMax;
    DWORD cEntries;
    DWORD iLastEntry;
    DEVICE_PHYSMEMMAP_ENTRY Runs[DEVICE_PHYSMEMMAP_MAX_ENTRIES];
} DEVICE_PHYSMEMMAP, *PDEVICE_PHYSMEMMAP;

typedef struct tdLEECHCORE_CONTEXT {
    LEECHCORE_CONFIG cfg;
    CRITICAL_SECTION DeviceLock;
    LEECHCORE_STATISTICS Statistics;
    BOOL fPrintfEnable;
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
    BOOL fDeviceMultiThread;
    BOOL fDeviceLock;
    QWORD paMaxUserInput;
    HANDLE hDevice;
    VOID(*pfnReadScatterMEM)(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs);
    BOOL(*pfnWriteMEM)(_In_ QWORD pa, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);
    VOID(*pfnProbeMEM)(_In_ QWORD pa, _In_ DWORD cPages, _Inout_updates_bytes_(cPages) PBYTE pbResultMap);
    VOID(*pfnClose)();
    BOOL(*pfnGetOption)(_In_ QWORD fOption, _Out_ PQWORD pqwValue);
    BOOL(*pfnSetOption)(_In_ QWORD fOption, _In_ QWORD qwValue);
    BOOL(*pfnCommandData)(_In_ ULONG64 fOption, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(cbDataOut) PBYTE pbDataOut, _In_ DWORD cbDataOut, _Out_opt_ PDWORD pcbDataOut);
    DEVICE_PHYSMEMMAP MemMap;
    QWORD qwRpcClientID;
} LEECHCORE_CONTEXT, *PLEECHCORE_CONTEXT;

// ----------------------------------------------------------------------------
// LEECHCORE global variables below:
// ----------------------------------------------------------------------------

PLEECHCORE_CONTEXT ctxDeviceMain;

#define vprintf(format, ...)        { if(ctxDeviceMain && ctxDeviceMain->fPrintfEnable)    { if(ctxDeviceMain->cfg.pfn_printf_opt) { ctxDeviceMain->cfg.pfn_printf_opt(format, ##__VA_ARGS__); } else { printf(format, ##__VA_ARGS__); } } }
#define vprintfv(format, ...)       { if(ctxDeviceMain && ctxDeviceMain->fVerbose)         { if(ctxDeviceMain->cfg.pfn_printf_opt) { ctxDeviceMain->cfg.pfn_printf_opt(format, ##__VA_ARGS__); } else { printf(format, ##__VA_ARGS__); } } }
#define vprintfvv(format, ...)      { if(ctxDeviceMain && ctxDeviceMain->fVerboseExtra)    { if(ctxDeviceMain->cfg.pfn_printf_opt) { ctxDeviceMain->cfg.pfn_printf_opt(format, ##__VA_ARGS__); } else { printf(format, ##__VA_ARGS__); } } }
#define vprintfvvv(format, ...)     { if(ctxDeviceMain && ctxDeviceMain->fVerboseExtraTlp) { if(ctxDeviceMain->cfg.pfn_printf_opt) { ctxDeviceMain->cfg.pfn_printf_opt(format, ##__VA_ARGS__); } else { printf(format, ##__VA_ARGS__); } } }
#define vprintf_fn(format, ...)     vprintf("%s: "format, __func__, ##__VA_ARGS__);
#define vprintfv_fn(format, ...)    vprintfv("%s: "format, __func__, ##__VA_ARGS__);
#define vprintfvv_fn(format, ...)   vprintfvv("%s: "format, __func__, ##__VA_ARGS__);
#define vprintfvvv_fn(format, ...)  vprintfvvv("%s: "format, __func__, ##__VA_ARGS__);

#endif /* __DEVICE_H__ */
