// device_vmm.c : implementation of the vmm loopback device.
//                this is typically used for virtual machines.
// 
// Syntax: vmm://hvmm=0x<VMM_HANDLE>,hvm=0x<VMMVM_HANDLE>,max=<MAX_ADDRESS>
// 
// (c) Ulf Frisk, 2022-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
#include "util.h"

typedef struct tdVMM_HANDLE     *VMM_HANDLE;
typedef struct tdVMMVM_HANDLE   *VMMVM_HANDLE;
typedef BOOL(*FN_VMMDLL_ConfigGet)(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);
typedef DWORD(*FN_VMMDLL_VmMemReadScatter)(_In_ VMM_HANDLE hVMM, _In_ VMMVM_HANDLE hVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA, _In_ DWORD flags);
typedef DWORD(*FN_VMMDLL_VmMemWriteScatter)(_In_ VMM_HANDLE hVMM, _In_ VMMVM_HANDLE hVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA);

typedef struct tdDEVICE_CONTEXT_VMM {
    HMODULE hModuleVMM;
    VMM_HANDLE hVMM;
    VMMVM_HANDLE hVM;
    FN_VMMDLL_ConfigGet pfnFN_VMMDLL_ConfigGet;
    FN_VMMDLL_VmMemReadScatter pfnVMMDLL_VmMemReadScatter;
    FN_VMMDLL_VmMemWriteScatter pfnVMMDLL_VmMemWriteScatter;
} DEVICE_CONTEXT_VMM , *PDEVICE_CONTEXT_VMM;

//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DeviceVMM_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_VMM ctx = (PDEVICE_CONTEXT_VMM)ctxLC->hDevice;
    ctx->pfnVMMDLL_VmMemReadScatter(ctx->hVMM, ctx->hVM, ppMEMs, cpMEMs, 0);
}

VOID DeviceVMM_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_VMM ctx = (PDEVICE_CONTEXT_VMM)ctxLC->hDevice;
    ctx->pfnVMMDLL_VmMemWriteScatter(ctx->hVMM, ctx->hVM, ppMEMs, cpMEMs);
}

VOID DeviceVMM_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_VMM ctx = (PDEVICE_CONTEXT_VMM)ctxLC->hDevice;
    if(ctx) {
        ctxLC->hDevice = 0;
        if(ctx->hModuleVMM) { FreeLibrary(ctx->hModuleVMM); }
        LocalFree(ctx);
    }
}

#define VMM_PARAMETER_HANDLE_VMM    "hvmm"
#define VMM_PARAMETER_HANDLE_VM     "hvm"

_Success_(return)
BOOL DeviceVMM_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    PDEVICE_CONTEXT_VMM ctx;
    QWORD qwReadOnly = 0, qwVolatile = 0;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    // 1: initialize core context:
    if(sizeof(PVOID) < 8) { return FALSE; }     // only supported on 64-bit os (due to resource constraints)
    ctx = (PDEVICE_CONTEXT_VMM)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_VMM));
    if(!ctx) { return FALSE; }
    ctxLC->hDevice = (HANDLE)ctx;
    // 2: initialize vmm references:
    ctx->hModuleVMM = LoadLibraryA("vmm.dll");
    if(!ctx->hModuleVMM) {
        lcprintfv(ctxLC, "DEVICE: VMM: Unable to open loopback device #1.\n");
        goto fail;
    }
    ctx->pfnFN_VMMDLL_ConfigGet = (FN_VMMDLL_ConfigGet)GetProcAddress(ctx->hModuleVMM, "VMMDLL_ConfigGet");
    ctx->pfnVMMDLL_VmMemReadScatter = (FN_VMMDLL_VmMemReadScatter)GetProcAddress(ctx->hModuleVMM, "VMMDLL_VmMemReadScatter");
    ctx->pfnVMMDLL_VmMemWriteScatter = (FN_VMMDLL_VmMemWriteScatter)GetProcAddress(ctx->hModuleVMM, "VMMDLL_VmMemWriteScatter");
    if(!ctx->pfnFN_VMMDLL_ConfigGet || !ctx->pfnVMMDLL_VmMemReadScatter || !ctx->pfnVMMDLL_VmMemReadScatter) {
        lcprintfv(ctxLC, "DEVICE: VMM: Unable to open loopback device #2.\n");
        goto fail;
    }
    // 3: fetch config parameters:
    ctx->hVMM = (VMM_HANDLE)LcDeviceParameterGetNumeric(ctxLC, VMM_PARAMETER_HANDLE_VMM);
    ctx->hVM = (VMMVM_HANDLE)LcDeviceParameterGetNumeric(ctxLC, VMM_PARAMETER_HANDLE_VM);
    if(!ctx->pfnFN_VMMDLL_ConfigGet(ctx->hVMM, LC_OPT_CORE_VOLATILE, &qwVolatile)) {    // inherit from vm parent vmm
        lcprintfv(ctxLC, "DEVICE: VMM: Unable to communicate with loopback device #1.\n");
        goto fail;
    }
    if(!ctx->pfnFN_VMMDLL_ConfigGet(ctx->hVMM, LC_OPT_CORE_READONLY, &qwReadOnly)) {    // inherit from vm parent vmm
        lcprintfv(ctxLC, "DEVICE: VMM: Unable to communicate with loopback device #2.\n");
        goto fail;
    }
    // 4: set callback functions and fix up config
    ctxLC->fMultiThread = TRUE;
    ctxLC->Config.fVolatile = qwVolatile ? TRUE : FALSE;
    ctxLC->pfnClose = DeviceVMM_Close;
    ctxLC->pfnReadScatter = DeviceVMM_ReadScatter;
    ctxLC->pfnWriteScatter = qwReadOnly ? NULL : DeviceVMM_WriteScatter;
    return TRUE;
fail:
    DeviceVMM_Close(ctxLC);
    return FALSE;
}
