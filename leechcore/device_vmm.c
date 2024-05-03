// device_vmm.c : implementation of the vmm loopback device.
//                this is typically used for virtual machines.
// 
// Syntax: vmm://hvmm=0x<VMM_HANDLE>,hvm=0x<VMMVM_HANDLE>,max=<MAX_ADDRESS>
// 
// (c) Ulf Frisk, 2022-2024
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

//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DeviceVMM_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PLC_VMM ctx = (PLC_VMM)ctxLC->hDevice;
    ((FN_VMMDLL_VmMemReadScatter)ctx->pfnVMMDLL_VmMemReadScatter)(ctx->hVMM, ctx->hVMMVM, ppMEMs, cpMEMs, 0);
}

VOID DeviceVMM_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PLC_VMM ctx = (PLC_VMM)ctxLC->hDevice;
    ((FN_VMMDLL_VmMemWriteScatter)ctx->pfnVMMDLL_VmMemWriteScatter)(ctx->hVMM, ctx->hVMMVM, ppMEMs, cpMEMs);
}

VOID DeviceVMM_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PLC_VMM ctx = (PLC_VMM)ctxLC->hDevice;
    ctxLC->hDevice = 0;
    LocalFree(ctx);
}

#define VMM_PARAMETER_HANDLE_LCVMM    "hlcvmm"

_Success_(return)
BOOL DeviceVMM_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    PLC_VMM ctx, ctxSrc;
    QWORD qwReadOnly = 0, qwVolatile = 0;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    // 1: initialize core context:
    if(sizeof(PVOID) != 8) { return FALSE; }     // only supported on 64-bit os (due to resource constraints)
    ctx = (PLC_VMM)LocalAlloc(LMEM_ZEROINIT, sizeof(LC_VMM));
    if(!ctx) { return FALSE; }
    // 2: initialize device
    ctxSrc = (PLC_VMM)LcDeviceParameterGetNumeric(ctxLC, VMM_PARAMETER_HANDLE_LCVMM);
    if(!ctxSrc || (ctxSrc->dwVersion != LC_VMM_VERSION) || !ctxSrc->hVMM || !ctxSrc->hVMMVM || !ctxSrc->pfnVMMDLL_ConfigGet || !ctxSrc->pfnVMMDLL_VmMemReadScatter || !ctxSrc->pfnVMMDLL_VmMemWriteScatter) {
        lcprintfv(ctxLC, "DEVICE: VMM: Unable to open loopback device #1\n");
        goto fail;
    }
    memcpy(ctx, ctxSrc, sizeof(LC_VMM));
    // 3: fetch config parameters:
    if(!((FN_VMMDLL_ConfigGet)ctx->pfnVMMDLL_ConfigGet)(ctx->hVMM, LC_OPT_CORE_VOLATILE, &qwVolatile)) {    // inherit from vm parent vmm
        lcprintfv(ctxLC, "DEVICE: VMM: Unable to communicate with loopback device #1.\n");
        goto fail;
    }
    if(!((FN_VMMDLL_ConfigGet)ctx->pfnVMMDLL_ConfigGet)(ctx->hVMM, LC_OPT_CORE_READONLY, &qwReadOnly)) {    // inherit from vm parent vmm
        lcprintfv(ctxLC, "DEVICE: VMM: Unable to communicate with loopback device #2.\n");
        goto fail;
    }
    // 4: set callback functions and fix up config
    ctxLC->hDevice = (HANDLE)ctx;
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
