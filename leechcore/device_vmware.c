// device_vmware.c : implementation of the vmware acquisition device.
// 
// tested with vmware workstation 16.1.2
//
// (c) Ulf Frisk, 2022-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
#include "util.h"
#ifdef _WIN32

#include <psapi.h>

typedef struct tdDEVICE_CONTEXT_VMWARE {
    HANDLE hProcess;
} DEVICE_CONTEXT_VMWARE, *PDEVICE_CONTEXT_VMWARE;

//-----------------------------------------------------------------------------
// GENERAL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DeviceVMWare_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_VMWARE ctx = (PDEVICE_CONTEXT_VMWARE)ctxLC->hDevice;
    PMEM_SCATTER pMEM;
    DWORD i;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM)) { continue; }
        pMEM->f = ReadProcessMemory(ctx->hProcess, (LPCVOID)pMEM->qwA, pMEM->pb, pMEM->cb, NULL);
    }
}

VOID DeviceVMWare_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_VMWARE ctx = (PDEVICE_CONTEXT_VMWARE)ctxLC->hDevice;
    PMEM_SCATTER pMEM;
    DWORD i;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f || MEM_SCATTER_ADDR_ISINVALID(pMEM)) { continue; }
        pMEM->f = WriteProcessMemory(ctx->hProcess, (LPVOID)pMEM->qwA, pMEM->pb, pMEM->cb, NULL);
    }
}

VOID DeviceVMWare_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_VMWARE ctx = (PDEVICE_CONTEXT_VMWARE)ctxLC->hDevice;
    if(ctx) {
        ctxLC->hDevice = 0;
        CloseHandle(ctx->hProcess);
        LocalFree(ctx);
    }
}

_Success_(return)
BOOL DeviceVMWare_Open_GetRange(_In_ DWORD dwPID, _Out_writes_opt_(42) LPWSTR wszRegion, _Out_opt_ PQWORD pvaRegion, _Out_opt_ PQWORD pcbRegion)
{
    DWORD cch;
    HANDLE hProcess = 0;
    QWORD va = 0x0000001000000000;
    WCHAR wsz[MAX_PATH + 1] = { 0 };
    MEMORY_BASIC_INFORMATION BI;
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
    if(!hProcess) { goto fail; }
    while(VirtualQueryEx(hProcess, (LPCVOID)va, &BI, sizeof(MEMORY_BASIC_INFORMATION))) {
        va = (QWORD)BI.BaseAddress + BI.RegionSize;
        if((QWORD)BI.BaseAddress > 0x00006fffffffffff) { break; }
        if(BI.BaseAddress != BI.AllocationBase) { continue; }
        if((BI.RegionSize < 0x01000000) || (BI.RegionSize > 0x10000000000)) { continue; }
        if((BI.State != MEM_COMMIT) || (BI.Protect != PAGE_READWRITE) || (BI.AllocationProtect != PAGE_READWRITE)) { continue; }
        cch = GetMappedFileNameW(hProcess, BI.BaseAddress, wsz, _countof(wsz) - 1);
        if(!cch || (cch < 42) || _wcsicmp(L".vmem", wsz + cch - 5)) { continue; }
        if(wszRegion) { wcsncpy_s(wszRegion, 42, wsz + cch - 41, _TRUNCATE); }
        if(pvaRegion) { *pvaRegion = (QWORD)BI.BaseAddress; }
        if(pcbRegion) { *pcbRegion = (QWORD)BI.RegionSize; }
        CloseHandle(hProcess);
        return TRUE;
    }
fail:
    if(hProcess) { CloseHandle(hProcess); }
    return FALSE;
}

#define VMWARE_ERRORINFO_MAXCHAR        2048

VOID DeviceVMWare_Open_List(_Out_ PDWORD pdwSinglePID, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    HANDLE hProcess;
    QWORD cbRegion;
    DWORD cProcessVMWare = 0, iPID, cPIDs, cbPIDs, dwPID, dwPIDs[1024];
    WCHAR wsz[MAX_PATH + 1] = { 0 }, wszInfo[MAX_PATH];
    PLC_CONFIG_ERRORINFO pInfo = NULL;
    // 1: init
    *pdwSinglePID = 0;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    if(!EnumProcesses(dwPIDs, sizeof(dwPIDs), &cbPIDs)) { return; }
    cPIDs = cbPIDs / sizeof(DWORD);
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPIDs[0]);
    // 2: set up errorinfo (in case it's required later)
    if(!(pInfo = LocalAlloc(LMEM_ZEROINIT, sizeof(LC_CONFIG_ERRORINFO) + VMWARE_ERRORINFO_MAXCHAR * sizeof(WCHAR)))) { return; }
    pInfo->dwVersion = LC_CONFIG_ERRORINFO_VERSION;
    pInfo->cbStruct = sizeof(LC_CONFIG_ERRORINFO) + VMWARE_ERRORINFO_MAXCHAR * sizeof(WCHAR);
    pInfo->fUserInputRequest = TRUE;
    wcsncat_s(pInfo->wszUserText, VMWARE_ERRORINFO_MAXCHAR - 1, L"Multiple VMWare VMs detected. Select VM-ID.\n VM-ID   VM NAME\n=====================\n", _TRUNCATE);
    // 3: enumerate
    for(iPID = 0; iPID < cPIDs; iPID++) {
        dwPID = dwPIDs[iPID];
        if((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID))) {
            if(GetModuleFileNameEx(hProcess, NULL, wsz, MAX_PATH) && wcsstr(wsz, L"vmware-vmx.exe")) {
                if(DeviceVMWare_Open_GetRange(dwPID, wsz, NULL, &cbRegion)) {
                    *pdwSinglePID = cProcessVMWare ? 0 : dwPID;
                    cProcessVMWare++;
                    _snwprintf_s(wszInfo, _countof(wszInfo), _TRUNCATE, L"%6i = %s (%i MB)\n", dwPID, wsz, (DWORD)(cbRegion / (1024 * 1024)));
                    wcsncat_s(pInfo->wszUserText, VMWARE_ERRORINFO_MAXCHAR - 1, wszInfo, _TRUNCATE);
                }
            }
            CloseHandle(hProcess);
        }
    }
    // 4: finish
    if(cProcessVMWare > 1) {
        pInfo->cwszUserText = (DWORD)wcslen(pInfo->wszUserText);
        *ppLcCreateErrorInfo = pInfo;
    } else {
        LocalFree(pInfo);
    }
}

/*
* The debug privilege is required to attach to vmware process.
*/
VOID DeviceVMWare_Open_GetSeDebugPrivilege()
{
    HANDLE hToken = 0;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) { goto fail; }
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { goto fail; };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if(!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) { goto fail; };
fail:
    if(hToken) { CloseHandle(hToken); }
}

#define VMWARE_PARAMETER_ID         "id"
#define VMWARE_PARAMETER_READONLY   "ro"

_Success_(return)
BOOL DeviceVMWare_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    BOOL result = FALSE, fReadOnly;
    DWORD dwPID = 0, dwDesiredAccess;
    QWORD vaRegion, cbRegion;
    PDEVICE_CONTEXT_VMWARE ctx;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    fReadOnly = LcDeviceParameterGetNumeric(ctxLC, VMWARE_PARAMETER_READONLY) ? TRUE : FALSE;
    dwPID = (DWORD)LcDeviceParameterGetNumeric(ctxLC, VMWARE_PARAMETER_ID);
    // 1: vm list (if required)
    DeviceVMWare_Open_GetSeDebugPrivilege();
    if(!dwPID) {
        DeviceVMWare_Open_List(&dwPID, ppLcCreateErrorInfo);
        if(!dwPID && !ppLcCreateErrorInfo) {
            lcprintfv(ctxLC, "DEVICE: VMWARE: ERROR: no running VMs detected / not running as administrator?\n");
        }
        if(!dwPID) {
            return FALSE;
        }
    }
    // 2: vm region/range detect
    if(!DeviceVMWare_Open_GetRange(dwPID, NULL, &vaRegion, &cbRegion)) {
        lcprintfv(ctxLC, "DEVICE: VMWARE: ERROR: running VM not detected in process pid %i / not running as administrator?\n", dwPID);
        return FALSE;
    }
    // 3: initialize core context.
    ctx = (PDEVICE_CONTEXT_VMWARE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_VMWARE));
    if(!ctx) { return FALSE; }
    ctxLC->hDevice = (HANDLE)ctx;
    // 4: set callback functions and fix up config
    ctxLC->fMultiThread = TRUE;
    ctxLC->Config.fVolatile = TRUE;
    ctxLC->pfnClose = DeviceVMWare_Close;
    ctxLC->pfnReadScatter = DeviceVMWare_ReadScatter;
    ctxLC->pfnWriteScatter = fReadOnly ? NULL : DeviceVMWare_WriteScatter;
    // 5: connect to vmware vmm process
    dwDesiredAccess = fReadOnly ? PROCESS_VM_READ : (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
    ctx->hProcess = OpenProcess(dwDesiredAccess, FALSE, dwPID);
    if(ctx->hProcess) {
        LcMemMap_AddRange(ctxLC, 0, min(0xc0000000, cbRegion), vaRegion);
        if(cbRegion > 0xc0000000) {
            // account for vmware memory hole at 3-4GB
            LcMemMap_AddRange(ctxLC, 0x100000000, cbRegion - 0xc0000000, vaRegion + 0xc0000000);
        }
        lcprintfv(ctxLC, "DEVICE: VMWARE: Successfully connected to VM %i.\n", dwPID);
        return TRUE;
    }
    DeviceVMWare_Close(ctxLC);
    return FALSE;
}

#endif /* _WIN32 */
#ifdef LINUX

_Success_(return)
BOOL DeviceVMWare_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    lcprintfv(ctxLC, "DEVICE: VMWARE: FAIL: memory acquisition only supported on Windows.\n");
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    return FALSE;
}

#endif /* LINUX */
