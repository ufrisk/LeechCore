// memmap.h : implementation of the physical memory map.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "memmap.h"

BOOL MemMap_IsInitialized()
{
    return ctxDeviceMain->MemMap.fValid;
}

_Success_(return)
BOOL MemMap_GetMaxAddress(_Out_ PQWORD ppaMax)
{
    QWORD i, paMax = 0;
    for(i = 0; i < ctxDeviceMain->MemMap.cEntries; i++) {
        if(paMax < ctxDeviceMain->MemMap.Runs[i].paBase + ctxDeviceMain->MemMap.Runs[i].cbSize) {
            paMax = ctxDeviceMain->MemMap.Runs[i].paBase + ctxDeviceMain->MemMap.Runs[i].cbSize;
        }
    }
    *ppaMax = paMax;
    return paMax != 0;
}

VOID MemMap_Close()
{
    ZeroMemory(&ctxDeviceMain->MemMap, sizeof(DEVICE_PHYSMEMMAP));
}

_Success_(return)
BOOL MemMap_Initialize(_In_ QWORD paMaxAddress)
{
    if((paMaxAddress & 0xfff) == 0x000) { paMaxAddress--; }
    if((paMaxAddress & 0xfff) != 0xfff) { return FALSE; }
    MemMap_Close();
    ctxDeviceMain->MemMap.fValid = TRUE;
    ctxDeviceMain->MemMap.paMax = paMaxAddress;
    ctxDeviceMain->MemMap.cEntries = 1;
    ctxDeviceMain->MemMap.Runs[0].paBase = 0;
    ctxDeviceMain->MemMap.Runs[0].cbSize = paMaxAddress + 1;
    return TRUE;
}

_Success_(return)
BOOL MemMap_VerifyTranslateRange(_In_ QWORD pa, _In_ QWORD cb, _Out_opt_ PQWORD ppaDevice)
{
    DWORD i = ctxDeviceMain->MemMap.iLastEntry;
    if(!ctxDeviceMain->MemMap.fValid) { return TRUE; }
    if((pa >= ctxDeviceMain->MemMap.Runs[i].paBase) && (pa + cb <= ctxDeviceMain->MemMap.Runs[i].paBase + ctxDeviceMain->MemMap.Runs[i].cbSize)) {
        if(ppaDevice) {
            *ppaDevice = pa + ctxDeviceMain->MemMap.Runs[i].paRemapBase - ctxDeviceMain->MemMap.Runs[i].paBase;
        }
        return TRUE;
    }
    for(i = 0; i < ctxDeviceMain->MemMap.cEntries; i++) {
        if((pa >= ctxDeviceMain->MemMap.Runs[i].paBase) && (pa + cb <= ctxDeviceMain->MemMap.Runs[i].paBase + ctxDeviceMain->MemMap.Runs[i].cbSize)) {
            ctxDeviceMain->MemMap.iLastEntry = i;
            if(ctxDeviceMain->MemMap.Runs[i].paRemapBase) {
                if(ppaDevice) {
                    *ppaDevice = pa + ctxDeviceMain->MemMap.Runs[i].paRemapBase - ctxDeviceMain->MemMap.Runs[i].paBase;
                }
                return TRUE;
            }
            if(ppaDevice) {
                *ppaDevice = pa;
            }
            return TRUE;
        }
    }
    return FALSE;
}

_Success_(return)
BOOL MemMap_VerifyTranslateMEM(_In_ PMEM_IO_SCATTER_HEADER pMEM, _Out_opt_ PQWORD ppaDevice)
{
    return 
        pMEM && (pMEM->magic == MEM_IO_SCATTER_HEADER_MAGIC) && (pMEM->version == MEM_IO_SCATTER_HEADER_VERSION) &&
        pMEM->cbMax && (pMEM->cbMax <= 0x1000) && (pMEM->cb < pMEM->cbMax) &&
        MemMap_VerifyTranslateRange(pMEM->qwA, pMEM->cbMax, ppaDevice);
}

_Success_(return)
BOOL MemMap_AddRange(_In_ QWORD paBase, _In_ QWORD cbSize, _In_ QWORD paRemapBase)
{
    DWORD i;
    if(paBase + cbSize > ctxDeviceMain->cfg.paMax + 1) { return FALSE; }
    if(ctxDeviceMain->MemMap.cEntries == DEVICE_PHYSMEMMAP_MAX_ENTRIES) { return FALSE; }
    // default range -> replace!
    if((ctxDeviceMain->MemMap.cEntries == 1) && (ctxDeviceMain->MemMap.Runs[0].paBase == 0) && (ctxDeviceMain->MemMap.Runs[0].cbSize == ctxDeviceMain->MemMap.paMax + 1)) {
        ctxDeviceMain->MemMap.cEntries--;
    }
    // add range
    i = ctxDeviceMain->MemMap.cEntries;
    ctxDeviceMain->MemMap.Runs[i].paBase = paBase;
    ctxDeviceMain->MemMap.Runs[i].cbSize = cbSize;
    ctxDeviceMain->MemMap.Runs[i].paRemapBase = paRemapBase;
    ctxDeviceMain->MemMap.cEntries++;
    vprintfvv("device_physmemmap.c!MemMap_AddRange: %016llx-%016llx -> %016llx\n", paBase, paBase + cbSize - 1, paRemapBase);
    return TRUE;
}
