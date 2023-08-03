// memmap.c : implementation : memory map.
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "leechcore.h"
#include "leechcore_device.h"
#include "oscompatibility.h"

/*
* Check whether the memory map is initialized or not.
* -- ctxLC
* -- return
*/
EXPORTED_FUNCTION BOOL LcMemMap_IsInitialized(_In_ PLC_CONTEXT ctxLC)
{
    return ctxLC->cMemMap > 0;
}

/*
* Add a memory range to the memory map.
* -- ctxLC
* -- pa
* -- cb
* -- paRemap = remap offset within file (if relevant).
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcMemMap_AddRange(_In_ PLC_CONTEXT ctxLC, _In_ QWORD pa, _In_ QWORD cb, _In_opt_ QWORD paRemap)
{
    PVOID pvGrowMemMap;
    if((cb & 0xfff) == 1) { cb--; }
    if((pa & 0xfff) || (cb & 0xfff)) { return FALSE; }
    if(ctxLC->cMemMap >= 0x00100000) { return FALSE; }
    if(ctxLC->cMemMap == ctxLC->cMemMapMax) {
        // grow memmap with with factor x2:
        pvGrowMemMap = LocalAlloc(LMEM_ZEROINIT, ctxLC->cMemMapMax * sizeof(LC_MEMMAP_ENTRY) * 2);
        if(!pvGrowMemMap) { return FALSE; }
        memcpy(pvGrowMemMap, ctxLC->pMemMap, ctxLC->cMemMap * sizeof(LC_MEMMAP_ENTRY));
        LocalFree(ctxLC->pMemMap);
        ctxLC->pMemMap = (PLC_MEMMAP_ENTRY)pvGrowMemMap;
        ctxLC->cMemMapMax = ctxLC->cMemMapMax * 2;
    }
    if(ctxLC->cMemMap && (ctxLC->pMemMap[ctxLC->cMemMap - 1].pa + ctxLC->pMemMap[ctxLC->cMemMap - 1].cb > pa)) { return FALSE; }
    ctxLC->pMemMap[ctxLC->cMemMap].pa = pa;
    ctxLC->pMemMap[ctxLC->cMemMap].cb = cb;
    ctxLC->pMemMap[ctxLC->cMemMap].paRemap = paRemap ? (paRemap & ~LC_MEMMAP_FORCE_OFFSET) : pa;
    ctxLC->cMemMap++;
    lcprintfvv_fn(ctxLC, "%016llx-%016llx -> %016llx\n", pa, pa + cb - 1, paRemap);
    return TRUE;
}

/*
* Get the max physical address from the memory map.
* -- ctxLC
* -- return
*/
_Success_(return != 0)
EXPORTED_FUNCTION QWORD LcMemMap_GetMaxAddress(_In_ PLC_CONTEXT ctxLC)
{
    if(ctxLC->cMemMap == 0) { return 0x0000ffffffffffff; }
    return ctxLC->pMemMap[ctxLC->cMemMap - 1].pa + ctxLC->pMemMap[ctxLC->cMemMap - 1].cb;
}

/*
* Translate each individual MEM. The qwA field will be overwritten with the
* translated value - or on error -1.
* -- ctxLC
* -- cMEMs
* -- ppMEMs
*/
VOID LcMemMap_TranslateMEMs(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    DWORD iMEM, iMap, oMap;
    PMEM_SCATTER pMEM;
    PLC_MEMMAP_ENTRY peMap;
    if(ctxLC->cMemMap == 0) { return; }
    peMap = ctxLC->pMemMap + 0;
    for(iMEM = 0; iMEM < cMEMs; iMEM++) {
        pMEM = ppMEMs[iMEM];
        if(pMEM->qwA == (QWORD)-1) { continue; }
        // check already existing (optimization).
        if((pMEM->qwA >= peMap->pa) && (pMEM->qwA + pMEM->cb <= peMap->pa + peMap->cb)) {
            pMEM->qwA = pMEM->qwA + peMap->paRemap - peMap->pa;
            continue;
        }
        // check all memmap ranges.
        iMap = 0;
        if(ctxLC->cMemMap > 0x40) {             // fast find (large map optimization)
            iMap = ctxLC->cMemMap >> 1;
            oMap = iMap;
            while((oMap = oMap >> 1)) {
                iMap = (pMEM->qwA > ctxLC->pMemMap[iMap].pa) ? (iMap + oMap) : (iMap - oMap);
            }
            while(iMap && (pMEM->qwA < ctxLC->pMemMap[iMap].pa)) {
                iMap--;
            }
        }
        for(; iMap < ctxLC->cMemMap; iMap++) {  // find entry
            peMap = ctxLC->pMemMap + iMap;
            if((pMEM->qwA >= peMap->pa) && (pMEM->qwA + pMEM->cb <= peMap->pa + peMap->cb)) {
                break;
            }
            if(pMEM->qwA < peMap->pa) {
                break;
            }
        }
        if((pMEM->qwA >= peMap->pa) && (pMEM->qwA + pMEM->cb <= peMap->pa + peMap->cb)) {
            pMEM->qwA = pMEM->qwA + peMap->paRemap - peMap->pa;
        } else {
            pMEM->qwA = (QWORD)-1;
        }
    }
}

/*
* Retrieve the memory ranges as an array of LC_MEMMAP_ENTRY.
* -- ctxLC
* -- ppbDataOut
* -- pcbDataOut
*/
_Success_(return)
BOOL LcMemMap_GetRangesAsStruct(_In_ PLC_CONTEXT ctxLC, _Out_ PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    PBYTE pb;
    DWORD cb;
    if(ctxLC->cMemMap > 0x00100000) { return FALSE; }
    cb = ctxLC->cMemMap * sizeof(LC_MEMMAP_ENTRY);
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, cb))) { return FALSE; }
    memcpy(pb, ctxLC->pMemMap, cb);
    *ppbDataOut = pb;
    if(pcbDataOut) { *pcbDataOut = cb; }
    return TRUE;
}

/*
* Retrieve the memory ranges as ascii text in a null-terminated text buffer.
* CALLER LcFreeMem: *ppbDataOut
* -- ctxLC
* -- ppbDataOut
* -- pcbDataOut
*/
_Success_(return)
BOOL LcMemMap_GetRangesAsText(_In_ PLC_CONTEXT ctxLC, _Out_ PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    PBYTE pb;
    DWORD i, o, cb;
    if(ctxLC->cMemMap > 0x00100000) { return FALSE; }
    cb = ctxLC->cMemMap * (4 + 1 + 16 + 3 + 16 + 4 + 16 + 1);
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, cb))) { return FALSE; }
    for(i = 0, o = 0; i < ctxLC->cMemMap; i++) {
        o += snprintf(
            (LPSTR)pb + o,
            cb - o,
            "%04x %16llx - %16llx -> %16llx\n",
            i,
            ctxLC->pMemMap[i].pa,
            ctxLC->pMemMap[i].pa + ctxLC->pMemMap[i].cb - 1,
            ctxLC->pMemMap[i].paRemap
        );
    }
    pb[cb - 1] = '\n';
    *ppbDataOut = pb;
    if(pcbDataOut) { *pcbDataOut = cb; }
    return TRUE;
}

/*
* Set ranges by memmap struct data.
* NB! all previous ranges will be overwritten.
* -- ctxLC
* -- pStruct
* -- cStruct
* -- return
*/
_Success_(return)
BOOL LcMemMap_SetRangesFromStruct(_In_ PLC_CONTEXT ctxLC, _In_ PLC_MEMMAP_ENTRY pMemMap, _In_ DWORD cMemMap)
{
    DWORD i;
    ctxLC->cMemMap = 0;
    for(i = 0; i < cMemMap; i++) {
        LcMemMap_AddRange(ctxLC, pMemMap[i].pa, pMemMap[i].cb, pMemMap[i].paRemap);
    }
    return TRUE;
}

/*
* Set ranges by parsing ascii text in the buffer pb. The ranges should be
* specified on a line-by-line basis with hexascii numericals on the format:
* <range_base_address> <range_top_address> <optional_range_remap_address>
* NB! all previous ranges will be overwritten.
* -- ctxLC
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL LcMemMap_SetRangesFromText(_In_ PLC_CONTEXT ctxLC, _In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD i, iMax;
    LPSTR sz, szLine, szLineContext = NULL, szToken, szTokenContext;
    QWORD v[3];
    ctxLC->cMemMap = 0;
    if(!(sz = LocalAlloc(0, cb + 1ULL))) { return FALSE; }
    memcpy(sz, pb, cb);
    sz[cb] = 0;
    // parse
    szLine = strtok_s(sz, "\r\n", &szLineContext);
    while(szLine) {
        if(szLine[0] == '0' && szLine[1] == '0' && szLine[4] == ' ') {
            szLine += 4;
        }
        for(i = 0, iMax = (DWORD)strlen(szLine); i < iMax; i++) {
            if((szLine[i] == '0') && (szLine[i + 1] == 'x')) { szLine[i] = ' '; szLine[i + 1] = ' '; }
            if((szLine[i] >= '0') && (szLine[i] <= '9')) { continue; }
            if((szLine[i] >= 'a') && (szLine[i] <= 'f')) { continue; }
            if((szLine[i] >= 'A') && (szLine[i] <= 'F')) { continue; }
            if(szLine[i] == '#') { szLine[i] = 0; }
            szLine[i] = ' ';
        }
        i = 0;
        v[0] = 0, v[1] = 0, v[2] = 0;
        szTokenContext = NULL;
        szToken = strtok_s(szLine, " ", &szTokenContext);
        while((i < 3) && szToken) {
            v[i++] = strtoull(szToken, NULL, 16);
            szToken = strtok_s(NULL, " ", &szTokenContext);
        }
        if(!(v[0] & 0xfff) && (v[0] < v[1])) {
            if(!v[2]) { v[2] = v[0]; }
            LcMemMap_AddRange(ctxLC, v[0], v[1] + 1 - v[0], v[2]);
        }
        szLine = strtok_s(NULL, "\r\n", &szLineContext);
    }
    LocalFree(sz);
    return TRUE;
}
