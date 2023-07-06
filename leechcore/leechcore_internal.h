// leechcore_internal.h : definitions of internal leechcore functionality such
//                        as non exported parts of memory map functionality.
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __LEECHCORE_INTERNAL_H__
#define __LEECHCORE_INTERNAL_H__
#include "leechcore.h"
#include "leechcore_device.h"

/*
* Translate each individual MEM. The qwA field will be overwritten with the
* translated value - or on error -1.
* -- ctxLC
* -- cMEMs
* -- ppMEMs
*/
VOID LcMemMap_TranslateMEMs(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs);

/*
* Retrieve the memory ranges as an array of LC_MEMMAP_ENTRY.
* -- ctxLC
* -- ppbDataOut
* -- pcbDataOut
*/
_Success_(return)
BOOL LcMemMap_GetRangesAsStruct(_In_ PLC_CONTEXT ctxLC, _Out_ PBYTE * ppbDataOut, _Out_opt_ PDWORD pcbDataOut);

/*
* Retrieve the memory ranges as ascii text in a null-terminated text buffer.
* CALLER LcFreeMem: *ppbDataOut
* -- ctxLC
* -- ppbDataOut
* -- pcbDataOut
*/
_Success_(return)
BOOL LcMemMap_GetRangesAsText(_In_ PLC_CONTEXT ctxLC, _Out_ PBYTE *ppbDataOut, _Out_opt_ PDWORD pcbDataOut);

/*
* Set ranges by memmap struct data.
* NB! all previous ranges will be overwritten.
* -- ctxLC
* -- pStruct
* -- cStruct
* -- return
*/
_Success_(return)
BOOL LcMemMap_SetRangesFromStruct(_In_ PLC_CONTEXT ctxLC, _In_ PLC_MEMMAP_ENTRY pMemMap, _In_ DWORD cMemMap);

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
BOOL LcMemMap_SetRangesFromText(_In_ PLC_CONTEXT ctxLC, _In_ PBYTE pb, _In_ DWORD cb);

#endif /* __LEECHCORE_INTERNAL_H__ */
