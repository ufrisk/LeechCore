// device_physmemmap.h : definitions related to the physical memory map.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_PHYSMEMMAP_H__
#define __DEVICE_PHYSMEMMAP_H__
#include "leechcore.h"

/*
* Close the memory map and clean up any resources allocated.
*/
VOID MemMap_Close();

/*
* Initialize a new memory map with a default memory range of 0 .. paMaxAddress
* -- paMaxAddress
* -- return
*/
_Success_(return)
BOOL MemMap_Initialize(_In_ QWORD paMaxAddress);

/*
* Check whether the memory map given by the handle h is intialized or not.
* -- return
*/
BOOL MemMap_IsInitialized();

/*
* Retrieve the maximum address of this memory map.
* -- ppaMax
* -- return
*/
_Success_(return)
BOOL MemMap_GetMaxAddress(_Out_ PQWORD ppaMax);

/*
* Verify that a memory range is valid and if valid translate its base to a device-address.
* -- pa
* -- cb
* -- ppaDevice
* -- return
*/
_Success_(return)
BOOL MemMap_VerifyTranslateRange(_In_ QWORD pa, _In_ QWORD cb, _Out_opt_ PQWORD ppaDevice);

/*
* Verify a MemIO item and translate its base to a device-address.
* -- pMEM
* -- ppaDevice
* -- return
*/
_Success_(return)
BOOL MemMap_VerifyTranslateMEM(_In_ PMEM_IO_SCATTER_HEADER pMEM, _Out_opt_ PQWORD ppaDevice);

/*
* Add a memory range to the physical memory map.
* -- paBase
* -- cbSize
* -- paBaseRemap = Remap paBase to this address. Normally (1:1 mapping) paBaseRemap should equal paBase.
* -- return
*/
_Success_(return)
BOOL MemMap_AddRange(_In_ QWORD paBase, _In_ QWORD cbSize, _In_ QWORD paBaseRemap);

#endif /* __DEVICE_PHYSMEMMAP_H__ */
