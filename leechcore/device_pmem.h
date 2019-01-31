// device_pmem.h : definitions related the rekall winpmem memory acquisition device.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_PMEM_H__
#define __DEVICE_PMEM_H__
#include "leechcore.h"

/*
* Open a "connection" to the winpmem memory acquisition device.
* -- result
*/
BOOL DevicePMEM_Open();

#endif /* __DEVICE_PMEM_H__ */
