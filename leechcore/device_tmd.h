// device_tmd.h : definitions related to the "total meltdown" memory acquisition "device".
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_TMD_H__
#define __DEVICE_TMD_H__
#include "leechcore.h"

/*
* Open a connection to the "total meltdown" memory acquisition "device" (if exploitable).
* -- result
*/
BOOL DeviceTMD_Open();

#endif /* __DEVICE_TMD_H__ */
