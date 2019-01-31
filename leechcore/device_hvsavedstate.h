// device_hvsavedstate.h : definitions related to the Hyper-V Saved State "device".
// NB! this device is dependant on an active Hyper-V system on the machine and also
// of the file 'vmsavedstatedumpprovider.dll' being placed in the same folder as the
// 'leechcore.dll' libray.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_HVSAVEDSTATE_H__
#define __DEVICE_HVSAVEDSTATE_H__
#include "leechcore.h"

/*
* Open a connection to the USB3380 PCILeech flashed device.
* -- result
*/
BOOL DeviceHvSavedState_Open();

#endif /* __DEVICE_HVSAVEDSTATE_H__ */
