// device605_tcp.h : definitions related to the Xilinx SP605 dev board flashed with @d_olex bitstream.
//
// (c) Ulf Frisk & @d_olex, 2017-2020
//
#ifndef __DEVICE_SP605TCP_H__
#define __DEVICE_SP605TCP_H__
#include "leechcore.h"

/*
* Open a connection to the SP605/MicroBlaze PCILeech flashed device.
* -- result
*/
_Success_(return)
BOOL Device605_TCP_Open();

#endif /* __DEVICE_SP605TCP_H__ */
