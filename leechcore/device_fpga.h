// device_fpga.h : definitions related to the:
//     - Xilinx SP605 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - Xilinx AC701 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - PCIeScreamer board flashed with PCILeech bitstream.
//
// (c) Ulf Frisk, 2017-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_FPGA_H__
#define __DEVICE_FPGA_H__
#include "leechcore.h"

/*
* Open a connection to the PCILeech flashed FPGA device.
* -- result
*/
BOOL DeviceFPGA_Open();

#endif /* __DEVICE_FPGA_H__ */
