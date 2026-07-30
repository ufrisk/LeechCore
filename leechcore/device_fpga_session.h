// device_fpga_session.h : internal FPGA session protocol helpers.
//
#ifndef __DEVICE_FPGA_SESSION_H__
#define __DEVICE_FPGA_SESSION_H__

#include "oscompatibility.h"

typedef struct tdDEVICE_FPGA_IDENTITY {
    WORD wVersionMajor;
    WORD wVersionMinor;
    WORD wFpgaID;
} DEVICE_FPGA_IDENTITY, *PDEVICE_FPGA_IDENTITY;

typedef BOOL(*PFN_DEVICE_FPGA_SESSION_CONFIG_READ)(
    _In_ PVOID pvContext,
    _In_ WORD wBaseAddr,
    _Out_writes_(cb) PBYTE pb,
    _In_ WORD cb,
    _In_ WORD flags
);

_Success_(return)
BOOL DeviceFPGA_Session_ParseConfigReply(
    _In_reads_(cbReply) PBYTE pbReply,
    _In_ DWORD cbReply,
    _In_ WORD wBaseAddr,
    _Out_writes_(cbResult) PBYTE pbResult,
    _In_ WORD cbResult,
    _In_ WORD flags
);

_Success_(return)
BOOL DeviceFPGA_Session_ReadV4Identity(
    _In_ PVOID pvContext,
    _In_ PFN_DEVICE_FPGA_SESSION_CONFIG_READ pfnConfigRead,
    _In_ WORD flags,
    _Out_ PDEVICE_FPGA_IDENTITY pIdentity
);

_Success_(return)
BOOL DeviceFPGA_Session_ParseV3Identity(
    _In_reads_(cbReply) PBYTE pbReply,
    _In_ DWORD cbReply,
    _Out_ PDEVICE_FPGA_IDENTITY pIdentity,
    _Out_ PWORD pwPcieDeviceId
);

#endif /* __DEVICE_FPGA_SESSION_H__ */
