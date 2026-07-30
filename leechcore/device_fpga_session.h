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

typedef enum tdDEVICE_FPGA_SESSION_TLP_FRAME_ACTION {
    DEVICE_FPGA_SESSION_TLP_FRAME_IGNORE = 0,
    DEVICE_FPGA_SESSION_TLP_FRAME_APPEND,
    DEVICE_FPGA_SESSION_TLP_FRAME_COMPLETE,
    DEVICE_FPGA_SESSION_TLP_FRAME_RESTART,
    DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED
} DEVICE_FPGA_SESSION_TLP_FRAME_ACTION;

typedef struct tdDEVICE_FPGA_SESSION_TLP_FRAME_STATE {
    BOOL fRequireFirst;
    BOOL fInTlp;
    DWORD cdwTlp;
} DEVICE_FPGA_SESSION_TLP_FRAME_STATE, *PDEVICE_FPGA_SESSION_TLP_FRAME_STATE;

#ifdef LINUX
static __inline__ __attribute__((always_inline))
DEVICE_FPGA_SESSION_TLP_FRAME_ACTION
DeviceFPGA_Session_TlpFrameStep(
    _Inout_ PDEVICE_FPGA_SESSION_TLP_FRAME_STATE pState,
    _In_ BYTE bStatus,
    _In_ DWORD cdwMax
)
{
    DEVICE_FPGA_SESSION_TLP_FRAME_ACTION Action;
    if(!pState || !cdwMax) {
        return DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED;
    }
    bStatus &= 0x0f;
    if(bStatus & 0x03) {
        return DEVICE_FPGA_SESSION_TLP_FRAME_IGNORE;
    }
    if(bStatus & 0x08) {
        Action = pState->fInTlp ?
            DEVICE_FPGA_SESSION_TLP_FRAME_RESTART :
            DEVICE_FPGA_SESSION_TLP_FRAME_APPEND;
        pState->fInTlp = TRUE;
        pState->cdwTlp = 0;
    } else {
        if(!pState->fInTlp) {
            if(pState->fRequireFirst) {
                return DEVICE_FPGA_SESSION_TLP_FRAME_IGNORE;
            }
            pState->fInTlp = TRUE;
            pState->cdwTlp = 0;
        }
        Action = DEVICE_FPGA_SESSION_TLP_FRAME_APPEND;
    }
    if(pState->cdwTlp >= cdwMax) {
        pState->fInTlp = FALSE;
        pState->cdwTlp = 0;
        return DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED;
    }
    pState->cdwTlp++;
    if(bStatus & 0x04) {
        pState->fInTlp = FALSE;
        if(pState->cdwTlp < 3) {
            pState->cdwTlp = 0;
            return DEVICE_FPGA_SESSION_TLP_FRAME_MALFORMED;
        }
        return DEVICE_FPGA_SESSION_TLP_FRAME_COMPLETE;
    }
    return Action;
}
#else
DEVICE_FPGA_SESSION_TLP_FRAME_ACTION DeviceFPGA_Session_TlpFrameStep(
    _Inout_ PDEVICE_FPGA_SESSION_TLP_FRAME_STATE pState,
    _In_ BYTE bStatus,
    _In_ DWORD cdwMax
);
#endif /* LINUX */

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
