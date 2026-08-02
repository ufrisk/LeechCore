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

typedef ULONG(WINAPI *PFN_DEVICE_FPGA_SESSION_ABORT_PIPE)(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID
);

typedef ULONG(WINAPI *PFN_DEVICE_FPGA_SESSION_READ_PIPE)(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbTransferred,
    _In_ LPOVERLAPPED pOverlapped
);

typedef ULONG(WINAPI *PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT)(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _Out_ PULONG pulLengthTransferred,
    _In_ BOOL fWait
);

typedef ULONG(WINAPI *PFN_DEVICE_FPGA_SESSION_RELEASE_OVERLAPPED)(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped
);

typedef ULONG(WINAPI *PFN_DEVICE_FPGA_SESSION_INITIALIZE_OVERLAPPED)(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped
);

typedef ULONG(WINAPI *PFN_DEVICE_FPGA_SESSION_SET_PIPE_TIMEOUT)(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _In_ ULONG ulTimeoutInMs
);

#define DEVICE_FPGA_SESSION_FT_OK                  0
#define DEVICE_FPGA_SESSION_FT_TIMEOUT             19
#define DEVICE_FPGA_SESSION_FT_IO_PENDING          24
#define DEVICE_FPGA_SESSION_FT_IO_INCOMPLETE       25
#define DEVICE_FPGA_SESSION_WAIT_TIMEOUT_MS         1000
#define DEVICE_FPGA_SESSION_WAIT_POLL_MS            1
#define DEVICE_FPGA_SESSION_CANCEL_TIMEOUT_MS       100

typedef QWORD(*PFN_DEVICE_FPGA_SESSION_TICK)(
    _In_opt_ PVOID pvContext
);

typedef VOID(*PFN_DEVICE_FPGA_SESSION_SLEEP)(
    _In_opt_ PVOID pvContext,
    _In_ DWORD dwMilliseconds
);

typedef enum tdDEVICE_FPGA_SESSION_WAIT_OUTCOME {
    DEVICE_FPGA_SESSION_WAIT_COMPLETED = 0,
    DEVICE_FPGA_SESSION_WAIT_TIMED_OUT,
    DEVICE_FPGA_SESSION_WAIT_DRIVER_ERROR
} DEVICE_FPGA_SESSION_WAIT_OUTCOME;

typedef struct tdDEVICE_FPGA_SESSION_WAIT_RESULT {
    DEVICE_FPGA_SESSION_WAIT_OUTCOME outcome;
    ULONG status;
    ULONG cbTransferred;
} DEVICE_FPGA_SESSION_WAIT_RESULT, *PDEVICE_FPGA_SESSION_WAIT_RESULT;

typedef enum tdDEVICE_FPGA_SESSION_READ_OUTCOME {
    DEVICE_FPGA_SESSION_READ_DATA = 0,
    DEVICE_FPGA_SESSION_READ_QUIET,
    DEVICE_FPGA_SESSION_READ_DRIVER_ERROR
} DEVICE_FPGA_SESSION_READ_OUTCOME;

typedef struct tdDEVICE_FPGA_SESSION_READ_RESULT {
    DEVICE_FPGA_SESSION_READ_OUTCOME outcome;
    ULONG status;
    ULONG cbTransferred;
} DEVICE_FPGA_SESSION_READ_RESULT, *PDEVICE_FPGA_SESSION_READ_RESULT;

ULONG DeviceFPGA_Session_StartOverlappedRead(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbTransferred,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_READ_PIPE pfnReadPipe,
    _Out_ PBOOL pfReadPending
);

typedef enum tdDEVICE_FPGA_SESSION_RECOVERY_STAGE {
    DEVICE_FPGA_SESSION_RECOVERY_READY = 0,
    DEVICE_FPGA_SESSION_RECOVERY_QUIESCE_FAILED,
    DEVICE_FPGA_SESSION_RECOVERY_REOPEN_FAILED,
    DEVICE_FPGA_SESSION_RECOVERY_INITIALIZE_FAILED,
    DEVICE_FPGA_SESSION_RECOVERY_DRAIN_FAILED,
    DEVICE_FPGA_SESSION_RECOVERY_IDENTITY_FAILED
} DEVICE_FPGA_SESSION_RECOVERY_STAGE;

typedef BOOL(*PFN_DEVICE_FPGA_SESSION_RECOVERY_STEP)(
    _Inout_ PVOID pvContext
);

typedef VOID(*PFN_DEVICE_FPGA_SESSION_RECOVERY_INVALIDATE)(
    _Inout_ PVOID pvContext
);

typedef struct tdDEVICE_FPGA_SESSION_RECOVERY_OPS {
    PFN_DEVICE_FPGA_SESSION_RECOVERY_STEP pfnQuiesceOldHandle;
    PFN_DEVICE_FPGA_SESSION_RECOVERY_STEP pfnReopenHandle;
    PFN_DEVICE_FPGA_SESSION_RECOVERY_STEP pfnInitializeOverlapped;
    PFN_DEVICE_FPGA_SESSION_RECOVERY_INVALIDATE pfnInvalidateState;
    PFN_DEVICE_FPGA_SESSION_RECOVERY_STEP pfnDrainStaleTraffic;
    PFN_DEVICE_FPGA_SESSION_RECOVERY_STEP pfnValidateIdentity;
} DEVICE_FPGA_SESSION_RECOVERY_OPS, *PDEVICE_FPGA_SESSION_RECOVERY_OPS;

typedef enum tdDEVICE_FPGA_SESSION_DRAIN_OUTCOME {
    DEVICE_FPGA_SESSION_DRAIN_CLEAN = 0,
    DEVICE_FPGA_SESSION_DRAIN_READ_ERROR,
    DEVICE_FPGA_SESSION_DRAIN_BYTE_LIMIT,
    DEVICE_FPGA_SESSION_DRAIN_TIME_LIMIT
} DEVICE_FPGA_SESSION_DRAIN_OUTCOME;

typedef BOOL(*PFN_DEVICE_FPGA_SESSION_DRAIN_READ)(
    _Inout_ PVOID pvContext,
    _Out_writes_(cbBuffer) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _In_ DWORD dwTimeoutMs,
    _Out_ PDWORD pcbRead
);

DEVICE_FPGA_SESSION_WAIT_RESULT DeviceFPGA_Session_WaitOverlapped(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _In_ BOOL fUseEventWait,
    _In_ DWORD dwTimeoutMs,
    _In_ DWORD dwPollMs,
    _In_opt_ PVOID pvTimingContext,
    _In_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep
);

DEVICE_FPGA_SESSION_WAIT_RESULT DeviceFPGA_Session_ReadPipeBounded(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_READ_PIPE pfnReadPipe,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _Out_ PBOOL pfReadPending,
    _In_ BOOL fUseEventWait,
    _In_ DWORD dwTimeoutMs,
    _In_ DWORD dwPollMs,
    _In_opt_ PVOID pvTimingContext,
    _In_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep
);

DEVICE_FPGA_SESSION_READ_RESULT DeviceFPGA_Session_ReadPipeOpportunistic(
    _In_ HANDLE hFTDI,
    _In_ UCHAR ucPipeID,
    _Out_writes_(cbBuffer) PUCHAR pbBuffer,
    _In_ ULONG cbBuffer,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_READ_PIPE pfnReadPipe,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _In_ PFN_DEVICE_FPGA_SESSION_ABORT_PIPE pfnAbortPipe,
    _In_ PFN_DEVICE_FPGA_SESSION_RELEASE_OVERLAPPED pfnReleaseOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_INITIALIZE_OVERLAPPED pfnInitializeOverlapped,
    _In_ DWORD dwTimeoutMs,
    _In_ DWORD dwPollMs,
    _In_opt_ PVOID pvTimingContext,
    _In_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep,
    _Inout_ PBOOL pfOverlappedInitialized,
    _Inout_ PBOOL pfReadPending
);

DEVICE_FPGA_SESSION_RECOVERY_STAGE DeviceFPGA_Session_Recover(
    _Inout_ PVOID pvContext,
    _In_ PDEVICE_FPGA_SESSION_RECOVERY_OPS pOps
);

BOOL DeviceFPGA_Session_IsFillerOnly(
    _In_reads_(cb) PBYTE pb,
    _In_ DWORD cb
);

DEVICE_FPGA_SESSION_DRAIN_OUTCOME DeviceFPGA_Session_Drain(
    _Inout_ PVOID pvContext,
    _In_ PFN_DEVICE_FPGA_SESSION_DRAIN_READ pfnRead,
    _Out_writes_(cbBuffer) PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _In_ DWORD cbMaxNonFiller,
    _In_ DWORD dwQuietMs,
    _In_ DWORD dwTimeoutMs,
    _In_ DWORD dwPollMs,
    _In_ PVOID pvTimingContext,
    _In_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep
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

_Success_(return)
BOOL DeviceFPGA_Session_ConfigurePipeTimeouts(
    _In_ HANDLE hFTDI,
    _In_ ULONG ulTimeoutInMs,
    _In_ PFN_DEVICE_FPGA_SESSION_SET_PIPE_TIMEOUT pfnSetPipeTimeout
);

// Query completion before cancelling. Release only after completion is
// observed, either before cancellation or after a bounded cancellation wait.
// pfOverlappedReleased distinguishes cleanup success from resource ownership;
// FALSE means the initialized object must remain handle-owned until close.
_Success_(return)
BOOL DeviceFPGA_Session_CloseOverlapped(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ PFN_DEVICE_FPGA_SESSION_ABORT_PIPE pfnAbortPipe,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _In_ PFN_DEVICE_FPGA_SESSION_RELEASE_OVERLAPPED pfnReleaseOverlapped,
    _In_opt_ PVOID pvTimingContext,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep,
    _Out_ PBOOL pfOverlappedReleased
);

// Release an initialized idle OVERLAPPED object directly. If a read was
// submitted, query it before deciding whether cancellation is required.
_Success_(return)
BOOL DeviceFPGA_Session_TeardownOverlapped(
    _In_ HANDLE hFTDI,
    _In_ LPOVERLAPPED pOverlapped,
    _In_ BOOL fReadPending,
    _In_ PFN_DEVICE_FPGA_SESSION_ABORT_PIPE pfnAbortPipe,
    _In_ PFN_DEVICE_FPGA_SESSION_GET_OVERLAPPED_RESULT pfnGetOverlappedResult,
    _In_ PFN_DEVICE_FPGA_SESSION_RELEASE_OVERLAPPED pfnReleaseOverlapped,
    _In_opt_ PVOID pvTimingContext,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_TICK pfnTick,
    _In_opt_ PFN_DEVICE_FPGA_SESSION_SLEEP pfnSleep,
    _Out_ PBOOL pfOverlappedReleased
);

#endif /* __DEVICE_FPGA_SESSION_H__ */
