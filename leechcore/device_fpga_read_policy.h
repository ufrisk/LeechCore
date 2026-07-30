// device_fpga_read_policy.h : platform-neutral FPGA read outcome policy.
//
#ifndef __DEVICE_FPGA_READ_POLICY_H__
#define __DEVICE_FPGA_READ_POLICY_H__

#include "leechcore.h"

typedef struct tdFPGA_READ_PAGE_STATE {
    LC_READ_PAGE_RESULT result;
    DWORD cbExpected;
    DWORD cbReceived;
    DWORD cTagsIssued;
    DWORD cTagsRetired;
    BOOL fTransportError;
    BOOL fRetried;
} FPGA_READ_PAGE_STATE, *PFPGA_READ_PAGE_STATE;

typedef struct tdFPGA_READ_COUNTERS {
    QWORD cFirstPassFailed;
    QWORD cUnsupportedRequest;
    QWORD cCompleterAbort;
    QWORD cRetryAttempted;
    QWORD cRetryRecovered;
    QWORD cRetryExhausted;
    QWORD cProtocolError;
} FPGA_READ_COUNTERS, *PFPGA_READ_COUNTERS;

#define FPGA_READ_TAGS_PER_GENERATION 112

LC_READ_PAGE_RESULT FpgaReadPolicy_ClassifyCompletion(_In_ BOOL fHasData, _In_ DWORD dwStatus);
LC_READ_PAGE_RESULT FpgaReadPolicy_Merge(_In_ LC_READ_PAGE_RESULT current, _In_ LC_READ_PAGE_RESULT observed);
BOOL FpgaReadPolicy_IsRetryable(_In_ LC_READ_PAGE_RESULT result);
BOOL FpgaReadPolicy_ShouldEnableAdaptivePolling(_In_ DWORD cRetry);
VOID FpgaReadPolicy_PageBegin(_Out_ PFPGA_READ_PAGE_STATE state, _In_ DWORD cbExpected);
VOID FpgaReadPolicy_TagIssued(_Inout_ PFPGA_READ_PAGE_STATE state);
BOOL FpgaReadPolicy_TagRetire(_Inout_ PFPGA_READ_PAGE_STATE state, _Inout_ PBOOL pfTagRetired);
VOID FpgaReadPolicy_Observe(_Inout_ PFPGA_READ_PAGE_STATE state, _In_ LC_READ_PAGE_RESULT observed, _In_ DWORD cbData);
LC_READ_PAGE_RESULT FpgaReadPolicy_Finalize(_Inout_ PFPGA_READ_PAGE_STATE state);
VOID FpgaReadPolicy_RecordPass(_Inout_ PFPGA_READ_COUNTERS counters, _In_ LC_READ_PAGE_RESULT result, _In_ BOOL fRetryPass);

#endif /* __DEVICE_FPGA_READ_POLICY_H__ */
