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
#define FPGA_READ_TAG_PAGE_INVALID    0xffffffff

typedef struct tdFPGA_READ_TAG_MAP_ENTRY {
    DWORD iPage;
    BOOL fActive;
} FPGA_READ_TAG_MAP_ENTRY, *PFPGA_READ_TAG_MAP_ENTRY;

typedef struct tdFPGA_READ_TAG_MAP {
    BYTE bGeneration;
    DWORD cActive;
    FPGA_READ_TAG_MAP_ENTRY entries[0x100];
} FPGA_READ_TAG_MAP, *PFPGA_READ_TAG_MAP;

LC_READ_PAGE_RESULT FpgaReadPolicy_ClassifyCompletion(_In_ BOOL fHasData, _In_ DWORD dwStatus);
LC_READ_PAGE_RESULT FpgaReadPolicy_Merge(_In_ LC_READ_PAGE_RESULT current, _In_ LC_READ_PAGE_RESULT observed);
BOOL FpgaReadPolicy_IsRetryable(_In_ LC_READ_PAGE_RESULT result);
DWORD FpgaReadPolicy_BuildRetryList(_In_ DWORD cResults, _In_reads_(cResults) PLC_READ_PAGE_RESULT pResults, _In_ DWORD cIndices, _Out_writes_to_(cIndices, return) PDWORD pIndices);
DWORD FpgaReadPolicy_CountAdaptivePollingEvidence(_In_ DWORD cResults, _In_reads_(cResults) PLC_READ_PAGE_RESULT pResults);
BOOL FpgaReadPolicy_ShouldEnableAdaptivePolling(_In_ DWORD cEvidence);
BOOL FpgaReadPolicy_ShouldResetAdaptivePolling(_In_ BOOL fAdaptivePollingWait, _In_ DWORD dwPollingGeneration, _In_ DWORD dwTransportGeneration);
LC_READ_PAGE_RESULT FpgaReadPolicy_MergeRetryResult(_In_ LC_READ_PAGE_RESULT firstResult, _In_ LC_READ_PAGE_RESULT retryResult);
VOID FpgaReadPolicy_PageBegin(_Out_ PFPGA_READ_PAGE_STATE state, _In_ DWORD cbExpected);
VOID FpgaReadPolicy_TagIssued(_Inout_ PFPGA_READ_PAGE_STATE state);
BOOL FpgaReadPolicy_TagRetire(_Inout_ PFPGA_READ_PAGE_STATE state, _Inout_ PBOOL pfTagRetired);
VOID FpgaReadPolicy_Observe(_Inout_ PFPGA_READ_PAGE_STATE state, _In_ LC_READ_PAGE_RESULT observed, _In_ DWORD cbData);
VOID FpgaReadPolicy_MarkTransportError(_Inout_ PFPGA_READ_PAGE_STATE state);
LC_READ_PAGE_RESULT FpgaReadPolicy_Finalize(_Inout_ PFPGA_READ_PAGE_STATE state);
VOID FpgaReadPolicy_RecordPass(_Inout_ PFPGA_READ_COUNTERS counters, _In_ LC_READ_PAGE_RESULT result, _In_ BOOL fRetryPass);
BOOL FpgaReadPolicy_CountersHaveData(_In_ PFPGA_READ_COUNTERS counters);
VOID FpgaReadTagMap_Begin(_Out_ PFPGA_READ_TAG_MAP map, _In_ BYTE bGeneration);
BOOL FpgaReadTagMap_Assign(_Inout_ PFPGA_READ_TAG_MAP map, _In_ DWORD iPage, _Out_ PBYTE pTag);
BOOL FpgaReadTagMap_Resolve(_In_ PFPGA_READ_TAG_MAP map, _In_ BYTE tag, _Out_ PDWORD piPage);
BOOL FpgaReadTagMap_Retire(_Inout_ PFPGA_READ_TAG_MAP map, _In_ BYTE tag, _Out_opt_ PDWORD piPage);
VOID FpgaReadTagMap_Invalidate(_Inout_ PFPGA_READ_TAG_MAP map);

#endif /* __DEVICE_FPGA_READ_POLICY_H__ */
