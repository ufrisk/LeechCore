// device_fpga_read_policy.c : platform-neutral FPGA read outcome policy.
//
#include "device_fpga_read_policy.h"
#include <string.h>

static BOOL FpgaReadPolicy_IsSuccess(_In_ LC_READ_PAGE_RESULT result)
{
    return (result == LC_READ_PAGE_RESULT_SUCCESS) ||
        (result == LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY);
}

static BOOL FpgaReadPolicy_IsTerminal(_In_ LC_READ_PAGE_RESULT result)
{
    return (result == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST) ||
        (result == LC_READ_PAGE_RESULT_COMPLETER_ABORT);
}

static DWORD FpgaReadPolicy_Precedence(_In_ LC_READ_PAGE_RESULT result)
{
    switch(result) {
        case LC_READ_PAGE_RESULT_SUCCESS:
        case LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY:
            return 1;
        case LC_READ_PAGE_RESULT_NO_COMPLETION:
            return 2;
        case LC_READ_PAGE_RESULT_PARTIAL_COMPLETION:
            return 3;
        case LC_READ_PAGE_RESULT_TRANSPORT_ERROR:
            return 4;
        case LC_READ_PAGE_RESULT_PROTOCOL_ERROR:
        case LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR:
            return 5;
        case LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST:
        case LC_READ_PAGE_RESULT_COMPLETER_ABORT:
            return 6;
        default:
            return 0;
    }
}

LC_READ_PAGE_RESULT FpgaReadPolicy_ClassifyCompletion(_In_ BOOL fHasData, _In_ DWORD dwStatus)
{
    if(fHasData) {
        return (dwStatus == 0)
            ? LC_READ_PAGE_RESULT_SUCCESS
            : LC_READ_PAGE_RESULT_PROTOCOL_ERROR;
    }
    switch(dwStatus) {
        case 1:
            return LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST;
        case 4:
            return LC_READ_PAGE_RESULT_COMPLETER_ABORT;
        default:
            return LC_READ_PAGE_RESULT_PROTOCOL_ERROR;
    }
}

LC_READ_PAGE_RESULT FpgaReadPolicy_Merge(_In_ LC_READ_PAGE_RESULT current, _In_ LC_READ_PAGE_RESULT observed)
{
    if(FpgaReadPolicy_IsTerminal(current)) {
        return current;
    }
    if(FpgaReadPolicy_IsTerminal(observed)) {
        return observed;
    }
    if(FpgaReadPolicy_Precedence(observed) > FpgaReadPolicy_Precedence(current)) {
        return observed;
    }
    return current;
}

BOOL FpgaReadPolicy_IsRetryable(_In_ LC_READ_PAGE_RESULT result)
{
    switch(result) {
        case LC_READ_PAGE_RESULT_SUCCESS:
        case LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY:
        case LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST:
        case LC_READ_PAGE_RESULT_COMPLETER_ABORT:
            return 0;
        case LC_READ_PAGE_RESULT_NONE:
        case LC_READ_PAGE_RESULT_NO_COMPLETION:
        case LC_READ_PAGE_RESULT_PARTIAL_COMPLETION:
        case LC_READ_PAGE_RESULT_TRANSPORT_ERROR:
        case LC_READ_PAGE_RESULT_PROTOCOL_ERROR:
        case LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR:
        default:
            return 1;
    }
}

BOOL FpgaReadPolicy_ShouldEnableAdaptivePolling(_In_ DWORD cRetry)
{
    // A full tag generation distinguishes sustained completion loss from an
    // isolated retry that should not slow the remainder of a healthy session.
    return cRetry >= FPGA_READ_TAGS_PER_GENERATION;
}

VOID FpgaReadPolicy_PageBegin(_Out_ PFPGA_READ_PAGE_STATE state, _In_ DWORD cbExpected)
{
    memset(state, 0, sizeof(FPGA_READ_PAGE_STATE));
    state->result = LC_READ_PAGE_RESULT_NONE;
    state->cbExpected = cbExpected;
}

VOID FpgaReadPolicy_TagIssued(_Inout_ PFPGA_READ_PAGE_STATE state)
{
    state->cTagsIssued++;
}

BOOL FpgaReadPolicy_TagRetire(_Inout_ PFPGA_READ_PAGE_STATE state, _Inout_ PBOOL pfTagRetired)
{
    if(*pfTagRetired) {
        return 0;
    }
    *pfTagRetired = (BOOL)1;
    if(state->cTagsRetired < state->cTagsIssued) {
        state->cTagsRetired++;
    }
    return state->cTagsIssued && (state->cTagsRetired == state->cTagsIssued);
}

VOID FpgaReadPolicy_Observe(_Inout_ PFPGA_READ_PAGE_STATE state, _In_ LC_READ_PAGE_RESULT observed, _In_ DWORD cbData)
{
    if(cbData) {
        if((observed != LC_READ_PAGE_RESULT_SUCCESS) ||
            (state->cbReceived > state->cbExpected) ||
            (cbData > state->cbExpected - state->cbReceived)) {
            observed = LC_READ_PAGE_RESULT_PROTOCOL_ERROR;
        } else {
            state->cbReceived += cbData;
        }
    }
    state->result = FpgaReadPolicy_Merge(state->result, observed);
}

LC_READ_PAGE_RESULT FpgaReadPolicy_Finalize(_Inout_ PFPGA_READ_PAGE_STATE state)
{
    if(FpgaReadPolicy_IsTerminal(state->result) ||
        (state->result == LC_READ_PAGE_RESULT_PROTOCOL_ERROR) ||
        (state->result == LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR)) {
        return state->result;
    }
    if(state->cbReceived == state->cbExpected) {
        state->result = state->fRetried
            ? LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY
            : LC_READ_PAGE_RESULT_SUCCESS;
    } else if(state->fTransportError) {
        state->result = LC_READ_PAGE_RESULT_TRANSPORT_ERROR;
    } else if(state->cbReceived) {
        state->result = LC_READ_PAGE_RESULT_PARTIAL_COMPLETION;
    } else {
        state->result = LC_READ_PAGE_RESULT_NO_COMPLETION;
    }
    return state->result;
}

VOID FpgaReadPolicy_RecordPass(_Inout_ PFPGA_READ_COUNTERS counters, _In_ LC_READ_PAGE_RESULT result, _In_ BOOL fRetryPass)
{
    if(result == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST) {
        counters->cUnsupportedRequest++;
    } else if(result == LC_READ_PAGE_RESULT_COMPLETER_ABORT) {
        counters->cCompleterAbort++;
    } else if(result == LC_READ_PAGE_RESULT_PROTOCOL_ERROR) {
        counters->cProtocolError++;
    }
    if(fRetryPass) {
        counters->cRetryAttempted++;
        if(FpgaReadPolicy_IsSuccess(result)) {
            counters->cRetryRecovered++;
        } else {
            counters->cRetryExhausted++;
        }
    } else if(!FpgaReadPolicy_IsSuccess(result)) {
        counters->cFirstPassFailed++;
    }
}
