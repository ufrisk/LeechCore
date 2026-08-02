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
        (result == LC_READ_PAGE_RESULT_COMPLETER_ABORT) ||
        (result == LC_READ_PAGE_RESULT_NOT_ISSUED);
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
        case LC_READ_PAGE_RESULT_NOT_ISSUED:
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
        case LC_READ_PAGE_RESULT_NOT_ISSUED:
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

DWORD FpgaReadPolicy_BuildRetryList(_In_ DWORD cResults, _In_reads_(cResults) PLC_READ_PAGE_RESULT pResults, _In_ DWORD cIndices, _Out_writes_to_(cIndices, return) PDWORD pIndices)
{
    DWORD i, cRetry = 0;
    if(!pResults || !pIndices) {
        return 0;
    }
    for(i = 0; (i < cResults) && (cRetry < cIndices); i++) {
        if(FpgaReadPolicy_IsRetryable(pResults[i])) {
            pIndices[cRetry++] = i;
        }
    }
    return cRetry;
}

DWORD FpgaReadPolicy_CountAdaptivePollingEvidence(_In_ DWORD cResults, _In_reads_(cResults) PLC_READ_PAGE_RESULT pResults)
{
    DWORD i, cEvidence = 0;
    if(!pResults) { return 0; }
    for(i = 0; i < cResults; i++) {
        switch(pResults[i]) {
            case LC_READ_PAGE_RESULT_NO_COMPLETION:
            case LC_READ_PAGE_RESULT_PARTIAL_COMPLETION:
            case LC_READ_PAGE_RESULT_TRANSPORT_ERROR:
            case LC_READ_PAGE_RESULT_PROTOCOL_ERROR:
                cEvidence++;
                break;
            default:
                break;
        }
    }
    return cEvidence;
}

BOOL FpgaReadPolicy_ShouldEnableAdaptivePolling(_In_ DWORD cEvidence, _In_ DWORD dwEvidenceGeneration, _In_ DWORD dwTransportGeneration)
{
    // A full tag generation distinguishes sustained completion loss from an
    // isolated retry that should not slow the remainder of a healthy session.
    // Evidence collected before a transport recovery must not affect the new
    // transport generation.
    return
        (dwEvidenceGeneration == dwTransportGeneration) &&
        (cEvidence >= FPGA_READ_TAGS_PER_GENERATION);
}

BOOL FpgaReadPolicy_ShouldResetAdaptivePolling(_In_ BOOL fAdaptivePollingWait, _In_ DWORD dwPollingGeneration, _In_ DWORD dwTransportGeneration)
{
    return fAdaptivePollingWait && (dwPollingGeneration != dwTransportGeneration);
}

LC_READ_PAGE_RESULT FpgaReadPolicy_MergeRetryResult(_In_ LC_READ_PAGE_RESULT firstResult, _In_ LC_READ_PAGE_RESULT retryResult)
{
    if((retryResult == LC_READ_PAGE_RESULT_SUCCESS) ||
        (retryResult == LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY)) {
        return LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY;
    }
    if(retryResult == LC_READ_PAGE_RESULT_NONE) {
        return firstResult;
    }
    return retryResult;
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

VOID FpgaReadPolicy_MarkTransportError(_Inout_ PFPGA_READ_PAGE_STATE state)
{
    state->fTransportError = (BOOL)1;
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

BOOL FpgaReadPolicy_CountersHaveData(_In_ PFPGA_READ_COUNTERS counters)
{
    return counters &&
        (counters->cFirstPassFailed ||
         counters->cUnsupportedRequest ||
         counters->cCompleterAbort ||
         counters->cRetryAttempted ||
         counters->cRetryRecovered ||
         counters->cRetryExhausted ||
         counters->cProtocolError);
}

VOID FpgaReadTagMap_Begin(_Out_ PFPGA_READ_TAG_MAP map, _In_ BYTE bGeneration)
{
    DWORD i;
    memset(map, 0, sizeof(FPGA_READ_TAG_MAP));
    map->bGeneration = bGeneration & 0x80;
    for(i = 0; i < 0x100; i++) {
        map->entries[i].iPage = FPGA_READ_TAG_PAGE_INVALID;
    }
}

BOOL FpgaReadTagMap_Assign(_Inout_ PFPGA_READ_TAG_MAP map, _In_ DWORD iPage, _Out_ PBYTE pTag)
{
    DWORD i;
    BYTE tag;
    if(!pTag) {
        return (BOOL)0;
    }
    if(map && (map->cActive < FPGA_READ_TAGS_PER_GENERATION)) {
        for(i = 0; i < FPGA_READ_TAGS_PER_GENERATION; i++) {
            tag = (BYTE)(map->bGeneration + i);
            if(!map->entries[tag].fActive) {
                map->entries[tag].iPage = iPage;
                map->entries[tag].fActive = (BOOL)1;
                map->cActive++;
                *pTag = tag;
                return (BOOL)1;
            }
        }
    }
    *pTag = 0;
    return (BOOL)0;
}

BOOL FpgaReadTagMap_Resolve(_In_ PFPGA_READ_TAG_MAP map, _In_ BYTE tag, _Out_ PDWORD piPage)
{
    if(!piPage) {
        return (BOOL)0;
    }
    if(!map || ((tag & 0x80) != map->bGeneration) || !map->entries[tag].fActive) {
        *piPage = 0;
        return (BOOL)0;
    }
    *piPage = map->entries[tag].iPage;
    return (BOOL)1;
}

BOOL FpgaReadTagMap_Retire(_Inout_ PFPGA_READ_TAG_MAP map, _In_ BYTE tag, _Out_opt_ PDWORD piPage)
{
    DWORD iPage;
    if(!FpgaReadTagMap_Resolve(map, tag, &iPage)) {
        if(piPage) { *piPage = 0; }
        return (BOOL)0;
    }
    map->entries[tag].fActive = (BOOL)0;
    map->entries[tag].iPage = FPGA_READ_TAG_PAGE_INVALID;
    if(map->cActive) {
        map->cActive--;
    }
    if(piPage) { *piPage = iPage; }
    return (BOOL)1;
}

VOID FpgaReadTagMap_Invalidate(_Inout_ PFPGA_READ_TAG_MAP map)
{
    DWORD i;
    if(!map) { return; }
    for(i = 0; i < 0x100; i++) {
        map->entries[i].fActive = (BOOL)0;
        map->entries[i].iPage = FPGA_READ_TAG_PAGE_INVALID;
    }
    map->cActive = 0;
}
