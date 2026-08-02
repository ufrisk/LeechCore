#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../leechcore/device_fpga_read_policy.h"

static void test_public_result_values_are_stable(void)
{
    assert(sizeof(LC_READ_PAGE_RESULT) == sizeof(DWORD));
    assert(LC_READ_PAGE_RESULT_NONE == 0);
    assert(LC_READ_PAGE_RESULT_SUCCESS == 1);
    assert(LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY == 2);
    assert(LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST == 3);
    assert(LC_READ_PAGE_RESULT_COMPLETER_ABORT == 4);
    assert(LC_READ_PAGE_RESULT_NO_COMPLETION == 5);
    assert(LC_READ_PAGE_RESULT_PARTIAL_COMPLETION == 6);
    assert(LC_READ_PAGE_RESULT_TRANSPORT_ERROR == 7);
    assert(LC_READ_PAGE_RESULT_PROTOCOL_ERROR == 8);
    assert(LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR == 9);
    assert(LC_READ_PAGE_RESULT_NOT_ISSUED == 10);
}

static void test_completion_status_is_classified_without_guessing(void)
{
    assert(FpgaReadPolicy_ClassifyCompletion((BOOL)1, 0) == LC_READ_PAGE_RESULT_SUCCESS);
    assert(FpgaReadPolicy_ClassifyCompletion((BOOL)0, 1) == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST);
    assert(FpgaReadPolicy_ClassifyCompletion((BOOL)0, 4) == LC_READ_PAGE_RESULT_COMPLETER_ABORT);
    assert(FpgaReadPolicy_ClassifyCompletion((BOOL)0, 0) == LC_READ_PAGE_RESULT_PROTOCOL_ERROR);
    assert(FpgaReadPolicy_ClassifyCompletion((BOOL)0, 2) == LC_READ_PAGE_RESULT_PROTOCOL_ERROR);
    assert(FpgaReadPolicy_ClassifyCompletion((BOOL)1, 1) == LC_READ_PAGE_RESULT_PROTOCOL_ERROR);
}

static void test_only_transient_or_unclassified_results_are_retryable(void)
{
    assert(FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_NONE));
    assert(FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_NO_COMPLETION));
    assert(FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_PARTIAL_COMPLETION));
    assert(FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_TRANSPORT_ERROR));
    assert(FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_PROTOCOL_ERROR));
    assert(FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR));
    assert(!FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_SUCCESS));
    assert(!FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY));
    assert(!FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST));
    assert(!FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_COMPLETER_ABORT));
    assert(!FpgaReadPolicy_IsRetryable(LC_READ_PAGE_RESULT_NOT_ISSUED));
}

static void test_terminal_result_is_sticky_across_tiny_fragments(void)
{
    FPGA_READ_PAGE_STATE state;
    FpgaReadPolicy_PageBegin(&state, 0x100);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x80);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST, 0);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x80);
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST);

    FpgaReadPolicy_PageBegin(&state, 0x100);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_COMPLETER_ABORT, 0);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_PROTOCOL_ERROR, 0);
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_COMPLETER_ABORT);

    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_NOT_ISSUED, 0);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x1000);
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_NOT_ISSUED);
}

static void test_incomplete_data_is_distinguished_from_transport_failure(void)
{
    FPGA_READ_PAGE_STATE state;
    FpgaReadPolicy_PageBegin(&state, 0x1000);
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_NO_COMPLETION);

    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x800);
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_PARTIAL_COMPLETION);

    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x800);
    state.fTransportError = (BOOL)1;
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_TRANSPORT_ERROR);
}

static void test_success_after_retry_is_reported_distinctly(void)
{
    FPGA_READ_PAGE_STATE state;
    FpgaReadPolicy_PageBegin(&state, 0x1000);
    state.fRetried = (BOOL)1;
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x1000);
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY);
}

static void test_each_tag_retires_once(void)
{
    FPGA_READ_PAGE_STATE state;
    BOOL fTag0Retired = (BOOL)0;
    BOOL fTag1Retired = (BOOL)0;
    FpgaReadPolicy_PageBegin(&state, 0x100);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_TagIssued(&state);
    assert(!FpgaReadPolicy_TagRetire(&state, &fTag0Retired));
    assert(!FpgaReadPolicy_TagRetire(&state, &fTag0Retired));
    assert(FpgaReadPolicy_TagRetire(&state, &fTag1Retired));
    assert(!FpgaReadPolicy_TagRetire(&state, &fTag1Retired));
    assert(state.cTagsIssued == 2);
    assert(state.cTagsRetired == 2);
}

static void test_new_operation_does_not_inherit_terminal_result(void)
{
    FPGA_READ_PAGE_STATE state;
    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST, 0);
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST);

    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x1000);
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_SUCCESS);
}

static void test_retry_list_contains_only_retryable_results(void)
{
    LC_READ_PAGE_RESULT results[] = {
        LC_READ_PAGE_RESULT_SUCCESS,
        LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST,
        LC_READ_PAGE_RESULT_COMPLETER_ABORT,
        LC_READ_PAGE_RESULT_NO_COMPLETION,
        LC_READ_PAGE_RESULT_PARTIAL_COMPLETION,
        LC_READ_PAGE_RESULT_TRANSPORT_ERROR,
        LC_READ_PAGE_RESULT_PROTOCOL_ERROR,
        LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR,
        LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY,
        LC_READ_PAGE_RESULT_NOT_ISSUED
    };
    DWORD indices[10] = { 0 };
    DWORD count = FpgaReadPolicy_BuildRetryList(10, results, 10, indices);
    assert(count == 5);
    assert(indices[0] == 3);
    assert(indices[1] == 4);
    assert(indices[2] == 5);
    assert(indices[3] == 6);
    assert(indices[4] == 7);
}

static void test_adaptive_polling_requires_sustained_completion_loss(void)
{
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(0, 7, 7));
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(1, 7, 7));
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(
        FPGA_READ_TAGS_PER_GENERATION - 1, 7, 7));
    assert(FpgaReadPolicy_ShouldEnableAdaptivePolling(
        FPGA_READ_TAGS_PER_GENERATION, 7, 7));
}

static void test_adaptive_polling_rejects_stale_transport_evidence(void)
{
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(
        FPGA_READ_TAGS_PER_GENERATION, 7, 8));
}

static void test_probe_extra_receive_passes_are_native_ft601_only(void)
{
    assert(FpgaReadPolicy_ProbeReceiveMaxReads((BOOL)1) == 3);
    assert(FpgaReadPolicy_ProbeReceiveMaxReads((BOOL)0) == 1);
}

static void test_adaptive_polling_counts_only_transport_evidence(void)
{
    LC_READ_PAGE_RESULT results[] = {
        LC_READ_PAGE_RESULT_NONE,
        LC_READ_PAGE_RESULT_SUCCESS,
        LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY,
        LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST,
        LC_READ_PAGE_RESULT_COMPLETER_ABORT,
        LC_READ_PAGE_RESULT_NO_COMPLETION,
        LC_READ_PAGE_RESULT_PARTIAL_COMPLETION,
        LC_READ_PAGE_RESULT_TRANSPORT_ERROR,
        LC_READ_PAGE_RESULT_PROTOCOL_ERROR,
        LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR,
        LC_READ_PAGE_RESULT_NOT_ISSUED
    };
    LC_READ_PAGE_RESULT boundary[FPGA_READ_TAGS_PER_GENERATION];
    DWORD i, cEvidence;

    assert(FpgaReadPolicy_CountAdaptivePollingEvidence(
        sizeof(results) / sizeof(results[0]), results) == 4);
    assert(FpgaReadPolicy_CountAdaptivePollingEvidence(0, NULL) == 0);

    for(i = 0; i < FPGA_READ_TAGS_PER_GENERATION; i++) {
        boundary[i] = LC_READ_PAGE_RESULT_NO_COMPLETION;
    }
    cEvidence = FpgaReadPolicy_CountAdaptivePollingEvidence(
        FPGA_READ_TAGS_PER_GENERATION - 1, boundary);
    assert(cEvidence == FPGA_READ_TAGS_PER_GENERATION - 1);
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(cEvidence, 7, 7));

    cEvidence = FpgaReadPolicy_CountAdaptivePollingEvidence(
        FPGA_READ_TAGS_PER_GENERATION, boundary);
    assert(cEvidence == FPGA_READ_TAGS_PER_GENERATION);
    assert(FpgaReadPolicy_ShouldEnableAdaptivePolling(cEvidence, 7, 7));

    boundary[0] = LC_READ_PAGE_RESULT_NOT_ISSUED;
    cEvidence = FpgaReadPolicy_CountAdaptivePollingEvidence(
        FPGA_READ_TAGS_PER_GENERATION, boundary);
    assert(cEvidence == FPGA_READ_TAGS_PER_GENERATION - 1);
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(cEvidence, 7, 7));

    for(i = 0; i < FPGA_READ_TAGS_PER_GENERATION; i++) {
        boundary[i] = LC_READ_PAGE_RESULT_NOT_ISSUED;
    }
    assert(FpgaReadPolicy_CountAdaptivePollingEvidence(
        FPGA_READ_TAGS_PER_GENERATION, boundary) == 0);
}

static void test_adaptive_polling_is_reevaluated_after_transport_reopen(void)
{
    assert(!FpgaReadPolicy_ShouldResetAdaptivePolling(0, 4, 5));
    assert(!FpgaReadPolicy_ShouldResetAdaptivePolling(1, 5, 5));
    assert(FpgaReadPolicy_ShouldResetAdaptivePolling(1, 4, 5));
}

static void test_retry_result_replaces_transient_result(void)
{
    assert(FpgaReadPolicy_MergeRetryResult(
        LC_READ_PAGE_RESULT_NO_COMPLETION,
        LC_READ_PAGE_RESULT_SUCCESS) == LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY);
    assert(FpgaReadPolicy_MergeRetryResult(
        LC_READ_PAGE_RESULT_PARTIAL_COMPLETION,
        LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST) == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST);
    assert(FpgaReadPolicy_MergeRetryResult(
        LC_READ_PAGE_RESULT_PROTOCOL_ERROR,
        LC_READ_PAGE_RESULT_NO_COMPLETION) == LC_READ_PAGE_RESULT_NO_COMPLETION);
}

static void test_mixed_synchronous_pass_retries_only_transient_pages(void)
{
    FPGA_READ_PAGE_STATE states[6];
    LC_READ_PAGE_RESULT results[6];
    DWORD indices[6] = { 0 };

    FpgaReadPolicy_PageBegin(&states[0], 0x1000);
    FpgaReadPolicy_Observe(&states[0], LC_READ_PAGE_RESULT_SUCCESS, 0x1000);
    FpgaReadPolicy_PageBegin(&states[1], 0x1000);
    FpgaReadPolicy_Observe(&states[1], LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST, 0);
    FpgaReadPolicy_PageBegin(&states[2], 0x1000);
    FpgaReadPolicy_Observe(&states[2], LC_READ_PAGE_RESULT_COMPLETER_ABORT, 0);
    FpgaReadPolicy_PageBegin(&states[3], 0x1000);
    FpgaReadPolicy_Observe(&states[3], LC_READ_PAGE_RESULT_SUCCESS, 0x800);
    FpgaReadPolicy_PageBegin(&states[4], 0x1000);
    FpgaReadPolicy_PageBegin(&states[5], 0x1000);
    FpgaReadPolicy_Observe(&states[5], LC_READ_PAGE_RESULT_PROTOCOL_ERROR, 0);

    for(DWORD i = 0; i < 6; i++) {
        results[i] = FpgaReadPolicy_Finalize(&states[i]);
    }
    assert(results[0] == LC_READ_PAGE_RESULT_SUCCESS);
    assert(results[1] == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST);
    assert(results[2] == LC_READ_PAGE_RESULT_COMPLETER_ABORT);
    assert(results[3] == LC_READ_PAGE_RESULT_PARTIAL_COMPLETION);
    assert(results[4] == LC_READ_PAGE_RESULT_NO_COMPLETION);
    assert(results[5] == LC_READ_PAGE_RESULT_PROTOCOL_ERROR);
    assert(FpgaReadPolicy_BuildRetryList(6, results, 6, indices) == 3);
    assert(indices[0] == 3);
    assert(indices[1] == 4);
    assert(indices[2] == 5);
}

static void test_async_and_tiny_tag_sequences(void)
{
    FPGA_READ_PAGE_STATE state;
    BOOL retired0, retired1;

    retired0 = (BOOL)0;
    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x1000);
    assert(FpgaReadPolicy_TagRetire(&state, &retired0));
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_SUCCESS);

    retired0 = (BOOL)0;
    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST, 0);
    assert(FpgaReadPolicy_TagRetire(&state, &retired0));
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST);

    retired0 = (BOOL)0;
    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_COMPLETER_ABORT, 0);
    assert(FpgaReadPolicy_TagRetire(&state, &retired0));
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_COMPLETER_ABORT);

    retired0 = (BOOL)0;
    retired1 = (BOOL)0;
    FpgaReadPolicy_PageBegin(&state, 0x100);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST, 0);
    assert(!FpgaReadPolicy_TagRetire(&state, &retired0));
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x80);
    assert(FpgaReadPolicy_TagRetire(&state, &retired1));
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST);

    retired0 = (BOOL)0;
    retired1 = (BOOL)0;
    FpgaReadPolicy_PageBegin(&state, 0x100);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x80);
    assert(!FpgaReadPolicy_TagRetire(&state, &retired0));
    assert(FpgaReadPolicy_TagRetire(&state, &retired1));
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_PARTIAL_COMPLETION);
    assert(!FpgaReadPolicy_TagRetire(&state, &retired1));

    retired0 = (BOOL)0;
    FpgaReadPolicy_PageBegin(&state, 0x1000);
    FpgaReadPolicy_TagIssued(&state);
    FpgaReadPolicy_Observe(&state, LC_READ_PAGE_RESULT_SUCCESS, 0x800);
    FpgaReadPolicy_MarkTransportError(&state);
    assert(FpgaReadPolicy_TagRetire(&state, &retired0));
    assert(FpgaReadPolicy_Finalize(&state) == LC_READ_PAGE_RESULT_TRANSPORT_ERROR);
}

static void test_probe_tag_map_is_unique_and_generation_scoped(void)
{
    FPGA_READ_TAG_MAP map;
    BOOL seen[0x100] = { 0 };
    DWORD i, iPage;
    BYTE tag;

    FpgaReadTagMap_Begin(&map, 0);
    for(i = 0; i < FPGA_READ_TAGS_PER_GENERATION; i++) {
        assert(FpgaReadTagMap_Assign(&map, 1000 + i, &tag));
        assert(tag <= 0x6f);
        assert(!seen[tag]);
        seen[tag] = (BOOL)1;
        assert(FpgaReadTagMap_Resolve(&map, tag, &iPage));
        assert(iPage == 1000 + i);
    }
    assert(!FpgaReadTagMap_Assign(&map, 9999, &tag));
    assert(!FpgaReadTagMap_Resolve(&map, 0x70, &iPage));
    assert(!FpgaReadTagMap_Resolve(&map, 0xf0, &iPage));
    assert(FpgaReadTagMap_Retire(&map, 0x00, &iPage));
    assert(iPage == 1000);
    assert(!FpgaReadTagMap_Retire(&map, 0x00, &iPage));

    memset(seen, 0, sizeof(seen));
    FpgaReadTagMap_Begin(&map, 0x80);
    for(i = 0; i < FPGA_READ_TAGS_PER_GENERATION; i++) {
        assert(FpgaReadTagMap_Assign(&map, 2000 + i, &tag));
        assert((tag >= 0x80) && (tag <= 0xef));
        assert(!seen[tag]);
        seen[tag] = (BOOL)1;
    }
    assert(!FpgaReadTagMap_Resolve(&map, 0x00, &iPage));
    assert(FpgaReadTagMap_Resolve(&map, 0x80, &iPage));
    assert(iPage == 2000);
    FpgaReadTagMap_Invalidate(&map);
    assert(map.cActive == 0);
    assert(!FpgaReadTagMap_Resolve(&map, 0x80, &iPage));
}

static void test_probe_results_are_attributed_by_tag(void)
{
    FPGA_READ_TAG_MAP map;
    FPGA_READ_PAGE_STATE states[4];
    LC_READ_PAGE_RESULT results[4];
    BYTE resultMap[4] = { 0 };
    DWORD iPage, retryIndices[4];
    BYTE tagSuccess, tagUr, tagCa, tagSilent;

    FpgaReadTagMap_Begin(&map, 0);
    assert(FpgaReadTagMap_Assign(&map, 2, &tagSuccess));
    assert(FpgaReadTagMap_Assign(&map, 0, &tagUr));
    assert(FpgaReadTagMap_Assign(&map, 3, &tagCa));
    assert(FpgaReadTagMap_Assign(&map, 1, &tagSilent));
    FpgaReadPolicy_PageBegin(&states[0], 4);
    FpgaReadPolicy_PageBegin(&states[1], 4);
    FpgaReadPolicy_PageBegin(&states[2], 4);
    FpgaReadPolicy_PageBegin(&states[3], 4);

    assert(FpgaReadTagMap_Resolve(&map, tagSuccess, &iPage));
    assert(iPage == 2);
    FpgaReadPolicy_Observe(&states[iPage],
        FpgaReadPolicy_ClassifyCompletion((BOOL)1, 0), 4);
    resultMap[iPage] = 1;
    assert(FpgaReadTagMap_Retire(&map, tagSuccess, NULL));

    assert(FpgaReadTagMap_Resolve(&map, tagUr, &iPage));
    assert(iPage == 0);
    FpgaReadPolicy_Observe(&states[iPage],
        FpgaReadPolicy_ClassifyCompletion((BOOL)0, 1), 0);
    assert(FpgaReadTagMap_Retire(&map, tagUr, NULL));

    assert(FpgaReadTagMap_Resolve(&map, tagCa, &iPage));
    assert(iPage == 3);
    FpgaReadPolicy_Observe(&states[iPage],
        FpgaReadPolicy_ClassifyCompletion((BOOL)0, 4), 0);
    assert(FpgaReadTagMap_Retire(&map, tagCa, NULL));

    results[0] = FpgaReadPolicy_Finalize(&states[0]);
    results[1] = FpgaReadPolicy_Finalize(&states[1]);
    results[2] = FpgaReadPolicy_Finalize(&states[2]);
    results[3] = FpgaReadPolicy_Finalize(&states[3]);
    assert(results[0] == LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST);
    assert(results[1] == LC_READ_PAGE_RESULT_NO_COMPLETION);
    assert(results[2] == LC_READ_PAGE_RESULT_SUCCESS);
    assert(results[3] == LC_READ_PAGE_RESULT_COMPLETER_ABORT);
    assert(resultMap[0] == 0);
    assert(resultMap[1] == 0);
    assert(resultMap[2] == 1);
    assert(resultMap[3] == 0);
    assert(FpgaReadPolicy_BuildRetryList(4, results, 4, retryIndices) == 1);
    assert(retryIndices[0] == 1);
    assert(FpgaReadTagMap_Resolve(&map, tagSilent, &iPage));
    assert(iPage == 1);
}

static void test_probe_all_silent_batch_is_bounded_and_retryable(void)
{
    FPGA_READ_TAG_MAP map;
    FPGA_READ_PAGE_STATE states[FPGA_READ_TAGS_PER_GENERATION];
    LC_READ_PAGE_RESULT results[FPGA_READ_TAGS_PER_GENERATION];
    DWORD retries[FPGA_READ_TAGS_PER_GENERATION];
    DWORD i;
    BYTE tag;

    FpgaReadTagMap_Begin(&map, 0x80);
    for(i = 0; i < FPGA_READ_TAGS_PER_GENERATION; i++) {
        FpgaReadPolicy_PageBegin(&states[i], 4);
        assert(FpgaReadTagMap_Assign(&map, i, &tag));
        assert((tag >= 0x80) && (tag <= 0xef));
    }
    assert(map.cActive == FPGA_READ_TAGS_PER_GENERATION);
    assert(!FpgaReadTagMap_Assign(&map, FPGA_READ_TAGS_PER_GENERATION, &tag));
    for(i = 0; i < FPGA_READ_TAGS_PER_GENERATION; i++) {
        results[i] = FpgaReadPolicy_Finalize(&states[i]);
        assert(results[i] == LC_READ_PAGE_RESULT_NO_COMPLETION);
    }
    assert(FpgaReadPolicy_BuildRetryList(
        FPGA_READ_TAGS_PER_GENERATION,
        results,
        FPGA_READ_TAGS_PER_GENERATION,
        retries) == FPGA_READ_TAGS_PER_GENERATION);
    for(i = 0; i < FPGA_READ_TAGS_PER_GENERATION; i++) {
        assert(retries[i] == i);
    }
    FpgaReadTagMap_Invalidate(&map);
    assert(map.cActive == 0);
}

static void test_aggregate_counter_transitions(void)
{
    FPGA_READ_COUNTERS counters = { 0 };

    assert(!FpgaReadPolicy_CountersHaveData(&counters));
    FpgaReadPolicy_RecordPass(&counters, LC_READ_PAGE_RESULT_SUCCESS, (BOOL)0);
    FpgaReadPolicy_RecordPass(&counters, LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST, (BOOL)0);
    FpgaReadPolicy_RecordPass(&counters, LC_READ_PAGE_RESULT_COMPLETER_ABORT, (BOOL)0);
    FpgaReadPolicy_RecordPass(&counters, LC_READ_PAGE_RESULT_NO_COMPLETION, (BOOL)0);
    FpgaReadPolicy_RecordPass(&counters, LC_READ_PAGE_RESULT_PROTOCOL_ERROR, (BOOL)0);
    FpgaReadPolicy_RecordPass(&counters, LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY, (BOOL)1);
    FpgaReadPolicy_RecordPass(&counters, LC_READ_PAGE_RESULT_NO_COMPLETION, (BOOL)1);

    assert(FpgaReadPolicy_CountersHaveData(&counters));
    assert(counters.cFirstPassFailed == 4);
    assert(counters.cUnsupportedRequest == 1);
    assert(counters.cCompleterAbort == 1);
    assert(counters.cRetryAttempted == 2);
    assert(counters.cRetryRecovered == 1);
    assert(counters.cRetryExhausted == 1);
    assert(counters.cProtocolError == 1);
}

int main(void)
{
    test_public_result_values_are_stable();
    test_completion_status_is_classified_without_guessing();
    test_only_transient_or_unclassified_results_are_retryable();
    test_terminal_result_is_sticky_across_tiny_fragments();
    test_incomplete_data_is_distinguished_from_transport_failure();
    test_success_after_retry_is_reported_distinctly();
    test_each_tag_retires_once();
    test_new_operation_does_not_inherit_terminal_result();
    test_retry_list_contains_only_retryable_results();
    test_adaptive_polling_requires_sustained_completion_loss();
    test_adaptive_polling_rejects_stale_transport_evidence();
    test_probe_extra_receive_passes_are_native_ft601_only();
    test_adaptive_polling_counts_only_transport_evidence();
    test_adaptive_polling_is_reevaluated_after_transport_reopen();
    test_retry_result_replaces_transient_result();
    test_mixed_synchronous_pass_retries_only_transient_pages();
    test_async_and_tiny_tag_sequences();
    test_probe_tag_map_is_unique_and_generation_scoped();
    test_probe_results_are_attributed_by_tag();
    test_probe_all_silent_batch_is_bounded_and_retryable();
    test_aggregate_counter_transitions();
    puts("device_fpga_read_policy_test: all tests passed");
    return 0;
}
