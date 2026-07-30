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

static void test_adaptive_polling_requires_sustained_completion_loss(void)
{
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(0));
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(1));
    assert(!FpgaReadPolicy_ShouldEnableAdaptivePolling(
        FPGA_READ_TAGS_PER_GENERATION - 1));
    assert(FpgaReadPolicy_ShouldEnableAdaptivePolling(
        FPGA_READ_TAGS_PER_GENERATION));
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
    test_adaptive_polling_requires_sustained_completion_loss();
    puts("device_fpga_read_policy_test: all tests passed");
    return 0;
}
