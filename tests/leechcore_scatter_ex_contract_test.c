#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <leechcore.h>

typedef char lc_read_page_result_must_match_dword[
    (sizeof(LC_READ_PAGE_RESULT) == sizeof(DWORD)) ? 1 : -1
];

#if LC_READ_PAGE_RESULT_NONE != 0 || \
    LC_READ_PAGE_RESULT_SUCCESS != 1 || \
    LC_READ_PAGE_RESULT_SUCCESS_AFTER_RETRY != 2 || \
    LC_READ_PAGE_RESULT_UNSUPPORTED_REQUEST != 3 || \
    LC_READ_PAGE_RESULT_COMPLETER_ABORT != 4 || \
    LC_READ_PAGE_RESULT_NO_COMPLETION != 5 || \
    LC_READ_PAGE_RESULT_PARTIAL_COMPLETION != 6 || \
    LC_READ_PAGE_RESULT_TRANSPORT_ERROR != 7 || \
    LC_READ_PAGE_RESULT_PROTOCOL_ERROR != 8 || \
    LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR != 9 || \
    LC_READ_PAGE_RESULT_NOT_ISSUED != 10
#error LC_READ_PAGE_RESULT numeric ABI changed
#endif

static void test_invalid_handle_initializes_available_outputs(void)
{
    BYTE buffer[8] = { 0 };
    MEM_SCATTER mem;
    PMEM_SCATTER pMEM = &mem;
    LC_READ_PAGE_RESULT result = LC_READ_PAGE_RESULT_NONE;
    memset(&mem, 0, sizeof(mem));
    mem.version = MEM_SCATTER_VERSION;
    mem.f = (BOOL)1;
    mem.qwA = 0x1000;
    mem.pb = buffer;
    mem.cb = sizeof(buffer);

    assert(!LcReadScatterEx(NULL, 1, &pMEM, &result));
    assert(!mem.f);
    assert(result == LC_READ_PAGE_RESULT_UNSPECIFIED_ERROR);
}

static void test_legacy_invalid_handle_preserves_page_state(void)
{
    BYTE buffer[8] = { 0 };
    MEM_SCATTER mem;
    PMEM_SCATTER pMEM = &mem;
    memset(&mem, 0, sizeof(mem));
    mem.version = MEM_SCATTER_VERSION;
    mem.f = (BOOL)1;
    mem.qwA = 0x1000;
    mem.pb = buffer;
    mem.cb = sizeof(buffer);

    LcReadScatter(NULL, 1, &pMEM);
    assert(mem.f);
    assert(mem.qwA == 0x1000);
}

int main(void)
{
    test_invalid_handle_initializes_available_outputs();
    test_legacy_invalid_handle_preserves_page_state();
    puts("leechcore_scatter_ex_contract_test: all tests passed");
    return 0;
}
