// util.h : implementations of various utility functions.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "util.h"

VOID Util_wcsncat_s_N(_Inout_updates_z_(_SizeInWords) wchar_t* _Destination, _In_ rsize_t _SizeInWords, _In_ rsize_t _MaxCount, ...)
{
    LPWSTR wsz;
    va_list args;
    va_start(args, _MaxCount);
    while((wsz = va_arg(args, LPWSTR))) {
        wcsncat_s(_Destination, _SizeInWords, wsz, _MaxCount);
    }
    va_end(args);
}

VOID Util_GetPathDllW(_Out_writes_(MAX_PATH) PWCHAR wszPath, _In_opt_ HMODULE hModule)
{
    SIZE_T i;
    GetModuleFileNameW(hModule, wszPath, MAX_PATH - 4);
    for(i = wcslen(wszPath) - 1; i > 0; i--) {
        if(wszPath[i] == L'/' || wszPath[i] == L'\\') {
            wszPath[i + 1] = '\0';
            return;
        }
    }
}

#ifdef _WIN32

_Success_(return)
BOOL Util_GetBytesPipe(_In_ HANDLE hPipe_Rd, _Out_writes_opt_(cb) PBYTE pb, _In_ DWORD cb)
{
    DWORD cbReadTotal = 0, cbRead = 0;
    while((cbReadTotal < cb) && ReadFile(hPipe_Rd, pb + cbReadTotal, cb - cbReadTotal, &cbRead, NULL)) {
        cbReadTotal += cbRead;
    }
    return (cb == cbReadTotal);
}

#endif /* _WIN32 */
