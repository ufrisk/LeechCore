// util.c : implementation of various utility functions.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "util.h"
#include "device.h"

#define Util_2HexChar(x) (((((x) & 0xf) <= 9) ? '0' : ('a' - 10)) + ((x) & 0xf))

#define UTIL_PRINTASCII \
    "................................ !\"#$%&'()*+,-./0123456789:;<=>?" \
    "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ " \
    "................................................................" \
    "................................................................" \

BOOL Util_FillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Out_ PDWORD pcsz)
{
    DWORD i, j, o = 0, szMax, iMod;
    // checks
    if((cbInitialOffset > cb) || (cbInitialOffset > 0x1000) || (cbInitialOffset & 0xf)) { return FALSE; }
    *pcsz = szMax = cb * 5 + 80;
    if(cb > szMax) { return FALSE; }
    if(!sz) { return TRUE; }
    // fill buffer with bytes
    for(i = cbInitialOffset; i < cb + ((cb % 16) ? (16 - cb % 16) : 0); i++) {
        // address
        if(0 == i % 16) {
            iMod = i % 0x10000;
            sz[o++] = Util_2HexChar(iMod >> 12);
            sz[o++] = Util_2HexChar(iMod >> 8);
            sz[o++] = Util_2HexChar(iMod >> 4);
            sz[o++] = Util_2HexChar(iMod);
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
        } else if(0 == i % 8) {
            sz[o++] = ' ';
        }
        // hex
        if(i < cb) {
            sz[o++] = Util_2HexChar(pb[i] >> 4);
            sz[o++] = Util_2HexChar(pb[i]);
            sz[o++] = ' ';
        } else {
            sz[o++] = ' ';
            sz[o++] = ' ';
            sz[o++] = ' ';
        }
        // ascii
        if(15 == i % 16) {
            sz[o++] = ' ';
            sz[o++] = ' ';
            for(j = i - 15; j <= i; j++) {
                if(j >= cb) {
                    sz[o++] = ' ';
                } else {
                    sz[o++] = UTIL_PRINTASCII[pb[j]];
                }
            }
            sz[o++] = '\n';
        }
    }
    sz[o++] = 0;
    return TRUE;
}

VOID Util_PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset)
{
    DWORD szMax;
    LPSTR sz;
    if(cb > 0x10000) {
        vprintf("Large output. Only displaying first 65kB.\n");
        cb = 0x10000 - cbInitialOffset;
    }
    Util_FillHexAscii(pb, cb, cbInitialOffset, NULL, &szMax);
    if(!(sz = LocalAlloc(0, szMax))) { return; }
    Util_FillHexAscii(pb, cb, cbInitialOffset, sz, &szMax);
    vprintf("%s", sz);
    LocalFree(sz);
}

VOID Util_GetPathDll(_Out_writes_(MAX_PATH) PCHAR szPath, _In_opt_ HMODULE hModule)
{
    SIZE_T i;
    GetModuleFileNameA(hModule, szPath, MAX_PATH - 4);
    for(i = strlen(szPath) - 1; i > 0; i--) {
        if(szPath[i] == '/' || szPath[i] == '\\') {
            szPath[i + 1] = '\0';
            return;
        }
    }
}

VOID Util_Split2(_In_ LPSTR sz, CHAR chDelimiter, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2)
{
    DWORD i;
    strcpy_s(_szBuf, MAX_PATH, sz);
    *psz1 = _szBuf;
    for(i = 0; i < MAX_PATH; i++) {
        if('\0' == _szBuf[i]) {
            *psz2 = _szBuf + i;
            return;
        }
        if(chDelimiter == _szBuf[i]) {
            _szBuf[i] = '\0';
            *psz2 = _szBuf + i + 1;
            return;
        }
    }
}

VOID Util_Split3(_In_ LPSTR sz, CHAR chDelimiter, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2, _Out_ LPSTR *psz3)
{
    DWORD i;
    strcpy_s(_szBuf, MAX_PATH, sz);
    *psz1 = _szBuf;
    *psz2 = NULL;
    for(i = 0; i < MAX_PATH; i++) {
        if('\0' == _szBuf[i]) {
            if(!*psz2) {
                *psz2 = _szBuf + i;
            }
            *psz3 = _szBuf + i;
            return;
        }
        if(chDelimiter == _szBuf[i]) {
            _szBuf[i] = '\0';
            if(*psz2) {
                *psz3 = _szBuf + i + 1;
                return;
            }
            *psz2 = _szBuf + i + 1;
        }
    }
}

VOID Util_GenRandom(_Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD i = 0;
    srand((unsigned int)GetTickCount64());
    if(cb % 2) {
        *(PBYTE)(pb) = (BYTE)rand();
        i++;
    }
    for(; i <= cb - 2; i += 2) {
        *(PWORD)(pb + i) = (WORD)rand();
    }
}

BOOL Util_IsPlatformBitness64()
{
    BOOL f64 = TRUE;
#ifndef ARCH_64
    IsWow64Process(GetCurrentProcess(), &f64);
#endif /* ARCH_64 */
    return f64;
}

BOOL Util_IsProgramBitness64()
{
#ifndef _WIN64
    return FALSE;
#endif /* _WIN64 */
    return TRUE;
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

