// util.c : implementation of various utility functions.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "util.h"

/*
* Retrieve the operating system path of the directory which is containing this:
* .dll/.so file.
* -- szPath
*/
VOID Util_GetPathLib(_Out_writes_(MAX_PATH) PCHAR szPath)
{
    SIZE_T i;
    ZeroMemory(szPath, MAX_PATH);
#ifdef _WIN32
    HMODULE hModuleLeechCore;
    hModuleLeechCore = LoadLibraryA("leechcore.dll");
    GetModuleFileNameA(hModuleLeechCore, szPath, MAX_PATH - 4);
    if(hModuleLeechCore) { FreeLibrary(hModuleLeechCore); }
#endif /* _WIN32 */
#ifdef LINUX
    Dl_info Info = { 0 };
    if(!dladdr((void *)Util_GetPathLib, &Info) || !Info.dli_fname) { return; }
    strncpy(szPath, Info.dli_fname, MAX_PATH - 1);
#endif /* LINUX */
    for(i = strlen(szPath) - 1; i > 0; i--) {
        if(szPath[i] == '/' || szPath[i] == '\\') {
            szPath[i + 1] = '\0';
            return;
        }
    }
}

/*
* Try retrieve a numerical value from sz. If sz starts with '0x' it will be
* interpreted as hex (base 16), otherwise decimal (base 10).
* -- sz
* -- return
*/
QWORD Util_GetNumericA(_In_ LPSTR sz)
{
    BOOL fhex = sz[0] && sz[1] && (sz[0] == '0') && ((sz[1] == 'x') || (sz[1] == 'X'));
    return strtoull(sz, NULL, fhex ? 16 : 10);
}

//-----------------------------------------------------------------------------

#define Util_2HexChar(x) (((((x) & 0xf) <= 9) ? '0' : ('a' - 10)) + ((x) & 0xf))

#define UTIL_PRINTASCII \
    "................................ !\"#$%&'()*+,-./0123456789:;<=>?" \
    "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ " \
    "................................................................" \
    "................................................................" \

BOOL Util_FillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Inout_ PDWORD pcsz)
{
    DWORD i, j, o = 0, iMod, cRows;
    // checks
    if((cbInitialOffset > cb) || (cbInitialOffset > 0x1000) || (cbInitialOffset & 0xf)) { return FALSE; }
    cRows = (cb + 0xf) >> 4;
    if(!sz) {
        *pcsz = 1 + cRows * 76;
        return TRUE;
    }
    if(!pb || (*pcsz <= cRows * 76)) { return FALSE; }
    // fill buffer with bytes
    for(i = cbInitialOffset; i < cb + ((cb % 16) ? (16 - cb % 16) : 0); i++)
    {
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
    sz[o] = 0;
    *pcsz = o;
    return TRUE;
}

VOID Util_PrintHexAscii(_In_opt_ PLC_CONTEXT ctxLC, _In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset)
{
    DWORD szMax = 0;
    LPSTR sz;
    if(cb > 0x10000) {
        if(ctxLC) {
            lcprintf(ctxLC, "Large output. Only displaying first 65kB.\n");
        } else {
            printf("Large output. Only displaying first 65kB.\n");
        }
        cb = 0x10000 - cbInitialOffset;
    }
    Util_FillHexAscii(pb, cb, cbInitialOffset, NULL, &szMax);
    if(!(sz = LocalAlloc(0, szMax))) { return; }
    Util_FillHexAscii(pb, cb, cbInitialOffset, sz, &szMax);
    if(ctxLC) {
        lcprintf(ctxLC, "%s", sz);
    } else {
        printf("%s", sz);
    }
    LocalFree(sz);
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
    BOOL fWow64 = TRUE;
    if(Util_IsProgramBitness64()) {
        return TRUE;
    }
    IsWow64Process(GetCurrentProcess(), &fWow64);
    return fWow64;
}

BOOL Util_IsProgramBitness64()
{
#ifndef _WIN64
    return FALSE;
#endif /* _WIN64 */
    return TRUE;
}
