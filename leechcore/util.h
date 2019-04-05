// util.h : definitions of various utility functions.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __UTIL_H__
#define __UTIL_H__
#include "device.h"

/*
* Print a maximum of 8192 bytes of binary data as hexascii on the screen.
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
*/
VOID Util_PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset);

/*
* Fill a human readable hex ascii memory dump into the caller supplied sz buffer.
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
* -- sz = buffer to fill, NULL to retrieve size in pcsz parameter.
* -- pcsz = ptr to size of buffer on entry, size of characters on exit.
*/
BOOL Util_FillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Out_ PDWORD pcsz);

/*
* Return the path of the specified hModule (DLL) - ending with a backslash, or current Executable.
* -- szPath
* -- hModule = Optional, HMODULE handle for path to DLL, NULL for path to EXE.
*/
VOID Util_GetPathDll(_Out_writes_(MAX_PATH) PCHAR szPath, _In_opt_ HMODULE hModule);

/*
* Split a string into two at the first chDelimiter character. If no 2nd string
* is not found then it's returned as null character '\0' (i.e. not as NULL).
* The Util_Split3 function is analogous to Util_Split2.
* -- sz = the original string to split (of maximum MAX_PATH length)
* -- szDelimiter = the delimiter character splitting the string.
* -- _szBuf = MAX_PATH sized buffer that will be overwritten and used throughout the lifetime of psz1/psz2 outputs.
* -- psz1
* -- psz2
*/
VOID Util_Split2(_In_ LPSTR sz, CHAR chDelimiter, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2);
VOID Util_Split3(_In_ LPSTR sz, CHAR chDelimiter, _Out_writes_(MAX_PATH) PCHAR _szBuf, _Out_ LPSTR *psz1, _Out_ LPSTR *psz2, _Out_ LPSTR *psz3);

/*
* Simple random number function.
* -- pb = buffer to receive random data.
* -- cb = length of random data to create.
*/
VOID Util_GenRandom(_Out_ PBYTE pb, _In_ DWORD cb);

/*
* Returns true if this is a 64-bit Windows operating system.
* This is regardless of whether this is a 32-bit WoW process or not.
* Function have no meaning on Linux.
* -- return
*/
BOOL Util_IsPlatformBitness64();

/*
* Return true if this program is a 64-bit program.
* -- return
*/
BOOL Util_IsProgramBitness64();

#ifdef _WIN32

/*
* "Eternal" reading loop until all requested data is read or until there is an error.
* -- hPipe_Rd
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL Util_GetBytesPipe(_In_ HANDLE hPipe_Rd, _Out_writes_opt_(cb) PBYTE pb, _In_ DWORD cb);

#endif /* _WIN32 */

#endif /* __UTIL_H__ */
