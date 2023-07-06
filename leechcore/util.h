// util.h : definitions of various utility functions.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __UTIL_H__
#define __UTIL_H__
#include "leechcore.h"
#include "leechcore_device.h"
#include "oscompatibility.h"

/*
* Retrieve the operating system path of the directory which is containing this:
* .dll/.so file.
* -- szPath
*/
VOID Util_GetPathLib(_Out_writes_(MAX_PATH) PCHAR szPath);

/*
* Try retrieve a numerical value from sz. If sz starts with '0x' it will be
* interpreted as hex (base 16), otherwise decimal (base 10).
* -- sz
* -- return
*/
QWORD Util_GetNumericA(_In_ LPSTR sz);

/*
* Print a maximum of 8192 bytes of binary data as hexascii on the screen.
* -- ctxLC
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
*/
VOID Util_PrintHexAscii(_In_opt_ PLC_CONTEXT ctxLC, _In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset);

/*
* Fill a human readable hex ascii memory dump into the caller supplied sz buffer.
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
* -- sz = buffer to fill, NULL to retrieve size in pcsz parameter.
* -- pcsz = IF sz==NULL :: size of buffer (including space for terminating NULL) on exit
*           IF sz!=NULL :: size of buffer on entry, size of characters (excluding terminating NULL) on exit.
*/
BOOL Util_FillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Inout_opt_ LPSTR sz, _Inout_ PDWORD pcsz);

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
