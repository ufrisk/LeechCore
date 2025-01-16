// util.h : definitions of various utility functions.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __UTIL_H__
#define __UTIL_H__
#include "leechcore.h"

/*
* Return the path of the specified hModule (DLL) - ending with a backslash, or current Executable.
* -- szPath
* -- hModule = Optional, HMODULE handle for path to DLL, NULL for path to EXE.
*/
VOID Util_GetPathDllW(_Out_writes_(MAX_PATH) PWCHAR wszPath, _In_opt_ HMODULE hModule);

/*
* Perform a wszncat_s on an arbitrary number of LPWSTR that is terminated by a NULL argument.
* -- _Destination
* -- _SizeInWords
* -- _MaxCount
* -- ... = arbitrary number of LPWSTR terminated with NULL argument.
*/
VOID Util_wcsncat_s_N(_Inout_updates_z_(_SizeInWords) wchar_t* _Destination, _In_ rsize_t _SizeInWords, _In_ rsize_t _MaxCount, ...);

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
