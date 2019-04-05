//	leechcorepyc.c : Implementation of the LeechCore Python API
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHCOREPYC_H__
#define __LEECHCOREPYC_H__
#include <Windows.h>

/*
* Initialize and clean up the standard output from the embedded Python console
* used by the LeechAgent.
*/
VOID LeechCorePyC_StdOutCaptureInitialize();
VOID LeechCorePyC_StdOutCaptureClose();

/*
* Start capturing redirected standard output from the Python console instead of
* printing it on the screen.
*/
VOID LeechCorePyC_StdOutCaptureStart();

/*
* Verify that a memory range is valid and if valid translate its base to a device-address.
* NB! CALLER_FREE: LocalFree(ppbBuffer)
* -- ppbBuffer = function allocated buffer with text that CALLER function must LocalFree!
* -- pcbBuffer
* -- return
*/
_Success_(return)
BOOL LeechCorePyc_StdOutCaptureEnd(_Out_writes_opt_(*pcbBuffer) PBYTE *ppbBuffer, _Out_opt_ PDWORD pcbBuffer);


#endif __LEECHCOREPYC_H__