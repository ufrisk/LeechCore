// leechsvc.h : definitions related to the leech service.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHSVC_H__
#define __LEECHSVC_H__
#include <windows.h>

#define LEECHSVC_NAME           L"LeechSvc"
#define LEECHSVC_DISPLAY_NAME   L"Leech Memory Acquisition Service"
#define LEECHSVC_DESCR_LONG     L"Enables users of the LeechCore library to remotely connect over RPC to the Leech Memory Acquisition Service."
#define LEECHSVC_TCP_PORT       L"28473"
#define SVC_ERROR				0x0000

#endif /* __LEECHSVC_H__ */
