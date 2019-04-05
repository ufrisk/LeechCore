// leechagent.h : definitions related to the leech agent.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHAGENT_H__
#define __LEECHAGENT_H__
#include <windows.h>

#define LEECHSVC_NAME           L"LeechAgent"
#define LEECHSVC_DISPLAY_NAME   L"Leech Memory Acquisition Agent"
#define LEECHSVC_DESCR_LONG     L"The Leech Memory Acquisition Agent allows for LeechCore library users to connect remotely to the agent."
#define LEECHSVC_TCP_PORT       L"28473"
#define SVC_ERROR				0x0000

#define LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS            0x10
#define LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS          75*1000    // recommended to be less than LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS
#define LEECHAGENT_CHILDPROCESS_TIMEOUT_MAX_MS      30*60*1000
#define LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS   2*60*1000

BOOL g_LeechAgent_IsService;

#endif /* __LEECHAGENT_H__ */
