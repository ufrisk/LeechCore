// leechagent.h : definitions related to the leech agent.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHAGENT_H__
#define __LEECHAGENT_H__

#include "oscompatibility.h"

#define LEECHSVC_NAME           "LeechAgent"
#define LEECHSVC_DISPLAY_NAME   "Leech Memory Acquisition Agent"
#define LEECHSVC_DESCR_LONG     "The Leech Memory Acquisition Agent allows for LeechCore library users to connect remotely to the agent."
#define LEECHSVC_TCP_PORT_GRPC  "28474"
#define LEECHSVC_LOCKFILE       "/var/run/lock/leechagent.pid"

#define LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS            0x40
#define LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS          75*1000    // recommended to be less than LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS
#define LEECHAGENT_CHILDPROCESS_TIMEOUT_MAX_MS      30*60*1000
#define LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS   2*60*1000

#define LEECHGRPC_LIBRARY_NAME "libleechgrpc"LC_LIBRARY_FILETYPE
#define LEECHAGENT_CONFIG_FILE "leechagent_config.txt"

typedef struct tdLEECHAGENT_CONFIG {
    BOOL fDaemon;
    BOOL fNoLock;
    BOOL fInteractive;
    BOOL fInsecure;
    CHAR szRemote[MAX_PATH];
    CHAR szTcpPortGRPC[0x10];
    HMODULE hModuleGRPC;
    struct {
        CHAR szCurrentDirectory[MAX_PATH];
        CHAR szListenAddress[MAX_PATH];
        CHAR szTlsClientCaCert[MAX_PATH];
        CHAR szTlsServerP12[MAX_PATH];
        CHAR szTlsServerP12Pass[MAX_PATH];
    } grpc;
    int fdLockFile;
} LEECHSVC_CONFIG, *PLEECHSVC_CONFIG;

/*
* Read arguments from a the config file 'leechagent_config.txt' into the config.
*/
VOID LeechSvc_ParseArgs_FromConfigFile(_In_ PLEECHSVC_CONFIG pConfig);

#endif /* __LEECHAGENT_H__ */
