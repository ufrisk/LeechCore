// leechagent_rpc.h : definitions of RPC related functionality.
//
// (c) Ulf Frisk, 2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHAGENT_RPC_H__
#define __LEECHAGENT_RPC_H__

#include "oscompatibility.h"

_Success_(return) BOOL RpcStartGRPC(_In_ PLEECHSVC_CONFIG pConfig);
void RpcStop();

#endif /* __LEECHAGENT_RPC_H__ */
