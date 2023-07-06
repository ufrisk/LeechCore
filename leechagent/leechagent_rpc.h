// leechagent_rpc.h : definitions of RPC related functionality.
//
// (c) Ulf Frisk, 2018-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHAGENT_RPC_H__
#define __LEECHAGENT_RPC_H__

#include <Windows.h>

RPC_STATUS RpcStart(_In_ BOOL fInsecure, _In_ BOOL fSvc);
void RpcStop();

#endif /* __LEECHAGENT_RPC_H__ */
