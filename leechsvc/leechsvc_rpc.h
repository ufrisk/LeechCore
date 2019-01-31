// leechsvc_rpc.h : definitions of RPC related functionality.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHSVC_RPC_H__
#define __LEECHSVC_RPC_H__

#include <Windows.h>

RPC_STATUS RpcStart(_In_ BOOL fInsecure, _In_ BOOL fSvc);
void RpcStop();

#endif /* __LEECHSVC_RPC_H__ */
