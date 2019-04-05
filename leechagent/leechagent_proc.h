//	leechagent_proc.h : Definitions of parent/child process functionality.
//                 Child processes host execution environments such as the
//                 Python environment which allows for execution of scripts.
//                 Child processes are spawned and controlled by the main
//                 LeechAgent process.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHAGENT_PROC_H__
#define __LEECHAGENT_PROC_H__
#include "leechagent.h"

#define LEECHAGENT_PROC_CMD_MAGIC           0x20f02ab8
#define LEECHAGENT_PROC_CMD_EXITCLIENT      0x00000001
#define LEECHAGENT_PROC_CMD_INIT_VMM        0x00000002
#define LEECHAGENT_PROC_CMD_INIT_PYTHON     0x00000003
#define LEECHAGENT_PROC_CMD_EXEC_PYTHON     0x00000004

typedef struct tdLEECHAGENT_PROC_CMD {
    DWORD dwMagic;
    DWORD dwCmd;
    BOOL fSuccess;
    DWORD cb;
    BYTE pb[];
} LEECHAGENT_PROC_CMD, *PLEECHAGENT_PROC_CMD;

VOID LeechAgent_ProcChild_Main(int argc, wchar_t* argv[]);

_Success_(return)
BOOL LeechAgent_ProcParent_ExecPy(_In_ ULONG64 fDataIn, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(*pcbDataOut) PBYTE* ppbDataOut, _Out_opt_ PDWORD pcbDataOut);

#endif /* __LEECHAGENT_PROC_H__ */
