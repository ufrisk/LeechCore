// leechagent.h : definitions related to the leech agent.
//
// (c) Ulf Frisk, 2018-2023
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

#define LEECHAGENT_CLIENTKEEPALIVE_MAX_CLIENTS            0x40
#define LEECHAGENT_CLIENTKEEPALIVE_TIMEOUT_MS          75*1000    // recommended to be less than LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS
#define LEECHAGENT_CHILDPROCESS_TIMEOUT_MAX_MS      30*60*1000
#define LEECHAGENT_CHILDPROCESS_TIMEOUT_DEFAULT_MS   2*60*1000

typedef struct tdLEECHAGENT_REMOTE_ENTRY {
    BOOL f32;
    BOOL f64;
    LPWSTR wsz;
} LEECHAGENT_REMOTE_ENTRY, *PLEECHAGENT_REMOTE_ENTRY;

static LEECHAGENT_REMOTE_ENTRY g_REMOTE_FILES_REQUIRED[] = {
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"leechagent.exe"}, // LeechAgent is required to be 1st entry (used in service creation)
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"leechcore.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"vcruntime140.dll"},
};
static LEECHAGENT_REMOTE_ENTRY g_REMOTE_FILES_OPTIONAL[] = {
    // 32/64-bit MemProcFS
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"vmm.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"info.db"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"libpdbcrust.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"vmmyara.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"dbghelp.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"symsrv.dll"},
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"symsrv.yes"},
    // 64-bit MemProcFS Python
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"leechcorepyc.pyd"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmmpyc.pyd"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"memprocfs.py"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmmpyplugin.py"},
    // 32-bit winpmem
    {.f32 = TRUE,.f64 = FALSE,.wsz = L"winpmem_x86.sys"},
    // 64-bit winpmem
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"winpmem_x64.sys"},
    // 64-bit HyperV saved state
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"leechcore_device_hvsavedstate.dll"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"vmsavedstatedumpprovider.dll"},
    // 64-bit HyperV HVMM (LiveCloudKd)
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"leechcore_device_hvmm.dll"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"LiveCloudKdSdk.dll"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"hvlib.dll"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"hvmm.sys"},
    // 32/64-bit FTDI driver (PCIe DMA FPGA)
    {.f32 = TRUE,.f64 = TRUE,.wsz = L"FTD3XX.dll"},
};
static LEECHAGENT_REMOTE_ENTRY g_REMOTE_DIRS_OPTIONAL[] = {
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Plugins"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Python"},
    {.f32 = FALSE,.f64 = TRUE,.wsz = L"Yara"},
};

BOOL g_LeechAgent_IsService;

#endif /* __LEECHAGENT_H__ */
