// device_hvsavedstate.c : implementation of the Hyper-V Saved State "device".
// NB! this device is dependant on an active Hyper-V system on the machine and also
// of the file 'vmsavedstatedumpprovider.dll' being placed in the same folder as the
// 'leechcore.dll' libray.
// Hyper-V Saved State is the former name for Microsoft Hyper-V  Runtime State (.VMRS)
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
// (c) Matt Suiche, 2019
// Author: Matt Suiche, msuiche@comae.com
//
#ifdef _WIN32
#include "device.h"
#include "memmap.h"
#include "util.h"

typedef VOID* VM_SAVED_STATE_DUMP_HANDLE;

typedef UINT64 GUEST_VIRTUAL_ADDRESS;
typedef UINT64 GUEST_PHYSICAL_ADDRESS;

// 
// Define paging modes 
// 
typedef enum PAGING_MODE
{
    Paging_Invalid = 0,
    Paging_NonPaged,
    Paging_32Bit,
    Paging_Pae,
    Paging_Long,
} PAGING_MODE;


// 
// Define guest physical memory chunks 
// 
typedef struct GPA_MEMORY_CHUNK
{
    UINT64  GuestPhysicalStartPageIndex;
    UINT64  PageCount;
} GPA_MEMORY_CHUNK;


// 
// Define Virtual Processors dump information 
// 
typedef enum VIRTUAL_PROCESSOR_ARCH
{
    Arch_Unkown = 0,
    Arch_x86,
    Arch_x64,
} VIRTUAL_PROCESSOR_ARCH;


typedef enum REGISTER_ID_X86
{
    // 
    // General Purpose Registers 
    // 
    X86_RegisterEax = 0,
    X86_RegisterEcx,
    X86_RegisterEdx,
    X86_RegisterEbx,
    X86_RegisterEsp,
    X86_RegisterEbp,
    X86_RegisterEsi,
    X86_RegisterEdi,
    X86_RegisterEip,
    X86_RegisterEFlags,

    // 
    // Floating Point Registers 
    // 
    X86_RegisterLowXmm0,
    X86_RegisterHighXmm0,
    X86_RegisterLowXmm1,
    X86_RegisterHighXmm1,
    X86_RegisterLowXmm2,
    X86_RegisterHighXmm2,
    X86_RegisterLowXmm3,
    X86_RegisterHighXmm3,
    X86_RegisterLowXmm4,
    X86_RegisterHighXmm4,
    X86_RegisterLowXmm5,
    X86_RegisterHighXmm5,
    X86_RegisterLowXmm6,
    X86_RegisterHighXmm6,
    X86_RegisterLowXmm7,
    X86_RegisterHighXmm7,
    X86_RegisterLowXmm8,
    X86_RegisterHighXmm8,
    X86_RegisterLowXmm9,
    X86_RegisterHighXmm9,
    X86_RegisterLowXmm10,
    X86_RegisterHighXmm10,
    X86_RegisterLowXmm11,
    X86_RegisterHighXmm11,
    X86_RegisterLowXmm12,
    X86_RegisterHighXmm12,
    X86_RegisterLowXmm13,
    X86_RegisterHighXmm13,
    X86_RegisterLowXmm14,
    X86_RegisterHighXmm14,
    X86_RegisterLowXmm15,
    X86_RegisterHighXmm15,
    X86_RegisterLowXmmControlStatus,
    X86_RegisterHighXmmControlStatus,
    X86_RegisterLowFpControlStatus,
    X86_RegisterHighFpControlStatus,

    // 
    // Control Registers 
    // 
    X86_RegisterCr0,
    X86_RegisterCr2,
    X86_RegisterCr3,
    X86_RegisterCr4,
    X86_RegisterCr8,
    X86_RegisterEfer,

    // 
    // Debug Registers 
    // 
    X86_RegisterDr0,
    X86_RegisterDr1,
    X86_RegisterDr2,
    X86_RegisterDr3,
    X86_RegisterDr6,
    X86_RegisterDr7,

    // 
    // Segment Registers 
    // 
    X86_RegisterBaseGs,
    X86_RegisterBaseFs,
    X86_RegisterSegCs,
    X86_RegisterSegDs,
    X86_RegisterSegEs,
    X86_RegisterSegFs,
    X86_RegisterSegGs,
    X86_RegisterSegSs,
    X86_RegisterTr,
    X86_RegisterLdtr,

    // 
    // Table Registers 
    // 
    X86_RegisterBaseIdtr,
    X86_RegisterLimitIdtr,
    X86_RegisterBaseGdtr,
    X86_RegisterLimitGdtr,

    // 
    // Register Count 
    // 
    X86_RegisterCount,
} REGISTER_ID_X86;


typedef enum REGISTER_ID_X64
{
    // 
    // General Purpose Registers 
    // 
    X64_RegisterRax = 0,
    X64_RegisterRcx,
    X64_RegisterRdx,
    X64_RegisterRbx,
    X64_RegisterRsp,
    X64_RegisterRbp,
    X64_RegisterRsi,
    X64_RegisterRdi,
    X64_RegisterR8,
    X64_RegisterR9,
    X64_RegisterR10,
    X64_RegisterR11,
    X64_RegisterR12,
    X64_RegisterR13,
    X64_RegisterR14,
    X64_RegisterR15,
    X64_RegisterRip,
    X64_RegisterRFlags,

    // 
    // Floating Point Registers 
    // 
    X64_RegisterLowXmm0,
    X64_RegisterHighXmm0,
    X64_RegisterLowXmm1,
    X64_RegisterHighXmm1,
    X64_RegisterLowXmm2,
    X64_RegisterHighXmm2,
    X64_RegisterLowXmm3,
    X64_RegisterHighXmm3,
    X64_RegisterLowXmm4,
    X64_RegisterHighXmm4,
    X64_RegisterLowXmm5,
    X64_RegisterHighXmm5,
    X64_RegisterLowXmm6,
    X64_RegisterHighXmm6,
    X64_RegisterLowXmm7,
    X64_RegisterHighXmm7,
    X64_RegisterLowXmm8,
    X64_RegisterHighXmm8,
    X64_RegisterLowXmm9,
    X64_RegisterHighXmm9,
    X64_RegisterLowXmm10,
    X64_RegisterHighXmm10,
    X64_RegisterLowXmm11,
    X64_RegisterHighXmm11,
    X64_RegisterLowXmm12,
    X64_RegisterHighXmm12,
    X64_RegisterLowXmm13,
    X64_RegisterHighXmm13,
    X64_RegisterLowXmm14,
    X64_RegisterHighXmm14,
    X64_RegisterLowXmm15,
    X64_RegisterHighXmm15,
    X64_RegisterLowXmmControlStatus,
    X64_RegisterHighXmmControlStatus,
    X64_RegisterLowFpControlStatus,
    X64_RegisterHighFpControlStatus,

    // 
    // Control Registers 
    // 
    X64_RegisterCr0,
    X64_RegisterCr2,
    X64_RegisterCr3,
    X64_RegisterCr4,
    X64_RegisterCr8,
    X64_RegisterEfer,

    // 
    // Debug Registers 
    // 
    X64_RegisterDr0,
    X64_RegisterDr1,
    X64_RegisterDr2,
    X64_RegisterDr3,
    X64_RegisterDr6,
    X64_RegisterDr7,

    // 
    // Segment Registers 
    // 
    X64_RegisterBaseGs,
    X64_RegisterBaseFs,
    X64_RegisterSegCs,
    X64_RegisterSegDs,
    X64_RegisterSegEs,
    X64_RegisterSegFs,
    X64_RegisterSegGs,
    X64_RegisterSegSs,
    X64_RegisterTr,
    X64_RegisterLdtr,

    // 
    // Table Registers 
    // 
    X64_RegisterBaseIdtr,
    X64_RegisterLimitIdtr,
    X64_RegisterBaseGdtr,
    X64_RegisterLimitGdtr,

    // 
    // Register Count 
    // 
    X64_RegisterCount,
} REGISTER_ID_X64;


typedef struct VIRTUAL_PROCESSOR_REGISTER
{
    VIRTUAL_PROCESSOR_ARCH  Architecture;
    UINT64                  RegisterValue;
    union {
        REGISTER_ID_X86     RegisterId_x86;
        REGISTER_ID_X64     RegisterId_x64;
        DWORD               RegisterId;
    };
} VIRTUAL_PROCESSOR_REGISTER;

typedef struct tdHVSAVEDSTATE_CONTEXT {
    HMODULE hDll;
    VM_SAVED_STATE_DUMP_HANDLE hVmSavedStateDumpHandle;

    struct {
        HRESULT(WINAPI *ApplyPendingSavedStateFileReplayLog)(_In_ LPCWSTR VmrsFile);
        HRESULT(WINAPI *GetArchitecture)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _In_ UINT32 VpId, _Out_ VIRTUAL_PROCESSOR_ARCH* Architecture);
        HRESULT(WINAPI *GetGuestPhysicalMemoryChunks)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _Out_ UINT64* MemoryChunkPageSize, _Out_ GPA_MEMORY_CHUNK* MemoryChunks, _Inout_ UINT64* MemoryChunkCount);
        HRESULT(WINAPI *GetGuestRawSavedMemorySize)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _Out_ UINT64* GuestRawSavedMemorySize);
        HRESULT(WINAPI *GetPagingMode)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _In_ UINT32 VpId, _Out_ PAGING_MODE* PagingMode);
        HRESULT(WINAPI *GetRegisterValue)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _In_ UINT32 VpId, _Inout_ VIRTUAL_PROCESSOR_REGISTER* Register);
        HRESULT(WINAPI *GetVpCount)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _Out_ UINT32* VpCount);
        HRESULT(WINAPI *GuestPhysicalAddressToRawSavedMemoryOffset)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _In_ GUEST_PHYSICAL_ADDRESS PhysicalAddress, _Out_ UINT64* RawSavedMemoryOffset);
        HRESULT(WINAPI *GuestVirtualAddressToPhysicalAddress)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _In_ UINT32 VpId, _In_ const GUEST_VIRTUAL_ADDRESS VirtualAddress, _Out_ GUEST_PHYSICAL_ADDRESS* PhysicalAddress);
        HRESULT(WINAPI *LoadSavedStateFile)(_In_ LPCWSTR VmrsFile, _Out_ VM_SAVED_STATE_DUMP_HANDLE* VmSavedStateDumpHandle);
        HRESULT(WINAPI *LoadSavedStateFiles)(_In_ LPCWSTR BinFile, _In_ LPCWSTR VsvFile, _Out_ VM_SAVED_STATE_DUMP_HANDLE* VmSavedStateDumpHandle);
        HRESULT(WINAPI *LocateSavedStateFiles)(_In_ LPCWSTR VmName, _In_opt_ LPCWSTR SnapshotName, _Out_ LPWSTR* BinPath, _Out_ LPWSTR* VsvPath, _Out_ LPWSTR* VmrsPath);
        HRESULT(WINAPI *ReadGuestPhysicalAddress)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _In_ GUEST_PHYSICAL_ADDRESS PhysicalAddress, _Out_writes_bytes_(BufferSize) LPVOID Buffer, _In_ UINT32 BufferSize, _Out_opt_ UINT32* BytesRead);
        HRESULT(WINAPI *ReadGuestRawSavedMemory)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle, _In_ UINT64 RawSavedMemoryOffset, _Out_writes_bytes_(BufferSize) LPVOID Buffer, _In_ UINT32 BufferSize, _Out_opt_ UINT32* BytesRead);
        HRESULT(WINAPI *ReleaseSavedStateFiles)(_In_ VM_SAVED_STATE_DUMP_HANDLE VmSavedStateDumpHandle);
    } fn;

    VIRTUAL_PROCESSOR_ARCH architecture;
    ULONG64 paMax;
    ULONG64 regCr3;
    ULONG64 regRip;
} HVSAVEDSTATE_CONTEXT, *PHVSAVEDSTATE_CONTEXT;

VOID DeviceHvSavedState_ReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    PHVSAVEDSTATE_CONTEXT ctx = (PHVSAVEDSTATE_CONTEXT)ctxDeviceMain->hDevice;
    HRESULT hr;
    PMEM_IO_SCATTER_HEADER pMEM;
    DWORD i;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if((pMEM->cb < pMEM->cbMax) || (pMEM->qwA == (QWORD)-1)) { continue; } // skip already completed pMEMs
        //
        // ReadGuestPhysicalAddress() takes care of the sanity checks.
        //
        // if(!MemMap_VerifyTranslateMEM(pMEM, NULL)) { continue; }
        hr = ctx->fn.ReadGuestPhysicalAddress(ctx->hVmSavedStateDumpHandle, pMEM->qwA, (LPVOID)pMEM->pb, pMEM->cbMax, &pMEM->cb);
        if(FAILED(hr)) {
            pMEM->cb = 0;
        }
    }
}

VOID DeviceHvSavedState_Close()
{
    PHVSAVEDSTATE_CONTEXT ctx = (PHVSAVEDSTATE_CONTEXT)ctxDeviceMain->hDevice;
    if(!ctx) { return; }
    if(ctx->hVmSavedStateDumpHandle) {
        ctx->fn.ReleaseSavedStateFiles(ctx->hVmSavedStateDumpHandle);
    }
    if(ctx->hDll) {
        FreeLibrary(ctx->hDll);
    }
    LocalFree(ctx);
    ctxDeviceMain->hDevice = 0;
}

BOOL DeviceHvSavedState_Open_OpenHvHandle(PHVSAVEDSTATE_CONTEXT ctx)
{
    HRESULT hr;
    WCHAR wszVmrs[MAX_PATH] = { 0 };
    if(_strnicmp("HvSavedState://", ctxDeviceMain->cfg.szDevice, 15)) { return FALSE; }
    MultiByteToWideChar(CP_ACP, 0, ctxDeviceMain->cfg.szDevice + 15, _countof(ctxDeviceMain->cfg.szDevice) - 15, wszVmrs, _countof(wszVmrs));
    hr = ctx->fn.LoadSavedStateFile(wszVmrs, &ctx->hVmSavedStateDumpHandle);
    if(FAILED(hr)) {
        vprintf("DEVICE: FAILED: Hyper-V Saved State found - but not possible to open. Result 0x%08x\n", hr);
        return FALSE;
    }
    return TRUE;
}

BOOL DeviceHvSavedState_Open_MemMap(PHVSAVEDSTATE_CONTEXT ctx)
{
    HRESULT hr;
    BOOL result;
    QWORD i, cbPageSize, cChunks = 0;
    GPA_MEMORY_CHUNK *pChunks;
    hr = ctx->fn.GetGuestPhysicalMemoryChunks(ctx->hVmSavedStateDumpHandle, &cbPageSize, NULL, &cChunks);
    if((hr != E_OUTOFMEMORY) || !cChunks) { return FALSE; }
    if(!(pChunks = (GPA_MEMORY_CHUNK*)LocalAlloc(0, (SIZE_T)(cChunks * sizeof(GPA_MEMORY_CHUNK))))) { return FALSE; }
    hr = ctx->fn.GetGuestPhysicalMemoryChunks(ctx->hVmSavedStateDumpHandle, &cbPageSize, pChunks, &cChunks);
    if(FAILED(hr)) {
        LocalFree(pChunks);
        return FALSE; 
    }
    MemMap_Initialize(0x0000ffffffffffff);
    for(i = 0; i < cChunks; i++) {
        result = MemMap_AddRange(
            cbPageSize * pChunks[i].GuestPhysicalStartPageIndex,
            cbPageSize * pChunks[i].PageCount,
            cbPageSize * pChunks[i].GuestPhysicalStartPageIndex);
        if(!result) {
            LocalFree(pChunks);
            return FALSE;
        }
    }
    MemMap_GetMaxAddress(&ctx->paMax);
    LocalFree(pChunks);
    return TRUE;
}

BOOL DeviceHvSavedState_Init(PHVSAVEDSTATE_CONTEXT ctx) {
    VIRTUAL_PROCESSOR_REGISTER reg;

    UINT64 GuestRawSavedMemorySize = 0;
    UINT32 vpCount;

    if (ctx->fn.GetGuestRawSavedMemorySize(ctx->hVmSavedStateDumpHandle, &GuestRawSavedMemorySize) != S_OK) {
        wprintf(L"Error: GetGuestRawSavedMemorySize() failed.\n");
        return FALSE;
    }
    vprintfvv(__FUNCTION__ ": GuestRawSavedMemorySize: 0x%I64X\n", GuestRawSavedMemorySize);

    //
    // This overrides the previous DeviceHvSavedState_Open_MemMap() call.
    //
    ctx->paMax = GuestRawSavedMemorySize;

    if (ctx->fn.GetVpCount(ctx->hVmSavedStateDumpHandle, &vpCount) != S_OK) {
        vprintfvv(__FUNCTION__ ": Error: GetVpCount() failed.\n");
        return FALSE;
    }

    UINT32 vpId = 0;
    if (ctx->fn.GetArchitecture(ctx->hVmSavedStateDumpHandle, vpId, &ctx->architecture) != S_OK) {
        vprintfvv(__FUNCTION__ ": ERROR: GetPagingMode() failed.\n");
        return FALSE;
    }

    reg.Architecture = ctx->architecture;
    reg.RegisterId = ctx->architecture == Arch_x64 ? X64_RegisterCr3 : X86_RegisterCr3;
    if (ctx->fn.GetRegisterValue(ctx->hVmSavedStateDumpHandle, vpId, &reg) != S_OK) {
        vprintfvv(__FUNCTION__ ": ERROR: GetPagingMode(Cr3) failed.\n");
        return FALSE;
    }
    ctx->regCr3 = reg.RegisterValue;

    reg.Architecture = ctx->architecture;
    reg.RegisterId = ctx->architecture == Arch_x64 ? X64_RegisterRip : X86_RegisterEip;
    if (ctx->fn.GetRegisterValue(ctx->hVmSavedStateDumpHandle, vpId, &reg) != S_OK) {
        vprintfvv(__FUNCTION__ ": ERROR: GetPagingMode() failed.\n");
        return FALSE;
    }
    ctx->regRip = reg.RegisterValue;

    vprintfv("[%d] VP Architecture %s\n", vpId, ctx->architecture == Arch_x64 ? "x64" : "x86");
    vprintfv("[%d] CR3 0x%I64X\n", vpId, ctx->regCr3);
    vprintfv("[%d] RIP 0x%I64X\n", vpId, ctx->regRip);

    return TRUE;
}

BOOL DeviceHvSavedState_Open_InitializeDll(PHVSAVEDSTATE_CONTEXT ctx)
{
    const LPSTR FN_LIST[] = { "ApplyPendingSavedStateFileReplayLog", "GetArchitecture", "GetGuestPhysicalMemoryChunks", "GetGuestRawSavedMemorySize", "GetPagingMode", "GetRegisterValue", "GetVpCount", "GuestPhysicalAddressToRawSavedMemoryOffset", "GuestVirtualAddressToPhysicalAddress", "LoadSavedStateFile", "LoadSavedStateFiles", "LocateSavedStateFiles", "ReadGuestPhysicalAddress", "ReadGuestRawSavedMemory", "ReleaseSavedStateFiles" };
    DWORD i;
    if(sizeof(ctx->fn) != sizeof(FN_LIST)) { return FALSE; }
    ctx->hDll = LoadLibraryA("vmsavedstatedumpprovider.dll");
    if(!ctx->hDll) { return FALSE; }
    for(i = 0; i < sizeof(FN_LIST) / sizeof(LPSTR); i++) {
        if(!(*((PQWORD)&ctx->fn + i) = (QWORD)GetProcAddress(ctx->hDll, FN_LIST[i]))) { return FALSE; }
    }
    return TRUE;
}

_Success_(return)
BOOL DeviceHvSavedState_GetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PHVSAVEDSTATE_CONTEXT ctx = (PHVSAVEDSTATE_CONTEXT)ctxDeviceMain->hDevice;
    if (fOption == LEECHCORE_OPT_MEMORYINFO_VALID) {
        *pqwValue = 0;
        return TRUE;
    }
    switch (fOption) {
        case LEECHCORE_OPT_MEMORYINFO_ADDR_MAX:
            *pqwValue = ctx->paMax;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_DTB:
            *pqwValue = ctx->regCr3;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_KERNELHINT:
            *pqwValue = ctx->regRip;
            return TRUE;
        default:
            vprintfvv(__FUNCTION__ ": No option for 0x%I64X\n", fOption);
            break;
    }
    *pqwValue = 0;
    return FALSE;
}

BOOL DeviceHvSavedState_Open()
{
    PHVSAVEDSTATE_CONTEXT ctx = (PHVSAVEDSTATE_CONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(HVSAVEDSTATE_CONTEXT));
    if(!ctx) { return FALSE; }
    if(!DeviceHvSavedState_Open_InitializeDll(ctx)) { 
        vprintf(
            "DEVICE: FAILED: Hyper-V Saved State API DLL 'vmsavedstatedumpprovider.dll' was \n" \
            "        not found in the current process directory. Please copy a valid version\n" \
            "        of the required file to your process directory. The file may be located\n" \
            "        in 'C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.17763.0\\x64' ( or  \n" \
            "        any later version ) if Windows SDK / Visual Studio is installed.       \n");
        goto fail;
    }
    if(!DeviceHvSavedState_Open_OpenHvHandle(ctx)) {
        // function self-contains necessary printf functionality. 
        goto fail;
    }
    if(!DeviceHvSavedState_Open_MemMap(ctx)) {
        vprintf("DEVICE: FAILED: Hyper-V Saved State - unable to parse guest memory map.");
        goto fail;
    }

    if (!DeviceHvSavedState_Init(ctx)) {
        vprintf("DEVICE: FAILED: Hyper-V Saved State - unable to get guest virtual machine data.");
        goto fail;
    }

    // set callback functions and fix up config
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    ctxDeviceMain->cfg.tpDevice = LEECHCORE_DEVICE_HVSAVEDSTATE;
    ctxDeviceMain->cfg.fVolatile = FALSE;
    ctxDeviceMain->cfg.cbMaxSizeMemIo = ctxDeviceMain->cfg.cbMaxSizeMemIo ? min(ctxDeviceMain->cfg.cbMaxSizeMemIo, 0x01000000) : 0x01000000; // 16MB (or lower user-value)
    ctxDeviceMain->cfg.paMaxNative = ctx->paMax;
    ctxDeviceMain->pfnClose = DeviceHvSavedState_Close;
    ctxDeviceMain->pfnReadScatterMEM = DeviceHvSavedState_ReadScatterMEM;
    ctxDeviceMain->pfnGetOption = DeviceHvSavedState_GetOption;
    vprintfv("DEVICE: Successfully opened Hyper-V Saved State '%s'.\n", ctxDeviceMain->cfg.szDevice)
    return TRUE;
fail:
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    DeviceHvSavedState_Close();
    return FALSE;
}

#endif /* _WIN32 */
#ifdef LINUX
#include "device.h"

BOOL DeviceHvSavedState_Open()
{
    vprintf("DEVICE: FAILED: Hyper-V Saved State API is only available in Windows.\n");
    return FALSE;
}

#endif /* LINUX */
