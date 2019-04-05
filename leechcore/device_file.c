// device_file.c : implementation related to file backed memory acquisition device.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "memmap.h"
#include "util.h"

#define DUMP_SIGNATURE              0x45474150
#define DUMP_VALID_DUMP             0x504d5544
#define DUMP_VALID_DUMP64           0x34365544
#define DUMP_TYPE_FULL              1
#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_AMD64    0x8664
#define _PHYSICAL_MEMORY_MAX_RUNS   0x20

typedef struct {
    QWORD BasePage;
    QWORD PageCount;
} _PHYSICAL_MEMORY_RUN64;

typedef struct {
    DWORD NumberOfRuns;
    DWORD Reserved1;
    DWORD NumberOfPages;
    DWORD Reserved2;
    _PHYSICAL_MEMORY_RUN64 Run[_PHYSICAL_MEMORY_MAX_RUNS];
} _PHYSICAL_MEMORY_DESCRIPTOR64;

typedef struct {
    DWORD BasePage;
    DWORD PageCount;
} _PHYSICAL_MEMORY_RUN32;

typedef struct {
    DWORD NumberOfRuns;
    DWORD NumberOfPages;
    _PHYSICAL_MEMORY_RUN32 Run[_PHYSICAL_MEMORY_MAX_RUNS];
} _PHYSICAL_MEMORY_DESCRIPTOR32;

typedef struct tdDUMP_HEADER32 {
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG DirectoryTableBase;
    ULONG PfnDataBase;
    ULONG PsLoadedModuleList;
    ULONG PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG BugCheckParameter1;
    ULONG BugCheckParameter2;
    ULONG BugCheckParameter3;
    ULONG BugCheckParameter4;
    CHAR VersionUser[32];
    CHAR PaeEnabled;
    CHAR KdSecondaryVersion;
    CHAR spare[2];
    ULONG KdDebuggerDataBlock;
    union {
        _PHYSICAL_MEMORY_DESCRIPTOR32 PhysicalMemoryBlock;
        UCHAR PhysicalMemoryBlockBuffer[700];
    };
    union {
        //CONTEXT Context; // 32-bit CONTEXT REQUIRED - not too large 32-bit
        UCHAR ContextRecord[1200];
    };
    EXCEPTION_RECORD32 ExceptionRecord;
    CHAR Comment[128];
    UCHAR reserved0[1768];
    ULONG DumpType;
    ULONG MiniDumpFields;
    ULONG SecondaryDataState;
    ULONG ProductType;
    ULONG SuiteMask;
    UCHAR reserved1[4];
    LARGE_INTEGER RequiredDumpSpace;
    UCHAR reserved2[16];
    FILETIME SystemUpTime;
    FILETIME SystemTime;
    UCHAR reserved3[56];
} DUMP_HEADER32, *PDUMP_HEADER32;

typedef struct tdDUMP_HEADER64 {
	ULONG Signature;					// 0x0000
	ULONG ValidDump;					// 0x0004
	ULONG MajorVersion;					// 0x0008
	ULONG MinorVersion;					// 0x000c
	ULONG64 DirectoryTableBase;			// 0x0010
	ULONG64 PfnDataBase;				// 0x0018
	ULONG64 PsLoadedModuleList;			// 0x0020
	ULONG64 PsActiveProcessHead;		// 0x0028
	ULONG MachineImageType;				// 0x0030
	ULONG NumberProcessors;				// 0x0034
	ULONG BugCheckCode;					// 0x0038
	ULONG64 BugCheckParameter1;			// 0x0040
	ULONG64 BugCheckParameter2;			// 0x0048
	ULONG64 BugCheckParameter3;			// 0x0050
	ULONG64 BugCheckParameter4;			// 0x0058
	CHAR VersionUser[32];				// 0x0060
	ULONG64 KdDebuggerDataBlock;		// 0x0080
	union {								// 0x0088
		_PHYSICAL_MEMORY_DESCRIPTOR64 PhysicalMemoryBlock;
		UCHAR PhysicalMemoryBlockBuffer[700];
	};
	UCHAR ContextRecord[3000];			// 0x0348
	EXCEPTION_RECORD64 ExceptionRecord;	// 0x0F00
	ULONG DumpType;						// 0x0F98
	LARGE_INTEGER RequiredDumpSpace;	// 0x0FA0
	FILETIME SystemTime;				// 0x0FA8 
	CHAR Comment[0x80];					// 0x0FB0 May not be present.
	FILETIME SystemUpTime;				// 0x1030
	ULONG MiniDumpFields;				// 0x1038
	ULONG SecondaryDataState;			// 0x103c
	ULONG ProductType;					// 0x1040
	ULONG SuiteMask;					// 0x1044
	ULONG WriterStatus;					// 0x1048
	UCHAR Unused1;						// 0x104c
	UCHAR KdSecondaryVersion;			// 0x104d Present only for W2K3 SP1 and better
	UCHAR Unused[2];					// 0x104e
	UCHAR _reserved0[4016];				// 0x1050
} DUMP_HEADER64, *PDUMP_HEADER64;

typedef struct tdDEVICE_CONTEXT_FILE {
    FILE *pFile;
    QWORD cbFile;
    CHAR szFileName[MAX_PATH];
    struct {
        BOOL fValid;
        BOOL f32;
        QWORD paMax;
        union {
            BYTE pbHdr[0x2000];
            DUMP_HEADER64 Hdr64;
            DUMP_HEADER32 Hdr32;
        };
    } CrashDump;
} DEVICE_CONTEXT_FILE, *PDEVICE_CONTEXT_FILE;

//-----------------------------------------------------------------------------
// GENERAL 'DEVICE' FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DeviceFile_ReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxDeviceMain->hDevice;
    DWORD i;
    QWORD qwA_File;
    PMEM_IO_SCATTER_HEADER pMEM;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(!MemMap_VerifyTranslateMEM(pMEM, &qwA_File)) {
            if(pMEM->cbMax && (pMEM->cb < pMEM->cbMax)) {
                vprintfvvv_fn("FAILED: no memory at address %016llx\n", pMEM->qwA);
            }
            continue;
        }
        if(qwA_File >= ctx->cbFile) { continue; }
        if(pMEM->cbMax > ctx->cbFile - qwA_File) { continue; }
        if(qwA_File != _ftelli64(ctx->pFile)) {
            if(_fseeki64(ctx->pFile, qwA_File, SEEK_SET)) { continue; }
        }
        pMEM->cb = (DWORD)fread(pMEM->pb, 1, pMEM->cbMax, ctx->pFile);
        if(ctxDeviceMain->fVerboseExtraTlp) {
            vprintf_fn(
                "READ:\n        file='%s'\n        offset=%016llx req_len=%08x rsp_len=%08x\n",
                ctx->szFileName,
                pMEM->qwA,
                pMEM->cbMax,
                pMEM->cb
            );
            Util_PrintHexAscii(pMEM->pb, pMEM->cb, 0);
        }
    }
}

//-----------------------------------------------------------------------------
// MICROSOFT CRASH DUMP PARSING BELOW:
//-----------------------------------------------------------------------------

/*
* Try to initialize a Microsoft Crash Dump file (full dump only). This is done
* by reading the dump header. If this is not a dump file the function will
* still return TRUE - but not initialize the ctxFile->MsCrashDump struct.
* On fatal non-recoverable errors FALSE will be returned.
* -- return
*/
BOOL DeviceFile_MsCrashDumpInitialize()
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxDeviceMain->hDevice;
    BYTE pb[0x2000] = { 0 };
    QWORD i, cbFileOffset;
    PDUMP_HEADER64 pDump64 = (PDUMP_HEADER64)pb;
    PDUMP_HEADER32 pDump32 = (PDUMP_HEADER32)pb;
    _fseeki64(ctx->pFile, 0, SEEK_SET);
    fread(pb, 1, 0x2000, ctx->pFile);
    if((pDump64->Signature == DUMP_SIGNATURE) && (pDump64->ValidDump == DUMP_VALID_DUMP64) && (pDump64->DumpType == DUMP_TYPE_FULL) && (pDump64->MachineImageType == IMAGE_FILE_MACHINE_AMD64)) {
        vprintfvv_fn("64-bit dump identified.\n");
        memcpy(ctx->CrashDump.pbHdr, pb, sizeof(DUMP_HEADER64));
        ctx->CrashDump.fValid = TRUE;
        ctx->CrashDump.f32 = FALSE;
        // process runs
        if(pDump64->PhysicalMemoryBlock.NumberOfRuns > _PHYSICAL_MEMORY_MAX_RUNS) {
            vprintf("DEVICE: FAIL: too many memory segments in crash dump file. (%i)\n", pDump64->PhysicalMemoryBlock.NumberOfRuns);
            return FALSE;
        }
        cbFileOffset = 0x2000;  // initial offset of 0x2000 bytes in 64-bit dump file
        MemMap_Initialize(0x0000ffffffffffff);
        for(i = 0; i < pDump64->PhysicalMemoryBlock.NumberOfRuns; i++) {
            if(!MemMap_AddRange(pDump64->PhysicalMemoryBlock.Run[i].BasePage << 12, pDump64->PhysicalMemoryBlock.Run[i].PageCount << 12, cbFileOffset)) {
                vprintf("DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", pDump64->PhysicalMemoryBlock.Run[i].BasePage << 12, pDump64->PhysicalMemoryBlock.Run[i].PageCount << 12, cbFileOffset);
                return FALSE;
            }
            cbFileOffset += pDump64->PhysicalMemoryBlock.Run[i].PageCount << 12;
        }
        MemMap_GetMaxAddress(&ctx->CrashDump.paMax);
    }
    if((pDump32->Signature == DUMP_SIGNATURE) && (pDump32->ValidDump == DUMP_VALID_DUMP) && (pDump32->DumpType == DUMP_TYPE_FULL) && (pDump32->MachineImageType == IMAGE_FILE_MACHINE_I386)) {
        // PAGEDUMP (32-bit memory dump) and FULL DUMP
        vprintfvv_fn("32-bit dump identified.\n");
        memcpy(ctx->CrashDump.pbHdr, pb, sizeof(DUMP_HEADER32));
        ctx->CrashDump.fValid = TRUE;
        ctx->CrashDump.f32 = TRUE;
        if(pDump32->PhysicalMemoryBlock.NumberOfRuns > _PHYSICAL_MEMORY_MAX_RUNS) {
            vprintf("DEVICE: FAIL: too many memory segments in crash dump file. (%i)\n", pDump32->PhysicalMemoryBlock.NumberOfRuns);
            return FALSE;
        }
        cbFileOffset = 0x1000;  // initial offset of 0x1000 bytes in 64-bit dump file
        MemMap_Initialize(0xffffffff);
        for(i = 0; i < pDump32->PhysicalMemoryBlock.NumberOfRuns; i++) {
            if(!MemMap_AddRange((QWORD)pDump32->PhysicalMemoryBlock.Run[i].BasePage << 12, (QWORD)pDump32->PhysicalMemoryBlock.Run[i].PageCount << 12, cbFileOffset)) {
                vprintf("DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", (QWORD)pDump32->PhysicalMemoryBlock.Run[i].BasePage << 12, (QWORD)pDump32->PhysicalMemoryBlock.Run[i].PageCount << 12, cbFileOffset);
                return FALSE;
            }
            cbFileOffset += (QWORD)pDump32->PhysicalMemoryBlock.Run[i].PageCount << 12;
        }
        MemMap_GetMaxAddress(&ctx->CrashDump.paMax);
    }
    return TRUE;
}

BOOL DeviceFile_GetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxDeviceMain->hDevice;
    if(fOption == LEECHCORE_OPT_MEMORYINFO_VALID) {
        *pqwValue = ctx->CrashDump.fValid ? 1 : 0;
        return TRUE;
    }
    if(!ctx->CrashDump.fValid) {
        *pqwValue = 0;
        return FALSE;
    }
    switch(fOption) {
        case LEECHCORE_OPT_MEMORYINFO_ADDR_MAX:
            *pqwValue = ctx->CrashDump.paMax;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_FLAG_32BIT:
            *pqwValue = ctx->CrashDump.f32 ? 1 : 0;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_FLAG_PAE:
            *pqwValue = (ctx->CrashDump.f32 && ctx->CrashDump.Hdr32.PaeEnabled) ? 1 : 0;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_VERSION_MINOR:
            *pqwValue = ctx->CrashDump.f32 ? ctx->CrashDump.Hdr32.MinorVersion : ctx->CrashDump.Hdr64.MinorVersion;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_VERSION_MAJOR:
            *pqwValue = ctx->CrashDump.f32 ? ctx->CrashDump.Hdr32.MajorVersion : ctx->CrashDump.Hdr64.MajorVersion;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_DTB:
            *pqwValue = ctx->CrashDump.f32 ? ctx->CrashDump.Hdr32.DirectoryTableBase : ctx->CrashDump.Hdr64.DirectoryTableBase;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PFN:
            *pqwValue = ctx->CrashDump.f32 ? ctx->CrashDump.Hdr32.PfnDataBase : ctx->CrashDump.Hdr64.PfnDataBase;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PsLoadedModuleList:
            *pqwValue = ctx->CrashDump.f32 ? ctx->CrashDump.Hdr32.PsLoadedModuleList : ctx->CrashDump.Hdr64.PsLoadedModuleList;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PsActiveProcessHead:
            *pqwValue = ctx->CrashDump.f32 ? ctx->CrashDump.Hdr32.PsActiveProcessHead : ctx->CrashDump.Hdr64.PsActiveProcessHead;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP:
            *pqwValue = ctx->CrashDump.f32 ? ctx->CrashDump.Hdr32.MachineImageType : ctx->CrashDump.Hdr64.MachineImageType;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_NUM_PROCESSORS:
            *pqwValue = ctx->CrashDump.f32 ? ctx->CrashDump.Hdr32.NumberProcessors : ctx->CrashDump.Hdr64.NumberProcessors;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_SYSTEMTIME:
            *pqwValue = ctx->CrashDump.f32 ? *(PQWORD)&ctx->CrashDump.Hdr32.SystemTime : *(PQWORD)&ctx->CrashDump.Hdr64.SystemTime;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_UPTIME:
            *pqwValue = ctx->CrashDump.f32 ? *(PQWORD)&ctx->CrashDump.Hdr32.SystemUpTime : *(PQWORD)&ctx->CrashDump.Hdr64.SystemUpTime;
            return TRUE;
    }
    *pqwValue = 0;
    return FALSE;
}

//-----------------------------------------------------------------------------
// OPEN/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DeviceFile_Close()
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxDeviceMain->hDevice;
    if(!ctx) { return; }
    if(ctx->pFile) { fclose(ctx->pFile); }
    LocalFree(ctx);
    ctxDeviceMain->hDevice = 0;
}

BOOL DeviceFile_Open()
{
    PDEVICE_CONTEXT_FILE ctx;
    ctx = (PDEVICE_CONTEXT_FILE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FILE));
    if(!ctx) { return FALSE; }
    if(0 == _strnicmp("file://", ctxDeviceMain->cfg.szDevice, 7)) {
        strncpy_s(ctx->szFileName, _countof(ctx->szFileName), ctxDeviceMain->cfg.szDevice + 7, _countof(ctxDeviceMain->cfg.szDevice) - 7);
    } else if(0 == _stricmp(ctxDeviceMain->cfg.szDevice, "dumpit")) {
        strcpy_s(ctx->szFileName, _countof(ctx->szFileName), "C:\\WINDOWS\\DumpIt.dmp");
    } else {
        strncpy_s(ctx->szFileName, _countof(ctx->szFileName), ctxDeviceMain->cfg.szDevice, _countof(ctxDeviceMain->cfg.szDevice));
    }
    // open backing file
    if(fopen_s(&ctx->pFile, ctx->szFileName, "rb") || !ctx->pFile) { goto fail; }
    if(_fseeki64(ctx->pFile, 0, SEEK_END)) { goto fail; }   // seek to end of file
    ctx->cbFile = _ftelli64(ctx->pFile);                    // get current file pointer
    if(ctx->cbFile < 0x01000000) { goto fail; }             // minimum allowed dump file size = 16MB
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    // set callback functions and fix up config
    ctxDeviceMain->cfg.tpDevice = LEECHCORE_DEVICE_FILE;
    ctxDeviceMain->cfg.fVolatile = FALSE;   // Files are assumed to be static non-volatile.
    if(strstr(ctx->szFileName, "DumpIt.dmp")) {
        ctxDeviceMain->cfg.fVolatile = TRUE; // DumpIt LIVEKD files are volatile.
    }
    ctxDeviceMain->cfg.cbMaxSizeMemIo = ctxDeviceMain->cfg.cbMaxSizeMemIo ? min(ctxDeviceMain->cfg.cbMaxSizeMemIo, 0x01000000) : 0x01000000; // 16MB (or lower user-value)
    ctxDeviceMain->pfnClose = DeviceFile_Close;
    ctxDeviceMain->pfnReadScatterMEM = DeviceFile_ReadScatterMEM;
    ctxDeviceMain->pfnGetOption = DeviceFile_GetOption;
    if(!DeviceFile_MsCrashDumpInitialize()) { goto fail; }
    if(ctx->CrashDump.fValid) {
        ctxDeviceMain->cfg.paMaxNative = ctx->CrashDump.paMax;
        vprintfv("DEVICE: Successfully opened file: '%s' as Microsoft Crash Dump.\n", ctxDeviceMain->cfg.szDevice);
    } else {
        ctxDeviceMain->cfg.paMaxNative = ctx->cbFile;
        if(!MemMap_Initialize(ctxDeviceMain->cfg.paMaxNative)) { goto fail; }
        vprintfv("DEVICE: Successfully opened file: '%s' as RAW Memory Dump.\n", ctxDeviceMain->cfg.szDevice);
    }
    return TRUE;
fail:
    if(ctx->pFile) { fclose(ctx->pFile); }
    LocalFree(ctx);
    ctxDeviceMain->hDevice = 0;
    printf("DEVICE: ERROR: Failed opening file: '%s'.\n", ctxDeviceMain->cfg.szDevice);
    return FALSE;
}
