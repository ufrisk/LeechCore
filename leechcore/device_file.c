// device_file.c : implementation related to file backed memory acquisition device.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "memmap.h"
#include "util.h"

//-----------------------------------------------------------------------------
// DEFINES: MICROSOFT CRASH DUMP DEFINES
//-----------------------------------------------------------------------------

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
    ULONG Signature;                    // 0x0000
    ULONG ValidDump;                    // 0x0004
    ULONG MajorVersion;                 // 0x0008
    ULONG MinorVersion;					// 0x000c
    ULONG DirectoryTableBase;			// 0x0010
    ULONG PfnDataBase;                  // 0x0014
    ULONG PsLoadedModuleList;           // 0x0018
    ULONG PsActiveProcessHead;          // 0x001c
    ULONG MachineImageType;             // 0x0020
    ULONG NumberProcessors;             // 0x0024
    ULONG BugCheckCode;                 // 0x0028
    ULONG BugCheckParameter1;           // 0x002c
    ULONG BugCheckParameter2;           // 0x0030
    ULONG BugCheckParameter3;           // 0x0034
    ULONG BugCheckParameter4;           // 0x0038
    CHAR VersionUser[32];               // 0x003c
    CHAR PaeEnabled;                    // 0x005c
    CHAR KdSecondaryVersion;            // 0x005d
    CHAR spare[2];                      // 0x005e
    ULONG KdDebuggerDataBlock;          // 0x0060
    union {                             // 0x0064
        _PHYSICAL_MEMORY_DESCRIPTOR32 PhysicalMemoryBlock;
        UCHAR PhysicalMemoryBlockBuffer[700];
    };
    UCHAR ContextRecord[1200];          // 0x0320
    EXCEPTION_RECORD32 ExceptionRecord; // 0x07d0
    CHAR Comment[128];                  // 0x0820
    UCHAR reserved0[1768];              // 0x08a0
    ULONG DumpType;                     // 0x0f88
    ULONG MiniDumpFields;               // 0x0f8c
    ULONG SecondaryDataState;           // 0x0f90
    ULONG ProductType;                  // 0x0f94
    ULONG SuiteMask;                    // 0x0f98
    UCHAR reserved1[4];                 // 0x0f9c
    ULONG64 RequiredDumpSpace;          // 0x0fa0
    UCHAR reserved2[16];                // 0x0fa8
    ULONG64 SystemUpTime;               // 0x0fb8
    ULONG64 SystemTime;                 // 0x0fc0
    UCHAR reserved3[56];                // 0x0fc8
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
    ULONG64 RequiredDumpSpace;	        // 0x0FA0
    ULONG64 SystemTime;				    // 0x0FA8 
    CHAR Comment[0x80];					// 0x0FB0 May not be present.
    ULONG64 SystemUpTime;				// 0x1030
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

//-----------------------------------------------------------------------------
// DEFINES: ELF HEADER DEFINES BELOW (USED FOR VIRTUALBOX .core DUMP FILES)
//-----------------------------------------------------------------------------

#define ELF_EI_MAGIC            0x464c457f
#define ELF_EI_CLASSDATA_32     0x0101
#define ELF_EI_CLASSDATA_64     0x0102
#define ELF_ET_CORE             0x04
#define ELF_ET_VERSION          0x01
#define ELF_PHDR_OFFSET_32      0x34
#define ELF_PHDR_OFFSET_64      0x40
#define ELF_PT_LOAD             0x00000001

typedef struct tdElf32_Phdr {
    DWORD p_type;
    DWORD p_offset;
    DWORD p_vaddr;
    DWORD p_paddr;
    DWORD p_filesz;
    DWORD p_memsz;
    DWORD p_flags;
    DWORD p_align;
} Elf32_Phdr, *PElf32_Phdr;

typedef struct tdElf64_Phdr {
    DWORD p_type;
    DWORD p_flags;
    QWORD p_offset;
    QWORD p_vaddr;
    QWORD p_paddr;
    QWORD p_filesz;
    QWORD p_memsz;
    QWORD p_align;
} Elf64_Phdr, *PElf64_Phdr;

typedef struct tdElf32_Ehdr {
    unsigned char e_ident[16];
    WORD e_type;
    WORD e_machine;
    DWORD e_version;
    DWORD e_entry;
    DWORD e_phoff;
    DWORD e_shoff;
    DWORD e_flags;
    WORD e_ehsize;
    WORD e_phentsize;
    WORD e_phnum;
    WORD e_shentsize;
    WORD e_shnum;
    WORD e_shstrndx;
    Elf32_Phdr Phdr[];
} Elf32_Ehdr, *PElf32_Ehdr;

typedef struct tdElf64_Ehdr {
    unsigned char e_ident[16];
    WORD e_type;
    WORD e_machine;
    DWORD e_version;
    QWORD e_entry;
    QWORD e_phoff;
    QWORD e_shoff;
    DWORD e_flags;
    WORD e_ehsize;
    WORD e_phentsize;
    WORD e_phnum;
    WORD e_shentsize;
    WORD e_shnum;
    WORD e_shstrndx;
    Elf64_Phdr Phdr[];
} Elf64_Ehdr, *PElf64_Ehdr;

//-----------------------------------------------------------------------------
// DEFINES: GENERAL
//-----------------------------------------------------------------------------

typedef struct tdDEVICE_CONTEXT_FILE {
    FILE *pFile;
    QWORD cbFile;
    CHAR szFileName[MAX_PATH];
    struct {
        BOOL fValidCoreDump;
        BOOL fValidCrashDump;
        BOOL f32;
        QWORD paMax;
        union {
            BYTE pbHdr[0x2000];
            DUMP_HEADER64 Hdr64;
            DUMP_HEADER32 Hdr32;
            Elf64_Ehdr Elf64;
            Elf32_Ehdr Elf32;
        };
    } CrashOrCoreDump;
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
    //BYTE pb[0x2000] = { 0 };
    BOOL f, fElfLoadSegment = FALSE;
    QWORD i, cbFileOffset;
    PDUMP_HEADER64 pDump64 = &ctx->CrashOrCoreDump.Hdr64;
    PDUMP_HEADER32 pDump32 = &ctx->CrashOrCoreDump.Hdr32;
    PElf64_Ehdr pElf64 = &ctx->CrashOrCoreDump.Elf64;
    PElf32_Ehdr pElf32 = &ctx->CrashOrCoreDump.Elf32;
    _fseeki64(ctx->pFile, 0, SEEK_SET);
    fread(ctx->CrashOrCoreDump.pbHdr, 1, 0x2000, ctx->pFile);
    if((pDump64->Signature == DUMP_SIGNATURE) && (pDump64->ValidDump == DUMP_VALID_DUMP64) && (pDump64->DumpType == DUMP_TYPE_FULL) && (pDump64->MachineImageType == IMAGE_FILE_MACHINE_AMD64)) {
        // PAGEDUMP (64-bit memory dump) and FULL DUMP
        vprintfvv_fn("64-bit Microsoft Crash Dump identified.\n");
        ctx->CrashOrCoreDump.fValidCrashDump = TRUE;
        ctx->CrashOrCoreDump.f32 = FALSE;
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
        MemMap_GetMaxAddress(&ctx->CrashOrCoreDump.paMax);
    }
    if((pDump32->Signature == DUMP_SIGNATURE) && (pDump32->ValidDump == DUMP_VALID_DUMP) && (pDump32->DumpType == DUMP_TYPE_FULL) && (pDump32->MachineImageType == IMAGE_FILE_MACHINE_I386)) {
        // PAGEDUMP (32-bit memory dump) and FULL DUMP
        vprintfvv_fn("32-bit Microsoft Crash Dump identified.\n");
        ctx->CrashOrCoreDump.fValidCrashDump = TRUE;
        ctx->CrashOrCoreDump.f32 = TRUE;
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
        MemMap_GetMaxAddress(&ctx->CrashOrCoreDump.paMax);
    }
    if((*(PDWORD)pElf64->e_ident == ELF_EI_MAGIC) && (*(PWORD)(pElf64->e_ident + 4) == ELF_EI_CLASSDATA_64)) {
        // ELF CORE DUMP - 64-bit full dump
        vprintfvv_fn("64-bit ELF Core Dump identified.\n");
        if((pElf64->e_type != ELF_ET_CORE) || (pElf64->e_version != ELF_ET_VERSION) || (pElf64->e_phoff != ELF_PHDR_OFFSET_64) || (pElf64->e_phentsize != sizeof(Elf64_Phdr)) || !pElf64->e_phnum || (pElf64->e_phnum > 0x200)) {
            vprintf("DEVICE: FAIL: unable to parse elf header\n");
            return FALSE;
        }
        MemMap_Initialize(0xffffffff);
        for(i = 0; i < pElf64->e_phnum; i++) {
            f = (pElf64->Phdr[i].p_type == ELF_PT_LOAD) &&
                pElf64->Phdr[i].p_offset && (pElf64->Phdr[i].p_offset < ctx->cbFile) &&
                pElf64->Phdr[i].p_filesz && (pElf64->Phdr[i].p_filesz < ctx->cbFile) &&
                (pElf64->Phdr[i].p_filesz == pElf64->Phdr[i].p_memsz) &&
                (pElf64->Phdr[i].p_offset + pElf64->Phdr[i].p_filesz <= ctx->cbFile) &&
                !(pElf64->Phdr[i].p_paddr & 0xfff) && !(pElf64->Phdr[i].p_filesz & 0xfff);
            if(f) {
                fElfLoadSegment = TRUE;
                if(!MemMap_AddRange(pElf64->Phdr[i].p_paddr, pElf64->Phdr[i].p_filesz, pElf64->Phdr[i].p_offset)) {
                    vprintf("DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", pElf64->Phdr[i].p_paddr, pElf64->Phdr[i].p_filesz, pElf64->Phdr[i].p_offset);
                    return FALSE;
                }
            }
        }
        if(!fElfLoadSegment) { return FALSE; }
        ctx->CrashOrCoreDump.fValidCoreDump = TRUE;
        MemMap_GetMaxAddress(&ctx->CrashOrCoreDump.paMax);
    }
    if((*(PDWORD)pElf32->e_ident == ELF_EI_MAGIC) && (*(PWORD)(pElf32->e_ident + 4) == ELF_EI_CLASSDATA_32)) {
        // ELF CORE DUMP - 32-bit full dump
        vprintfvv_fn("32-bit ELF Core Dump identified.\n");
        if((pElf32->e_type != ELF_ET_CORE) || (pElf32->e_version != ELF_ET_VERSION) || (pElf32->e_phoff != ELF_PHDR_OFFSET_64) || (pElf32->e_phentsize != sizeof(Elf32_Phdr)) || !pElf32->e_phnum || (pElf32->e_phnum > 0x200)) {
            vprintf("DEVICE: FAIL: unable to parse elf header\n");
            return FALSE;
        }
        MemMap_Initialize(0xffffffff);
        for(i = 0; i < pElf32->e_phnum; i++) {
            f = (pElf32->Phdr[i].p_type == ELF_PT_LOAD) &&
                pElf32->Phdr[i].p_offset && (pElf32->Phdr[i].p_offset < ctx->cbFile) &&
                pElf32->Phdr[i].p_filesz && (pElf32->Phdr[i].p_filesz < ctx->cbFile) &&
                (pElf32->Phdr[i].p_filesz == pElf32->Phdr[i].p_memsz) &&
                ((QWORD)pElf32->Phdr[i].p_offset + pElf32->Phdr[i].p_filesz <= ctx->cbFile) &&
                !(pElf32->Phdr[i].p_paddr & 0xfff) && !(pElf32->Phdr[i].p_filesz & 0xfff);
            if(f) {
                fElfLoadSegment = TRUE;
                if(!MemMap_AddRange(pElf32->Phdr[i].p_paddr, pElf32->Phdr[i].p_filesz, pElf32->Phdr[i].p_offset)) {
                    vprintf("DEVICE: FAIL: unable to add range to memory map. (%08x %08x %08x)\n", pElf32->Phdr[i].p_paddr, pElf32->Phdr[i].p_filesz, pElf32->Phdr[i].p_offset);
                    return FALSE;
                }
            }
        }
        if(!fElfLoadSegment) { return FALSE; }
        ctx->CrashOrCoreDump.fValidCoreDump = TRUE;
        MemMap_GetMaxAddress(&ctx->CrashOrCoreDump.paMax);
    }
    return TRUE;
}

_Success_(return)
BOOL DeviceFile_GetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxDeviceMain->hDevice;
    if(fOption == LEECHCORE_OPT_MEMORYINFO_VALID) {
        *pqwValue = ctx->CrashOrCoreDump.fValidCrashDump ? 1 : 0;
        return TRUE;
    }
    if(!ctx->CrashOrCoreDump.fValidCrashDump) {
        *pqwValue = 0;
        return FALSE;
    }
    switch(fOption) {
        case LEECHCORE_OPT_MEMORYINFO_ADDR_MAX:
            *pqwValue = ctx->CrashOrCoreDump.paMax;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_FLAG_32BIT:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? 1 : 0;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_FLAG_PAE:
            *pqwValue = (ctx->CrashOrCoreDump.f32 && ctx->CrashOrCoreDump.Hdr32.PaeEnabled) ? 1 : 0;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_VERSION_MINOR:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.MinorVersion : ctx->CrashOrCoreDump.Hdr64.MinorVersion;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_VERSION_MAJOR:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.MajorVersion : ctx->CrashOrCoreDump.Hdr64.MajorVersion;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_DTB:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.DirectoryTableBase : ctx->CrashOrCoreDump.Hdr64.DirectoryTableBase;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PFN:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.PfnDataBase : ctx->CrashOrCoreDump.Hdr64.PfnDataBase;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PsLoadedModuleList:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.PsLoadedModuleList : ctx->CrashOrCoreDump.Hdr64.PsLoadedModuleList;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_PsActiveProcessHead:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.PsActiveProcessHead : ctx->CrashOrCoreDump.Hdr64.PsActiveProcessHead;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.MachineImageType : ctx->CrashOrCoreDump.Hdr64.MachineImageType;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_NUM_PROCESSORS:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.NumberProcessors : ctx->CrashOrCoreDump.Hdr64.NumberProcessors;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_SYSTEMTIME:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? *(PQWORD)&ctx->CrashOrCoreDump.Hdr32.SystemTime : *(PQWORD)&ctx->CrashOrCoreDump.Hdr64.SystemTime;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_UPTIME:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? *(PQWORD)&ctx->CrashOrCoreDump.Hdr32.SystemUpTime : *(PQWORD)&ctx->CrashOrCoreDump.Hdr64.SystemUpTime;
            return TRUE;
        case LEECHCORE_OPT_MEMORYINFO_OS_KdDebuggerDataBlock:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.Hdr32.KdDebuggerDataBlock : ctx->CrashOrCoreDump.Hdr64.KdDebuggerDataBlock;
            return TRUE;
    }
    *pqwValue = 0;
    return FALSE;
}

_Success_(return)
BOOL DeviceFile_CommandData(_In_ ULONG64 fOption, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(cbDataOut) PBYTE pbDataOut, _In_ DWORD cbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxDeviceMain->hDevice;
    if(fOption == LEECHCORE_COMMANDDATA_FILE_DUMPHEADER_GET) {
        if(!ctx->CrashOrCoreDump.fValidCrashDump || !pbDataOut || (cbDataOut < (ctx->CrashOrCoreDump.f32 ? 0x1000UL : 0x2000UL))) { return FALSE; }
        if(pcbDataOut) {
            *pcbDataOut = ctx->CrashOrCoreDump.f32 ? 0x1000 : 0x2000;
        }
        memcpy(pbDataOut, ctx->CrashOrCoreDump.pbHdr, (ctx->CrashOrCoreDump.f32 ? 0x1000 : 0x2000));
        return TRUE;
    }
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

_Success_(return)
BOOL DeviceFile_Open()
{
    PDEVICE_CONTEXT_FILE ctx;
    if(!ctxDeviceMain) { return FALSE; }
    if(!(ctx = (PDEVICE_CONTEXT_FILE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FILE)))) { return FALSE; }
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
    ctxDeviceMain->pfnClose = DeviceFile_Close;
    ctxDeviceMain->pfnReadScatterMEM = DeviceFile_ReadScatterMEM;
    ctxDeviceMain->pfnGetOption = DeviceFile_GetOption;
    ctxDeviceMain->pfnCommandData = DeviceFile_CommandData;
    if(!DeviceFile_MsCrashDumpInitialize()) { goto fail; }
    if(ctx->CrashOrCoreDump.fValidCrashDump) {
        ctxDeviceMain->cfg.paMaxNative = ctx->CrashOrCoreDump.paMax;
        vprintfv("DEVICE: Successfully opened file: '%s' as Microsoft Crash Dump.\n", ctxDeviceMain->cfg.szDevice);
    } else if(ctx->CrashOrCoreDump.fValidCoreDump) {
        ctxDeviceMain->cfg.paMaxNative = ctx->CrashOrCoreDump.paMax;
        vprintfv("DEVICE: Successfully opened file: '%s' as ELF Core Dump.\n", ctxDeviceMain->cfg.szDevice);
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
