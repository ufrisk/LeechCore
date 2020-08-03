// device_file.c : implementation related to file backed memory acquisition device.
//
// (c) Ulf Frisk, 2018-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
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
} _PHYSICAL_MEMORY_DESCRIPTOR64, *_PPHYSICAL_MEMORY_DESCRIPTOR64;

typedef struct {
    DWORD BasePage;
    DWORD PageCount;
} _PHYSICAL_MEMORY_RUN32;

typedef struct {
    DWORD NumberOfRuns;
    DWORD NumberOfPages;
    _PHYSICAL_MEMORY_RUN32 Run[_PHYSICAL_MEMORY_MAX_RUNS];
} _PHYSICAL_MEMORY_DESCRIPTOR32, *_PPHYSICAL_MEMORY_DESCRIPTOR32;

#define CDMP_DWORD(o)                               (*(PDWORD)(ctx->CrashOrCoreDump.pbHdr + o))
#define CDMP_QWORD(o)                               (*(PQWORD)(ctx->CrashOrCoreDump.pbHdr + o))
#define VMM_PTR_OFFSET_DUAL(f32, pb, o32, o64)      ((f32) ? *(PDWORD)((o32) + (PBYTE)(pb)) : *(PQWORD)((o64) + (PBYTE)(pb)))

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
        BOOL fValidVMwareDump;
        BOOL f32;
        union {
            BYTE pbHdr[0x2000];
            Elf64_Ehdr Elf64;
            Elf32_Ehdr Elf32;
        };
    } CrashOrCoreDump;
} DEVICE_CONTEXT_FILE, *PDEVICE_CONTEXT_FILE;

//-----------------------------------------------------------------------------
// GENERAL 'DEVICE' FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DeviceFile_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    DWORD i;
    PMEM_SCATTER pMEM;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f || (pMEM->qwA == (QWORD)-1)) { continue; }
        if(pMEM->qwA != _ftelli64(ctx->pFile)) {
            if(_fseeki64(ctx->pFile, pMEM->qwA, SEEK_SET)) { continue; }
        }
        pMEM->f = pMEM->cb == (DWORD)fread(pMEM->pb, 1, pMEM->cb, ctx->pFile);
        if(pMEM->f) {
            if(ctxLC->fPrintf[LC_PRINTF_VVV]) {
                lcprintf_fn(
                    ctxLC,
                    "READ:\n        offset=%016llx req_len=%08x\n",
                    pMEM->qwA,
                    pMEM->cb
                );
                Util_PrintHexAscii(ctxLC, pMEM->pb, pMEM->cb, 0);
            }
        } else {
            lcprintfvvv_fn(ctxLC, "READ FAILED:\n        offset=%016llx req_len=%08x\n", pMEM->qwA, pMEM->cb);
        }
    }
}

VOID DeviceFile_ReadContigious(_Inout_ PLC_READ_CONTIGIOUS_CONTEXT ctxRC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxRC->ctxLC->hDevice;
    if(_fseeki64(ctx->pFile, ctxRC->paBase, SEEK_SET)) { return; }
    ctxRC->cbRead = (DWORD)fread(ctxRC->pb, 1, ctxRC->cb, ctx->pFile);
}

//-----------------------------------------------------------------------------
// PARSING OF DUMP FILE FORMATS BELOW:
// - VMware .vmem + vmss/vmsn Dump Files.
// - Full Microsoft Crash Dumps (DumpIt).
// - VirtualBox ELF CORE Dumps.
//-----------------------------------------------------------------------------

typedef struct tdFILE_VMWARE_HEADER {
    DWORD magic;
    DWORD _Filler;
    DWORD cGroups;
} FILE_VMWARE_HEADER;

typedef struct tdFILE_VMWARE_GROUP {
    CHAR szName[64];
    QWORD cbOffset;
    QWORD cbSize;
} FILE_VMWARE_GROUP;

#define FILE_VMWARE_MEMORY_REGIONS_MAX      0x40

typedef struct tdFILE_VMWARE_MEMORY_REGION {
    BOOL fOffsetFile;
    BOOL fOffsetMemory;
    BOOL fSize;
    QWORD cbOffsetFile;
    QWORD cbOffsetMemory;
    QWORD cbSize;
} FILE_VMWARE_MEMORY_REGION;

/*
* Try to initialize a VMware Dump/Save File (.vmem + vmss/vmsn).
*/
VOID DeviceFile_VMwareDumpInitialize(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    FILE_VMWARE_HEADER hdr = { 0 };
    FILE_VMWARE_GROUP grp = { 0 };
    FILE_VMWARE_MEMORY_REGION regions[FILE_VMWARE_MEMORY_REGIONS_MAX] = { 0 };
    CHAR szFileName[MAX_PATH];
    FILE *pFile = NULL;
    PBYTE pb;
    QWORD oTag;
    DWORD iGroup, iMemoryRegion, cbTag, cchTag;
    strcpy_s(szFileName, _countof(szFileName), ctx->szFileName);
    // 1: open and verify metadata file
    memcpy(szFileName + strlen(szFileName) - 5, ".vmss", 5);
    fopen_s(&pFile, szFileName, "rb");
    if(!pFile) {
        memcpy(szFileName + strlen(szFileName) - 5, ".vmsn", 5);
        fopen_s(&pFile, szFileName, "rb");
    }
    if(!pFile) {
        lcprintf(ctxLC, "DEVICE: WARN: Unable to open VMWare .vmss or .vmsn file - assuming 1:1 memory space.\n");
        goto fail;
    }
    _fseeki64(pFile, 0, SEEK_SET);
    fread(&hdr, 1, sizeof(FILE_VMWARE_HEADER), pFile);
    if((hdr.magic != 0xbed3bed3) && (hdr.magic != 0xbed2bed2) && (hdr.magic != 0xbad1bad1) /* && (hdr.magic != 0xbed2bed0) */) {
        lcprintf(ctxLC, "DEVICE: WARN: Unable to verify file '%s'.\n", szFileName);
        goto fail;
    }
    // 2: locate memory group(s) and parse memory regions from group tags.
    for(iGroup = 0; iGroup < hdr.cGroups; iGroup++) {
        _fseeki64(pFile, 12 + iGroup * sizeof(FILE_VMWARE_GROUP), SEEK_SET);
        fread(&grp, 1, sizeof(FILE_VMWARE_GROUP), pFile);
        if(0 == strcmp("memory", grp.szName)) {
            if(grp.cbSize > 0x01000000) { continue; }
            if(_fseeki64(pFile, grp.cbOffset, SEEK_SET)) { continue; }
            if(!(pb = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)grp.cbSize))) { continue; }
            if(grp.cbSize != fread(pb, 1, (SIZE_T)grp.cbSize, pFile)) {
                LocalFree(pb);
                continue;
            }
            oTag = 0;
            while((oTag + 6 <= grp.cbSize) && *(PBYTE)(pb + oTag)) {
                cchTag = *(PBYTE)(pb + oTag + 1);
                cbTag = 2 + cchTag + 4 + 4 * ((*(PBYTE)(pb + oTag) >> 6) & 3ULL);
                if(!cchTag || (oTag + cbTag >= grp.cbSize)) { break; }
                if((cchTag == 0x0a) && !memcmp(pb + oTag + 2, "regionSize", 0x0a) && ((iMemoryRegion = *(PDWORD)(pb + oTag + 2 + 0x0a)) < FILE_VMWARE_MEMORY_REGIONS_MAX)) {
                    regions[iMemoryRegion].fSize = TRUE;
                    regions[iMemoryRegion].cbSize = *(PDWORD)(pb + oTag + 2 + 0x0a + 4) * 0x1000ULL;
                }
                if((cchTag == 0x09) && !memcmp(pb + oTag + 2, "regionPPN", 0x09) && ((iMemoryRegion = *(PDWORD)(pb + oTag + 2 + 0x09)) < FILE_VMWARE_MEMORY_REGIONS_MAX)) {
                    regions[iMemoryRegion].fOffsetMemory = TRUE;
                    regions[iMemoryRegion].cbOffsetMemory = *(PDWORD)(pb + oTag + 2 + 0x09 + 4) * 0x1000ULL;
                }
                if((cchTag == 0x0d) && !memcmp(pb + oTag + 2, "regionPageNum", 0x0d) && ((iMemoryRegion = *(PDWORD)(pb + oTag + 2 + 0x0d)) < FILE_VMWARE_MEMORY_REGIONS_MAX)) {
                    regions[iMemoryRegion].fOffsetFile = TRUE;
                    regions[iMemoryRegion].cbOffsetFile = *(PDWORD)(pb + oTag + 2 + 0x0d + 4) * 0x1000ULL;
                }
                oTag += cbTag;
            }
            LocalFree(pb);
            for(iMemoryRegion = 0; iMemoryRegion < FILE_VMWARE_MEMORY_REGIONS_MAX; iMemoryRegion++) {
                if(regions[iMemoryRegion].fSize && regions[iMemoryRegion].fOffsetMemory && regions[iMemoryRegion].fOffsetFile) {
                    LcMemMap_AddRange(ctxLC, regions[iMemoryRegion].cbOffsetMemory, regions[iMemoryRegion].cbSize, regions[iMemoryRegion].cbOffsetFile);
                    ctx->CrashOrCoreDump.fValidVMwareDump = TRUE;
                }
            }

        }
    }
    if(!LcMemMap_IsInitialized(ctxLC)) {
        lcprintf(ctxLC, "DEVICE: WARN: No VMware memory regions located - file will be treated as single-region.\n");
    }
fail:
    if(pFile) { fclose(pFile); }
}

/*
* Try to initialize a Microsoft Crash Dump file (full dump only) _or_ a VirtualBox
* core dump file. This is done by reading the dump header. If this is not a
* dump file the function will still return TRUE - but not initialize the
* ctxFile->MsCrashDump struct.On fatal non-recoverable errors FALSE is returned.
* -- return
*/
_Success_(return)
BOOL DeviceFile_MsCrashCoreDumpInitialize(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    BOOL f, fElfLoadSegment = FALSE;
    QWORD i, cbFileOffset;
    PElf64_Ehdr pElf64 = &ctx->CrashOrCoreDump.Elf64;
    PElf32_Ehdr pElf32 = &ctx->CrashOrCoreDump.Elf32;
    _PPHYSICAL_MEMORY_DESCRIPTOR64 pM32 = (_PPHYSICAL_MEMORY_DESCRIPTOR64)(ctx->CrashOrCoreDump.pbHdr + 0x064);
    _PPHYSICAL_MEMORY_DESCRIPTOR64 pM64 = (_PPHYSICAL_MEMORY_DESCRIPTOR64)(ctx->CrashOrCoreDump.pbHdr + 0x088);
    _fseeki64(ctx->pFile, 0, SEEK_SET);
    fread(ctx->CrashOrCoreDump.pbHdr, 1, 0x2000, ctx->pFile);
    if((CDMP_DWORD(0x000) == DUMP_SIGNATURE) && (CDMP_DWORD(0x004) == DUMP_VALID_DUMP64) && (CDMP_DWORD(0xf98) == DUMP_TYPE_FULL) && (CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_AMD64)) {
        // PAGEDUMP (64-bit memory dump) and FULL DUMP
        lcprintfvv_fn(ctxLC, "64-bit Microsoft Crash Dump identified.\n");
        ctx->CrashOrCoreDump.fValidCrashDump = TRUE;
        ctx->CrashOrCoreDump.f32 = FALSE;
        // process runs
        if(pM64->NumberOfRuns > _PHYSICAL_MEMORY_MAX_RUNS) {
            lcprintf(ctxLC, "DEVICE: FAIL: too many memory segments in crash dump file. (%i)\n", pM64->NumberOfRuns);
            return FALSE;
        }
        cbFileOffset = 0x2000;  // initial offset of 0x2000 bytes in 64-bit dump file
        for(i = 0; i < pM64->NumberOfRuns; i++) {
            if(!LcMemMap_AddRange(ctxLC, pM64->Run[i].BasePage << 12, pM64->Run[i].PageCount << 12, cbFileOffset)) {
                lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", pM64->Run[i].BasePage << 12, pM64->Run[i].PageCount << 12, cbFileOffset);
                return FALSE;
            }
            cbFileOffset += pM64->Run[i].PageCount << 12;
        }
    }
    if((CDMP_DWORD(0x000) == DUMP_SIGNATURE) && (CDMP_DWORD(0x004) == DUMP_VALID_DUMP) && (CDMP_DWORD(0xf88) == DUMP_TYPE_FULL) && (CDMP_DWORD(0x020) == IMAGE_FILE_MACHINE_I386)) {
        // PAGEDUMP (32-bit memory dump) and FULL DUMP
        lcprintfvv_fn(ctxLC, "32-bit Microsoft Crash Dump identified.\n");
        ctx->CrashOrCoreDump.fValidCrashDump = TRUE;
        ctx->CrashOrCoreDump.f32 = TRUE;
        if(pM32->NumberOfRuns > _PHYSICAL_MEMORY_MAX_RUNS) {
            lcprintf(ctxLC, "DEVICE: FAIL: too many memory segments in crash dump file. (%i)\n", pM32->NumberOfRuns);
            return FALSE;
        }
        cbFileOffset = 0x1000;  // initial offset of 0x1000 bytes in 64-bit dump file
        for(i = 0; i < pM32->NumberOfRuns; i++) {
            if(!LcMemMap_AddRange(ctxLC, (QWORD)pM32->Run[i].BasePage << 12, (QWORD)pM32->Run[i].PageCount << 12, cbFileOffset)) {
                lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", (QWORD)pM32->Run[i].BasePage << 12, (QWORD)pM32->Run[i].PageCount << 12, cbFileOffset);
                return FALSE;
            }
            cbFileOffset += (QWORD)pM32->Run[i].PageCount << 12;
        }
    }
    if((*(PDWORD)pElf64->e_ident == ELF_EI_MAGIC) && (*(PWORD)(pElf64->e_ident + 4) == ELF_EI_CLASSDATA_64)) {
        // ELF CORE DUMP - 64-bit full dump
        lcprintfvv_fn(ctxLC, "64-bit ELF Core Dump identified.\n");
        if((pElf64->e_type != ELF_ET_CORE) || (pElf64->e_version != ELF_ET_VERSION) || (pElf64->e_phoff != ELF_PHDR_OFFSET_64) || (pElf64->e_phentsize != sizeof(Elf64_Phdr)) || !pElf64->e_phnum || (pElf64->e_phnum > 0x200)) {
            lcprintf(ctxLC, "DEVICE: FAIL: unable to parse elf header\n");
            return FALSE;
        }
        for(i = 0; i < pElf64->e_phnum; i++) {
            f = (pElf64->Phdr[i].p_type == ELF_PT_LOAD) &&
                pElf64->Phdr[i].p_offset && (pElf64->Phdr[i].p_offset < ctx->cbFile) &&
                pElf64->Phdr[i].p_filesz && (pElf64->Phdr[i].p_filesz < ctx->cbFile) &&
                (pElf64->Phdr[i].p_filesz == pElf64->Phdr[i].p_memsz) &&
                (pElf64->Phdr[i].p_offset + pElf64->Phdr[i].p_filesz <= ctx->cbFile) &&
                !(pElf64->Phdr[i].p_paddr & 0xfff) && !(pElf64->Phdr[i].p_filesz & 0xfff);
            if(f) {
                fElfLoadSegment = TRUE;
                if(!LcMemMap_AddRange(ctxLC, pElf64->Phdr[i].p_paddr, pElf64->Phdr[i].p_filesz, pElf64->Phdr[i].p_offset)) {
                    lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", pElf64->Phdr[i].p_paddr, pElf64->Phdr[i].p_filesz, pElf64->Phdr[i].p_offset);
                    return FALSE;
                }
            }
        }
        if(!fElfLoadSegment) { return FALSE; }
        ctx->CrashOrCoreDump.fValidCoreDump = TRUE;
    }
    if((*(PDWORD)pElf32->e_ident == ELF_EI_MAGIC) && (*(PWORD)(pElf32->e_ident + 4) == ELF_EI_CLASSDATA_32)) {
        // ELF CORE DUMP - 32-bit full dump
        lcprintfvv_fn(ctxLC, "32-bit ELF Core Dump identified.\n");
        if((pElf32->e_type != ELF_ET_CORE) || (pElf32->e_version != ELF_ET_VERSION) || (pElf32->e_phoff != ELF_PHDR_OFFSET_64) || (pElf32->e_phentsize != sizeof(Elf32_Phdr)) || !pElf32->e_phnum || (pElf32->e_phnum > 0x200)) {
            lcprintf(ctxLC, "DEVICE: FAIL: unable to parse elf header\n");
            return FALSE;
        }
        for(i = 0; i < pElf32->e_phnum; i++) {
            f = (pElf32->Phdr[i].p_type == ELF_PT_LOAD) &&
                pElf32->Phdr[i].p_offset && (pElf32->Phdr[i].p_offset < ctx->cbFile) &&
                pElf32->Phdr[i].p_filesz && (pElf32->Phdr[i].p_filesz < ctx->cbFile) &&
                (pElf32->Phdr[i].p_filesz == pElf32->Phdr[i].p_memsz) &&
                ((QWORD)pElf32->Phdr[i].p_offset + pElf32->Phdr[i].p_filesz <= ctx->cbFile) &&
                !(pElf32->Phdr[i].p_paddr & 0xfff) && !(pElf32->Phdr[i].p_filesz & 0xfff);
            if(f) {
                fElfLoadSegment = TRUE;
                if(!LcMemMap_AddRange(ctxLC, pElf32->Phdr[i].p_paddr, pElf32->Phdr[i].p_filesz, pElf32->Phdr[i].p_offset)) {
                    lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%08x %08x %08x)\n", pElf32->Phdr[i].p_paddr, pElf32->Phdr[i].p_filesz, pElf32->Phdr[i].p_offset);
                    return FALSE;
                }
            }
        }
        if(!fElfLoadSegment) { return FALSE; }
        ctx->CrashOrCoreDump.fValidCoreDump = TRUE;
    }
    return TRUE;
}

_Success_(return)
BOOL DeviceFile_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    BOOL f32 = ctx->CrashOrCoreDump.f32;
    if(fOption == LC_OPT_MEMORYINFO_VALID) {
        *pqwValue = ctx->CrashOrCoreDump.fValidCrashDump ? 1 : 0;
        return TRUE;
    }
    if(!ctx->CrashOrCoreDump.fValidCrashDump) {
        *pqwValue = 0;
        return FALSE;
    }
    switch(fOption) {
        case LC_OPT_MEMORYINFO_FLAG_32BIT:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? 1 : 0;
            return TRUE;
        case LC_OPT_MEMORYINFO_FLAG_PAE:
            *pqwValue = ctx->CrashOrCoreDump.f32 ? ctx->CrashOrCoreDump.pbHdr[0x5c] : 0;
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_VERSION_MINOR:
            *pqwValue = *(PDWORD)(ctx->CrashOrCoreDump.pbHdr + 0x00c);
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_VERSION_MAJOR:
            *pqwValue = *(PDWORD)(ctx->CrashOrCoreDump.pbHdr + 0x008);
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_DTB:
            *pqwValue = VMM_PTR_OFFSET_DUAL(f32, ctx->CrashOrCoreDump.pbHdr, 0x010, 0x010);
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PFN:
            *pqwValue = VMM_PTR_OFFSET_DUAL(f32, ctx->CrashOrCoreDump.pbHdr, 0x014, 0x018);
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PsLoadedModuleList:
            *pqwValue = VMM_PTR_OFFSET_DUAL(f32, ctx->CrashOrCoreDump.pbHdr, 0x018, 0x020);
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_PsActiveProcessHead:
            *pqwValue = VMM_PTR_OFFSET_DUAL(f32, ctx->CrashOrCoreDump.pbHdr, 0x01c, 0x028);
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP:
            *pqwValue = *(PDWORD)(ctx->CrashOrCoreDump.pbHdr + (f32 ? 0x020 : 0x030));
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_NUM_PROCESSORS:
            *pqwValue = *(PDWORD)(ctx->CrashOrCoreDump.pbHdr + (f32 ? 0x024 : 0x034));
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_SYSTEMTIME:
            *pqwValue = *(PQWORD)(ctx->CrashOrCoreDump.pbHdr + (f32 ? 0xfc0 : 0xfa8));
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_UPTIME:
            *pqwValue = *(PQWORD)(ctx->CrashOrCoreDump.pbHdr + (f32 ? 0xfb8 : 0x1030));
            return TRUE;
        case LC_OPT_MEMORYINFO_OS_KdDebuggerDataBlock:
            *pqwValue = VMM_PTR_OFFSET_DUAL(f32, ctx->CrashOrCoreDump.pbHdr, 0x060, 0x080);
            return TRUE;
    }
    *pqwValue = 0;
    return FALSE;
}

_Success_(return)
BOOL DeviceFile_Command(
    _In_ PLC_CONTEXT ctxLC,
    _In_ ULONG64 fOption,
    _In_ DWORD cbDataIn,
    _In_reads_opt_(cbDataIn) PBYTE pbDataIn,
    _Out_opt_ PBYTE *ppbDataOut,
    _Out_opt_ PDWORD pcbDataOut
) {
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    BOOL f32 = ctx->CrashOrCoreDump.f32;
    PBYTE pb;
    DWORD cb;
    UNREFERENCED_PARAMETER(cbDataIn);
    UNREFERENCED_PARAMETER(pbDataIn);
    // GET DUMP HEADER:
    if(fOption == LC_CMD_FILE_DUMPHEADER_GET) {
        if(!ppbDataOut || !ctx->CrashOrCoreDump.fValidCrashDump) { return FALSE; }
        cb = ctx->CrashOrCoreDump.f32 ? 0x1000 : 0x2000;
        if(!(pb = LocalAlloc(0, cb))) { return FALSE; }
        memcpy(pb, ctx->CrashOrCoreDump.pbHdr, cb);
        if(pcbDataOut) { *pcbDataOut = cb; }
        *ppbDataOut = pb;
        return TRUE;
    }
    return FALSE;
}

//-----------------------------------------------------------------------------
// OPEN/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DeviceFile_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    if(!ctx) { return; }
    if(ctx->pFile) { fclose(ctx->pFile); }
    LocalFree(ctx);
    ctxLC->hDevice = 0;
}

_Success_(return)
BOOL DeviceFile_Open(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx;
    if(!(ctx = (PDEVICE_CONTEXT_FILE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FILE)))) { return FALSE; }
    lcprintfv(ctxLC, "DEVICE OPEN: %s\n", ctxLC->Config.szDeviceName);
    if(0 == _strnicmp("file://", ctxLC->Config.szDevice, 7)) {
        strncpy_s(ctx->szFileName, _countof(ctx->szFileName), ctxLC->Config.szDevice + 7, _countof(ctxLC->Config.szDevice) - 7);
    } else if(0 == _stricmp(ctxLC->Config.szDevice, "livekd")) {
        strcpy_s(ctx->szFileName, _countof(ctx->szFileName), "C:\\WINDOWS\\livekd.dmp");
    } else if(0 == _stricmp(ctxLC->Config.szDevice, "dumpit")) {
        strcpy_s(ctx->szFileName, _countof(ctx->szFileName), "C:\\WINDOWS\\DumpIt.dmp");
    } else {
        strncpy_s(ctx->szFileName, _countof(ctx->szFileName), ctxLC->Config.szDevice, _countof(ctxLC->Config.szDevice));
    }
    // open backing file
    if(fopen_s(&ctx->pFile, ctx->szFileName, "rb") || !ctx->pFile) { goto fail; }
    if(_fseeki64(ctx->pFile, 0, SEEK_END)) { goto fail; }   // seek to end of file
    ctx->cbFile = _ftelli64(ctx->pFile);                    // get current file pointer
    if(ctx->cbFile < 0x01000000) { goto fail; }             // minimum allowed dump file size = 16MB
    ctxLC->hDevice = (HANDLE)ctx;
    // set callback functions and fix up config
    ctxLC->pfnClose = DeviceFile_Close;
    ctxLC->pfnReadScatter = DeviceFile_ReadScatter;
    ctxLC->pfnGetOption = DeviceFile_GetOption;
    ctxLC->pfnCommand = DeviceFile_Command;
    ctxLC->Config.fVolatile = FALSE;                  // Files are assumed to be static non-volatile.
    if(strstr(ctx->szFileName, "DumpIt.dmp")) {
        ctxLC->Config.fVolatile = TRUE;               // DumpIt LIVEKD files are volatile.
    }
    if(strstr(ctx->szFileName, "livekd.dmp")) {
        // LiveKd files are volatile. LiveKd is also currently super slow -
        // almost so slow it's useless. But doing linear reads speeds things up
        // very marginally (10-15%); doing multi-threaded reads does not help :(
        ctxLC->Config.fVolatile = TRUE;
        ctxLC->pfnReadScatter = NULL;
        ctxLC->pfnReadContigious = DeviceFile_ReadContigious;
    }
    if((strlen(ctx->szFileName) >= 6) && (0 == _stricmp(".vmem", ctx->szFileName + strlen(ctx->szFileName) - 5))) {
        DeviceFile_VMwareDumpInitialize(ctxLC);
    }
    if(!ctx->CrashOrCoreDump.fValidVMwareDump) {
        if(!DeviceFile_MsCrashCoreDumpInitialize(ctxLC)) { goto fail; }
    }    
    if(ctx->CrashOrCoreDump.fValidCrashDump) {
        lcprintfv(ctxLC, "DEVICE: Successfully opened file: '%s' as Microsoft Crash Dump.\n", ctx->szFileName);
    } else if(ctx->CrashOrCoreDump.fValidCoreDump) {
        lcprintfv(ctxLC, "DEVICE: Successfully opened file: '%s' as ELF Core Dump.\n", ctx->szFileName);
    } else if(ctx->CrashOrCoreDump.fValidVMwareDump) {
        lcprintfv(ctxLC, "DEVICE: Successfully opened file: '%s' as VMware Dump.\n", ctx->szFileName);
    } else {
        LcMemMap_AddRange(ctxLC, 0, ctx->cbFile, 0);
        lcprintfv(ctxLC, "DEVICE: Successfully opened file: '%s' as RAW Memory Dump.\n", ctx->szFileName);
    }
    return TRUE;
fail:
    if(ctx->pFile) { fclose(ctx->pFile); }
    LocalFree(ctx);
    ctxLC->hDevice = 0;
    lcprintf(ctxLC, "DEVICE: ERROR: Failed opening file: '%s'.\n", ctxLC->Config.szDevice);
    return FALSE;
}
