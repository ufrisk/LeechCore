// device_file.c : implementation related to file backed memory acquisition device.
//
// (c) Ulf Frisk, 2018-2023
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
#define DUMP_TYPE_BITMAP_FULL       5
#define DUMP_TYPE_ACTIVE_MEMORY     6
#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_AMD64    0x8664
#define IMAGE_FILE_MACHINE_ARM64    0xAA64
#define _PHYSICAL_MEMORY_MAX_RUNS   0x80

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

typedef struct tdDUMP_HEADER_BITMAP_FULL64 {
    QWORD Signature;        // + 0x00
    QWORD _Filler[3];       // + 0x08
    QWORD cbFileBase;       // + 0x20
    QWORD cPages;           // + 0x28
    QWORD cBits;            // + 0x30
    BYTE pbBitmap[0];       // + 0x38
} _DUMP_HEADER_BITMAP_FULL64, *P_DUMP_HEADER_BITMAP_FULL64;

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
// DEFINES: LiME DUMP DEFINES
//-----------------------------------------------------------------------------

#define LIME_MAGIC              0x4C694D45
#define LIME_VERSION            0x00000001

typedef struct tdLIME_MEM_RANGE_HEADER {
    unsigned int magic;
    unsigned int version;
    unsigned long long _s_addr;
    unsigned long long _e_addr;
    unsigned char reserved[8];
} LIME_MEM_RANGE_HEADER, *PLIME_MEM_RANGE_HEADER;

//-----------------------------------------------------------------------------
// DEFINES: GENERAL
//-----------------------------------------------------------------------------

#define FILE_MAX_THREADS        4

typedef struct tdDEVICE_CONTEXT_FILE {
    struct {
        FILE *h;
        CRITICAL_SECTION Lock;
    } File[FILE_MAX_THREADS];
    BOOL fMultiThreaded;
    DWORD iFileNext;                // next file handle to use for a read (in multi-threaded mode)
    QWORD cbFile;
    CHAR szFileName[MAX_PATH];
    struct {
        BOOL fValidCoreDump;
        BOOL fValidCrashDump;
        BOOL fValidLimeDump;
        BOOL fValidVMwareDump;
        BOOL f32;
        union {
            BYTE pbHdr[0x2000];
            Elf64_Ehdr Elf64;
            Elf32_Ehdr Elf32;
            LIME_MEM_RANGE_HEADER LiME;
        };
    } CrashOrCoreDump;
    LC_ARCH_TP tpArch;              // LC_ARCH_TP
    QWORD paDtbHint;
} DEVICE_CONTEXT_FILE, *PDEVICE_CONTEXT_FILE;

//-----------------------------------------------------------------------------
// GENERAL 'DEVICE' FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Contigious file read. This is used by LiveKD since it is otherwise very slow
* to read scattered memory using LiveKD.
* -- ctxRC
*/
VOID DeviceFile_ReadContigious(_Inout_ PLC_READ_CONTIGIOUS_CONTEXT ctxRC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxRC->ctxLC->hDevice;
    EnterCriticalSection(&ctx->File[0].Lock);
    if(0 == _fseeki64(ctx->File[0].h, ctxRC->paBase, SEEK_SET)) {
        ctxRC->cbRead = (DWORD)fread(ctxRC->pb, 1, ctxRC->cb, ctx->File[0].h);
    }
    LeaveCriticalSection(&ctx->File[0].Lock);
}

/*
* Default scatter read function - to be called by LeechCore. This function may
* be called in multi-threaded mode if the ctx->fMultiThreaded flag is set. In
* that case load-balance accesses amongst the file handles in the ctx->File[].
* -- ctxLC
* -- cpMEMs
* -- ppMEMs
*/
VOID DeviceFile_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    DWORD iMEM, iFile = 0, cTryLock = 0;
    PMEM_SCATTER pMEM;
    if(ctx->fMultiThreaded) {
        // in a multi-threaded environment:
        // load-balance file access amongst available file handles
        iFile = InterlockedIncrement(&ctx->iFileNext) % FILE_MAX_THREADS;
        while(!TryEnterCriticalSection(&ctx->File[iFile].Lock)) {
            iFile = InterlockedIncrement(&ctx->iFileNext) % FILE_MAX_THREADS;
            if(++cTryLock == FILE_MAX_THREADS) {
                EnterCriticalSection(&ctx->File[iFile].Lock);
                break;
            }
        }
    }
    for(iMEM = 0; iMEM < cpMEMs; iMEM++) {
        pMEM = ppMEMs[iMEM];
        if(pMEM->f || (pMEM->qwA == (QWORD)-1)) { continue; }
        if(pMEM->qwA != (QWORD)_ftelli64(ctx->File[iFile].h)) {
            if(_fseeki64(ctx->File[iFile].h, pMEM->qwA, SEEK_SET)) { continue; }
        }
        pMEM->f = pMEM->cb == (DWORD)fread(pMEM->pb, 1, pMEM->cb, ctx->File[iFile].h);
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
    if(ctx->fMultiThreaded) {
        LeaveCriticalSection(&ctx->File[iFile].Lock);
    }
}

/*
* Scatter write function - to be called by LeechCore. This function may
* be called in multi-threaded mode if the ctx->fMultiThreaded flag is set. In
* that case load-balance accesses amongst the file handles in the ctx->File[].
* Writes are only supported by special devices and must be set in the write=1
* parameter in the device string.
* Do not use for normal file access - it may corrupt files!
* -- ctxLC
* -- cpMEMs
* -- ppMEMs
*/
VOID DeviceFile_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    DWORD iMEM, iFile = 0, cTryLock = 0;
    PMEM_SCATTER pMEM;
    if(ctx->fMultiThreaded) {
        // in a multi-threaded environment:
        // load-balance file access amongst available file handles
        iFile = InterlockedIncrement(&ctx->iFileNext) % FILE_MAX_THREADS;
        while(!TryEnterCriticalSection(&ctx->File[iFile].Lock)) {
            iFile = InterlockedIncrement(&ctx->iFileNext) % FILE_MAX_THREADS;
            if(++cTryLock == FILE_MAX_THREADS) {
                EnterCriticalSection(&ctx->File[iFile].Lock);
                break;
            }
        }
    }
    for(iMEM = 0; iMEM < cpMEMs; iMEM++) {
        pMEM = ppMEMs[iMEM];
        if(pMEM->f || (pMEM->qwA == (QWORD)-1)) { continue; }
        if(pMEM->qwA != (QWORD)_ftelli64(ctx->File[iFile].h)) {
            if(_fseeki64(ctx->File[iFile].h, pMEM->qwA, SEEK_SET)) { continue; }
        }
        pMEM->f = pMEM->cb == (DWORD)fwrite(pMEM->pb, 1, pMEM->cb, ctx->File[iFile].h);
        if(pMEM->f) {
            if(ctxLC->fPrintf[LC_PRINTF_VVV]) {
                lcprintf_fn(
                    ctxLC,
                    "WRITE:\n        offset=%016llx req_len=%08x\n",
                    pMEM->qwA,
                    pMEM->cb
                );
                Util_PrintHexAscii(ctxLC, pMEM->pb, pMEM->cb, 0);
            }
        } else {
            lcprintfvvv_fn(ctxLC, "WRITE FAILED:\n        offset=%016llx req_len=%08x\n", pMEM->qwA, pMEM->cb);
        }
    }
    if(ctx->fMultiThreaded) {
        LeaveCriticalSection(&ctx->File[iFile].Lock);
    }
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
* Try to initialize a VMWare Dump/Save File (.vmem + vmss/vmsn).
* Also, older VMWare versions may have memory in-lined inside the vmsn file.
*/
VOID DeviceFile_VMwareDumpInitialize(_In_ PLC_CONTEXT ctxLC, _In_ BOOL fInlineMemory)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    FILE_VMWARE_HEADER hdr = { 0 };
    FILE_VMWARE_GROUP grp = { 0 };
    FILE_VMWARE_MEMORY_REGION regions[FILE_VMWARE_MEMORY_REGIONS_MAX] = { 0 };
    CHAR szFileName[MAX_PATH];
    FILE *pFile = NULL;
    PBYTE pb;
    QWORD oTag, paDtbHint = 0, qwMemorySizeMB = 0, qwInlineMemoryOffset = 0;
    DWORD iGroup, iMemoryRegion, cbTag, cchTag, dwPlatform = 0;
    strcpy_s(szFileName, _countof(szFileName), ctx->szFileName);
    // 1: open and verify metadata file
    memcpy(szFileName + strlen(szFileName) - 5, ".vmss", 5);
    fopen_s(&pFile, szFileName, "rb");
    if(!pFile) {
        memcpy(szFileName + strlen(szFileName) - 5, ".vmsn", 5);
        fopen_s(&pFile, szFileName, "rb");
    }
    if(!pFile) {
        lcprintf(ctxLC, "DEVICE: WARN: Unable to open VMware .vmss or .vmsn file - assuming 1:1 memory space.\n");
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
        if(0 == strcmp("Checkpoint", grp.szName)) {
            if(grp.cbSize > 0x00100000) { continue; }
            if(_fseeki64(pFile, grp.cbOffset, SEEK_SET)) { continue; }
            if(!(pb = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)grp.cbSize))) { continue; }
            if(grp.cbSize != fread(pb, 1, (SIZE_T)grp.cbSize, pFile)) {
                LocalFree(pb);
                continue;
            }
            oTag = 0;
            while(oTag + 8 + 4 <= grp.cbSize) {
                if(!dwPlatform && !memcmp(pb + oTag, "Platform", 0x08)) {
                    dwPlatform = *(PDWORD)(pb + oTag + 0x08);
                }
                if(!qwMemorySizeMB && !memcmp(pb + oTag, "memSize", 0x07)) {
                    qwMemorySizeMB = *(PDWORD)(pb + oTag + 0x07);
                }
                oTag++;
            }
        }
        if(0 == strcmp("cpu", grp.szName)) {
            if(grp.cbSize > 0x00100000) { continue; }
            if(_fseeki64(pFile, grp.cbOffset, SEEK_SET)) { continue; }
            if(!(pb = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)grp.cbSize))) { continue; }
            if(grp.cbSize != fread(pb, 1, (SIZE_T)grp.cbSize, pFile)) {
                LocalFree(pb);
                continue;
            }
            oTag = 0;
            while(oTag + 13 + 8 <= grp.cbSize) {
                if(!paDtbHint && !memcmp(pb + oTag, "hv:ttbrEL1[0]", 13)) {
                    if(*(PDWORD)(pb + oTag + 13 + 4) >= 0x80000000) {
                        paDtbHint = *(PDWORD)(pb + oTag + 13 + 4);
                    }
                }
                oTag++;
            }
        }
        if(0 == strcmp("memory", grp.szName)) {
            if(grp.cbSize > 0x01000000) { 
                if(fInlineMemory) {
                    qwInlineMemoryOffset = (grp.cbOffset + (grp.cbSize & 0xfffff)) & ~0xfff;
                    grp.cbSize = grp.cbSize & 0xfffff;
                } else {
                    continue;
                }
            }
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
                    regions[iMemoryRegion].cbOffsetFile = qwInlineMemoryOffset + *(PDWORD)(pb + oTag + 2 + 0x0d + 4) * 0x1000ULL;
                }
                oTag += cbTag;
                if((oTag + 4 <= grp.cbSize) && (0 == *(PDWORD)(pb + oTag))) { oTag += 4; }
            }
            LocalFree(pb);
            for(iMemoryRegion = 0; iMemoryRegion < FILE_VMWARE_MEMORY_REGIONS_MAX; iMemoryRegion++) {
                if(regions[iMemoryRegion].fSize && regions[iMemoryRegion].fOffsetMemory && regions[iMemoryRegion].fOffsetFile) {
                    LcMemMap_AddRange(ctxLC, regions[iMemoryRegion].cbOffsetMemory, regions[iMemoryRegion].cbSize, LC_MEMMAP_FORCE_OFFSET | regions[iMemoryRegion].cbOffsetFile);
                    ctx->CrashOrCoreDump.fValidVMwareDump = TRUE;
                }
            }
        }
    }
    ctx->paDtbHint = paDtbHint;
    if(!LcMemMap_IsInitialized(ctxLC) && (dwPlatform == 3) && (qwMemorySizeMB > 16)) {
        // ARM64 - initialize with default physical memory offset of 0x80000000 at zero file offset.
        ctx->tpArch = LC_ARCH_ARM64;
        LcMemMap_AddRange(ctxLC, 0x80000000, qwMemorySizeMB * 0x00100000ULL, LC_MEMMAP_FORCE_OFFSET | 0);
    }
    if(!LcMemMap_IsInitialized(ctxLC)) {
        lcprintf(ctxLC, "DEVICE: WARN: No VMware memory regions located - file will be treated as single-region.\n");
    }
fail:
    if(pFile) { fclose(pFile); }
}

/*
* Parsing of the Full Bitmap Microsoft Crashdump file (currently only 64-bits).
* -- ctxLC
* -- return
*/
BOOL DeviceFile_MsCrashCoreDumpInitialize_BitmapFullOrActiveMemory(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    _DUMP_HEADER_BITMAP_FULL64 hdr = { 0 };
    PBYTE pb = NULL;
    BOOL fResult = FALSE, fPageValid = FALSE;
    QWORD cb, cbFileBase, iPageBase, iPage, cMaxBits, iPageEx, b;
    // 1: fetch header:
    _fseeki64(ctx->File[0].h, 0x2000, SEEK_SET);
    fread(&hdr, 1, sizeof(_DUMP_HEADER_BITMAP_FULL64), ctx->File[0].h);
    if((hdr.Signature != 0x504d5544504d4446) && (hdr.Signature != 0x504d5544504d4453)) { goto fail; }   // !'FDMPDUMP' && !'SDMPDUMP' && 
    if((hdr.cPages > hdr.cBits) || (hdr.cBits > 0x7fffffff) || (hdr.cbFileBase & 0xfff) || (hdr.cbFileBase > 0x01000000)) { goto fail; }
    cbFileBase = hdr.cbFileBase;
    // 2: fetch bits:
    cb = hdr.cBits / 8;
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)cb))) { goto fail; }
    if(cb != fread(pb, 1, (SIZE_T)cb, ctx->File[0].h)) { goto fail; }
    // 3: walk bitmap - add ranges!
    cMaxBits = hdr.cBits & 0xffffffc0;
    for(iPage = 0; iPage < cMaxBits; iPage += 64) {
        b = *(PQWORD)(pb + (iPage >> 3));
        // all pages valid!
        if(b == (QWORD)-1) {
            if(!fPageValid) {
                fPageValid = TRUE;
                iPageBase = iPage;
            }
            continue;
        }
        // no pages valid!
        if(!b && !fPageValid) { continue; }
        // some valid pages
        for(iPageEx = 0; iPageEx < 64; iPageEx++) {
            if((b >> iPageEx) & 1) {
                // valid
                if(!fPageValid) {
                    fPageValid = TRUE;
                    iPageBase = iPage + iPageEx;
                }
            } else {
                // invalid
                if(fPageValid) {
                    cb = (iPage + iPageEx - iPageBase) << 12;
                    if(!LcMemMap_AddRange(ctxLC, iPageBase << 12, cb, cbFileBase)) {
                        lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", iPageBase << 12, cb, cbFileBase);
                        return FALSE;
                    }
                    cbFileBase += cb;
                    fPageValid = FALSE;
                }
            }
        }
    }
    // 4: finalize remaining
    if(fPageValid) {
        cb = (iPage - iPageBase) << 12;
        if(!LcMemMap_AddRange(ctxLC, iPageBase << 12, cb, cbFileBase)) {
            lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", iPageBase << 12, cb, cbFileBase);
            return FALSE;
        }
    }
    ctx->CrashOrCoreDump.fValidCrashDump = TRUE;
    fResult = TRUE;
fail:
    if(!fResult) {
        lcprintf(ctxLC, "DEVICE: FAIL: error parsing 64-bit full bitmap dump.\n");
    }
    return fResult;
}

/*
* Initialize a LiME memory dump. In LiME memory dumps the headers are
* spread out throughout the dump file (before each memory range).
* -- ctxLC
* -- return
*/
_Success_(return)
BOOL DeviceFile_DumpInitialize_LiME(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    QWORD cbRangeMax, cbRangeFileMax, cbPreviousRangeMax = 0, oLimeHeader = 0;
    LIME_MEM_RANGE_HEADER LimeHeader;
    BOOL f;
    while((oLimeHeader + sizeof(LIME_MEM_RANGE_HEADER) + 0x1000) <= ctx->cbFile) {
        ZeroMemory(&LimeHeader, sizeof(LIME_MEM_RANGE_HEADER));
        _fseeki64(ctx->File[0].h, oLimeHeader, SEEK_SET);
        fread(&LimeHeader, 1, sizeof(LIME_MEM_RANGE_HEADER), ctx->File[0].h);
        if(oLimeHeader && !LimeHeader.magic && !LimeHeader.version) {
            return TRUE;
        }
        f = (LimeHeader.magic == LIME_MAGIC) && (LimeHeader.version == LIME_VERSION) &&
            ((LimeHeader._s_addr & 0xfff) == 0) && (LimeHeader._s_addr >= cbPreviousRangeMax) &&
            (((LimeHeader._e_addr & 0xfff) == 0xfff) || ((LimeHeader._e_addr & 0xfff) == 0x000)) &&
            (LimeHeader._s_addr < LimeHeader._e_addr);
        if(!f) {
            lcprintf(ctxLC, "DEVICE: FAIL: Parse LiME header at offset: 0x%llx\n", oLimeHeader);
            return FALSE;
        }
        cbRangeMax = (LimeHeader._e_addr + 1) & ~0xfff;
        cbRangeFileMax = (ctx->cbFile + LimeHeader._s_addr + oLimeHeader - sizeof(LIME_MEM_RANGE_HEADER)) & ~0xfff;
        if(cbRangeMax > cbRangeFileMax) {
            lcprintf(ctxLC, "DEVICE: WARN: memory range exceeds file size - adjusting...\n");
            cbRangeMax = cbRangeFileMax;
        }
        if(!LcMemMap_AddRange(ctxLC, (QWORD)LimeHeader._s_addr, cbRangeMax - (QWORD)LimeHeader._s_addr, oLimeHeader + 0x20)) {
            lcprintf(ctxLC, "DEVICE: FAIL: unable to add range to memory map. (%016llx %016llx %016llx)\n", LimeHeader._s_addr, cbRangeMax - LimeHeader._s_addr, oLimeHeader + 0x20);
            return FALSE;
        }
        oLimeHeader += sizeof(LIME_MEM_RANGE_HEADER) + cbRangeMax - (QWORD)LimeHeader._s_addr;
        cbPreviousRangeMax = cbRangeMax;
    }
    return cbPreviousRangeMax ? TRUE : FALSE;
}

/*
* Try to initialize a dump file of one of the supported formats below:
* - Microsoft Crash Dump file (full dump only).
* - LiME dump file.
* - VirtualBox core dump file.
* This is done by reading the dump header. If this is not a dump file the
* -- ctxLC
* -- return = FALSE on fatal non-recoverable error, otherwise TRUE.
*/
_Success_(return)
BOOL DeviceFile_DumpInitialize(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    BOOL f, fElfLoadSegment = FALSE;
    QWORD i, cbFileOffset;
    PElf64_Ehdr pElf64 = &ctx->CrashOrCoreDump.Elf64;
    PElf32_Ehdr pElf32 = &ctx->CrashOrCoreDump.Elf32;
    _PPHYSICAL_MEMORY_DESCRIPTOR32 pM32 = (_PPHYSICAL_MEMORY_DESCRIPTOR32)(ctx->CrashOrCoreDump.pbHdr + 0x064);
    _PPHYSICAL_MEMORY_DESCRIPTOR64 pM64 = (_PPHYSICAL_MEMORY_DESCRIPTOR64)(ctx->CrashOrCoreDump.pbHdr + 0x088);
    _fseeki64(ctx->File[0].h, 0, SEEK_SET);
    fread(ctx->CrashOrCoreDump.pbHdr, 1, 0x2000, ctx->File[0].h);
    if((CDMP_DWORD(0x000) == DUMP_SIGNATURE) && (CDMP_DWORD(0x004) == DUMP_VALID_DUMP64) && (CDMP_DWORD(0xf98) == DUMP_TYPE_FULL) && ((CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_AMD64) || (CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_ARM64))) {
        // PAGEDUMP (64-bit memory dump) and FULL DUMP
        lcprintfvv_fn(ctxLC, "64-bit Microsoft Crash Dump identified.\n");
        ctx->CrashOrCoreDump.fValidCrashDump = TRUE;
        ctx->CrashOrCoreDump.f32 = FALSE;
        if(CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_AMD64) { ctx->tpArch = LC_ARCH_X64; }
        if(CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_ARM64) { ctx->tpArch = LC_ARCH_ARM64; }
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
    if((CDMP_DWORD(0x000) == DUMP_SIGNATURE) && (CDMP_DWORD(0x004) == DUMP_VALID_DUMP64) && (CDMP_DWORD(0xf98) == DUMP_TYPE_BITMAP_FULL) && ((CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_AMD64) || (CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_ARM64))) {
        if(CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_AMD64) { ctx->tpArch = LC_ARCH_X64; }
        if(CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_ARM64) { ctx->tpArch = LC_ARCH_ARM64; }
        return DeviceFile_MsCrashCoreDumpInitialize_BitmapFullOrActiveMemory(ctxLC);
    }
    if((CDMP_DWORD(0x000) == DUMP_SIGNATURE) && (CDMP_DWORD(0x004) == DUMP_VALID_DUMP64) && (CDMP_DWORD(0xf98) == DUMP_TYPE_ACTIVE_MEMORY) && ((CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_AMD64) || (CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_ARM64))) {
        lcprintfv(ctxLC, "DEVICE: WARN: active only memory dump - analysis will be degraded!\n");
        if(CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_AMD64) { ctx->tpArch = LC_ARCH_X64; }
        if(CDMP_DWORD(0x030) == IMAGE_FILE_MACHINE_ARM64) { ctx->tpArch = LC_ARCH_ARM64; }
        return DeviceFile_MsCrashCoreDumpInitialize_BitmapFullOrActiveMemory(ctxLC);
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
    if((ctx->CrashOrCoreDump.LiME.magic == LIME_MAGIC) && (ctx->CrashOrCoreDump.LiME.version == LIME_VERSION)) {
        // LiME memory dump: ranges are spread out in file -> parse this in separate function:
        if(!DeviceFile_DumpInitialize_LiME(ctxLC)) { return FALSE; }
        ctx->CrashOrCoreDump.fValidLimeDump;
    }
    return TRUE;
}

_Success_(return)
BOOL DeviceFile_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    BOOL f32 = ctx->CrashOrCoreDump.f32;
    *pqwValue = 0;
    if(fOption == LC_OPT_MEMORYINFO_VALID) {
        *pqwValue = ctx->CrashOrCoreDump.fValidCrashDump ? 1 : 0;
        return TRUE;
    }
    // general options below:
    switch(fOption) {
        case LC_OPT_MEMORYINFO_ARCH:
            if(ctx->tpArch != LC_ARCH_NA) {
                *pqwValue = (QWORD)ctx->tpArch;
                return TRUE;
            }
            break;
        case LC_OPT_MEMORYINFO_OS_DTB:
            if(ctx->paDtbHint) {
                *pqwValue = ctx->paDtbHint;
                return TRUE;
            }
            break;
    }
    // crash dump options below:
    if(!ctx->CrashOrCoreDump.fValidCrashDump) {
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
    DWORD i;
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    if(ctx) {
        ctxLC->hDevice = 0;
        if(ctx->fMultiThreaded) {
            for(i = 0; i < FILE_MAX_THREADS; i++) {
                if(ctx->File[i].h) {
                    fclose(ctx->File[i].h);
                    DeleteCriticalSection(&ctx->File[i].Lock);
                }
            }
        } else {
            if(ctx->File[0].h) {
                fclose(ctx->File[0].h);
          }
        }  
        LocalFree(ctx);
    }
}

#define DEVICE_FILE_PARAMETER_FILE                  "file"
#define DEVICE_FILE_PARAMETER_WRITE                 "write"
#define DEVICE_FILE_PARAMETER_VOLATILE              "volatile"

_Success_(return)
BOOL DeviceFile_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    DWORD i;
    LPSTR szType;
    PDEVICE_CONTEXT_FILE ctx;
    PLC_DEVICE_PARAMETER_ENTRY pParam;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    if(!(ctx = (PDEVICE_CONTEXT_FILE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FILE)))) { return FALSE; }
    lcprintfv(ctxLC, "DEVICE OPEN: %s\n", ctxLC->Config.szDeviceName);
    ctxLC->Config.fWritable = FALSE;                    // Files are assumed to be read-only.
    ctxLC->Config.fVolatile = FALSE;                    // Files are assumed to be static non-volatile.
    if(0 == _strnicmp("file://", ctxLC->Config.szDevice, 7)) {
        if((pParam = LcDeviceParameterGet(ctxLC, DEVICE_FILE_PARAMETER_FILE)) && pParam->szValue) {
            // we have a file name on the new format, i.e. fpga://file=<filename> - use the new format.
            strncpy_s(ctx->szFileName, _countof(ctx->szFileName), pParam->szValue, _TRUNCATE);
            ctxLC->Config.fVolatile = LcDeviceParameterGetNumeric(ctxLC, DEVICE_FILE_PARAMETER_VOLATILE) ? TRUE : FALSE;
            ctxLC->Config.fWritable = LcDeviceParameterGetNumeric(ctxLC, DEVICE_FILE_PARAMETER_WRITE) ? TRUE : FALSE;
        } else {
            // we have a file name on the old format, i.e. fpga://<filename> - use the old format.
            strncpy_s(ctx->szFileName, _countof(ctx->szFileName), ctxLC->Config.szDevice + 7, _countof(ctxLC->Config.szDevice) - 7);
        }
    } else if(0 == _stricmp(ctxLC->Config.szDevice, "livekd")) {
        strcpy_s(ctx->szFileName, _countof(ctx->szFileName), "C:\\WINDOWS\\livekd.dmp");
    } else if(0 == _stricmp(ctxLC->Config.szDevice, "dumpit")) {
        strcpy_s(ctx->szFileName, _countof(ctx->szFileName), "C:\\WINDOWS\\DumpIt.dmp");
    } else {
        strncpy_s(ctx->szFileName, _countof(ctx->szFileName), ctxLC->Config.szDevice, _countof(ctxLC->Config.szDevice));
    }
    // open backing file:
    if(fopen_s(&ctx->File[0].h, ctx->szFileName, (ctxLC->Config.fWritable ? "r+b" : "rb")) || !ctx->File[0].h) { goto fail; }
    InitializeCriticalSection(&ctx->File[0].Lock);
    if(_fseeki64(ctx->File[0].h, 0, SEEK_END)) { goto fail; }   // seek to end of file
    ctx->cbFile = _ftelli64(ctx->File[0].h);                    // get current file pointer
    if(ctx->cbFile < 0x01000000) { goto fail; }                 // minimum allowed dump file size = 16MB
    if(ctx->cbFile > 0xffff000000000000) { goto fail; }         // file too large
    ctxLC->hDevice = (HANDLE)ctx;
    // set callback functions and fix up config:
    ctxLC->pfnClose = DeviceFile_Close;
    ctxLC->pfnReadScatter = DeviceFile_ReadScatter;
    ctxLC->pfnGetOption = DeviceFile_GetOption;
    ctxLC->pfnCommand = DeviceFile_Command;
    if(ctxLC->Config.fWritable) {
        ctxLC->pfnWriteScatter = DeviceFile_WriteScatter;
    }
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
        DeviceFile_VMwareDumpInitialize(ctxLC, FALSE);     // vmem - vmware memory dump
    } else if((ctx->cbFile > 0x10000000) && (strlen(ctx->szFileName) >= 6) && (0 == _stricmp(".vmsn", ctx->szFileName + strlen(ctx->szFileName) - 5))) {
        DeviceFile_VMwareDumpInitialize(ctxLC, TRUE);     // vmsn - vmware snapshot with memory in-line in file
    }
    if(!ctx->CrashOrCoreDump.fValidVMwareDump) {
        if(!DeviceFile_DumpInitialize(ctxLC)) { goto fail; }
    }
    // try upgrade to multi-threaded access:
    if(!fopen_s(&ctx->File[1].h, ctx->szFileName, (ctxLC->Config.fWritable ? "r+b" : "rb"))) {
        // 2nd file handle successfully opened - upgrade to multi-threaded access.
        ctxLC->fMultiThread = TRUE;
        ctx->fMultiThreaded = TRUE;
        InitializeCriticalSection(&ctx->File[1].Lock);
        for(i = 2; i < FILE_MAX_THREADS; i++) {
            if(fopen_s(&ctx->File[i].h, ctx->szFileName, (ctxLC->Config.fWritable ? "r+b" : "rb"))) { break; }
            InitializeCriticalSection(&ctx->File[i].Lock);
        }
    }
    // print result and return:
    if(ctx->CrashOrCoreDump.fValidCrashDump) {
        szType = "Microsoft Crash Dump";
    } else if(ctx->CrashOrCoreDump.fValidCoreDump) {
        szType = "ELF Core Dump";
    } else if(ctx->CrashOrCoreDump.fValidVMwareDump) {
        szType = "VMware Dump";
    } else {
        LcMemMap_AddRange(ctxLC, 0, ctx->cbFile, 0);
        szType = "RAW Memory Dump";
    }
    lcprintfv(ctxLC, "DEVICE: Successfully opened file: '%s' as %s%s%s.\n", ctx->szFileName, (ctxLC->Config.fVolatile ? "volatile " : ""), (ctxLC->Config.fWritable ? "writable " : ""), szType);
    return TRUE;
fail:
    for(i = 0; i < FILE_MAX_THREADS; i++) {
        if(ctx->File[i].h) {
            fclose(ctx->File[i].h);
            DeleteCriticalSection(&ctx->File[i].Lock);
        }
    }
    LocalFree(ctx);
    ctxLC->hDevice = 0;
    lcprintf(ctxLC, "DEVICE: ERROR: Failed opening file: '%s'.\n", ctxLC->Config.szDevice);
    return FALSE;
}
