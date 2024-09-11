// leechcore_device_hibr.c : implementation of hibernation file support for
//                           Windows 8+.
// 
// The hibernation file format of Windows 8+ is documented in the excellent
// blog post by ForensicXlab at: https://www.forensicxlab.com/posts/hibernation/
// Also the original paper at: https://www.cct.lsu.edu/~golden/Papers/sylvehiber.pdf
//
// (c) Ulf Frisk, 2024
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechcore_device.h"
#include "oscompatibility.h"
#include "util.h"



//-----------------------------------------------------------------------------
// HARD CODED HIBERNATION OFFSETS FOR WINDOWS 8+
//-----------------------------------------------------------------------------

typedef struct tdHIBR_OFFSET {
    DWORD LengthSelf;
    BOOL  f32;
    DWORD PageSize;
    DWORD SystemTime;
    DWORD NumPagesForLoader;
    DWORD FirstBootRestorePage;
    DWORD FirstKernelRestorePage;
    DWORD KernelPagesProcessed;
    DWORD HighestPhysicalPage;
} HIBR_OFFSET, *PHIBR_OFFSET;

const HIBR_OFFSET HIBR_OFFSET_PROFILES[] = {
    {.LengthSelf = 0x4d8, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x498},  // 64-bit build 26100
    {.LengthSelf = 0x448, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x400},  // 64-bit build 22621
    {.LengthSelf = 0x448, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x400},  // 64-bit build 22000
    {.LengthSelf = 0x448, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x400},  // 64-bit build 20348
    {.LengthSelf = 0x3e0, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x398},  // 64-bit build 19041
    {.LengthSelf = 0x3e0, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x398},  // 64-bit build 18363
    {.LengthSelf = 0x3e0, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x398},  // 64-bit build 18362
    {.LengthSelf = 0x3e0, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x398},  // 64-bit build 17763
    {.LengthSelf = 0x3d8, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x398},  // 64-bit build 17134
    {.LengthSelf = 0x3d8, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x398},  // 64-bit build 16299
    {.LengthSelf = 0x3d8, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x230, .HighestPhysicalPage = 0x398},  // 64-bit build 15063
    {.LengthSelf = 0x3c8, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x220, .HighestPhysicalPage = 0x388},  // 64-bit build 14393
    {.LengthSelf = 0x3b0, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x218, .HighestPhysicalPage = 0x380},  // 64-bit build 10586
    {.LengthSelf = 0x3b0, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x68, .FirstKernelRestorePage = 0x70, .KernelPagesProcessed = 0x218, .HighestPhysicalPage = 0x380},  // 64-bit build 10240
    {.LengthSelf = 0x360, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x60, .FirstKernelRestorePage = 0x68, .KernelPagesProcessed = 0x1c8, .HighestPhysicalPage = 0x330},  // 64-bit build 9600
    {.LengthSelf = 0x360, .f32 = FALSE, .PageSize = 0x18, .SystemTime = 0x20, .NumPagesForLoader = 0x58, .FirstBootRestorePage = 0x60, .FirstKernelRestorePage = 0x68, .KernelPagesProcessed = 0x1c8, .HighestPhysicalPage = 0x330},  // 64-bit build 9200
    {.LengthSelf = 0x340, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x210, .HighestPhysicalPage = 0x310},  // 32-bit build 19041
    {.LengthSelf = 0x340, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x210, .HighestPhysicalPage = 0x310},  // 32-bit build 18363
    {.LengthSelf = 0x340, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x210, .HighestPhysicalPage = 0x310},  // 32-bit build 18362
    {.LengthSelf = 0x340, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x210, .HighestPhysicalPage = 0x310},  // 32-bit build 17763
    {.LengthSelf = 0x338, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x210, .HighestPhysicalPage = 0x310},  // 32-bit build 17134
    {.LengthSelf = 0x338, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x210, .HighestPhysicalPage = 0x310},  // 32-bit build 16299
    {.LengthSelf = 0x338, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x210, .HighestPhysicalPage = 0x310},  // 32-bit build 15063
    {.LengthSelf = 0x328, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x200, .HighestPhysicalPage = 0x300},  // 32-bit build 14393
    {.LengthSelf = 0x310, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x1f8, .HighestPhysicalPage = 0x2f8},  // 32-bit build 10586
    {.LengthSelf = 0x310, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x1f8, .HighestPhysicalPage = 0x2f8},  // 32-bit build 10240
    {.LengthSelf = 0x2c8, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x1b0, .HighestPhysicalPage = 0x2b0},  // 32-bit build 9600
    {.LengthSelf = 0x2c8, .f32 = TRUE,  .PageSize = 0x14, .SystemTime = 0x18, .NumPagesForLoader = 0x48, .FirstBootRestorePage = 0x50, .FirstKernelRestorePage = 0x54, .KernelPagesProcessed = 0x1b0, .HighestPhysicalPage = 0x2b0},  // 32-bit build 9200
};



//-----------------------------------------------------------------------------
// DEFINES:
//-----------------------------------------------------------------------------

#define VMM_PTR_OFFSET(f32, pb, o)              ((f32) ? *(PDWORD)((o) + (PBYTE)(pb)) : *(PQWORD)((o) + (PBYTE)(pb)))

#define HIBR_MAGIC                              0x52424948
#define WAKE_MAGIC                              0x454b4157

#define COMPRESS_ALGORITHM_NONE                 0
#define COMPRESS_ALGORITHM_XPRESS               3
#define COMPRESS_ALGORITHM_XPRESS_HUFF          4

#define HIBR_STATUS_SUCCESS                     ((NTSTATUS)0x00000000L)
#define HIBR_STATUS_UNSUCCESSFUL                ((NTSTATUS)0xC0000001L)

#define HIBR_COMPRESSION_TABLE_SIZE             0x1000
#define HIBR_COMPRESSION_DIRECTORY_SIZE         0x1000
#define HIBR_COMPRESSION_INDEX_DIRECTORY(i)     ((i >> 12) & (HIBR_COMPRESSION_DIRECTORY_SIZE - 1))
#define HIBR_COMPRESSION_INDEX_TABLE(i)         (i & (HIBR_COMPRESSION_TABLE_SIZE - 1))

#define HIBR_NUM_CACHE_ENTRIES                  4

// decompression function pointer compatible with ntdll!RtlDecompressBuffer.
typedef NTSTATUS WINAPI HIBR_RtlDecompressBufferEx(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize,
    PVOID  WorkSpace
);

typedef struct tdHIBR_COMPRESSION_SET {
    QWORD o;    // byte offset of compressed data inside hiberfil.sys
    DWORD cb;   // compressed size in bytes
    WORD cpg;   // number of pages in this compression set
    BYTE tp;    // compression type
} HIBR_COMPRESSION_SET, *PHIBR_COMPRESSION_SET;

typedef struct tdHIBR_COMPRESSION_SET_TABLE {
    HIBR_COMPRESSION_SET v[HIBR_COMPRESSION_TABLE_SIZE];
} HIBR_COMPRESSION_SET_TABLE, *PHIBR_COMPRESSION_SET_TABLE;

typedef struct tdDEVICE_CONTEXT_FILE {
    FILE *hFile;
    QWORD cbFile;
    CHAR szFileName[MAX_PATH];
    BOOL f32;
    BOOL fWarningFirst;
    PHIBR_OFFSET po;
    HIBR_RtlDecompressBufferEx *pfnRtlDecompressBufferExOpt;
    DWORD cCS;                  // compression set count
    PHIBR_COMPRESSION_SET_TABLE CS_Directory[HIBR_COMPRESSION_DIRECTORY_SIZE];
    QWORD cPfns;
    PDWORD pdwPfn2CS;
    DWORD iCsCacheNext;
    struct {
        DWORD iCS;              // current compression set index
        BYTE pb[0x10000];       // buffer for decompression
    } CS_Cache[HIBR_NUM_CACHE_ENTRIES];
    BYTE pbBufferCompressedData[0x10000];
    BYTE pbWorkSpace[0x00100000];
} DEVICE_CONTEXT_FILE, *PDEVICE_CONTEXT_FILE;


//-----------------------------------------------------------------------------
// DECOMPRESSION FUNCTION FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#ifdef _WIN32
/*
* Try to initialize the decompression function pointer.
* Decompression is handled by ntdll.dll on Windows and by libMSCompression.so on Linux.
* -- ctx
* -- return = TRUE on success, FALSE on failure.
*/
_Success_(return)
BOOL DeviceHibr_InitializeFunctions(_In_ PDEVICE_CONTEXT_FILE ctx)
{
    HMODULE hNtDll = NULL;
    if((hNtDll = LoadLibraryA("ntdll.dll"))) {
        ctx->pfnRtlDecompressBufferExOpt = (HIBR_RtlDecompressBufferEx*)GetProcAddress(hNtDll, "RtlDecompressBufferEx");
        FreeLibrary(hNtDll);
    }
    return ctx->pfnRtlDecompressBufferExOpt ? TRUE : FALSE;
}
#endif /* _WIN32 */

#ifdef LINUX

/*
* Linux implementation of ntdll!RtlDecompressBuffer for COMPRESS_ALGORITHM_XPRESS:
* Dynamically load libMSCompression.so (if it exists) and use it. If library does
* not exist then fail gracefully (i.e. don't support XPRESS decompress).
* https://github.com/coderforlife/ms-compress   (License: GPLv3)
*/
NTSTATUS OSCOMPAT_RtlDecompressBufferEx(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG  UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG  CompressedBufferSize, PULONG FinalUncompressedSize, PVOID pv)
{
    int rc;
    void *lib_mscompress;
    SIZE_T cbOut;
    static BOOL fFirst = TRUE;
    static SRWLOCK LockSRW = SRWLOCK_INIT;
    static int(*pfn_xpress_decompress)(PBYTE pbIn, SIZE_T cbIn, PBYTE pbOut, SIZE_T *pcbOut) = NULL;
    static int(*pfn_xpress_decompress_huff)(PBYTE pbIn, SIZE_T cbIn, PBYTE pbOut, SIZE_T * pcbOut) = NULL;
    CHAR szPathLib[MAX_PATH] = { 0 };
    Util_GetPathLib(szPathLib);
    strncat_s(szPathLib, sizeof(szPathLib), "libMSCompression.so", _TRUNCATE);
    if((CompressionFormat != 3) && (CompressionFormat != 4)) { return HIBR_STATUS_UNSUCCESSFUL; } // 3 == COMPRESS_ALGORITHM_XPRESS, 4 == COMPRESS_ALGORITHM_XPRESS_HUFF
    if(fFirst) {
        AcquireSRWLockExclusive(&LockSRW);
        if(fFirst) {
            fFirst = FALSE;
            lib_mscompress = dlopen(szPathLib, RTLD_NOW);
            if(lib_mscompress) {
                pfn_xpress_decompress = (int(*)(PBYTE, SIZE_T, PBYTE, SIZE_T *))dlsym(lib_mscompress, "xpress_decompress");
                pfn_xpress_decompress_huff = (int(*)(PBYTE, SIZE_T, PBYTE, SIZE_T *))dlsym(lib_mscompress, "xpress_huff_decompress");
            }
        }
        ReleaseSRWLockExclusive(&LockSRW);
    }
    *FinalUncompressedSize = 0;
    if(pfn_xpress_decompress && pfn_xpress_decompress_huff) {
        cbOut = UncompressedBufferSize;
        rc = (CompressionFormat == 4) ?
            pfn_xpress_decompress_huff(CompressedBuffer, CompressedBufferSize, UncompressedBuffer, &cbOut) :
            pfn_xpress_decompress(CompressedBuffer, CompressedBufferSize, UncompressedBuffer, &cbOut);
        if(rc == 0) {
            *FinalUncompressedSize = cbOut;
            return HIBR_STATUS_SUCCESS;
        }
    }
    return HIBR_STATUS_UNSUCCESSFUL;
}


/*
* Verify that the compression library is available.
* -- ctx
* -- return = TRUE on success, FALSE on failure.
*/
_Success_(return)
BOOL DeviceHibr_InitializeFunctions(_In_ PDEVICE_CONTEXT_FILE ctx)
{
    void *lib_mscompress;
    CHAR szPathLib[MAX_PATH] = { 0 };
    Util_GetPathLib(szPathLib);
    strncat_s(szPathLib, sizeof(szPathLib), "libMSCompression.so", _TRUNCATE);
    lib_mscompress = dlopen(szPathLib, RTLD_NOW);
    if(lib_mscompress) {
        dlclose(lib_mscompress);
        ctx->pfnRtlDecompressBufferExOpt = OSCOMPAT_RtlDecompressBufferEx;
        return TRUE;
    }
    return FALSE;
}
#endif /* LINUX */



//-----------------------------------------------------------------------------
// GENERAL 'DEVICE' FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Read a decompressed page. Either from the cache or from the hibernation file (and decompress it).
* -- ctxLC
* -- pCS
* -- iCS
* -- iPB
* -- return = pointer to decompressed page, or NULL on error.
*/
_Success_(return != NULL)
PBYTE DeviceHibr_ReadPage(_In_ PLC_CONTEXT ctxLC, _In_ PHIBR_COMPRESSION_SET pCS, _In_ DWORD iCS, _In_ DWORD iPG)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    NTSTATUS nt;
    PBYTE pbBufferUncompressed;
    DWORD i, cbUncompressed, cbUncompressedResult = 0;
    if(!iCS || (iPG > pCS->cpg) || (iPG >= 0x10)) { return NULL; }
    // 1: try to find page in cache:
    for(i = 0; i < HIBR_NUM_CACHE_ENTRIES; i++) {
        if(ctx->CS_Cache[i].iCS == iCS) {
            return ctx->CS_Cache[i].pb + (iPG * 0x1000);
        }
    }
    // 2: not found in cache, try fetch from hiberfil.sys:
    if(_fseeki64(ctx->hFile, pCS->o, SEEK_SET)) { return NULL; }
    if(fread(ctx->pbBufferCompressedData, 1, pCS->cb, ctx->hFile) != pCS->cb) { return NULL; }
    // 3: decompress buffer and store in cache:
    ctx->CS_Cache[ctx->iCsCacheNext].iCS = 0;
    cbUncompressed = 0x1000 * pCS->cpg;
    pbBufferUncompressed = ctx->CS_Cache[ctx->iCsCacheNext].pb;
    if(pCS->tp == COMPRESS_ALGORITHM_NONE) {
        memcpy(pbBufferUncompressed, ctx->pbBufferCompressedData, cbUncompressed);
        cbUncompressedResult = cbUncompressed;
        nt = HIBR_STATUS_SUCCESS;
    } else {
        nt = ctx->pfnRtlDecompressBufferExOpt(pCS->tp, pbBufferUncompressed, cbUncompressed, ctx->pbBufferCompressedData, pCS->cb, &cbUncompressedResult, ctx->pbWorkSpace);
    }
    if((nt == HIBR_STATUS_SUCCESS) && (cbUncompressed == cbUncompressedResult)) {
        ctx->CS_Cache[ctx->iCsCacheNext].iCS = iCS;
        ctx->iCsCacheNext = (ctx->iCsCacheNext + 1) % HIBR_NUM_CACHE_ENTRIES;
        return pbBufferUncompressed + (iPG * 0x1000);
    }
    if(!ctx->fWarningFirst) {
        ctx->fWarningFirst = TRUE;
        lcprintf(ctxLC, "DEVICE: HIBR: WARNING: Decompression failed. Should not happen [only shown once].\n");
    }
    return NULL;
}

/*
* Default scatter read function - to be called by LeechCore. This function is
* currently not supported to be called in a multi-threaded way.
* -- ctxLC
* -- cpMEMs
* -- ppMEMs
*/
VOID DeviceHibr_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    DWORD iMEM, iCS, iPG;
    QWORD qwPfn;
    PBYTE pbPage;
    PMEM_SCATTER pMEM;
    PHIBR_COMPRESSION_SET pCS;
    for(iMEM = 0; iMEM < cpMEMs; iMEM++) {
        pMEM = ppMEMs[iMEM];
        if(pMEM->f || (pMEM->qwA == (QWORD)-1)) { continue; }
        qwPfn = pMEM->qwA >> 12;
        if(qwPfn >= ctx->cPfns) { continue; }
        iCS = ctx->pdwPfn2CS[qwPfn] & 0x00ffffff;
        iPG = ctx->pdwPfn2CS[qwPfn] >> 24;
        pCS = &ctx->CS_Directory[HIBR_COMPRESSION_INDEX_DIRECTORY(iCS)]->v[HIBR_COMPRESSION_INDEX_TABLE(iCS)];
        if(!pCS || !pCS->cb) {
            // failed to find compression set, probably a zero page, mark as successful read.
            ZeroMemory(pMEM->pb, pMEM->cb);
            pMEM->f = TRUE;
            continue;
        }
        pbPage = DeviceHibr_ReadPage(ctxLC, pCS, iCS, iPG);
        if(pbPage) {
            memcpy(pMEM->pb, pbPage + (pMEM->qwA & 0xfff), pMEM->cb);
            pMEM->f = TRUE;
        }
        if(pMEM->f) {
            if(ctxLC->fPrintf[LC_PRINTF_VVV]) {
                lcprintf_fn(
                    ctxLC,
                    "READ:\n        offset=%016llx req_len=%08x\n",
                    pMEM->qwA,
                    pMEM->cb
                );
            }
        } else {
            lcprintfvvv_fn(ctxLC, "READ FAILED:\n        offset=%016llx req_len=%08x\n", pMEM->qwA, pMEM->cb);
        }
    }
}

/*
* Parse a hibernation file restoration set consisting of multiple compression sets.
* -- ctx
* -- cbo
* -- cPageTotal
*/
VOID DeviceHibr_HibrInitialize_RestoreSet(_In_ PLC_CONTEXT ctxLC, _In_ QWORD cbo, _In_ QWORD cPageTotal)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    BOOL fWarning = FALSE;
    BYTE i, j, cDescCS;
    BYTE pb[0x1000];
    QWORD iDescPfn, qwStatusPGD;
    DWORD cDescPages, dwStatusCS, pbo, dwPfnOffsetPGD;
    PHIBR_COMPRESSION_SET pCS;
    if(!cPageTotal) { return; }
restart:
    // 1: fetch next compression set from context (allocate new empty if needed):
    if(0 == (ctx->cCS % HIBR_COMPRESSION_TABLE_SIZE)) {
        if((ctx->cCS + HIBR_COMPRESSION_DIRECTORY_SIZE) > 0x00ffffff) { return; }
        if(ctx->cCS == HIBR_COMPRESSION_TABLE_SIZE * HIBR_COMPRESSION_DIRECTORY_SIZE) { return; }
        if(!(ctx->CS_Directory[HIBR_COMPRESSION_INDEX_DIRECTORY(ctx->cCS)] = (PHIBR_COMPRESSION_SET_TABLE)LocalAlloc(LMEM_ZEROINIT, sizeof(HIBR_COMPRESSION_SET_TABLE)))) { return; }
    }
    pCS = &ctx->CS_Directory[HIBR_COMPRESSION_INDEX_DIRECTORY(ctx->cCS)]->v[HIBR_COMPRESSION_INDEX_TABLE(ctx->cCS)];
    // 2: fetch, from hibernation file, compression set header & parse compression set status dword:
    if(_fseeki64(ctx->hFile, cbo, SEEK_SET)) { return; }
    if(fread(pb, 1, sizeof(pb), ctx->hFile) != sizeof(pb)) { return; }
    dwStatusCS = *(PDWORD)(pb + 0x000);
    cDescCS = dwStatusCS & 0xff;
    pCS->cb = (dwStatusCS >> 8) & 0x3fffff;
    pCS->tp = (dwStatusCS & 0x80000000) ? COMPRESS_ALGORITHM_XPRESS_HUFF : COMPRESS_ALGORITHM_XPRESS;
    if(!cDescCS || !pCS->cb) { return; }
    // 2: iterate over page descriptors in the compression set.
    pbo = 4;
    for(i = 0; i < cDescCS; i++) {
        if(ctx->f32) {
            qwStatusPGD = *(PDWORD)(pb + pbo);
            pbo += 4;
        } else {
            qwStatusPGD = *(PQWORD)(pb + pbo);
            pbo += 8;
        }
        cDescPages = 1 + (qwStatusPGD & 0xf);
        iDescPfn = qwStatusPGD >> 4;
        // 2.1: store pfn -> cs mapping:
        if(iDescPfn + cDescPages < ctx->cPfns) {
            for(j = 0; j < cDescPages; j++) {
                dwPfnOffsetPGD = pCS->cpg + j;
                ctx->pdwPfn2CS[iDescPfn + j] = (dwPfnOffsetPGD << 24) | ctx->cCS;
            }
        }
        pCS->cpg += (WORD)cDescPages;
    }
    if((pCS->cpg > 0x10) && !fWarning) {
        lcprintf(ctxLC, "DEVICE: HIBR: WARNING: COMPRESSION SET #PAGES > 10 (only showed once).\n");
        fWarning = TRUE;
    }
    if(pCS->cb == ((DWORD)pCS->cpg << 12)) {
        pCS->tp = COMPRESS_ALGORITHM_NONE;
    }
    pCS->o = cbo + pbo;
    ctx->cCS++;
    cbo += pbo + pCS->cb;
    if(cPageTotal > pCS->cpg) {
        cPageTotal -= pCS->cpg;
        goto restart;
    }
}

/*
* Parse and initialize the hibernation file:
* -- ctxLC
* -- return = FALSE on fatal non-recoverable error, otherwise TRUE.
*/
_Success_(return)
BOOL DeviceHibr_HibrInitialize(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    BYTE pb[0x1000];
    DWORD i, cbPO_MEMORY_IMAGE;
    QWORD cboRestoreBoot = 0, cboRestoreKernel = 0, cPagesLoader = 0, cPagesKernel = 0;
    // 1: fetch header:
    if(_fseeki64(ctx->hFile, 0, SEEK_SET)) { goto fail; }
    if(fread(pb, 1, sizeof(pb), ctx->hFile) != sizeof(pb)) { goto fail; }
    if((*(PDWORD)(pb + 0x000) != HIBR_MAGIC) && (*(PDWORD)(pb + 0x000) != WAKE_MAGIC)) { goto fail; }
    // 2: fetch offsets to use by looking at struct length:
    cbPO_MEMORY_IMAGE = *(PDWORD)(pb + 0x00c);
    for(i = 0; i < _countof(HIBR_OFFSET_PROFILES); i++) {
        if(HIBR_OFFSET_PROFILES[i].LengthSelf == cbPO_MEMORY_IMAGE) {
            ctx->po = (PHIBR_OFFSET)&HIBR_OFFSET_PROFILES[i];
            ctx->f32 = ctx->po->f32;
            break;
        }
    }
    if(!ctx->po) {
        lcprintf(ctxLC, "DEVICE: HIBR: FAIL: Unable to determine hibernation profile (size=%i).\n", cbPO_MEMORY_IMAGE);
        goto fail;
    }
    if(0x1000 != *(PDWORD)(pb + ctx->po->PageSize)) {
        lcprintf(ctxLC, "DEVICE: HIBR: FAIL: Unsupported page size: %llu.\n", *(PQWORD)(pb + ctx->po->PageSize));
        goto fail;
    }
    // 3: fetch offsets and pages for boot and kernel restoration sets:
    cPagesLoader = *(PQWORD)(pb + ctx->po->NumPagesForLoader);
    cPagesKernel = *(PQWORD)(pb + ctx->po->KernelPagesProcessed);
    cboRestoreBoot = 0x1000 * (QWORD)VMM_PTR_OFFSET(ctx->f32, pb, ctx->po->FirstBootRestorePage);
    cboRestoreKernel = 0x1000 * (QWORD)VMM_PTR_OFFSET(ctx->f32, pb, ctx->po->FirstKernelRestorePage);
    // 4: fetch highest physical page and calculate max memory:
    ctx->cPfns = VMM_PTR_OFFSET(ctx->f32, pb, ctx->po->HighestPhysicalPage) + 1;
    if((ctx->cPfns < 0x1000) || (ctx->cPfns > 0x14000000)) {
        lcprintf(ctxLC, "DEVICE: HIBR: FAIL: Hibernation set shows incorrect memory dump size: %llu pages.\n", ctx->cPfns);
        goto fail;
    }
    if(!(ctx->pdwPfn2CS = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)ctx->cPfns * sizeof(DWORD)))) {
        lcprintf(ctxLC, "DEVICE: HIBR: FAIL: Out of memory, #PFNs: %llu.\n", ctx->cPfns);
        goto fail;
    }
    // 5: process restoration sets:
    DeviceHibr_HibrInitialize_RestoreSet(ctxLC, cboRestoreBoot, cPagesLoader);
    DeviceHibr_HibrInitialize_RestoreSet(ctxLC, cboRestoreKernel, cPagesKernel);
    if(ctx->cCS < 0x10) {
        lcprintf(ctxLC, "DEVICE: HIBR: FAIL: Too few compression sets found: %i.\n", ctx->cCS);
        goto fail;
    }
    return TRUE;
fail:
    return FALSE;
}



//-----------------------------------------------------------------------------
// OPEN/CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

VOID DeviceHibr_CloseInternal(_Frees_ptr_opt_ PDEVICE_CONTEXT_FILE ctx)
{
    DWORD i;
    if(ctx) {
        if(ctx->hFile) { fclose(ctx->hFile); }
        for(i = 0; (i < HIBR_COMPRESSION_DIRECTORY_SIZE) && ctx->CS_Directory[i]; i++) {
            LocalFree(ctx->CS_Directory[i]);
        }
        LocalFree(ctx->pdwPfn2CS);
        LocalFree(ctx);
    }
}

VOID DeviceHibr_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FILE ctx = (PDEVICE_CONTEXT_FILE)ctxLC->hDevice;
    DeviceHibr_CloseInternal(ctx);
}

#define DEVICE_FILE_PARAMETER_FILE                  "file"

/*
* Open a Windows hibernation file. Syntax: -device hibr://file=<filename>
* -- ctxLC
* -- ppLcCreateErrorInfo
* -- return = TRUE on success, FALSE on failure.
*/
_Success_(return)
BOOL DeviceHIBR_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    PDEVICE_CONTEXT_FILE ctx;
    PLC_DEVICE_PARAMETER_ENTRY pParam;
    QWORD tmEnd = 0, tmStart = GetTickCount64();
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    if(!(ctx = (PDEVICE_CONTEXT_FILE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FILE)))) { return FALSE; }
    if(!(ctx->CS_Directory[0] = (PHIBR_COMPRESSION_SET_TABLE)LocalAlloc(LMEM_ZEROINIT, sizeof(HIBR_COMPRESSION_SET_TABLE)))) { goto fail; }
    ctx->cCS = 1;   // 0 = reserved for invalid/not set compression set.
    if(0 == _strnicmp("hibr://", ctxLC->Config.szDevice, 7)) {
        if((pParam = LcDeviceParameterGet(ctxLC, DEVICE_FILE_PARAMETER_FILE)) && pParam->szValue[0]) {
            strncpy_s(ctx->szFileName, _countof(ctx->szFileName), pParam->szValue, _TRUNCATE);
        }
    }
    if(!ctx->szFileName[0]) { goto fail; }
    lcprintfv(ctxLC, "DEVICE: HIBR: OPEN: '%s'\n", ctx->szFileName);
    // initialize decompression:
    if(!DeviceHibr_InitializeFunctions(ctx)) {
        lcprintf(ctxLC, "DEVICE: HIBR: Failed to load compression function [libMSCompression.so missing?].\n");
        goto fail;
    }
    // open backing file:
    if(fopen_s(&ctx->hFile, ctx->szFileName, "rb") || !ctx->hFile) { goto fail; }
    if(_fseeki64(ctx->hFile, 0, SEEK_END)) { goto fail; }       // seek to end of file
    ctx->cbFile = _ftelli64(ctx->hFile);                        // get current file pointer
    if(ctx->cbFile < 0x01000000) { goto fail; }                 // minimum allowed file size = 16MB
    if(ctx->cbFile > 0xffff000000000000) { goto fail; }         // file too large
    // set callback functions and fix up config:
    ctxLC->hDevice = (HANDLE)ctx;
    ctxLC->pfnClose = DeviceHibr_Close;
    ctxLC->pfnReadScatter = DeviceHibr_ReadScatter;
    if(!DeviceHibr_HibrInitialize(ctxLC)) { ctxLC->hDevice = NULL; goto fail; }
    ctxLC->Config.paMax = ctx->cPfns * 0x1000;
    // print result and return:
    tmEnd = GetTickCount64();
    lcprintfv(ctxLC, "DEVICE: HIBR: Successfully hibernation file in %llus.\n", (tmEnd - tmStart) / 1000);
    return TRUE;
fail:
    DeviceHibr_CloseInternal(ctx);
    lcprintf(ctxLC, "DEVICE: HIBR: ERROR: Failed opening file: '%s'.\n", ctxLC->Config.szDevice);
    return FALSE;
}
