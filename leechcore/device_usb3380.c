// device_usb3380.c : implementation related to the USB3380 hardware device.
//
// (c) Ulf Frisk, 2017-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "memmap.h"

#define CSR_BYTE0                           0x01
#define CSR_BYTE1                           0x02
#define CSR_BYTE2                           0x04
#define CSR_BYTE3                           0x08
#define CSR_BYTEALL                         0x0f
#define CSR_CONFIGSPACE_PCIE                0x00
#define CSR_CONFIGSPACE_MEMM                0x10
#define CSR_CONFIGSPACE_8051                0x20
#define REG_USBSTAT                         0x90
#define REG_USBCTL2                         0xc8
#define REG_DMACTL_0                        0x180
#define REG_DMASTAT_0                       0x184
#define REG_DMACOUNT_0                      0x190
#define REG_DMAADDR_0                       0x194
#define REG_FIFOSTAT_0                      0x32c
#define REG_DMACTL_1                        0x1a0
#define REG_DMASTAT_1                       0x1a4
#define REG_DMACOUNT_1                      0x1b0
#define REG_DMAADDR_1                       0x1b4
#define REG_DMACTL_2                        0x1c0
#define REG_DMASTAT_2                       0x1c4
#define REG_DMACOUNT_2                      0x1d0
#define REG_DMAADDR_2                       0x1d4
#define REG_DMACTL_3                        0x1e0
#define REG_DMASTAT_3                       0x1e4
#define REG_DMACOUNT_3                      0x1f0
#define REG_DMAADDR_3                       0x1f4
#define REG_PCI_STATCMD                     0x04
#define USB_EP_PCIIN                        0x8e
#define USB_EP_PCIOUT                       0x0e
#define USB_EP_CSRIN                        0x8d
#define USB_EP_CSROUT                       0x0d
#define USB_EP_DMAOUT                       0x02
#define USB_EP_DMAIN1                       0x84
#define USB_EP_DMAIN2                       0x86
#define USB_EP_DMAIN3                       0x88

typedef struct tdEP_INFO {
    UCHAR pipe;
    WORD rCTL;
    WORD rSTAT;
    WORD rCOUNT;
    WORD rADDR;
} EP_INFO, *PEP_INFO;

EP_INFO CEP_INFO[3] = {
    {.pipe = USB_EP_DMAIN1,.rCTL = REG_DMACTL_1,.rSTAT = REG_DMASTAT_1,.rCOUNT = REG_DMACOUNT_1,.rADDR = REG_DMAADDR_1 },
    {.pipe = USB_EP_DMAIN2,.rCTL = REG_DMACTL_2,.rSTAT = REG_DMASTAT_2,.rCOUNT = REG_DMACOUNT_2,.rADDR = REG_DMAADDR_2 },
    {.pipe = USB_EP_DMAIN3,.rCTL = REG_DMACTL_3,.rSTAT = REG_DMASTAT_3,.rCOUNT = REG_DMACOUNT_3,.rADDR = REG_DMAADDR_3 }
};

typedef struct tdThreadDataReadEP {
    DWORD iEP;
    DWORD pa;
    DWORD cb;
    PBYTE pb;
    BOOL isFinished;
    BOOL result;
    PPMEM_IO_SCATTER_HEADER ppMEMs;
    DWORD cpMEMs;
} THREAD_DATA_READ_EP, *PTHREAD_DATA_READ_EP;

typedef struct _DEVICE_DATA {
    BOOL HandlesOpen;
    BOOL fMultiThreadDMA;
    WINUSB_INTERFACE_HANDLE WinusbHandle;
    HANDLE DeviceHandle;
    WCHAR DevicePath[MAX_PATH];
    THREAD_DATA_READ_EP ptd[3];
    BYTE pb18M[0x01200000];
} DEVICE_DATA, *PDEVICE_DATA;

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct tdPipeSendCsrWrite {
    UCHAR u1;
    UCHAR u2;
    UCHAR u3;
    UCHAR u4;
    DWORD dwRegValue;
} PIPE_SEND_CSR_WRITE;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

typedef struct _DEVICE_MEMORY_RANGE {
    DWORD BaseAddress;
    DWORD TopAddress;
} DEVICE_MEMORY_RANGE, *PDEVICE_MEMORY_RANGE;

#define NUMBER_OF_DEVICE_RESERVED_MEMORY_RANGES 2
DEVICE_MEMORY_RANGE CDEVICE_RESERVED_MEMORY_RANGES[NUMBER_OF_DEVICE_RESERVED_MEMORY_RANGES] = {
    {.BaseAddress = 0x000A0000,.TopAddress = 0x000FFFFF }, // SMM LOWER
    {.BaseAddress = 0xF0000000,.TopAddress = 0xFFFFFFFF }, // PCI SPACE
};

BOOL Device3380_WriteCsr(_In_ WORD wRegAddr, _In_ DWORD dwRegValue, _In_ BYTE fCSR)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    DWORD cbTransferred;
    PIPE_SEND_CSR_WRITE ps = { .u1 = fCSR | 0x40,.u2 = 0,.u3 = wRegAddr & 0xFF,.u4 = (wRegAddr >> 8) & 0xFF,.dwRegValue = dwRegValue };
    if(wRegAddr & 0x03) { return FALSE; } // must be dword aligned
    return WinUsb_WritePipe(ctx->WinusbHandle, USB_EP_CSROUT, (PUCHAR)&ps, sizeof(ps), &cbTransferred, NULL);
}

BOOL Device3380_ReadCsr(_In_ WORD wRegAddr, _Out_ PDWORD pdwRegValue, _In_ BYTE fCSR)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    DWORD cbTransferred;
    PIPE_SEND_CSR_WRITE ps = { .u1 = fCSR | 0xcf,.u2 = 0,.u3 = wRegAddr & 0xff,.u4 = (wRegAddr >> 8) & 0xff,.dwRegValue = 0 };
    if(wRegAddr & 0x03) { return FALSE; } // must be dword aligned
    return
        WinUsb_WritePipe(ctx->WinusbHandle, USB_EP_CSROUT, (PUCHAR)&ps, sizeof(ps), &cbTransferred, NULL) &&
        WinUsb_ReadPipe(ctx->WinusbHandle, USB_EP_CSRIN, (PUCHAR)pdwRegValue, 4, &cbTransferred, NULL);
}

BOOL Device3380_ReadDMA_Retry(PTHREAD_DATA_READ_EP ptd)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    BOOL result;
    DWORD cbTransferred;
    Device3380_WriteCsr(CEP_INFO[ptd->iEP].rCTL, 0xc2, CSR_CONFIGSPACE_MEMM | CSR_BYTE0); // DMA_ENABLE
    Device3380_WriteCsr(CEP_INFO[ptd->iEP].rADDR, ptd->pa, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
    Device3380_WriteCsr(CEP_INFO[ptd->iEP].rCOUNT, 0x40000000 | ptd->cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
    Device3380_WriteCsr(CEP_INFO[ptd->iEP].rSTAT, 0x080000c1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
    Device3380_WriteCsr(REG_PCI_STATCMD, 0x07, CSR_CONFIGSPACE_PCIE | CSR_BYTE0); // BUS_MASTER ??? needed ???
    result = WinUsb_ReadPipe(ctx->WinusbHandle, CEP_INFO[ptd->iEP].pipe, ptd->pb, ptd->cb, &cbTransferred, NULL);
    return result;
}

VOID Device3380_ReadDMA2(PTHREAD_DATA_READ_EP ptd)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    DWORD dwTimeout, cbTransferred;
    // set EP timeout value on conservative usb2 assumptions (3 parallel reads, 35MB/s total speed)
    // (XMB * 1000 * 3) / (35 * 1024 * 1024) -> 0x2fc9 ~> 0x3000 :: 4k->64ms, 5.3M->520ms
    dwTimeout = 64 + ptd->cb / 0x3000;
    WinUsb_SetPipePolicy(ctx->WinusbHandle, CEP_INFO[ptd->iEP].pipe, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &dwTimeout);
    // perform memory read
    Device3380_WriteCsr(CEP_INFO[ptd->iEP].rADDR, ptd->pa, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
    Device3380_WriteCsr(CEP_INFO[ptd->iEP].rCOUNT, 0x40000000 | ptd->cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
    Device3380_WriteCsr(CEP_INFO[ptd->iEP].rSTAT, 0x080000c1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
    ptd->result = WinUsb_ReadPipe(ctx->WinusbHandle, CEP_INFO[ptd->iEP].pipe, ptd->pb, ptd->cb, &cbTransferred, NULL);
    if(!ptd->result) {
        ptd->result = Device3380_ReadDMA_Retry(ptd);
    }
    ptd->isFinished = TRUE;
}

PTHREAD_DATA_READ_EP ReadScatterGather_Thread3_Collect(_In_ BOOL fAll)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    PTHREAD_DATA_READ_EP ptd;
    DWORD i, iMEM, cbMEM;
    // 1: If fAll is specified wait for all reads to complete!
    while(fAll && (!ctx->ptd[0].isFinished || !ctx->ptd[1].isFinished || !ctx->ptd[2].isFinished)) {
        SwitchToThread();
    }
    // 2: Collect a single finished read and return the PTHREAD_DATA_READ_EP for re-use, or collect all reads.
    while(TRUE) {
        for(i = 0; i < 3; i++) {
            ptd = ctx->ptd + i;
            if(ptd->isFinished) {
                if(ptd->result) {
                    // fill successful mem reads
                    for(iMEM = 0, cbMEM = 0; iMEM < ptd->cpMEMs; iMEM++) {
                        ptd->ppMEMs[iMEM]->cb = ptd->ppMEMs[iMEM]->cbMax;
                        memcpy(ptd->ppMEMs[iMEM]->pb, ptd->pb + cbMEM, ptd->ppMEMs[iMEM]->cb);
                        cbMEM += ptd->ppMEMs[iMEM]->cb;
                    }
                }
                if(!fAll) { return ptd; }  // return 1st finished 'single' for re-use if fAll not specified.
                if(i == 2) { return ptd; } // return once all is processed if fAll is specified.
            }
        }
        SwitchToThread();
    }
}

VOID ReadScatterGather_Thread3_Queue(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD pa, _In_ DWORD cb)
{
    PTHREAD_DATA_READ_EP ptd = ReadScatterGather_Thread3_Collect(FALSE);
    ptd->isFinished = FALSE;
    ptd->result = FALSE;
    ptd->pa = pa;
    ptd->cb = cb;
    ptd->ppMEMs = ppMEMs;
    ptd->cpMEMs = cpMEMs;
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Device3380_ReadDMA2, ptd, 0, NULL);
}

VOID ReadScatterGather_Thread3(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD cbThreadLimit)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    PMEM_IO_SCATTER_HEADER pMEM;
    QWORD i, iBase = 0;
    DWORD c = 0, paBase = 0, cbCurrent = 0;
    ZeroMemory(ctx->ptd, sizeof(ctx->ptd));
    for(i = 0; i < 3; i++) {
        ctx->ptd[i].iEP = (DWORD)i;
        ctx->ptd[i].pb = ctx->pb18M + (i * 0x00600000); // 6MB per thread
        ctx->ptd[i].isFinished = TRUE;
    }
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(!MemMap_VerifyTranslateMEM(pMEM, NULL)) { continue; }
        if(c == 0) {
            if(pMEM->cbMax && (pMEM->cb != pMEM->cbMax)) {
                c = 1;
                iBase = i;
                paBase = (DWORD)pMEM->qwA;
                cbCurrent = pMEM->cbMax;
            }
        } else if((paBase + cbCurrent == pMEM->qwA) && (cbCurrent < cbThreadLimit)) {
            c++;
            cbCurrent += pMEM->cbMax;
        } else {
            ReadScatterGather_Thread3_Queue(ppMEMs + iBase, c, paBase, cbCurrent);
            c = 0;
            if(pMEM->cbMax && (pMEM->cb != pMEM->cbMax)) {
                c = 1;
                iBase = i;
                paBase = (DWORD)pMEM->qwA;
                cbCurrent = pMEM->cbMax;
            }
        }
    }
    if(c) {
        ReadScatterGather_Thread3_Queue(ppMEMs + iBase, c, paBase, cbCurrent);
    }
    ReadScatterGather_Thread3_Collect(TRUE);
}

VOID ReadScatterGather_Thread1_QueueCollect(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD pa, _In_ DWORD cb)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    PTHREAD_DATA_READ_EP ptd = ctx->ptd;
    DWORD iMEM, cbMEM;
    ptd->result = FALSE;
    ptd->pa = pa;
    ptd->cb = cb;
    Device3380_ReadDMA2(ptd);
    if(ptd->result) {
        // fill successful mem reads
        for(iMEM = 0, cbMEM = 0; iMEM < cpMEMs; iMEM++) {
            ppMEMs[iMEM]->cb = ppMEMs[iMEM]->cbMax;
            memcpy(ppMEMs[iMEM]->pb, ptd->pb + cbMEM, ppMEMs[iMEM]->cb);
            cbMEM += ppMEMs[iMEM]->cb;
        }
    }
}

VOID ReadScatterGather_Thread1(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    PTHREAD_DATA_READ_EP ptd = ctx->ptd;
    PMEM_IO_SCATTER_HEADER pMEM;
    DWORD i, c = 0, iBase = 0, paBase = 0, cbCurrent = 0;
    ZeroMemory(ctx->ptd, sizeof(THREAD_DATA_READ_EP));
    ptd->pb = ctx->pb18M;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(!MemMap_VerifyTranslateMEM(pMEM, NULL)) { continue; }
        if(c == 0) {
            if(pMEM->cbMax && (pMEM->cb != pMEM->cbMax)) {
                c = 1;
                iBase = i;
                paBase = (DWORD)pMEM->qwA;
                cbCurrent = pMEM->cbMax;
            }
        } else if((paBase + cbCurrent == pMEM->qwA) && (cbCurrent + pMEM->cbMax <= 0x00800000)) {
            c++;
            cbCurrent += pMEM->cbMax;
        } else {
            ReadScatterGather_Thread1_QueueCollect(ppMEMs + iBase, c, paBase, cbCurrent);
            c = 0;
            if(pMEM->cbMax && (pMEM->cb != pMEM->cbMax)) {
                c = 1;
                iBase = i;
                paBase = (DWORD)pMEM->qwA;
                cbCurrent = pMEM->cbMax;
            }
        }
    }
    if(c) {
        ReadScatterGather_Thread1_QueueCollect(ppMEMs + iBase, c, paBase, cbCurrent);
    }
}

VOID Device3380_ReadScatterGather(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    DWORD cbThreadLimit, cpMEMsMax;
    cpMEMsMax = max(1, (DWORD)(ctxDeviceMain->cfg.cbMaxSizeMemIo >> 12));
    if(cpMEMs > cpMEMsMax) {
        while(TRUE) {
            Device3380_ReadScatterGather(ppMEMs, min(cpMEMsMax, cpMEMs));
            ppMEMs = ppMEMs + min(cpMEMsMax, cpMEMs);
            cpMEMs = cpMEMs - min(cpMEMsMax, cpMEMs);
            if(cpMEMs == 0) { return; }
        }
    }
    if(!ctx->fMultiThreadDMA || (cpMEMs <= 0x100)) {
        ReadScatterGather_Thread1(ppMEMs, cpMEMs);
    } else {
        cbThreadLimit = 0x1000 * (1 + (cpMEMs / 3));
        ReadScatterGather_Thread3(ppMEMs, cpMEMs, cbThreadLimit);
    }
}

BOOL Device3380_WriteDMA(_In_ QWORD pa, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    BOOL result;
    DWORD cbTransferred;
    if(pa + cb > 0x100000000) { return FALSE; }
    Device3380_WriteCsr(REG_FIFOSTAT_0, 0xffffffff, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // USB_FIFO0 FLUSH
    Device3380_WriteCsr(REG_DMACTL_0, 0xc2, CSR_CONFIGSPACE_MEMM | CSR_BYTE0); // DMA_ENABLE
    Device3380_WriteCsr(REG_DMAADDR_0, (DWORD)pa, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
    Device3380_WriteCsr(REG_DMACOUNT_0, 0x00000000 | cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
    Device3380_WriteCsr(REG_DMASTAT_0, 0x080000d1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
    Device3380_WriteCsr(REG_PCI_STATCMD, 0x07, CSR_CONFIGSPACE_PCIE | CSR_BYTE0); // BUS_MASTER ??? needed ???
    result = WinUsb_WritePipe(ctx->WinusbHandle, USB_EP_DMAOUT, pb, cb, &cbTransferred, NULL);
    Device3380_WriteCsr(REG_DMASTAT_0, 0x080000d1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT - must be here for 1st transfer to work.
    return result;
}

BOOL Device3380_Open2();

VOID Device3380_Close()
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    if(!ctx) { return; }
    if(!ctx->HandlesOpen) { return; }
    WinUsb_Free(ctx->WinusbHandle);
    if(ctx->DeviceHandle) { CloseHandle(ctx->DeviceHandle); }
    ctx->HandlesOpen = FALSE;
    LocalFree(ctx);
    ctxDeviceMain->hDevice = 0;
}

BOOL Device3380_Open()
{
    BOOL result;
    DWORD dwReg;
    QWORD paMax;
    result = Device3380_Open2();
    if(!result) { return FALSE; }
    Device3380_ReadCsr(REG_USBSTAT, &dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL);
    if((0 == _strnicmp("usb3380://usb2", ctxDeviceMain->cfg.szDevice, 15)) && (dwReg & 0x0100 /* Super-Speed(USB3) */)) {
        printf("Device Info: USB3380 running at USB3 speed; downgrading to USB2 ...\n");
        dwReg = 0x04; // USB2=ENABLE, USB3=DISABLE
        Device3380_WriteCsr(REG_USBCTL2, dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTE0);
        Device3380_Close();
        Sleep(1000);
        result = Device3380_Open2();
        if(!result) { return FALSE; }
        Device3380_ReadCsr(REG_USBSTAT, &dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL);
    }
    if(dwReg & 0xc0 /* Full-Speed(USB1)|High-Speed(USB2) */) {
        vprintf("Device Info: USB3380 running at USB2 speed.\n");
    } else {
        vprintfv("Device Info: USB3380 running at USB3 speed.\n");
    }
    vprintfv("Device Info: USB3380.\n");
    // set callback functions and fix up config
    ctxDeviceMain->cfg.tpDevice = LEECHCORE_DEVICE_USB3380;
    ctxDeviceMain->cfg.fVolatile = TRUE;
    ctxDeviceMain->cfg.cbMaxSizeMemIo = ctxDeviceMain->cfg.cbMaxSizeMemIo ? min(ctxDeviceMain->cfg.cbMaxSizeMemIo, 0x01000000) : 0x01000000; // 16MB (or lower user-value)
    ctxDeviceMain->cfg.paMaxNative = 0x00000000ffffffff;
    ctxDeviceMain->pfnClose = Device3380_Close;
    ctxDeviceMain->pfnReadScatterMEM = Device3380_ReadScatterGather;
    ctxDeviceMain->pfnWriteMEM = Device3380_WriteDMA;
    // initialize memory map
    paMax = min(ctxDeviceMain->cfg.paMax, ctxDeviceMain->cfg.paMaxNative);
    MemMap_Initialize(paMax);
    MemMap_AddRange(0x00000000, min(0x000A0000, paMax), 0x00000000);
    // ... SMM LOWER 0x000A0000-0x000FFFFF
    MemMap_AddRange(0x00100000, min(0xF0000000, paMax) - 0x00100000, 0x00100000);
    // ... PCI SPACE 0xF0000000-0xFFFFFFFF
    return TRUE;
}

#ifdef _WIN32

#include <versionhelpers.h>

// Device Interface GUID. Must match "DeviceInterfaceGUIDs" registry value specified in the INF file.
// F72FE0D4-CBCB-407d-8814-9ED673D0DD6B
DEFINE_GUID(GUID_DEVINTERFACE_android, 0xF72FE0D4, 0xCBCB, 0x407d, 0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B);

BOOL Device3380_RetrievePath(_Out_bytecap_(BufLen) LPWSTR wszDevicePath, _In_ ULONG BufLen)
{
    BOOL result;
    HDEVINFO deviceInfo;
    SP_DEVICE_INTERFACE_DATA interfaceData;
    PSP_DEVICE_INTERFACE_DETAIL_DATA detailData = NULL;
    ULONG length, requiredLength = 0;
    deviceInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_android, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if(deviceInfo == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
    result = SetupDiEnumDeviceInterfaces(deviceInfo, NULL, &GUID_DEVINTERFACE_android, 0, &interfaceData);
    if(!result) {
        SetupDiDestroyDeviceInfoList(deviceInfo);
        return FALSE;
    }
    result = SetupDiGetDeviceInterfaceDetail(deviceInfo, &interfaceData, NULL, 0, &requiredLength, NULL);
    if(!result && ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
        SetupDiDestroyDeviceInfoList(deviceInfo);
        return FALSE;
    }
    detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)LocalAlloc(LMEM_FIXED, requiredLength);
    if(!detailData) {
        SetupDiDestroyDeviceInfoList(deviceInfo);
        return FALSE;
    }
    detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
    length = requiredLength;
    result = SetupDiGetDeviceInterfaceDetail(deviceInfo, &interfaceData, detailData, length, &requiredLength, NULL);
    if(!result) {
        LocalFree(detailData);
        SetupDiDestroyDeviceInfoList(deviceInfo);
        return FALSE;
    }
    wcscpy_s(wszDevicePath, BufLen, (LPWSTR)detailData->DevicePath);
    LocalFree(detailData);
    SetupDiDestroyDeviceInfoList(deviceInfo);
    return TRUE;
}

VOID Device3380_Open_SetPipePolicy(_In_ PDEVICE_DATA pDeviceData)
{
    BOOL boolTRUE = TRUE;
    ULONG ulTIMEOUT = 500; // ms
    WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAOUT, AUTO_CLEAR_STALL, (ULONG)sizeof(BOOL), &boolTRUE);
    WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAOUT, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &ulTIMEOUT);
    WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN1, AUTO_CLEAR_STALL, (ULONG)sizeof(BOOL), &boolTRUE);
    WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN1, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &ulTIMEOUT);
    WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN2, AUTO_CLEAR_STALL, (ULONG)sizeof(BOOL), &boolTRUE);
    WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN2, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &ulTIMEOUT);
    WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN3, AUTO_CLEAR_STALL, (ULONG)sizeof(BOOL), &boolTRUE);
    WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN3, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &ulTIMEOUT);
}

BOOL Device3380_Open2()
{
    BOOL result;
    PDEVICE_DATA pDeviceData;
    if(!ctxDeviceMain->hDevice) {
        ctxDeviceMain->hDevice = (HANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_DATA));
        if(!ctxDeviceMain->hDevice) { return FALSE; }
    }
    pDeviceData = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    result = Device3380_RetrievePath(pDeviceData->DevicePath, MAX_PATH);
    if(!result) { return FALSE; }
    pDeviceData->DeviceHandle = CreateFile(pDeviceData->DevicePath,
        GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_WRITE | FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL);
    if(INVALID_HANDLE_VALUE == pDeviceData->DeviceHandle) {
        return FALSE;
    }
    result = WinUsb_Initialize(pDeviceData->DeviceHandle, &pDeviceData->WinusbHandle);
    if(!result) {
        CloseHandle(pDeviceData->DeviceHandle);
        return FALSE;
    }
    Device3380_Open_SetPipePolicy(pDeviceData);
    pDeviceData->HandlesOpen = TRUE;
    pDeviceData->fMultiThreadDMA = IsWindows8OrGreater(); // multi threaded DMA read fails on WIN7.
    return TRUE;
}

#endif /* _WIN32 */
#ifdef LINUX

BOOL Device3380_Open2()
{
    PDEVICE_DATA pDeviceData;
    if(libusb_init(NULL)) { return FALSE; }
    if(!ctxDeviceMain->hDevice) {
        ctxDeviceMain->hDevice = (HANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_DATA));
        if(!ctxDeviceMain->hDevice) { return FALSE; }
    }
    pDeviceData = (PDEVICE_DATA)ctxDeviceMain->hDevice;
    pDeviceData->WinusbHandle = libusb_open_device_with_vid_pid(NULL, 0x18d1, 0x9001);
    if(!pDeviceData->WinusbHandle) {
        libusb_exit(NULL);
        LocalFree(ctxDeviceMain->hDevice);
        ctxDeviceMain->hDevice = NULL;
        return FALSE;
    }
    libusb_claim_interface(pDeviceData->WinusbHandle, 0);
    pDeviceData->HandlesOpen = TRUE;
    // synchronous libusb bulk read/write doesn't seem to support multi threaded accesses.
    pDeviceData->fMultiThreadDMA = FALSE;
    return TRUE;
}

#endif /* LINUX */
