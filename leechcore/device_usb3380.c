// device_usb3380.c : implementation related to the USB3380 hardware device.
//
// (c) Ulf Frisk, 2017-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
#include "oscompatibility.h"

#define USB3380_MAX_PAGES_READ              0x1000

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

typedef struct _DEVICE_DATA {
    BOOL HandlesOpen;
    WINUSB_INTERFACE_HANDLE WinusbHandle;
    HANDLE DeviceHandle;
    WCHAR DevicePath[MAX_PATH];
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

_Success_(return)
BOOL Device3380_WriteCsr(_In_ PLC_CONTEXT ctxLC, _In_ WORD wRegAddr, _In_ DWORD dwRegValue, _In_ BYTE fCSR)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxLC->hDevice;
    DWORD cbTransferred;
    PIPE_SEND_CSR_WRITE ps = { .u1 = fCSR | 0x40,.u2 = 0,.u3 = wRegAddr & 0xFF,.u4 = (wRegAddr >> 8) & 0xFF,.dwRegValue = dwRegValue };
    if(wRegAddr & 0x03) { return FALSE; } // must be dword aligned
    return WinUsb_WritePipe(ctx->WinusbHandle, USB_EP_CSROUT, (PUCHAR)&ps, sizeof(ps), &cbTransferred, NULL);
}

_Success_(return)
BOOL Device3380_ReadCsr(_In_ PLC_CONTEXT ctxLC, _In_ WORD wRegAddr, _Out_ PDWORD pdwRegValue, _In_ BYTE fCSR)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxLC->hDevice;
    DWORD cbTransferred;
    PIPE_SEND_CSR_WRITE ps = { .u1 = fCSR | 0xcf,.u2 = 0,.u3 = wRegAddr & 0xff,.u4 = (wRegAddr >> 8) & 0xff,.dwRegValue = 0 };
    if(wRegAddr & 0x03) { return FALSE; } // must be dword aligned
    return
        WinUsb_WritePipe(ctx->WinusbHandle, USB_EP_CSROUT, (PUCHAR)&ps, sizeof(ps), &cbTransferred, NULL) &&
        WinUsb_ReadPipe(ctx->WinusbHandle, USB_EP_CSRIN, (PUCHAR)pdwRegValue, 4, &cbTransferred, NULL);
}

VOID Device3380_ReadContigious_Retry(_Inout_ PLC_READ_CONTIGIOUS_CONTEXT ctxRC)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxRC->ctxLC->hDevice;
    Device3380_WriteCsr(ctxRC->ctxLC, CEP_INFO[ctxRC->iRL].rCTL, 0xc2, CSR_CONFIGSPACE_MEMM | CSR_BYTE0); // DMA_ENABLE
    Device3380_WriteCsr(ctxRC->ctxLC, CEP_INFO[ctxRC->iRL].rADDR, (DWORD)ctxRC->paBase, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
    Device3380_WriteCsr(ctxRC->ctxLC, CEP_INFO[ctxRC->iRL].rCOUNT, 0x40000000 | ctxRC->cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
    Device3380_WriteCsr(ctxRC->ctxLC, CEP_INFO[ctxRC->iRL].rSTAT, 0x080000c1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
    Device3380_WriteCsr(ctxRC->ctxLC, REG_PCI_STATCMD, 0x07, CSR_CONFIGSPACE_PCIE | CSR_BYTE0); // BUS_MASTER ??? needed ???
    WinUsb_ReadPipe(ctx->WinusbHandle, CEP_INFO[ctxRC->iRL].pipe, ctxRC->pb, ctxRC->cb, &ctxRC->cbRead, NULL);
}

VOID Device3380_ReadContigious(_Inout_ PLC_READ_CONTIGIOUS_CONTEXT ctxRC)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxRC->ctxLC->hDevice;
    DWORD dwTimeout;
    // set EP timeout value on conservative usb2 assumptions (3 parallel reads, 35MB/s total speed)
    // (XMB * 1000 * 3) / (35 * 1024 * 1024) -> 0x2fc9 ~> 0x3000 :: 4k->64ms, 5.3M->520ms
    dwTimeout = 64 + ctxRC->cb / 0x3000;
    WinUsb_SetPipePolicy(ctx->WinusbHandle, CEP_INFO[ctxRC->iRL].pipe, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &dwTimeout);
    // perform memory read
    Device3380_WriteCsr(ctxRC->ctxLC, CEP_INFO[ctxRC->iRL].rADDR, (DWORD)ctxRC->paBase, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
    Device3380_WriteCsr(ctxRC->ctxLC, CEP_INFO[ctxRC->iRL].rCOUNT, 0x40000000 | ctxRC->cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
    Device3380_WriteCsr(ctxRC->ctxLC, CEP_INFO[ctxRC->iRL].rSTAT, 0x080000c1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
    if(!WinUsb_ReadPipe(ctx->WinusbHandle, CEP_INFO[ctxRC->iRL].pipe, ctxRC->pb, ctxRC->cb, &ctxRC->cbRead, NULL)) {
        Device3380_ReadContigious_Retry(ctxRC);
    }
}

_Success_(return)
BOOL Device3380_Write(_In_ PLC_CONTEXT ctxLC, _In_ QWORD pa, _In_ DWORD cb, _In_reads_(cb) PBYTE pb)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxLC->hDevice;
    BOOL result;
    DWORD cbTransferred;
    if(pa + cb > 0x100000000) { return FALSE; }
    Device3380_WriteCsr(ctxLC, REG_FIFOSTAT_0, 0xffffffff, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // USB_FIFO0 FLUSH
    Device3380_WriteCsr(ctxLC, REG_DMACTL_0, 0xc2, CSR_CONFIGSPACE_MEMM | CSR_BYTE0); // DMA_ENABLE
    Device3380_WriteCsr(ctxLC, REG_DMAADDR_0, (DWORD)pa, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
    Device3380_WriteCsr(ctxLC, REG_DMACOUNT_0, 0x00000000 | cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
    Device3380_WriteCsr(ctxLC, REG_DMASTAT_0, 0x080000d1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
    Device3380_WriteCsr(ctxLC, REG_PCI_STATCMD, 0x07, CSR_CONFIGSPACE_PCIE | CSR_BYTE0); // BUS_MASTER ??? needed ???
    result = WinUsb_WritePipe(ctx->WinusbHandle, USB_EP_DMAOUT, pb, cb, &cbTransferred, NULL);
    Device3380_WriteCsr(ctxLC, REG_DMASTAT_0, 0x080000d1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT - must be here for 1st transfer to work.
    return result;
}

_Success_(return) BOOL Device3380_Open2(_Inout_ PLC_CONTEXT ctxLC);

VOID Device3380_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_DATA ctx = (PDEVICE_DATA)ctxLC->hDevice;
    if(!ctx) { return; }
    if(!ctx->HandlesOpen) { return; }
    WinUsb_Free(ctx->WinusbHandle);
    if(ctx->DeviceHandle) { CloseHandle(ctx->DeviceHandle); }
    ctx->HandlesOpen = FALSE;
    LocalFree(ctx);
    ctxLC->hDevice = 0;
}

_Success_(return)
BOOL Device3380_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    BOOL result;
    DWORD dwReg;
    QWORD paMax;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    result = Device3380_Open2(ctxLC);
    if(!result) { return FALSE; }
    Device3380_ReadCsr(ctxLC, REG_USBSTAT, &dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL);
    if((2 == LcDeviceParameterGetNumeric(ctxLC, "usb")) && (dwReg & 0x0100 /* Super-Speed(USB3) */)) {
        lcprintf(ctxLC, "Device Info: USB3380 running at USB3 speed; downgrading to USB2 ...\n");
        dwReg = 0x04; // USB2=ENABLE, USB3=DISABLE
        Device3380_WriteCsr(ctxLC, REG_USBCTL2, dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTE0);
        Device3380_Close(ctxLC);
        Sleep(1000);
        result = Device3380_Open2(ctxLC);
        if(!result) { return FALSE; }
        Device3380_ReadCsr(ctxLC, REG_USBSTAT, &dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL);
    }
    if(dwReg & 0xc0 /* Full-Speed(USB1)|High-Speed(USB2) */) {
        lcprintf(ctxLC, "Device Info: USB3380 running at USB2 speed.\n");
    } else {
        lcprintfv(ctxLC, "Device Info: USB3380 running at USB3 speed.\n");
    }
    lcprintfv(ctxLC, "Device Info: USB3380.\n");
    // set callback functions and fix up config
    ctxLC->Config.fVolatile = TRUE;
    ctxLC->ReadContigious.fLoadBalance = TRUE;
    ctxLC->ReadContigious.cbChunkSize = 0x00800000;
    ctxLC->pfnReadContigious = Device3380_ReadContigious;
    ctxLC->pfnClose = Device3380_Close;
    ctxLC->pfnWriteContigious = Device3380_Write;
    // initialize memory map
    if(!ctxLC->Config.paMax) { ctxLC->Config.paMax = 0xffffffff; }
    paMax = min(0xffffffff, ctxLC->Config.paMax);
    if(ctxLC->Config.paMax) {
        paMax = min(paMax, ctxLC->Config.paMax);
    }
    LcMemMap_AddRange(ctxLC, 0x00000000, min(0x000A0000, paMax), 0x00000000);
    // ... SMM LOWER 0x000A0000-0x000FFFFF
    LcMemMap_AddRange(ctxLC, 0x00100000, min(0xF0000000, paMax) - 0x00100000, 0x00100000);
    // ... PCI SPACE 0xF0000000-0xFFFFFFFF (guess)
    return TRUE;
}

#ifdef _WIN32

#include <versionhelpers.h>

// Device Interface GUID. Must match "DeviceInterfaceGUIDs" registry value specified in the INF file.
// F72FE0D4-CBCB-407d-8814-9ED673D0DD6B
DEFINE_GUID(GUID_DEVINTERFACE_android, 0xF72FE0D4, 0xCBCB, 0x407d, 0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B);

_Success_(return)
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

_Success_(return)
BOOL Device3380_Open2(_Inout_ PLC_CONTEXT ctxLC)
{
    BOOL result;
    PDEVICE_DATA pDeviceData;
    if(!ctxLC->hDevice) {
        ctxLC->hDevice = (HANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_DATA));
        if(!ctxLC->hDevice) { return FALSE; }
    }
    pDeviceData = (PDEVICE_DATA)ctxLC->hDevice;
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
    ctxLC->ReadContigious.cThread = IsWindows8OrGreater() ? 3 : 1; // multi threaded DMA read fails on WIN7.
    return TRUE;
}

#endif /* _WIN32 */
#ifdef LINUX

_Success_(return)
BOOL Device3380_Open2(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_DATA pDeviceData;
    if(libusb_init(NULL)) { return FALSE; }
    if(!ctxLC->hDevice) {
        ctxLC->hDevice = (HANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_DATA));
        if(!ctxLC->hDevice) { return FALSE; }
    }
    pDeviceData = (PDEVICE_DATA)ctxLC->hDevice;
    pDeviceData->WinusbHandle = libusb_open_device_with_vid_pid(NULL, 0x18d1, 0x9001);
    if(!pDeviceData->WinusbHandle) {
        libusb_exit(NULL);
        LocalFree(ctxLC->hDevice);
        ctxLC->hDevice = NULL;
        return FALSE;
    }
    libusb_claim_interface(pDeviceData->WinusbHandle, 0);
    pDeviceData->HandlesOpen = TRUE;
    // synchronous libusb bulk read/write doesn't seem to support multi threaded accesses.
    return TRUE;
}

#endif /* LINUX */
