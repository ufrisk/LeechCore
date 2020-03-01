// devicefpga.h : implementation related to the:
//     - Xilinx SP605 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - Xilinx AC701 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - PCIeScreamer board flashed with PCILeech bitstream.
//     - RawUDP protocol - access FPGA over raw UDP packet stream (NeTV2 ETH)
//
// (c) Ulf Frisk, 2017-2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "device.h"
#include "memmap.h"
#include "tlp.h"
#include "util.h"

//-------------------------------------------------------------------------------
// FPGA defines below.
//-------------------------------------------------------------------------------

#define FPGA_CMD_VERSION_MAJOR          0x01
#define FPGA_CMD_DEVICE_ID              0x03
#define FPGA_CMD_VERSION_MINOR          0x05

#define FPGA_CONFIG_CORE                0x0003
#define FPGA_CONFIG_PCIE                0x0001
#define FPGA_CONFIG_SPACE_READONLY      0x0000
#define FPGA_CONFIG_SPACE_READWRITE     0x8000

#define ENDIAN_SWAP_DWORD(x)    (x = (x << 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x >> 24))

typedef struct tdDEV_CFG_PHY {
    BYTE magic;
    BYTE tp_cfg : 4;
    BYTE tp : 4;
    struct {
        BYTE pl_directed_link_auton : 1;
        BYTE pl_directed_link_change : 2;
        BYTE pl_directed_link_speed : 1;
        BYTE pl_directed_link_width : 2;
        BYTE pl_upstream_prefer_deemph : 1;
        BYTE pl_transmit_hot_rst : 1;
        BYTE pl_downstream_deemph_source : 1;
        BYTE _filler : 7;
    } wr;
    struct {
        BYTE pl_ltssm_state : 6;
        BYTE pl_rx_pm_state : 2;
        BYTE pl_tx_pm_state : 3;
        BYTE pl_initial_link_width : 3;
        BYTE pl_lane_reversal_mode : 2;
        BYTE pl_sel_lnk_width : 2;
        BYTE pl_phy_lnk_up : 1;
        BYTE pl_link_gen2_cap : 1;
        BYTE pl_link_partner_gen2_supported : 1;
        BYTE pl_link_upcfg_cap : 1;
        BYTE pl_sel_lnk_rate : 1;
        BYTE pl_directed_change_done : 1;
        BYTE pl_received_hot_rst : 1;
        BYTE _filler : 7;
    } rd;
} DEV_CFG_PHY, *PDEV_CFG_PHY;

typedef struct tdDEVICE_PERFORMANCE {
    LPSTR SZ_DEVICE_NAME;
    DWORD PROBE_MAXPAGES;    // 0x400
    DWORD RX_FLUSH_LIMIT;
    DWORD MAX_SIZE_RX;        // in data bytes (excl. overhead/TLP headers)
    DWORD MAX_SIZE_TX;        // in total data (incl. overhead/TLP headers)
    DWORD DELAY_PROBE_READ;
    DWORD DELAY_PROBE_WRITE;
    DWORD DELAY_WRITE;
    DWORD DELAY_READ;
    DWORD RETRY_ON_ERROR;
} DEVICE_PERFORMANCE, *PDEVICE_PERFORMANCE;

typedef union tdFPGA_HANDLESOCKET {
    HANDLE h;
    SOCKET Socket;
} FPGA_HANDLESOCKET;

#define DEVICE_ID_SP605_FT601                   0
#define DEVICE_ID_PCIESCREAMER                  1
#define DEVICE_ID_AC701_FT601                   2
#define DEVICE_ID_PCIESCREAMER_R2               3
#define DEVICE_ID_PCIESCREAMER_M2               4
#define DEVICE_ID_NETV2_UDP                     5
#define DEVICE_ID_MAX                           5

const DEVICE_PERFORMANCE PERFORMANCE_PROFILES[DEVICE_ID_MAX + 1] = {
    {
        .SZ_DEVICE_NAME = "SP605 / FT601",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0x8000,
        .MAX_SIZE_RX = 0x1f000,
        .MAX_SIZE_TX = 0x2000,
        .DELAY_PROBE_READ = 500,
        .DELAY_PROBE_WRITE = 0,
        .DELAY_WRITE = 175,
        .DELAY_READ = 400,
        .RETRY_ON_ERROR = 0
    }, {
        // The PCIeScreamer R1 have a problem with the PCIe link stability
        // which results on lost or delayed TLPS - workarounds are in place
        // to retry after a delay.
        .SZ_DEVICE_NAME = "PCIeScreamer R1",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x1c000,
        .MAX_SIZE_TX = 0x1000,
        .DELAY_PROBE_READ = 1000,
        .DELAY_PROBE_WRITE = 150,
        .DELAY_WRITE = 0,
        .DELAY_READ = 500,
        .RETRY_ON_ERROR = 1
    }, {
        .SZ_DEVICE_NAME = "AC701 / FT601",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x1c000,
        .MAX_SIZE_TX = 0x8000,
        .DELAY_PROBE_READ = 500,
        .DELAY_PROBE_WRITE = 0,
        .DELAY_WRITE = 0,
        .DELAY_READ = 300,
        .RETRY_ON_ERROR = 0
    }, {
        .SZ_DEVICE_NAME = "PCIeScreamer R2",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x1c000,
        .MAX_SIZE_TX = 0x1000,
        .DELAY_PROBE_READ = 750,
        .DELAY_PROBE_WRITE = 150,
        .DELAY_WRITE = 0,
        .DELAY_READ = 400,
        .RETRY_ON_ERROR = 0
    }, {
        .SZ_DEVICE_NAME = "ScreamerM2",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x1c000,
        .MAX_SIZE_TX = 0x1000,
        .DELAY_PROBE_READ = 500,
        .DELAY_PROBE_WRITE = 150,
        .DELAY_WRITE = 0,
        .DELAY_READ = 300,
        .RETRY_ON_ERROR = 0
    }, {
        .SZ_DEVICE_NAME = "NeTV2 RawUDP",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x1c000,
        .MAX_SIZE_TX = 0x400,
        .DELAY_PROBE_READ = 0,
        .DELAY_PROBE_WRITE = 0,
        .DELAY_WRITE = 0,
        .DELAY_READ = 0,
        .RETRY_ON_ERROR = 0
    }
};

typedef struct tdDEVICE_CONTEXT_FPGA {
    WORD wDeviceId;
    WORD wFpgaVersionMajor;
    WORD wFpgaVersionMinor;
    WORD wFpgaID;
    BOOL phySupported;
    DEV_CFG_PHY phy;
    DEVICE_PERFORMANCE perf;
    BOOL fAlgorithmReadTiny;
    struct {
        PBYTE pb;
        DWORD cb;
        DWORD cbMax;
    } rxbuf;
    struct {
        PBYTE pb;
        DWORD cb;
        DWORD cbMax;
    } txbuf;
    struct {
        HMODULE hModule;
        BOOL fInitialized;
        union {
            HANDLE hFTDI;
            SOCKET SocketUDP;
        };
        ULONG(*pfnFT_Create)(
            PVOID pvArg,
            DWORD dwFlags,
            HANDLE *pftHandle
            );
        ULONG(*pfnFT_Close)(
            HANDLE ftHandle
            );
        ULONG(*pfnFT_WritePipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID,
            PUCHAR pucBuffer,
            ULONG ulBufferLength,
            PULONG pulBytesTransferred,
            LPOVERLAPPED pOverlapped
            );
        ULONG(*pfnFT_ReadPipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID,
            PUCHAR pucBuffer,
            ULONG ulBufferLength,
            PULONG pulBytesTransferred,
            LPOVERLAPPED pOverlapped
            );
        ULONG(*pfnFT_AbortPipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID
            );
    } dev;
    PVOID pMRdBufferX; // NULL || PTLP_CALLBACK_BUF_MRd || PTLP_CALLBACK_BUF_MRd_2
    VOID(*hRxTlpCallbackFn)(_Inout_ PVOID pBufferMrd, _In_ PBYTE pb, _In_ DWORD cb);
    BYTE RxEccBit;
} DEVICE_CONTEXT_FPGA, *PDEVICE_CONTEXT_FPGA;

// STRUCT FROM FTD3XX.h
typedef struct {
    USHORT       VendorID;
    USHORT       ProductID;
    UCHAR        StringDescriptors[128];
    UCHAR        Reserved;
    UCHAR        PowerAttributes;
    USHORT       PowerConsumption;
    UCHAR        Reserved2;
    UCHAR        FIFOClock;
    UCHAR        FIFOMode;
    UCHAR        ChannelConfig;
    USHORT       OptionalFeatureSupport;
    UCHAR        BatteryChargingGPIOConfig;
    UCHAR        FlashEEPROMDetection;
    ULONG        MSIO_Control;
    ULONG        GPIO_Control;
} FT_60XCONFIGURATION, *PFT_60XCONFIGURATION;

//-------------------------------------------------------------------------------
// UDP connectivity implementation below:
//-------------------------------------------------------------------------------

/*
* Emulate the FT601 Close function by closing socket.
*/
ULONG DeviceFPGA_UDP_FT60x_FT_Close(HANDLE ftHandle)
{
    FPGA_HANDLESOCKET hs;
    hs.h = ftHandle;
    closesocket(hs.Socket);
    return 0;
}

/*
* Dummy function to keep compatibility with FT601 calls when using UDP.
*/
ULONG DeviceFPGA_UDP_FT60x_FT_AbortPipe(HANDLE ftHandle, UCHAR ucPipeID)
{
    return 0;
}

/*
* Emulate the FT601 WritePipe function when writing UDP packets to keep
* function call compatibility for the FPGA device module.
*/
ULONG DeviceFPGA_UDP_FT60x_FT_WritePipe(HANDLE ftHandle, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
{
    FPGA_HANDLESOCKET hs;
    hs.h = ftHandle;
    int retval = send(hs.Socket, pucBuffer, ulBufferLength, 0);
    if(retval == SOCKET_ERROR) {
        *pulBytesTransferred = 0;
        return 1;
    }
    *pulBytesTransferred = (ULONG)retval;
    return 0;
}

/*
* Emulate the FT601 WritePipe function when reading UDP packets to keep
* function call compatibility for the FPGA device module.
*/
ULONG DeviceFPGA_UDP_FT60x_FT_ReadPipe(HANDLE ftHandle, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
{
    int status;
    DWORD cbTx, cSleep = 0, cbRead, cbReadTotal = 0, cPass = 0;
    BYTE pbTx[] = { 0x01, 0x00, 0x01, 0x00,  0x80, 0x02, 0x23, 0x77 };                  // cmd msg: inactivity timer enable - 1ms
    FPGA_HANDLESOCKET hs;
    hs.h = ftHandle;
    DeviceFPGA_UDP_FT60x_FT_WritePipe(ftHandle, 0, pbTx, sizeof(pbTx), &cbTx, NULL);    //          - previously configured by DeviceFPGA_GetDeviceID_FpgaVersion()
    *pulBytesTransferred = 0;
    status = 1;
    while(status && ulBufferLength) {
        status = recvfrom(hs.Socket, pucBuffer, ulBufferLength, 0, NULL, NULL);
        if(status == SOCKET_ERROR) {
            if((cbReadTotal >= 32) && (*(PDWORD)(pucBuffer - 32) == 0xeffffff3) && (*(PDWORD)(pucBuffer - 28) == 0xdeceffff)) { // "inactivity timer" signal packet.
                break;
            }
            if(WSAEWOULDBLOCK == WSAGetLastError()) {
                if(++cSleep < 10 * 50) {    // wait for completion max ~50ms
                    if(cSleep < 5) {
                        SwitchToThread();
                    } else {
                        usleep(100);
                    }
                    continue;
                }
                break;
            }
            return 1;
        }
        cSleep = 0;
        cPass++;
        cbRead = min(ulBufferLength, (DWORD)status);
        cbReadTotal += cbRead;
        ulBufferLength -= cbRead;
        pucBuffer += cbRead;
    }
    *pulBytesTransferred = cbReadTotal;
    return 0;
}

/*
* Create a non-blocking UDP socket by connecting to the address/port specified.
* -- dwIpv4Addr
* -- wUdpPort
* -- return = the socket, 0 on error.
*/
SOCKET DeviceFPGA_UDP_Connect(_In_ DWORD dwIpv4Addr, _In_ WORD wUdpPort)
{
    int status;
    struct sockaddr_in sAddr;
    SOCKET Sock = 0;
    int rcvbuf = 0x00080000;
    u_long mode = 1;  // 1 == non-blocking socket - Windows only ???
#ifdef _WIN32
    WSADATA WsaData;
    if(WSAStartup(MAKEWORD(2, 2), &WsaData)) { return 0; }
#endif /* _WIN32 */
    sAddr.sin_family = AF_INET;
    sAddr.sin_port = htons(wUdpPort);
    sAddr.sin_addr.s_addr = dwIpv4Addr;
    if((Sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)) != INVALID_SOCKET) {
#ifdef _WIN32
        ioctlsocket(Sock, FIONBIO, &mode);
#endif /* _WIN32 */
        setsockopt(Sock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(int));
        status = connect(Sock, (struct sockaddr*)&sAddr, sizeof(sAddr));
        if(status == SOCKET_ERROR) {
            closesocket(Sock);
            return 0;
        }
        rcvbuf = 0x00080000;
        setsockopt(Sock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(int));
        return Sock;
    }
    return 0;
}

/*
* Initialize a FPGA RawUDP Device.
* -- ctx
* -- return = NULL on success, Error message on fail.
*/
LPSTR DeviceFPGA_InitializeUDP(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ DWORD dwIpv4Addr)
{
    ctx->dev.SocketUDP = DeviceFPGA_UDP_Connect(dwIpv4Addr, 28474);
    if(!ctx->dev.SocketUDP) {
        return "Unable to connect to RawUDP FPGA device";
    }
    ctx->dev.pfnFT_AbortPipe = DeviceFPGA_UDP_FT60x_FT_AbortPipe;
    ctx->dev.pfnFT_Create = NULL;
    ctx->dev.pfnFT_Close = DeviceFPGA_UDP_FT60x_FT_Close;
    ctx->dev.pfnFT_ReadPipe = DeviceFPGA_UDP_FT60x_FT_ReadPipe;
    ctx->dev.pfnFT_WritePipe = DeviceFPGA_UDP_FT60x_FT_WritePipe;
    ctx->dev.fInitialized = TRUE;
    return NULL;
}

//-------------------------------------------------------------------------------
// FPGA implementation below:
//-------------------------------------------------------------------------------

LPSTR DeviceFPGA_InitializeFTDI(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ QWORD qwDeviceIndex)
{
    LPSTR szErrorReason;
    CHAR c;
    DWORD status;
    ULONG(*pfnFT_GetChipConfiguration)(HANDLE ftHandle, PVOID pvConfiguration);
    ULONG(*pfnFT_SetChipConfiguration)(HANDLE ftHandle, PVOID pvConfiguration);
    ULONG(*pfnFT_SetSuspendTimeout)(HANDLE ftHandle, ULONG Timeout);
    FT_60XCONFIGURATION oCfgNew, oCfgOld;
    // Load FTDI Library
    ctx->dev.hModule = LoadLibrary(L"FTD3XX.dll");
    if(!ctx->dev.hModule) {
        szErrorReason = "Unable to load FTD3XX.dll";
        goto fail;
    }
    ctx->dev.pfnFT_AbortPipe = (ULONG(*)(HANDLE, UCHAR))
        GetProcAddress(ctx->dev.hModule, "FT_AbortPipe");
    ctx->dev.pfnFT_Create = (ULONG(*)(PVOID, DWORD, HANDLE*))
        GetProcAddress(ctx->dev.hModule, "FT_Create");
    ctx->dev.pfnFT_Close = (ULONG(*)(HANDLE))
        GetProcAddress(ctx->dev.hModule, "FT_Close");
    ctx->dev.pfnFT_ReadPipe = (ULONG(*)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_ReadPipeEx");
    ctx->dev.pfnFT_WritePipe = (ULONG(*)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_WritePipeEx");
    pfnFT_GetChipConfiguration = (ULONG(*)(HANDLE, PVOID))GetProcAddress(ctx->dev.hModule, "FT_GetChipConfiguration");
    pfnFT_SetChipConfiguration = (ULONG(*)(HANDLE, PVOID))GetProcAddress(ctx->dev.hModule, "FT_SetChipConfiguration");
    pfnFT_SetSuspendTimeout = (ULONG(*)(HANDLE, ULONG))GetProcAddress(ctx->dev.hModule, "FT_SetSuspendTimeout");
    if(!ctx->dev.pfnFT_Create || !ctx->dev.pfnFT_ReadPipe || !ctx->dev.pfnFT_WritePipe) {
        szErrorReason = ctx->dev.pfnFT_ReadPipe ?
            "Unable to retrieve required functions from FTD3XX.dll" :
            "Unable to retrieve required functions from FTD3XX.dll v1.3.0.2 or later";
        goto fail;
    }
    // Open FTDI
    status = ctx->dev.pfnFT_Create((PVOID)qwDeviceIndex, 0x10 /*FT_OPEN_BY_INDEX*/, &ctx->dev.hFTDI);
    if(status || !ctx->dev.hFTDI) {
        szErrorReason = "Unable to connect to USB/FT601 device";
        goto fail;
    }
    ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x02);
    ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x82);
    pfnFT_SetSuspendTimeout(ctx->dev.hFTDI, 0);
    // Check FTDI chip configuration and update if required
    status = pfnFT_GetChipConfiguration(ctx->dev.hFTDI, &oCfgOld);
    if(status) {
        szErrorReason = "Unable to retrieve device configuration";
        goto fail;
    }
    memcpy(&oCfgNew, &oCfgOld, sizeof(FT_60XCONFIGURATION));
    oCfgNew.FIFOMode = 0; // FIFO MODE FT245
    oCfgNew.ChannelConfig = 2; // 1 CHANNEL ONLY
    oCfgNew.OptionalFeatureSupport = 0;
    if(memcmp(&oCfgNew, &oCfgOld, sizeof(FT_60XCONFIGURATION))) {
        printf(
            "IMPORTANT NOTE! FTDI FT601 USB CONFIGURATION DIFFERS FROM RECOMMENDED\n" \
            "PLEASE ENSURE THAT ONLY PCILEECH FPGA FTDI FT601 DEVICE IS CONNECED  \n" \
            "BEFORE UPDATING CONFIGURATION. DO YOU WISH TO CONTINUE Y/N?          \n"
        );
        while(TRUE) {
            c = (CHAR)getchar();
            if(c == 'Y' || c == 'y') { break; }
            if(c == 'N' || c == 'n') {
                szErrorReason = "User abort required device configuration";
                goto fail;
            }

        }
        status = pfnFT_SetChipConfiguration(ctx->dev.hFTDI, &oCfgNew);
        if(status) {
            szErrorReason = "Unable to set required device configuration";
            goto fail;
        }
        printf("FTDI USB CONFIGURATION UPDATED - RESETTING AND CONTINUING ...\n");
        ctx->dev.pfnFT_Close(ctx->dev.hFTDI);
        FreeLibrary(ctx->dev.hModule);
        ctx->dev.hModule = NULL;
        ctx->dev.hFTDI = NULL;
        Sleep(3000);
        return DeviceFPGA_InitializeFTDI(ctx, qwDeviceIndex);
    }
    ctx->dev.fInitialized = TRUE;
    return NULL;
fail:
    if(ctx->dev.hFTDI && ctx->dev.pfnFT_Close) { ctx->dev.pfnFT_Close(ctx->dev.hFTDI); }
    if(ctx->dev.hModule) { FreeLibrary(ctx->dev.hModule); }
    ctx->dev.hModule = NULL;
    ctx->dev.hFTDI = NULL;
    return szErrorReason;
}

VOID DeviceFPGA_ReInitializeFTDI(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    // called to try to recover link in case of instable devices.
    ctx->dev.pfnFT_Close(ctx->dev.hFTDI);
    ctx->dev.hFTDI = NULL;
    Sleep(250);
    ctx->dev.pfnFT_Create(NULL, 0x10 /*FT_OPEN_BY_INDEX*/, &ctx->dev.hFTDI);
}

VOID DeviceFPGA_Close()
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    if(!ctx) { return; }
    if(ctx->dev.hFTDI) { ctx->dev.pfnFT_Close(ctx->dev.hFTDI); }
    if(ctx->dev.hModule) { FreeLibrary(ctx->dev.hModule); }
    LocalFree(ctx->rxbuf.pb);
    LocalFree(ctx->txbuf.pb);
    LocalFree(ctx);
    ctxDeviceMain->hDevice = 0;
}

/*
* Read bitstream v4 configuration registers. The bitstream v4 have four register
* spaces, one read-only and one read-write for each of core and pcie.
* When calling the DeviceFPGA_ConfigRead() function please specify the correct
* combination of CORE/PCIE and READONLY/READWRITE config spaces.
* -- ctx
* -- wBaseAddr
* -- pb
* -- cb
* -- flags = flags as defined by FPGA_CONFIG_*
* -- return
*/
_Success_(return)
BOOL DeviceFPGA_ConfigRead(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ WORD wBaseAddr, _Out_writes_(cb) PBYTE pb, _In_ WORD cb, _In_ WORD flags)
{
    BOOL f, fReturn = FALSE;
    PBYTE pbRxTx = NULL;
    DWORD i, j, status, dwStatus, dwData, cbRxTx = 0;
    PDWORD pdwData;
    WORD wAddr;
    if(!cb || (cb > 0x1000) || (wBaseAddr > 0x1000)) { goto fail; }
    if(!(pbRxTx = LocalAlloc(LMEM_ZEROINIT, 0x20000))) { goto fail; }
    // WRITE requests
    for(wAddr = wBaseAddr; wAddr < wBaseAddr + cb; wAddr += 2) {
        pbRxTx[cbRxTx + 4] = (wAddr | (flags & 0x8000)) >> 8;
        pbRxTx[cbRxTx + 5] = wAddr & 0xff;
        pbRxTx[cbRxTx + 6] = 0x10 | (flags & 0x03);
        pbRxTx[cbRxTx + 7] = 0x77;
        cbRxTx += 8;
    }
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbRxTx, cbRxTx, &cbRxTx, NULL);
    if(status) { goto fail; }
    Sleep(10);
    // READ and interpret result
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRxTx, 0x20000, &cbRxTx, NULL);
    if(status) { goto fail; }
    ZeroMemory(pb, cb);
    for(i = 0; i < cbRxTx; i += 32) {
        while(*(PDWORD)(pbRxTx + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
            i += 4;
            if(i + 32 > cbRxTx) { goto fail; }
        }
        dwStatus = *(PDWORD)(pbRxTx + i);
        pdwData = (PDWORD)(pbRxTx + i + 4);
        if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
        for(j = 0; j < 7; j++) {
            f = (dwStatus & 0x0f) == (flags & 0x03);
            dwData = *pdwData;
            pdwData++;                              // move ptr to next data
            dwStatus >>= 4;                         // move to next status
            if(!f) { continue; }                    // status src flags does not match source
            wAddr = _byteswap_ushort((WORD)dwData);
            wAddr -= (flags & 0x8000) + wBaseAddr;  // adjust for base address and read-write config memory
            if(wAddr >= cb) { continue; }           // address read is out of range
            if(wAddr == cb - 1) {
                *(PBYTE)(pb + wAddr) = (dwData >> 16) & 0xff;
            } else {
                *(PWORD)(pb + wAddr) = (dwData >> 16) & 0xffff;
            }
        }
    }
    fReturn = TRUE;
fail:
    LocalFree(pbRxTx);
    return fReturn;
}

/*
* Write a two-byte value with a write mask to the FPGA bistream v4 register space.
* -- ctx
* -- wBaseAddr
* -- pbData
* -- pbMask
* -- flags = flags as defined by FPGA_CONFIG_*
* -- return
*/
_Success_(return)
BOOL DeviceFPGA_ConfigWriteEx(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ WORD wBaseAddr, _In_reads_(2) PBYTE pbData, _In_reads_(2) PBYTE pbMask, _In_ WORD flags)
{
    DWORD status, cbTx;
    BYTE pbTx[0x8];
    // WRITE requests
    pbTx[0] = pbData[0];                            // [0] = byte_value_addr
    pbTx[1] = pbData[1];                            // [1] = byte_value_addr+1
    pbTx[2] = pbMask[0];                            // [2] = byte_mask_addr
    pbTx[3] = pbMask[1];                            // [3] = byte_mask_addr+1
    pbTx[4] = (wBaseAddr | (flags & 0x8000)) >> 8;  // [4] = addr_high = bit[6:0], write_regbank = bit[7]
    pbTx[5] = wBaseAddr & 0xff;                     // [5] = addr_low
    pbTx[6] = 0x20 | (flags & 0x03);                // [6] = target = bit[0:1], read = bit[4], write = bit[5]
    pbTx[7] = 0x77;                                 // [7] = MAGIC 0x77
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, 8, &cbTx, NULL);
    return (status == 0);
}

/*
* Write to the FPGA bistream v4 register space.
* -- ctx
* -- wBaseAddr
* -- pb
* -- cb
* -- flags = flags as defined by FPGA_CONFIG_*
* -- return
*/
_Success_(return)
BOOL DeviceFPGA_ConfigWrite(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ WORD wBaseAddr, _In_reads_(cb) PBYTE pb, _In_ WORD cb, _In_ WORD flags)
{
    BOOL fReturn = FALSE;
    BYTE pbTx[0x800];
    DWORD status, cbTx = 0;
    WORD i, wAddr;
    if(!cb || (cb > 0x200) || (wBaseAddr > 0x1000)) { return FALSE; }
    // WRITE requests
    for(i = 0; i < cb; i += 2) {
        wAddr = (wBaseAddr + i) | (flags & 0x8000);
        pbTx[cbTx + 0] = pb[i];                         // [0] = byte_value_addr
        pbTx[cbTx + 1] = (cb == i + 1) ? 0 : pb[i + 1]; // [1] = byte_value_addr+1
        pbTx[cbTx + 2] = 0xff;                          // [2] = byte_mask_addr
        pbTx[cbTx + 3] = (cb == i + 1) ? 0 : 0xff;      // [3] = byte_mask_addr+1
        pbTx[cbTx + 4] = wAddr >> 8;                    // [4] = addr_high = bit[6:0], write_regbank = bit[7]
        pbTx[cbTx + 5] = wAddr & 0xff;                  // [5] = addr_low
        pbTx[cbTx + 6] = 0x20 | (flags & 0x03);         // [6] = target = bit[0:1], read = bit[4], write = bit[5]
        pbTx[cbTx + 7] = 0x77;                          // [7] = MAGIC 0x77
        cbTx += 8;
    }
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, cbTx, &cbTx, NULL);
    return (status == 0);
}

/*
* Write a single DWORD to the FPGA bistream v4.2 "shadow" PCIe configuration space.
* -- ctx
* -- wBaseAddr
* -- pb
* -- cb
* -- return
*/
_Success_(return)
BOOL DeviceFPGA_PCIeCfgSpaceWrite(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ WORD wBaseAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
    BOOL fReturn = FALSE;
    BYTE pbTx[0x2000];
    DWORD status, cbTx = 0;
    WORD i, wAddr;
    if(!cb || (cb > 0x1000) || (wBaseAddr > 0x1000)) { return FALSE; }
    // WRITE requests
    for(i = 0; i < cb - 3; i += 4) {
        wAddr = wBaseAddr + i;
        pbTx[cbTx + 0] = pb[i + 0];                     // [0] = byte_value_addr
        pbTx[cbTx + 1] = pb[i + 1];                     // [1] = byte_value_addr+1
        pbTx[cbTx + 2] = pb[i + 2];                     // [2] = byte_value_addr+2
        pbTx[cbTx + 3] = pb[i + 3];                     // [3] = byte_value_addr+3
        pbTx[cbTx + 4] = wAddr >> 8;                    // [4] = addr_high
        pbTx[cbTx + 5] = wAddr & 0xff;                  // [5] = addr_low
        pbTx[cbTx + 6] = 0x21;                          // [6] = target
        pbTx[cbTx + 7] = 0x77;                          // [7] = MAGIC 0x77
        cbTx += 8;
    }
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, cbTx, &cbTx, NULL);
    return (status == 0);
}

/*
* Read from the device PCIe configuration space. Only the values used by the
* xilinx ip core itself is read. Custom "shadow" user-provided configuration
* space is not readable from USB-side of things. Please use "lspci" on target
* system to read any custom user-provided "shadow" configuration space.
* -- ctx
* -- pb = only the 1st 0x200 bytes are read
*/
_Success_(return)
BOOL DeviceFPGA_PCIeCfgSpaceRead(_In_ PDEVICE_CONTEXT_FPGA ctx, _Out_writes_(0x200) PBYTE pb)
{
    BYTE pbTxLockEnable[]   = { 0x04, 0x00, 0x04, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxLockDisable[]  = { 0x00, 0x00, 0x04, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxReadEnable[]   = { 0x01, 0x00, 0x01, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxReadAddress[]  = { 0x00, 0x00, 0xff, 0x03, 0x80, 0x14, 0x21, 0x77 };
    BYTE pbTxResultMeta[]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x11, 0x77 };
    BYTE pbTxResultDataLo[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x11, 0x77 };
    BYTE pbTxResultDataHi[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x11, 0x77 };
    BOOL f, fReturn = FALSE;
    BYTE oAddr, pbRxTx[0x1000];
    DWORD i, j, status, dwStatus, dwData, cbRxTx;
    PDWORD pdwData;
    WORD wDWordAddr, oDWord, wAddr = 0;
    ZeroMemory(pb, 0x200);
    for(wDWordAddr = 0; wDWordAddr < 0x200; wDWordAddr += 32) {
        // enable read/write lock (instruction serialization)
        cbRxTx = 0;
        memcpy(pbRxTx + cbRxTx, pbTxLockEnable, 8); cbRxTx += 8;
        for(oDWord = 0; oDWord < 32; oDWord++) {
            // WRITE request setup (address)
            pbTxReadAddress[0] = (wDWordAddr + oDWord) & 0xff;
            pbTxReadAddress[1] = ((wDWordAddr + oDWord) >> 8) & 0x03;
            memcpy(pbRxTx + cbRxTx, pbTxReadAddress, 8); cbRxTx += 8;
            // WRITE read enable bit
            memcpy(pbRxTx + cbRxTx, pbTxReadEnable, 8); cbRxTx += 8;
            // READ result
            memcpy(pbRxTx + cbRxTx, pbTxResultMeta, 8); cbRxTx += 8;
            memcpy(pbRxTx + cbRxTx, pbTxResultDataLo, 8); cbRxTx += 8;
            memcpy(pbRxTx + cbRxTx, pbTxResultDataHi, 8); cbRxTx += 8;
        }
        // disable read/write lock
        memcpy(pbRxTx + cbRxTx, pbTxLockDisable, 8); cbRxTx += 8;
        // WRITE TxData
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbRxTx, cbRxTx, &cbRxTx, NULL);
        if(status) { return FALSE; }
        Sleep(10);
        // READ and interpret result
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRxTx, 0x1000, &cbRxTx, NULL);
        if(status) { return FALSE; }
        for(i = 0; i < cbRxTx; i += 32) {
            while(*(PDWORD)(pbRxTx + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
                i += 4;
                if(i + 32 > cbRxTx) { return FALSE; }
            }
            dwStatus = *(PDWORD)(pbRxTx + i);
            pdwData = (PDWORD)(pbRxTx + i + 4);
            if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
            for(j = 0; j < 7; j++) {
                f = (dwStatus & 0x0f) == 0x01;
                dwData = *pdwData;
                pdwData++;                              // move ptr to next data
                dwStatus >>= 4;                         // move to next status
                if(!f) { continue; }                    // status src flags does not match source
                if((dwData & 0x0800ffff) == 0x08002a00) {
                    wAddr = ((dwData >> 16) & 0x03ff) << 2;
                    continue;
                }
                oAddr = (BYTE)(dwData >> 8);
                if((oAddr != 0x2c) && (oAddr != 0x2e)) { continue; }
                oAddr -= 0x2c;
                if(wAddr + oAddr + 1 >= 0x200) { continue; }
                *(PBYTE)(pb + wAddr + oAddr + 1) = (dwData >> 24) & 0xff;
                *(PBYTE)(pb + wAddr + oAddr + 0) = (dwData >> 16) & 0xff;
            }
        }
    }
    return TRUE;
}

/*
* Sample function for reading the DRP address space of the Xilinx 7-Series Core.
* Please consult "DRP Address Map for PCIE_2_1 Library Element Attributes" in
* Xilinx manual for further info. Also please not that each DRP address is
* 16-bits wide - hence the need for 0x100 bytes to hold the 0x80 DRP address space.
*/
_Success_(return)
BOOL DeviceFPGA_PCIeDrpRead(_In_ PDEVICE_CONTEXT_FPGA ctx, _Out_writes_(0x100) PBYTE pb)
{
    // 64-bit data is as follows:
    // [63:48] : DATA (little endian)
    // [47:32] : MASK for DATA (little endian)
    // [31:16] : PCILeech Config Register Address: (big endian)
    // [15:12] : READ/WRITE [1 = READ, 2 = WRITE]
    // [11:08] : DESTINATION [1 = PCIe CFG, 3 = CFG]
    // [08:00] : MAGIC [MUST BE SET TO 0x77 for validity]
    BYTE pbTxReadEnable[] = { 0x10, 0x00, 0x10, 0x00, 0x80, 0x02, 0x23, 0x77 };
    BYTE pbTxReadAddress[] = { 0x00, 0x00, 0xff, 0xff, 0x80, 0x1c, 0x23, 0x77 };
    BYTE pbTxResultMeta[] = { 0x00, 0x00, 0x00, 0x00, 0x80, 0x1c, 0x13, 0x77 };
    BYTE pbTxResultData[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x13, 0x77 };
    BOOL f, fReturn = FALSE;
    BYTE pbRxTx[0x1000];
    DWORD i, j, status, dwStatus, dwData, cbRxTx;
    PDWORD pdwData;
    WORD wDWordAddr, oDWord, wAddr = 0;
    ZeroMemory(pb, 0x100);
    /*
    {
        // WRITE DRP EXAMPLE - NOT IN USE
        // IF WRITING DRP IT IS FIRST RECOMMENDED TO BRING PCIE CORE
        // OFFLINE BY WRITING "PCIE CORE RESET" BIT TO FPGA CONFIG REGISTER.
        BYTE pbTxWriteEnable[] = { 0x20, 0x00, 0x20, 0x00, 0x80, 0x02, 0x23, 0x77 };
        BYTE pbTxWriteData[] = { 0x00, 0x00, 0xff, 0xff, 0x80, 0x1a, 0x23, 0x77 };
        cbRxTx = 0;
         // WRITE request setup (address)
        pbTxReadAddress[0] = 0x07;      // BAR0[15:0]
        memcpy(pbRxTx + cbRxTx, pbTxReadAddress, 8); cbRxTx += 8;
        // WRITE data
        memcpy(pbRxTx + cbRxTx, pbTxWriteData, 8); cbRxTx += 8;
        // WRITE Write enable bit
        memcpy(pbRxTx + cbRxTx, pbTxWriteEnable, 8); cbRxTx += 8;
        // WRITE TxData
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbRxTx, cbRxTx, &cbRxTx, NULL);
        if(status) { return; }
    }
    */
    for(wDWordAddr = 0; wDWordAddr < 0x100; wDWordAddr += 32) {
        cbRxTx = 0;
        for(oDWord = 0; oDWord < 32; oDWord += 2) {
            // WRITE request setup (address)
            pbTxReadAddress[0] = ((wDWordAddr + oDWord) >> 1) & 0xff;
            memcpy(pbRxTx + cbRxTx, pbTxReadAddress, 8); cbRxTx += 8;
            // WRITE read enable bit
            memcpy(pbRxTx + cbRxTx, pbTxReadEnable, 8); cbRxTx += 8;
            // READ result
            memcpy(pbRxTx + cbRxTx, pbTxResultMeta, 8); cbRxTx += 8;
            memcpy(pbRxTx + cbRxTx, pbTxResultData, 8); cbRxTx += 8;
        }
        // WRITE TxData
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbRxTx, cbRxTx, &cbRxTx, NULL);
        if(status) { return FALSE; }
        Sleep(10);
        // READ and interpret result
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRxTx, 0x1000, &cbRxTx, NULL);
        if(status) { return FALSE; }
        for(i = 0; i < cbRxTx; i += 32) {
            while(*(PDWORD)(pbRxTx + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
                i += 4;
                if(i + 32 > cbRxTx) { return FALSE; }
            }
            dwStatus = *(PDWORD)(pbRxTx + i);
            pdwData = (PDWORD)(pbRxTx + i + 4);
            if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
            for(j = 0; j < 7; j++) {
                f = (dwStatus & 0x0f) == 0x03;
                dwData = *pdwData;
                pdwData++;                              // move ptr to next data
                dwStatus >>= 4;                         // move to next status
                if(!f) { continue; }                    // status src flags does not match source
                if((dwData & 0xff00ffff) == 0x00001c80) {
                    wAddr = ((dwData >> 16) & 0x00ff) << 1;
                    continue;
                }
                if(wAddr > 0x100 - 2) { continue; }
                if((dwData & 0xffff) != 0x2000) { continue; }
                *(PBYTE)(pb + wAddr + 0) = (dwData >> 24) & 0xff;
                *(PBYTE)(pb + wAddr + 1) = (dwData >> 16) & 0xff;
            }
        }
    }
    return TRUE;
}

VOID DeviceFPGA_ConfigPrint(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    WORD flags[] = {
        FPGA_CONFIG_CORE | FPGA_CONFIG_SPACE_READONLY,
        FPGA_CONFIG_CORE | FPGA_CONFIG_SPACE_READWRITE,
        FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READONLY,
        FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READWRITE };
    LPSTR szNAME[] = { "CORE-READ-ONLY ", "CORE-READ-WRITE", "PCIE-READ-ONLY ", "PCIE-READ-WRITE" };
    BYTE pb[0x1000];
    WORD i, cb;
    for(i = 0; i < 4; i++) {
        if(DeviceFPGA_ConfigRead(ctx, 0x0004, (PBYTE)&cb, 2, flags[i])) {
            vprintf("\n----- FPGA DEVICE CONFIG REGISTERS: %s    SIZE: %i BYTES -----\n", szNAME[i], cb);
            cb = min(cb, sizeof(pb));
            DeviceFPGA_ConfigRead(ctx, 0x0000, pb, cb, flags[i]);
            Util_PrintHexAscii(pb, cb, 0);
        }
    }
    if(DeviceFPGA_PCIeDrpRead(ctx, pb)) {
        vprintf("\n----- PCIe CORE Dynamic Reconfiguration Port (DRP)  SIZE: 0x100 BYTES -----\n");
        Util_PrintHexAscii(pb, 0x100, 0);
    }
    if(DeviceFPGA_PCIeCfgSpaceRead(ctx, pb)) {
        vprintf("\n----- PCIe CONFIGURATION SPACE (no user set values) SIZE: 0x200 BYTES -----\n");
        Util_PrintHexAscii(pb, 0x200, 0);
    }
    vprintf("\n");
}

_Success_(return)
BOOL DeviceFPGA_GetPHYv4(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    return
        DeviceFPGA_ConfigRead(ctx, 0x0016, (PBYTE)&ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READWRITE) &&
        DeviceFPGA_ConfigRead(ctx, 0x000a, (PBYTE)&ctx->phy.rd, sizeof(ctx->phy.rd), FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READONLY);
}

_Success_(return)
BOOL DeviceFPGA_GetSetPHYv3(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ BOOL isUpdate)
{
    DWORD status;
    DWORD i, j, cbRxTx, dwStatus;
    PDWORD pdwData;
    BYTE pbRx[0x1000];
    BYTE pbTx[16] = {
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // dummy: to be overwritten
        0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x03, 0x77, // cmd msg: version (filler)
    };
    if(isUpdate) {
        ctx->phy.magic = 0x77;
        ctx->phy.tp_cfg = 1;
        ctx->phy.tp = 4;
        *(PQWORD)pbTx = _byteswap_uint64(*(PQWORD)&ctx->phy);
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, sizeof(pbTx), &cbRxTx, NULL);
        if(status) { return FALSE; }
        Sleep(10);
    }
    *(PQWORD)&ctx->phy = 0;
    *(PQWORD)pbTx = 0x7731000000000000; // phy read (3) + cfg (1) + magic (77)
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, sizeof(pbTx), &cbRxTx, NULL);
    if(status) { return FALSE; }
    Sleep(10);
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRx, 0x1000, &cbRxTx, NULL);
    if(status) { return FALSE; }
    for(i = 0; i < cbRxTx; i += 32) {
        while(*(PDWORD)(pbRx + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
            i += 4;
            if(i + 32 > cbRxTx) { return FALSE; }
        }
        dwStatus = *(PDWORD)(pbRx + i);
        pdwData = (PDWORD)(pbRx + i + 4);
        if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
        for(j = 0; j < 7; j++) {
            if(((dwStatus & 0x03) == 0x01) && ((*pdwData & 0xffff0000) == 0x77310000)) { // PCIe CFG REPLY
                // sloppy algorithm below, but it works unless high amount of interfering incoming TLPs
                *(PQWORD)(&ctx->phy) = _byteswap_uint64(*(PQWORD)(pdwData - 1));
                return TRUE;
            }
            pdwData++;
            dwStatus >>= 4;
        }
    }
    return FALSE;
}

BYTE DeviceFPGA_PHY_GetLinkWidth(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    const BYTE LINK_WIDTH[4] = { 1, 2, 4, 8 };
    return LINK_WIDTH[ctx->phy.rd.pl_sel_lnk_width];
}

BYTE DeviceFPGA_PHY_GetPCIeGen(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    return 1 + ctx->phy.rd.pl_sel_lnk_rate;
}

VOID DeviceFPGA_SetSpeedPCIeGen(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ DWORD dwPCIeGen)
{
    BYTE i, lnk_rate_new;
    // v4 bitstream
    if((ctx->wFpgaVersionMajor >= 4) && ((dwPCIeGen == 1) || (dwPCIeGen == 2))) {
        lnk_rate_new = (dwPCIeGen == 2) ? 1 : 0;
        if(lnk_rate_new == ctx->phy.rd.pl_sel_lnk_rate) { return; }
        if(lnk_rate_new && !ctx->phy.rd.pl_link_gen2_cap) { return; }
        ctx->phy.wr.pl_directed_link_auton = 1;
        ctx->phy.wr.pl_directed_link_speed = lnk_rate_new;
        ctx->phy.wr.pl_directed_link_change = 2;
        DeviceFPGA_ConfigWrite(ctx, 0x0016, (PBYTE)&ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READWRITE);
        for(i = 0; i < 32; i++) {
            if(!DeviceFPGA_GetPHYv4(ctx) || ctx->phy.rd.pl_directed_change_done) { break; }
            Sleep(10);
        }
        ctx->phy.wr.pl_directed_link_auton = 0;
        ctx->phy.wr.pl_directed_link_speed = 0;
        ctx->phy.wr.pl_directed_link_change = 0;
        DeviceFPGA_ConfigWrite(ctx, 0x0016, (PBYTE)&ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READWRITE);
        DeviceFPGA_GetPHYv4(ctx);
    }
    // v3 bitstream - keep old slightly faulty way of doing things
    if((ctx->wFpgaVersionMajor <= 3) && ctx->phySupported && ctx->phy.rd.pl_sel_lnk_rate && (dwPCIeGen == 1)) {
        ctx->phy.wr.pl_directed_link_auton = 1;
        ctx->phy.wr.pl_directed_link_speed = 0;
        ctx->phy.wr.pl_directed_link_change = 2;
        DeviceFPGA_GetSetPHYv3(ctx, TRUE);
    }
}

VOID DeviceFPGA_GetDeviceId_FpgaVersion_ClearPipe(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DWORD status, cbTX, cbRX;
    PBYTE pbRX;
    BYTE pbTX_Dummy[] = {
        // cmd msg: FPGA bitstream version (major.minor)    v4
        0x00, 0x00, 0x00, 0x00,  0x00, 0x08, 0x13, 0x77,
        // cmd msg: FPGA bitstream version (major)          v3
        0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x03, 0x77,
    };
    if(!(pbRX = LocalAlloc(0, 0x01000000))) { return; }
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTX_Dummy, sizeof(pbTX_Dummy), &cbTX, NULL);
    if(status) { goto fail; }
    Sleep(25);
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, 0x1000, &cbRX, NULL);
    if(status) { goto fail; }
    if(cbRX >= 0x1000) {
        Sleep(10);
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, 0x01000000, &cbRX, NULL);
        if(status) { goto fail; }
    }
fail:
    LocalFree(pbRX);
}

VOID DeviceFPGA_HotResetV4(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DeviceFPGA_GetPHYv4(ctx);
    ctx->phy.wr.pl_transmit_hot_rst = 1;
    DeviceFPGA_ConfigWrite(ctx, 0x0016, (PBYTE)&ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READWRITE);
    Sleep(250);     // sloppy w/ sleep instead of poll pl_ltssm_state - but 250ms should be plenty of time ...
    ctx->phy.wr.pl_transmit_hot_rst = 0;
    DeviceFPGA_ConfigWrite(ctx, 0x0016, (PBYTE)& ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READWRITE);
}

_Success_(return)
BOOL DeviceFPGA_GetDeviceID_FpgaVersionV4(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    WORD wbsDeviceId, wMagicPCIe;
    DWORD dwInactivityTimer = 0x000186a0;       // set inactivity timer to 1ms ( 0x0186a0 * 100MHz ) [only later activated on UDP bitstreams]
    if(!DeviceFPGA_ConfigRead(ctx, 0x0008, (PBYTE)&ctx->wFpgaVersionMajor, 1, FPGA_CONFIG_CORE | FPGA_CONFIG_SPACE_READONLY) || ctx->wFpgaVersionMajor < 4) { return FALSE; }
    DeviceFPGA_ConfigRead(ctx, 0x0009, (PBYTE)&ctx->wFpgaVersionMinor, 1, FPGA_CONFIG_CORE | FPGA_CONFIG_SPACE_READONLY);
    DeviceFPGA_ConfigRead(ctx, 0x000a, (PBYTE)&ctx->wFpgaID, 1, FPGA_CONFIG_CORE | FPGA_CONFIG_SPACE_READONLY);
    DeviceFPGA_ConfigWrite(ctx, 0x0008, (PBYTE)&dwInactivityTimer, 4, FPGA_CONFIG_CORE | FPGA_CONFIG_SPACE_READWRITE);
    DeviceFPGA_ConfigRead(ctx, 0x0008, (PBYTE)&wbsDeviceId, 2, FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READONLY);
    // PCIe
    DeviceFPGA_ConfigRead(ctx, 0x0008, (PBYTE)& wbsDeviceId, 2, FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READONLY);
    if(!wbsDeviceId && DeviceFPGA_ConfigRead(ctx, 0x0000, (PBYTE)&wMagicPCIe, 2, FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READWRITE) && (wMagicPCIe == 0x6745)) {
        // failed getting device id - assume device is connected -> try recover the bad link with hot-reset.
        DeviceFPGA_HotResetV4(ctx);
        DeviceFPGA_ConfigRead(ctx, 0x0008, (PBYTE)&wbsDeviceId, 2, FPGA_CONFIG_PCIE | FPGA_CONFIG_SPACE_READONLY);
    }
    ctx->wDeviceId = _byteswap_ushort(wbsDeviceId);
    ctx->phySupported = DeviceFPGA_GetPHYv4(ctx);
    return TRUE;
}

VOID DeviceFPGA_GetDeviceID_FpgaVersionV3(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DWORD status;
    DWORD cbTX, cbRX, i, j;
    BYTE pbRX[0x1000];
    DWORD dwStatus, dwData, cdwCfg = 0;
    PDWORD pdwData;
    BYTE pbTX[] = {
        // cfg status: (pcie bus,dev,fn id)
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x01, 0x77,
        // cmd msg: FPGA bitstream version (major)
        0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x03, 0x77,
        // cmd msg: FPGA bitstream version (minor)
        0x00, 0x00, 0x00, 0x00,  0x05, 0x00, 0x03, 0x77,
        // cmd msg: FPGA bitstream device id
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x03, 0x77
    };
    // Write and read data from device.
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTX, sizeof(pbTX), &cbTX, NULL);
    if(status) { return; }
    Sleep(10);
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, sizeof(pbRX), &cbRX, NULL);
    if(status) { return; }
    // Interpret read data
    for(i = 0; i < cbRX; i += 32) {
        while(*(PDWORD)(pbRX + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
            i += 4;
            if(i + 32 > cbRX) { return; }
        }
        dwStatus = *(PDWORD)(pbRX + i);
        pdwData = (PDWORD)(pbRX + i + 4);
        if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
        for(j = 0; j < 7; j++) {
            dwData = *pdwData;
            if((dwStatus & 0x03) == 0x03) { // CMD REPLY (or filler)
                switch(dwData >> 24) {
                    case FPGA_CMD_VERSION_MAJOR:
                        ctx->wFpgaVersionMajor = (WORD)dwData;
                        break;
                    case FPGA_CMD_VERSION_MINOR:
                        ctx->wFpgaVersionMinor = (WORD)dwData;
                        break;
                    case FPGA_CMD_DEVICE_ID:
                        ctx->wFpgaID = (WORD)dwData;
                        break;
                }
            }
            if((dwStatus & 0x03) == 0x01) { // PCIe CFG REPLY
                if(((++cdwCfg % 2) == 0) && (WORD)dwData) {    // DeviceID: (pcie bus,dev,fn id)
                    ctx->wDeviceId = (WORD)dwData;
                }
            }
            pdwData++;
            dwStatus >>= 4;
        }
    }
    ctx->phySupported = (ctx->wFpgaVersionMajor >= 3) ? DeviceFPGA_GetSetPHYv3(ctx, FALSE) : FALSE;
}

VOID DeviceFPGA_GetDeviceID_FpgaVersion(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DeviceFPGA_GetDeviceId_FpgaVersion_ClearPipe(ctx);
    if(!DeviceFPGA_GetDeviceID_FpgaVersionV4(ctx)) {
        DeviceFPGA_GetDeviceID_FpgaVersionV3(ctx);
    }
}

VOID DeviceFPGA_SetPerformanceProfile(_Inout_ PDEVICE_CONTEXT_FPGA ctx)
{
    memcpy(&ctx->perf, &PERFORMANCE_PROFILES[(ctx->wFpgaID <= DEVICE_ID_MAX) ? ctx->wFpgaID : 0], sizeof(DEVICE_PERFORMANCE));
}

//-------------------------------------------------------------------------------
// TLP handling functionality below:
//-------------------------------------------------------------------------------

_Success_(return)
BOOL DeviceFPGA_TxTlp(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_reads_(cbTlp) PBYTE pbTlp, _In_ DWORD cbTlp, _In_ BOOL fRdKeepalive, _In_ BOOL fFlush)
{
    DWORD status;
    PBYTE pbTx;
    QWORD i;
    DWORD cbTx, cbTxed = 0;
    if(cbTlp & 0x3) { return FALSE; }
    if(cbTlp > 2048) { return FALSE; }
    if(ctxDeviceMain->fVerboseExtraTlp) {
        TLP_Print(pbTlp, cbTlp, TRUE);
    }
    // prepare transmit buffer
    pbTx = ctx->txbuf.pb + ctx->txbuf.cb;
    cbTx = 2 * cbTlp;
    for(i = 0; i < cbTlp; i += 4) {
        *(PDWORD)(pbTx + (i << 1)) = *(PDWORD)(pbTlp + i);
        *(PDWORD)(pbTx + ((i << 1) + 4)) = 0x77000000;    // TX TLP
    }
    if(cbTlp) {
        *(PDWORD)(pbTx + ((i << 1) - 4)) = 0x77040000;    // TX TLP VALID LAST
    }
    if(fRdKeepalive) {
        cbTx += 8;
        *(PDWORD)(pbTx + (i << 1)) = 0xffeeddcc;
        *(PDWORD)(pbTx + ((i << 1) + 4)) = 0x77020000;    // LOOPBACK TX
    }
    ctx->txbuf.cb += cbTx;
    // transmit
    if((ctx->txbuf.cb > ctx->perf.MAX_SIZE_TX) || (fFlush && ctx->txbuf.cb)) {
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, ctx->txbuf.pb, ctx->txbuf.cb, &cbTxed, NULL);
        if(status == 0x20 && ctx->perf.RETRY_ON_ERROR) {
            DeviceFPGA_ReInitializeFTDI(ctx); // try recovery if possible.
            status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, ctx->txbuf.pb, ctx->txbuf.cb, &cbTxed, NULL);
        }
        ctx->txbuf.cb = 0;
        return (0 == status);
    }
    return TRUE;
}

#define TLP_RX_MAX_SIZE        2048
VOID DeviceFPGA_RxTlpSynchronous(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DWORD status;
    DWORD i, j, cdwTlp = 0;
    BYTE pbTlp[TLP_RX_MAX_SIZE];
    PDWORD pdwTlp = (PDWORD)pbTlp;
    PDWORD pdwRx = (PDWORD)ctx->rxbuf.pb;
    DWORD dwStatus, *pdwData;
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, ctx->rxbuf.pb, ctx->rxbuf.cbMax, &ctx->rxbuf.cb, NULL);
    if(status == 0x20 && ctx->perf.RETRY_ON_ERROR) {
        DeviceFPGA_ReInitializeFTDI(ctx); // try recovery if possible.
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, ctx->rxbuf.pb, ctx->rxbuf.cbMax, &ctx->rxbuf.cb, NULL);
    }
    if(status) {
        ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x82);
        return;
    }
    for(i = 0; i < ctx->rxbuf.cb; i += 32) { // index in 64-bit (QWORD)
        while(*(PDWORD)(ctx->rxbuf.pb + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
            i += 4;
            if(i + 32 > ctx->rxbuf.cb) { return; }
        }
        dwStatus = *(PDWORD)(ctx->rxbuf.pb + i);
        pdwData = (PDWORD)(ctx->rxbuf.pb + i + 4);
        if((dwStatus & 0xf0000000) != 0xe0000000) {
            continue;
        }
        for(j = 0; j < 7; j++) {
            if((dwStatus & 0x03) == 0x00) { // PCIe TLP
                pdwTlp[cdwTlp] = *pdwData;
                cdwTlp++;
                if(cdwTlp >= TLP_RX_MAX_SIZE / sizeof(DWORD)) { return; }
            }
            if((dwStatus & 0x07) == 0x04) { // PCIe TLP and LAST
                if(cdwTlp >= 3) {
                    if(ctxDeviceMain->fVerboseExtraTlp) {
                        TLP_Print(pbTlp, cdwTlp << 2, FALSE);
                    }
                    if(ctx->hRxTlpCallbackFn) {
                        ctx->hRxTlpCallbackFn(ctx->pMRdBufferX, pbTlp, cdwTlp << 2);
                    }
                } else {
                    printf("Device Info: FPGA: Bad PCIe TLP received! Should not happen!\n");
                }
                cdwTlp = 0;
            }
            pdwData++;
            dwStatus >>= 4;
        }
    }
}

VOID DeviceFPGA_ReadScatterMEM_Impl(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cMEMs)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    TLP_CALLBACK_BUF_MRd_SCATTER rxbuf;
    DWORD tx[4] = { 0 };
    DWORD o, i, j, cb, cbFlush, cbTotalInCycle = 0;
    BOOL is32;
    PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
    PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
    PMEM_IO_SCATTER_HEADER pDMA;
    BYTE bTag;
    i = 0;
    ctx->pMRdBufferX = &rxbuf;
    while(i < cMEMs) {
        // Prepare callback buffer
        ctx->RxEccBit = ctx->RxEccBit ? 0 : 1;
        rxbuf.bEccBit = ctx->RxEccBit;
        rxbuf.cbReadTotal = 0;
        rxbuf.cph = cMEMs - i;
        rxbuf.pph = ppMEMs + i;
        ctx->hRxTlpCallbackFn = (VOID(*)(PVOID, PBYTE, DWORD))TLP_CallbackMRd_Scatter;
        // Transmit TLPs
        cbFlush = 0;
        cbTotalInCycle = 0;
        bTag = (ctx->RxEccBit ? 0x80 : 0) + (ctx->fAlgorithmReadTiny ? 0x40 : 0);
        for(; i < cMEMs; i++) {
            pDMA = *(ppMEMs + i);
            if((pDMA->cbMax <= pDMA->cb) || (pDMA->cbMax % 8) || (pDMA->cbMax > 0x1000) || !MemMap_VerifyTranslateMEM(pDMA, NULL)) { // already completed, unsupported size, not in memmap -> skip over
                bTag += ctx->fAlgorithmReadTiny ? 0x20 : 1;
                if(!(bTag & 0x3f)) { break; }
                continue;
            }
            cbTotalInCycle += pDMA->cbMax;
            if(cbTotalInCycle > ctx->perf.MAX_SIZE_RX) { break; } // over max size -> break loop and read result
            o = 0;
            while(o < pDMA->cbMax) {
                cb = ctx->fAlgorithmReadTiny ? 0x80 : pDMA->cbMax;
                is32 = pDMA->qwA + o < 0x100000000;
                if(is32) {
                    hdrRd32->h.TypeFmt = TLP_MRd32;
                    hdrRd32->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
                    hdrRd32->RequesterID = ctx->wDeviceId;
                    hdrRd32->Tag = bTag;
                    hdrRd32->FirstBE = 0xf;
                    hdrRd32->LastBE = 0xf;
                    hdrRd32->Address = (DWORD)(pDMA->qwA + o);
                } else {
                    hdrRd64->h.TypeFmt = TLP_MRd64;
                    hdrRd64->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
                    hdrRd64->RequesterID = ctx->wDeviceId;
                    hdrRd64->Tag = bTag;
                    hdrRd64->FirstBE = 0xf;
                    hdrRd64->LastBE = 0xf;
                    hdrRd64->AddressHigh = (DWORD)((pDMA->qwA + o) >> 32);
                    hdrRd64->AddressLow = (DWORD)(pDMA->qwA + o);
                }
                for(j = 0; j < 4; j++) {
                    ENDIAN_SWAP_DWORD(tx[j]);
                }
                cbFlush += cb;
                if((cbFlush >= ctx->perf.RX_FLUSH_LIMIT) || (ctx->fAlgorithmReadTiny && (cbFlush >= 0x1000))) {
                    DeviceFPGA_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, TRUE);
                    usleep(ctx->perf.DELAY_WRITE);
                    cbFlush = 0;
                } else {
                    DeviceFPGA_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, FALSE);
                }
                o += cb;
                bTag++;
            }
            if(ctx->fAlgorithmReadTiny) {
                if(i % 2) {
                    i++;
                    break;
                }
                bTag = (ctx->RxEccBit ? 0x80 : 0) + 0x40 + 0x20;
            } else if(!(bTag & 0x3f)) {
                i++;
                break;
            }
        }
        // Receive TLPs
        DeviceFPGA_TxTlp(ctx, NULL, 0, TRUE, TRUE);
        usleep(ctx->perf.DELAY_READ);
        DeviceFPGA_RxTlpSynchronous(ctx);
    }
    ctx->hRxTlpCallbackFn = NULL;
    ctx->pMRdBufferX = NULL;
}

VOID DeviceFPGA_ReadScatterMEM(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    DWORD iRetry, iMEM;
    BOOL fRetry;
    DeviceFPGA_ReadScatterMEM_Impl(ppMEMs, cpMEMs);
    for(iRetry = 0; iRetry < ctx->perf.RETRY_ON_ERROR; iRetry++) {
        fRetry = FALSE;
        for(iMEM = 0; iMEM < cpMEMs; iMEM++) {
            if((ppMEMs[iMEM]->cb < ppMEMs[iMEM]->cbMax) && MemMap_VerifyTranslateMEM(ppMEMs[iMEM], NULL)) {
                fRetry = TRUE;
                break;
            }
        }
        if(!fRetry) { return; }
        Sleep(25);
        DeviceFPGA_ReadScatterMEM_Impl(ppMEMs, cpMEMs);
    }
}

VOID DeviceFPGA_ProbeMEM_Impl(_In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_updates_bytes_(cPages) PBYTE pbResultMap)
{
    QWORD i;
    DWORD j, cTxTlp = 0;
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    TLP_CALLBACK_BUF_MRd bufMRd;
    DWORD tx[4];
    BOOL is32, isFlush;
    PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
    PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
    // split probe into processing chunks if too large...
    while(cPages > ctx->perf.PROBE_MAXPAGES) {
        DeviceFPGA_ProbeMEM_Impl(qwAddr, ctx->perf.PROBE_MAXPAGES, pbResultMap);
        cPages -= ctx->perf.PROBE_MAXPAGES;
        pbResultMap += ctx->perf.PROBE_MAXPAGES;
        qwAddr += (QWORD)ctx->perf.PROBE_MAXPAGES << 12;
    }
    // prepare
    bufMRd.cb = 0;
    bufMRd.pb = pbResultMap;
    bufMRd.cbMax = cPages;
    ctx->pMRdBufferX = &bufMRd;
    ctx->hRxTlpCallbackFn = (VOID(*)(PVOID, PBYTE, DWORD))TLP_CallbackMRdProbe;
    // transmit TLPs
    for(i = 0; i < cPages; i++) {
        if(pbResultMap[i]) { continue; } // skip over if page already marked as ok
        memset(tx, 0, 16);
        is32 = qwAddr + (i << 12) < 0x100000000;
        if(is32) {
            hdrRd32->h.TypeFmt = TLP_MRd32;
            hdrRd32->h.Length = 1;
            hdrRd32->RequesterID = ctx->wDeviceId;
            hdrRd32->FirstBE = 0xf;
            hdrRd32->LastBE = 0;
            hdrRd32->Address = (DWORD)(qwAddr + (i << 12) + ((i & 0x1f) << 2)); // 5 low address bits coded into the dword read.
            hdrRd32->Tag = (BYTE)((i >> 5) & 0x1f); // 5 high address bits coded into tag.
        } else {
            hdrRd64->h.TypeFmt = TLP_MRd64;
            hdrRd64->h.Length = 1;
            hdrRd64->RequesterID = ctx->wDeviceId;
            hdrRd64->FirstBE = 0xf;
            hdrRd64->LastBE = 0;
            hdrRd64->AddressHigh = (DWORD)((qwAddr + (i << 12)) >> 32);
            hdrRd64->AddressLow = (DWORD)(qwAddr + (i << 12) + ((i & 0x1f) << 2)); // 5 low address bits coded into the dword read.
            hdrRd64->Tag = (BYTE)((i >> 5) & 0x1f); // 5 high address bits coded into tag.
        }
        for(j = 0; j < 4; j++) {
            ENDIAN_SWAP_DWORD(tx[j]);
        }
        isFlush = (++cTxTlp % 24 == 0);
        if(isFlush) {
            DeviceFPGA_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, TRUE);
            usleep(ctx->perf.DELAY_PROBE_WRITE);
        } else {
            DeviceFPGA_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, FALSE);
        }
    }
    DeviceFPGA_TxTlp(ctx, NULL, 0, TRUE, TRUE);
    usleep(ctx->perf.DELAY_PROBE_READ);
    DeviceFPGA_RxTlpSynchronous(ctx);
    ctx->hRxTlpCallbackFn = NULL;
    ctx->pMRdBufferX = NULL;
}

VOID DeviceFPGA_ProbeMEM(_In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_updates_bytes_(cPages) PBYTE pbResultMap)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    DWORD i;
    DeviceFPGA_ProbeMEM_Impl(qwAddr, cPages, pbResultMap);
    if(ctx->perf.RETRY_ON_ERROR) {
        for(i = 0; i < cPages; i++) {
            if(0 == pbResultMap[i]) {
                Sleep(100);
                DeviceFPGA_ProbeMEM_Impl(qwAddr, cPages, pbResultMap);
                return;
            }
        }
    }
}

// write max 128 byte packets.
_Success_(return)
BOOL DeviceFPGA_WriteMEM_TXP(_Inout_ PDEVICE_CONTEXT_FPGA ctx, _In_ QWORD pa, _In_ BYTE bFirstBE, _In_ BYTE bLastBE, _In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD txbuf[36], i, cbTlp;
    PBYTE pbTlp = (PBYTE)txbuf;
    PTLP_HDR_MRdWr32 hdrWr32 = (PTLP_HDR_MRdWr32)txbuf;
    PTLP_HDR_MRdWr64 hdrWr64 = (PTLP_HDR_MRdWr64)txbuf;
    memset(pbTlp, 0, 16);
    if(pa < 0x100000000) {
        hdrWr32->h.TypeFmt = TLP_MWr32;
        hdrWr32->h.Length = (WORD)(cb + 3) >> 2;
        hdrWr32->FirstBE = bFirstBE;
        hdrWr32->LastBE = bLastBE;
        hdrWr32->RequesterID = ctx->wDeviceId;
        hdrWr32->Address = (DWORD)pa;
        for(i = 0; i < 3; i++) {
            ENDIAN_SWAP_DWORD(txbuf[i]);
        }
        memcpy(pbTlp + 12, pb, cb);
        cbTlp = (12 + cb + 3) & ~0x3;
    } else {
        hdrWr64->h.TypeFmt = TLP_MWr64;
        hdrWr64->h.Length = (WORD)(cb + 3) >> 2;
        hdrWr64->FirstBE = bFirstBE;
        hdrWr64->LastBE = bLastBE;
        hdrWr64->RequesterID = ctx->wDeviceId;
        hdrWr64->AddressHigh = (DWORD)(pa >> 32);
        hdrWr64->AddressLow = (DWORD)pa;
        for(i = 0; i < 4; i++) {
            ENDIAN_SWAP_DWORD(txbuf[i]);
        }
        memcpy(pbTlp + 16, pb, cb);
        cbTlp = (16 + cb + 3) & ~0x3;
    }
    return DeviceFPGA_TxTlp(ctx, pbTlp, cbTlp, FALSE, FALSE);
}

_Success_(return)
BOOL DeviceFPGA_WriteMEM(_In_ QWORD pa, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    BOOL result = TRUE;
    BYTE be, pbb[4];
    DWORD cbtx;
    // TX 1st dword if not aligned
    if(cb && (pa & 0x3)) {
        be = (cb < 3) ? (0xf >> (4 - cb)) : 0xf;
        be <<= pa & 0x3;
        cbtx = min(cb, 4 - (pa & 0x3));
        memcpy(pbb + (pa & 0x3), pb, cbtx);
        result = DeviceFPGA_WriteMEM_TXP(ctx, pa & ~0x3, be, 0, pbb, 4);
        pb += cbtx;
        cb -= cbtx;
        pa += cbtx;
    }
    // TX as 128-byte packets (aligned to 128-byte boundaries)
    while(result && cb) {
        cbtx = min(128 - (pa & 0x7f), cb);
        be = (cbtx & 0x3) ? (0xf >> (4 - (cbtx & 0x3))) : 0xf;
        result = (cbtx <= 4) ?
            DeviceFPGA_WriteMEM_TXP(ctx, pa, be, 0, pb, 4) :
            DeviceFPGA_WriteMEM_TXP(ctx, pa, 0xf, be, pb, cbtx);
        pb += cbtx;
        cb -= cbtx;
        pa += cbtx;
    }
    return DeviceFPGA_TxTlp(ctx, NULL, 0, FALSE, TRUE) && result; // Flush and Return.
}

_Success_(return)
BOOL DeviceFPGA_ListenTlp(_In_ DWORD dwTime)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    QWORD tmStart = GetTickCount64();
    ctx->hRxTlpCallbackFn = NULL;
    while(GetTickCount64() - tmStart < dwTime) {
        DeviceFPGA_TxTlp(ctx, NULL, 0, TRUE, TRUE);
        Sleep(10);
        DeviceFPGA_RxTlpSynchronous(ctx);
    }
    return TRUE;
}

_Success_(return)
BOOL DeviceFPGA_WriteTlp(_In_ PBYTE pbTlp, _In_ DWORD cbTlp)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    return DeviceFPGA_TxTlp(ctx, pbTlp, cbTlp, FALSE, TRUE);
}

_Success_(return)
BOOL DeviceFPGA_GetOption(_In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    PDEVICE_PERFORMANCE perf = &ctx->perf;
    if(!pqwValue) { return FALSE; }
    switch(fOption) {
        case LEECHCORE_OPT_FPGA_PROBE_MAXPAGES:
            *pqwValue = perf->PROBE_MAXPAGES;
            return TRUE;
        case LEECHCORE_OPT_FPGA_RX_FLUSH_LIMIT:
            *pqwValue = perf->RX_FLUSH_LIMIT;
            return TRUE;
        case LEECHCORE_OPT_FPGA_MAX_SIZE_RX:
            *pqwValue = perf->MAX_SIZE_RX;
            return TRUE;
        case LEECHCORE_OPT_FPGA_MAX_SIZE_TX:
            *pqwValue = perf->MAX_SIZE_TX;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DELAY_PROBE_READ:
            *pqwValue = perf->DELAY_PROBE_READ;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DELAY_PROBE_WRITE:
            *pqwValue = perf->DELAY_PROBE_WRITE;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DELAY_WRITE:
            *pqwValue = perf->DELAY_WRITE;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DELAY_READ:
            *pqwValue = perf->DELAY_READ;
            return TRUE;
        case LEECHCORE_OPT_FPGA_RETRY_ON_ERROR:
            *pqwValue = perf->RETRY_ON_ERROR;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DEVICE_ID:
            *pqwValue = ctx->wDeviceId;
            return TRUE;
        case LEECHCORE_OPT_FPGA_FPGA_ID:
            *pqwValue = ctx->wFpgaID;
            return TRUE;
        case LEECHCORE_OPT_FPGA_VERSION_MAJOR:
            *pqwValue = ctx->wFpgaVersionMajor;
            return TRUE;
        case LEECHCORE_OPT_FPGA_VERSION_MINOR:
            *pqwValue = ctx->wFpgaVersionMinor;
            return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL DeviceFPGA_SetOption(_In_ QWORD fOption, _In_ QWORD qwValue)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    PDEVICE_PERFORMANCE perf = &ctx->perf;
    switch(fOption) {
        case  LEECHCORE_OPT_FPGA_PROBE_MAXPAGES:
            perf->PROBE_MAXPAGES = (DWORD)qwValue;
            return TRUE;
        case LEECHCORE_OPT_FPGA_RX_FLUSH_LIMIT:
            perf->RX_FLUSH_LIMIT = (DWORD)qwValue;
            return TRUE;
        case LEECHCORE_OPT_FPGA_MAX_SIZE_RX:
            perf->MAX_SIZE_RX = (DWORD)qwValue;
            return TRUE;
        case LEECHCORE_OPT_FPGA_MAX_SIZE_TX:
            perf->MAX_SIZE_TX = (DWORD)qwValue;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DELAY_PROBE_READ:
            perf->DELAY_PROBE_READ = (DWORD)qwValue;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DELAY_PROBE_WRITE:
            perf->DELAY_PROBE_WRITE = (DWORD)qwValue;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DELAY_WRITE:
            perf->DELAY_WRITE = (DWORD)qwValue;
            return TRUE;
        case LEECHCORE_OPT_FPGA_DELAY_READ:
            perf->DELAY_READ = (DWORD)qwValue;
            return TRUE;
        case LEECHCORE_OPT_FPGA_RETRY_ON_ERROR:
            perf->RETRY_ON_ERROR = qwValue ? 1 : 0;
            return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL DeviceFPGA_CommandData(_In_ ULONG64 fOption, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(cbDataOut) PBYTE pbDataOut, _In_ DWORD cbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    DWORD fOptionHi, fOptionLo;
    WORD fCfgRegConfig;
    if(pcbDataOut) { *pcbDataOut = 0; }
    fOptionHi = fOption >> 32;
    fOptionLo = fOption & 0xffffffff;
    switch(fOptionLo) {
        case LEECHCORE_COMMANDDATA_FPGA_WRITE_TLP:
            return (cbDataIn >= 12) && !(cbDataIn % 4) && pbDataIn && DeviceFPGA_WriteTlp(pbDataIn, cbDataIn);
        case LEECHCORE_COMMANDDATA_FPGA_LISTEN_TLP:
            return (cbDataIn == 4) && !(cbDataIn % 4) && pbDataIn && DeviceFPGA_ListenTlp(*(PDWORD)pbDataIn);
        case LEECHCORE_COMMANDDATA_FPGA_PCIECFGSPACE:
            if(!pbDataOut || (cbDataOut < 0x1000) || (ctx->wFpgaVersionMajor < 4)) { return FALSE; }
            if(pcbDataOut) { *pcbDataOut = 0x1000; };
            DeviceFPGA_PCIeCfgSpaceRead(ctx, pbDataOut);
            return TRUE;
        case LEECHCORE_COMMANDDATA_FPGA_CFGREGCFG:
        case LEECHCORE_COMMANDDATA_FPGA_CFGREGPCIE:
            if(ctx->wFpgaVersionMajor < 4) { return FALSE; }
            fCfgRegConfig =
                ((fOptionLo == LEECHCORE_COMMANDDATA_FPGA_CFGREGCFG) ? FPGA_CONFIG_CORE : FPGA_CONFIG_PCIE) |
                ((fOptionHi & 0x8000) ? FPGA_CONFIG_SPACE_READWRITE : FPGA_CONFIG_SPACE_READONLY);
            if(pbDataIn) {
                DeviceFPGA_ConfigWrite(ctx, fOptionHi & 0x3fff, pbDataIn, (WORD)cbDataIn, fCfgRegConfig);
            }
            if(pbDataOut) {
                DeviceFPGA_ConfigRead(ctx, fOptionHi & 0x3fff, pbDataOut, (WORD)cbDataOut, fCfgRegConfig);
                if(pcbDataOut) { *pcbDataOut = (WORD)cbDataOut; }
            }
            return TRUE;
        case LEECHCORE_COMMANDDATA_FPGA_CFGREGDRP:
            if(ctx->wFpgaVersionMajor < 4) { return FALSE; }
            if((cbDataOut != 0x100) || pbDataIn || cbDataIn) { return FALSE; }
            DeviceFPGA_PCIeDrpRead(ctx, pbDataOut);
            if(pcbDataOut) { *pcbDataOut = 0x100; }
            return TRUE;
        case LEECHCORE_COMMANDDATA_FPGA_CFGREGCFG_MARKWR:
        case LEECHCORE_COMMANDDATA_FPGA_CFGREGPCIE_MARKWR:
            if(ctx->wFpgaVersionMajor < 4) { return FALSE; }
            if(!pbDataIn || (cbDataIn != 4)) { return FALSE; }
            fCfgRegConfig =
                ((fOptionLo == LEECHCORE_COMMANDDATA_FPGA_CFGREGCFG_MARKWR) ? FPGA_CONFIG_CORE : FPGA_CONFIG_PCIE) |
                FPGA_CONFIG_SPACE_READWRITE;
            return DeviceFPGA_ConfigWriteEx(ctx, fOptionHi & 0x3fff, pbDataIn, pbDataIn + 2, fCfgRegConfig);
        case LEECHCORE_COMMANDDATA_FPGA_PCIECFGSPACE_WR:
            if(ctx->wFpgaVersionMajor < 4) { return FALSE; }
            if((ctx->wFpgaVersionMajor == 4) && (ctx->wFpgaVersionMinor == 2)) { return FALSE; }
            if(pbDataIn || !cbDataIn || !(cbDataIn % 4) || (cbDataIn > 0x1000)) { return FALSE; }
            return DeviceFPGA_PCIeCfgSpaceWrite(ctx, fOptionHi & 0x3fff, pbDataIn, cbDataIn);
        case LEECHCORE_COMMANDDATA_FPGA_CFGREG_DEBUGPRINT:
            DeviceFPGA_ConfigPrint(ctx);
            return TRUE;
    }
    return FALSE;
}

#define FPGA_OPTION_UDP_ADDRESS     0
#define FPGA_OPTION_PCIE            1
#define FPGA_OPTION_DELAY_READ      2
#define FPGA_OPTION_DELAY_WRITE     3
#define FPGA_OPTION_DELAY_PROBE     4
#define FPGA_OPTION_READ_ALGORITHM  5
#define FPGA_OPTION_READ_SIZE       6
#define FPGA_OPTION_READ_RETRY      7
#define FPGA_OPTION_DEVICE_INDEX    8
#define FPGA_OPTION_MAX             8

VOID DeviceFPGA_Open_ParseParams(_Out_writes_(FPGA_OPTION_MAX + 1) PDWORD dwOptions)
{
    SIZE_T i = 0, j;
    CHAR sz[MAX_PATH];
    LPCSTR szOPTIONS[] = { "ip=", "pciegen=", "tmread=", "tmwrite=", "tmprobe=", "algo=", "readsize=", "readretry=", "deviceindex=" };
    ZeroMemory(dwOptions, 6 * sizeof(DWORD));
    if(0 == _strnicmp("fpga://", ctxDeviceMain->cfg.szDevice, 7)) { i = 7; }
    if(0 == _strnicmp("rawudp://", ctxDeviceMain->cfg.szDevice, 9)) { i = 9; }
    if(!i) { return; }
    strncpy_s(sz, MAX_PATH, ctxDeviceMain->cfg.szDevice + i, _TRUNCATE);
    i = strlen(sz);
    while(TRUE) {
        if((i == 0) || (sz[i] == ',')) {
            if((sz[i] == ',')) {
                sz[i] = '\0';
                i++;
            }
            for(j = 0; j <= FPGA_OPTION_MAX; j++) {
                if(0 == _strnicmp(szOPTIONS[j], sz + i, strlen(szOPTIONS[j]))) {
                    dwOptions[j] = j ? (DWORD)Util_GetNumericA(sz + i + strlen(szOPTIONS[j])) : inet_addr(sz + i + strlen(szOPTIONS[j]));
                }
            }
        }
        if(i == 0) { return; }
        i--;
    }
}

_Success_(return)
BOOL DeviceFPGA_Open()
{
    LPSTR szDeviceError;
    PDEVICE_CONTEXT_FPGA ctx;
    DWORD dwOption[FPGA_OPTION_MAX + 1] = { 0 };
    ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FPGA));
    if(!ctx) { return FALSE; }
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    // parse parameters (if any)
    DeviceFPGA_Open_ParseParams(dwOption);
    if(dwOption[FPGA_OPTION_UDP_ADDRESS]) {
        szDeviceError = DeviceFPGA_InitializeUDP(ctx, dwOption[FPGA_OPTION_UDP_ADDRESS]);
    } else {
        szDeviceError = DeviceFPGA_InitializeFTDI(ctx, dwOption[FPGA_OPTION_DEVICE_INDEX]);
    }
    if(szDeviceError) { goto fail; }
    DeviceFPGA_GetDeviceID_FpgaVersion(ctx);
    // verify parameters and set version&speed
    DeviceFPGA_SetSpeedPCIeGen(ctx, dwOption[FPGA_OPTION_PCIE]);
    if(!ctx->wDeviceId) {
        szDeviceError = "Unable to retrieve required Device PCIe ID";
        goto fail;
    }
    DeviceFPGA_SetPerformanceProfile(ctx);
    ctx->rxbuf.cbMax = (DWORD)(1.30 * ctx->perf.MAX_SIZE_RX + 0x2000);  // buffer size tuned to lowest possible (+margin) for performance.
    ctx->rxbuf.pb = LocalAlloc(0, ctx->rxbuf.cbMax);
    if(!ctx->rxbuf.pb) { goto fail; }
    ctx->txbuf.cbMax = ctx->perf.MAX_SIZE_TX + 0x10000;
    ctx->txbuf.pb = LocalAlloc(0, ctx->txbuf.cbMax);
    if(!ctx->txbuf.pb) { goto fail; }
    // set callback functions and fix up config
    ctxDeviceMain->cfg.tpDevice = LEECHCORE_DEVICE_FPGA;
    ctxDeviceMain->cfg.fVolatile = TRUE;
    ctxDeviceMain->cfg.paMaxNative = 0x0000ffffffffffff;
    ctxDeviceMain->pfnClose = DeviceFPGA_Close;
    ctxDeviceMain->pfnProbeMEM = DeviceFPGA_ProbeMEM;
    ctxDeviceMain->pfnReadScatterMEM = DeviceFPGA_ReadScatterMEM;
    ctxDeviceMain->pfnWriteMEM = DeviceFPGA_WriteMEM;
    ctxDeviceMain->pfnCommandData = DeviceFPGA_CommandData;
    ctxDeviceMain->pfnGetOption = DeviceFPGA_GetOption;
    ctxDeviceMain->pfnSetOption = DeviceFPGA_SetOption;
    if(dwOption[FPGA_OPTION_DELAY_READ]) { ctx->perf.DELAY_READ = dwOption[FPGA_OPTION_DELAY_READ]; }
    if(dwOption[FPGA_OPTION_DELAY_WRITE]) { ctx->perf.DELAY_WRITE = dwOption[FPGA_OPTION_DELAY_WRITE]; }
    if(dwOption[FPGA_OPTION_DELAY_PROBE]) { ctx->perf.DELAY_PROBE_READ = dwOption[FPGA_OPTION_DELAY_PROBE]; }
    if(dwOption[FPGA_OPTION_READ_RETRY]) { ctx->perf.RETRY_ON_ERROR = dwOption[FPGA_OPTION_READ_RETRY]; }
    if(dwOption[FPGA_OPTION_READ_SIZE] >= 0x1000) { ctx->perf.MAX_SIZE_RX = min(ctx->perf.MAX_SIZE_RX, dwOption[FPGA_OPTION_READ_SIZE] & ~0xfff); }
    ctx->fAlgorithmReadTiny = (dwOption[FPGA_OPTION_READ_ALGORITHM] == 2);
    // return
    if(ctxDeviceMain->fVerbose) {
        printf(
            "DEVICE: FPGA: %s PCIe gen%i x%i [%i,%i,%i] [v%i.%i,%04x]\n",
            ctx->perf.SZ_DEVICE_NAME,
            DeviceFPGA_PHY_GetPCIeGen(ctx),
            DeviceFPGA_PHY_GetLinkWidth(ctx),
            ctx->perf.DELAY_READ,
            ctx->perf.DELAY_WRITE,
            ctx->perf.DELAY_PROBE_READ,
            ctx->wFpgaVersionMajor,
            ctx->wFpgaVersionMinor,
            ctx->wDeviceId);
    }
    if(ctxDeviceMain->fVerboseExtra) {
        DeviceFPGA_ConfigPrint(ctx);
    }
    return TRUE;
fail:
    if(ctxDeviceMain->fVerboseExtra && ctx->dev.fInitialized) {
        DeviceFPGA_ConfigPrint(ctx);
    }
    if(szDeviceError && ctxDeviceMain->fVerbose) {
        printf(
            "DEVICE: FPGA: ERROR: %s [%i,v%i.%i,%04x]\n",
            szDeviceError,
            ctx->wFpgaID,
            ctx->wFpgaVersionMajor,
            ctx->wFpgaVersionMinor,
            ctx->wDeviceId);
    }
    DeviceFPGA_Close();
    return FALSE;
}
