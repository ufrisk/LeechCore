// devicefpga.h : implementation related to the:
//     - Xilinx SP605 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - Xilinx AC701 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - PCIeScreamer board flashed with PCILeech bitstream.
//
// (c) Ulf Frisk, 2017-2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "device.h"
#include "memmap.h"
#include "tlp.h"
#include "util.h"

//-------------------------------------------------------------------------------
// FPGA defines below.
//-------------------------------------------------------------------------------

#define FPGA_CMD_VERSION_MAJOR  0x01
#define FPGA_CMD_DEVICE_ID      0x03
#define FPGA_CMD_VERSION_MINOR  0x05

#define ENDIAN_SWAP_WORD(x)     (x = (x << 8) | (x >> 8))
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
    BOOL RETRY_ON_ERROR;
} DEVICE_PERFORMANCE, *PDEVICE_PERFORMANCE;

#define DEVICE_ID_SP605_FT601                   0
#define DEVICE_ID_PCIESCREAMER                  1
#define DEVICE_ID_AC701_FT601                   2
#define DEVICE_ID_PCIESCREAMER_R2               3
#define DEVICE_ID_PCIECARD                      4
#define DEVICE_ID_MAX                           4

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
        .RETRY_ON_ERROR = FALSE
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
        .RETRY_ON_ERROR = TRUE
    }, {
        .SZ_DEVICE_NAME = "AC701 / FT601",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x20000,
        .MAX_SIZE_TX = 0x8000,
        .DELAY_PROBE_READ = 500,
        .DELAY_PROBE_WRITE = 0,
        .DELAY_WRITE = 0,
        .DELAY_READ = 300,
        .RETRY_ON_ERROR = FALSE
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
        .RETRY_ON_ERROR = FALSE
    }, {
        .SZ_DEVICE_NAME = "PCIe Card",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x1c000,
        .MAX_SIZE_TX = 0x1000,
        .DELAY_PROBE_READ = 500,
        .DELAY_PROBE_WRITE = 150,
        .DELAY_WRITE = 0,
        .DELAY_READ = 300,
        .RETRY_ON_ERROR = FALSE
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
        HANDLE hFTDI;
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
// FPGA implementation below:
//-------------------------------------------------------------------------------

LPSTR DeviceFPGA_InitializeFTDI(_In_ PDEVICE_CONTEXT_FPGA ctx)
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
        GetProcAddress(ctx->dev.hModule, "FT_ReadPipe");
    ctx->dev.pfnFT_WritePipe = (ULONG(*)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_WritePipe");
    pfnFT_GetChipConfiguration = (ULONG(*)(HANDLE, PVOID))GetProcAddress(ctx->dev.hModule, "FT_GetChipConfiguration");
    pfnFT_SetChipConfiguration = (ULONG(*)(HANDLE, PVOID))GetProcAddress(ctx->dev.hModule, "FT_SetChipConfiguration");
    pfnFT_SetSuspendTimeout = (ULONG(*)(HANDLE, ULONG))GetProcAddress(ctx->dev.hModule, "FT_SetSuspendTimeout");
    if(!ctx->dev.pfnFT_Create) {
        szErrorReason = "Unable to retrieve required functions from FTD3XX.dll";
        goto fail;
    }
    // Open FTDI
    status = ctx->dev.pfnFT_Create(NULL, 0x10 /*FT_OPEN_BY_INDEX*/, &ctx->dev.hFTDI);
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
        return DeviceFPGA_InitializeFTDI(ctx);
    }
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

BOOL DeviceFPGA_GetSetPHY(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ BOOL isUpdate)
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

VOID DeviceFPGA_SetSpeedPCIeGen1(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    if(ctx->phySupported && ctx->phy.rd.pl_sel_lnk_rate) {
        ctx->phy.wr.pl_directed_link_auton = 1;
        ctx->phy.wr.pl_directed_link_speed = 0;
        ctx->phy.wr.pl_directed_link_change = 2;
        DeviceFPGA_GetSetPHY(ctx, TRUE);
    }
}

VOID DeviceFPGA_GetDeviceID_FpgaVersion(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DWORD status;
    DWORD cbTX, cbRX, i, j;
    PBYTE pbRX;
    DWORD dwStatus, dwData, cdwCfg = 0;
    PDWORD pdwData;
    BYTE pbTX[32] = {
        // cfg status: (pcie bus,dev,fn id)
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x01, 0x77,
        // cmd msg: FPGA bitstream version (major)
        0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x03, 0x77,
        // cmd msg: FPGA bitstream version (minor)
        0x00, 0x00, 0x00, 0x00,  0x05, 0x00, 0x03, 0x77,
        // cmd msg: FPGA bitstream device id
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x03, 0x77
    };
    if(!(pbRX = LocalAlloc(0, 0x01000000))) { return; }
    // Write and read data from device. Initially 0x1000 bytes of data is read
    // - this is enough in most situations, but if there is previous crap data
    // 16MB may be read to clear queued device data (= slow, 3-4 extra seconds)
    while(TRUE) {
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTX, sizeof(pbTX), &cbTX, NULL);
        if(status) { goto fail; }
        Sleep(10);
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, 0x1000, &cbRX, NULL);
        if(status) { goto fail; }
        if(cbRX < 0x1000) { break; }
        Sleep(10);
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, 0x01000000, &cbRX, NULL);
        if(status) { goto fail; }
    }
    // Interpret read data
    for(i = 0; i < cbRX; i += 32) {
        while(*(PDWORD)(pbRX + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
            i += 4;
            if(i + 32 > cbRX) { goto fail; }
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
    ctx->phySupported = (ctx->wFpgaVersionMajor >= 3) ? DeviceFPGA_GetSetPHY(ctx, FALSE) : FALSE;
fail:
    LocalFree(pbRX);
}

VOID DeviceFPGA_SetPerformanceProfile(_Inout_ PDEVICE_CONTEXT_FPGA ctx)
{
    memcpy(&ctx->perf, &PERFORMANCE_PROFILES[(ctx->wFpgaID <= DEVICE_ID_MAX) ? ctx->wFpgaID : 0], sizeof(DEVICE_PERFORMANCE));
}

//-------------------------------------------------------------------------------
// TLP handling functionality below:
//-------------------------------------------------------------------------------

BOOL DeviceFPGA_TxTlp(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_reads_(cbTlp) PBYTE pbTlp, _In_ DWORD cbTlp, BOOL fRdKeepalive, BOOL fFlush)
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
            if(ctx->fAlgorithmReadTiny && ((bTag & 0x3f) < 0x20)) { bTag = 0x20; }
            if(!(bTag & 0x3f)) { break; }
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
    DWORD i = 0;
    BOOL fRetry = FALSE;
    DeviceFPGA_ReadScatterMEM_Impl(ppMEMs, cpMEMs);
    if(ctx->perf.RETRY_ON_ERROR) {
        while(i < cpMEMs) {
            if((ppMEMs[i]->cb < ppMEMs[i]->cbMax) && ctx->perf.RETRY_ON_ERROR && MemMap_VerifyTranslateMEM(ppMEMs[i], NULL) && !fRetry) {
                Sleep(100);
                DeviceFPGA_ReadScatterMEM_Impl(ppMEMs, cpMEMs);
                fRetry = TRUE;
            }
            i++;
        }
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
        qwAddr += ctx->perf.PROBE_MAXPAGES << 12;
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

BOOL DeviceFPGA_WriteTlp(_In_ PBYTE pbTlp, _In_ DWORD cbTlp)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxDeviceMain->hDevice;
    return DeviceFPGA_TxTlp(ctx, pbTlp, cbTlp, FALSE, TRUE);
}

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

BOOL DeviceFPGA_CommandData(_In_ ULONG64 fOption, _In_reads_(cbDataIn) PBYTE pbDataIn, _In_ DWORD cbDataIn, _Out_writes_opt_(cbDataOut) PBYTE pbDataOut, _In_ DWORD cbDataOut, _Out_opt_ PDWORD pcbDataOut)
{
    switch(fOption) {
        case LEECHCORE_COMMANDDATA_FPGA_WRITE_TLP:
            return (cbDataIn >= 12) && pbDataIn && DeviceFPGA_WriteTlp(pbDataIn, cbDataIn);
        case LEECHCORE_COMMANDDATA_FPGA_LISTEN_TLP:
            return (cbDataIn == 4) && pbDataIn && DeviceFPGA_ListenTlp(*(PDWORD)pbDataIn);
    }
    return FALSE;
}

VOID DeviceFPGA_Open_ParseParams(_Out_writes_(4) PDWORD dwOptions)
{
    CHAR _szBuf[MAX_PATH];
    DWORD i, j;
    LPSTR sz;
    if(0 == _strnicmp("fpga://", ctxDeviceMain->cfg.szDevice, 7)) {
        strcpy_s(_szBuf, _countof(_szBuf), ctxDeviceMain->cfg.szDevice);
        sz = _szBuf + 7;
        for(i = 7, j = 0; i < _countof(_szBuf); i++) {

            if(':' == _szBuf[i]) {
                _szBuf[i] = 0;
                dwOptions[j] = atoi(sz);
                if(++j == 4) { return; }
                sz = _szBuf + i + 1;
                continue;
            }

            if('\0' == _szBuf[i]) {
                dwOptions[j] = atoi(sz);
                return;
            }

        }
    }
}

#define OPTION_PCIE             0
#define OPTION_DELAY_READ       1
#define OPTION_DELAY_WRITE      2
#define OPTION_DELAY_PROBE      3

BOOL DeviceFPGA_Open()
{
    LPSTR szDeviceError;
    PDEVICE_CONTEXT_FPGA ctx;
    DWORD dwOption[4] = { 0 };
    ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FPGA));
    if(!ctx) { return FALSE; }
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    szDeviceError = DeviceFPGA_InitializeFTDI(ctx);
    if(szDeviceError) { goto fail; }
    DeviceFPGA_GetDeviceID_FpgaVersion(ctx);
    // parse parameters (if any)
    DeviceFPGA_Open_ParseParams(dwOption);
    if(dwOption[OPTION_PCIE] == 1) {
        DeviceFPGA_SetSpeedPCIeGen1(ctx);
        DeviceFPGA_GetDeviceID_FpgaVersion(ctx);
    }
    if(!ctx->wDeviceId) {
        szDeviceError = "Unable to retrieve required Device PCIe ID";
        goto fail;
    }
    DeviceFPGA_SetPerformanceProfile(ctx);
    ctx->rxbuf.cbMax = (DWORD)(1.30 * ctx->perf.MAX_SIZE_RX + 0x1000);  // buffer size tuned to lowest possible (+margin) for performance.
    ctx->rxbuf.pb = LocalAlloc(0, ctx->rxbuf.cbMax);
    if(!ctx->rxbuf.pb) { goto fail; }
    ctx->txbuf.cbMax = ctx->perf.MAX_SIZE_TX + 0x10000;
    ctx->txbuf.pb = LocalAlloc(0, ctx->txbuf.cbMax);
    if(!ctx->txbuf.pb) { goto fail; }
    // set callback functions and fix up config
    ctxDeviceMain->cfg.tpDevice = LEECHCORE_DEVICE_FPGA;
    ctxDeviceMain->cfg.fVolatile = TRUE;
    ctxDeviceMain->cfg.cbMaxSizeMemIo = ctxDeviceMain->cfg.cbMaxSizeMemIo ? min(ctxDeviceMain->cfg.cbMaxSizeMemIo, ctx->perf.MAX_SIZE_RX) : ctx->perf.MAX_SIZE_RX; // ctx->perf.MAX_SIZE_RX (or lower user-value)
    ctxDeviceMain->cfg.paMaxNative = 0x0000ffffffffffff;
    ctxDeviceMain->pfnClose = DeviceFPGA_Close;
    ctxDeviceMain->pfnProbeMEM = DeviceFPGA_ProbeMEM;
    ctxDeviceMain->pfnReadScatterMEM = DeviceFPGA_ReadScatterMEM;
    ctxDeviceMain->pfnWriteMEM = DeviceFPGA_WriteMEM;
    ctxDeviceMain->pfnCommandData = DeviceFPGA_CommandData;
    ctxDeviceMain->pfnGetOption = DeviceFPGA_GetOption;
    ctxDeviceMain->pfnSetOption = DeviceFPGA_SetOption;
    if(dwOption[OPTION_DELAY_READ]) { ctx->perf.DELAY_READ = dwOption[OPTION_DELAY_READ]; }
    if(dwOption[OPTION_DELAY_WRITE]) { ctx->perf.DELAY_WRITE = dwOption[OPTION_DELAY_WRITE]; }
    if(dwOption[OPTION_DELAY_PROBE]) { ctx->perf.DELAY_PROBE_READ = dwOption[OPTION_DELAY_PROBE]; }
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
    return TRUE;
fail:
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
