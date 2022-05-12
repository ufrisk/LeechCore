// device_fpga.c : implementation related to the:
//     - Xilinx SP605 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - Xilinx AC701 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - PCIeScreamer board flashed with PCILeech bitstream.
//     - ScreamerM2 board flashed with PCILeech bitstream.
//     - RawUDP protocol - access FPGA over raw UDP packet stream (NeTV2 ETH)
//     - FT2232H/FT245 protocol - access FPGA via FT2232H USB2 instead of FT601 USB3.
//
// (c) Ulf Frisk, 2017-2022
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcore.h"
#include "leechcore_device.h"
#include "leechcore_internal.h"
#include "oscompatibility.h"
#include "util.h"

//-------------------------------------------------------------------------------
// FPGA defines below.
//-------------------------------------------------------------------------------

#define FPGA_CMD_VERSION_MAJOR          0x01
#define FPGA_CMD_DEVICE_ID              0x03
#define FPGA_CMD_VERSION_MINOR          0x05

#define FPGA_REG_CORE                 0x0003
#define FPGA_REG_PCIE                 0x0001
#define FPGA_REG_READONLY             0x0000
#define FPGA_REG_READWRITE            0x8000
#define FPGA_REG_SHADOWCFGSPACE       0xC000

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
    DWORD PROBE_MAXPAGES;     // 0x400
    DWORD RX_FLUSH_LIMIT;
    DWORD MAX_SIZE_RX;        // in data bytes (excl. overhead/TLP headers)
    DWORD MAX_SIZE_TX;        // in total data (incl. overhead/TLP headers)
    DWORD DELAY_PROBE_READ;
    DWORD DELAY_PROBE_WRITE;
    DWORD DELAY_WRITE;
    DWORD DELAY_READ;
    DWORD RETRY_ON_ERROR;
    DWORD F_TINY;
} DEVICE_PERFORMANCE, *PDEVICE_PERFORMANCE;

typedef union tdFPGA_HANDLESOCKET {
    HANDLE h;
    SOCKET Socket;
} FPGA_HANDLESOCKET;

#define DEVICE_ID_SP605_FT601                   0x00
#define DEVICE_ID_PCIESCREAMER                  0x01
#define DEVICE_ID_AC701_FT601                   0x02
#define DEVICE_ID_PCIESCREAMER_R2               0x03
#define DEVICE_ID_PCIESCREAMER_M2               0x04
#define DEVICE_ID_NETV2_UDP                     0x05
#define DEVICE_ID_UNSUPPORTED1                  0x06
#define DEVICE_ID_UNSUPPORTED2                  0x07
#define DEVICE_ID_FT2232H                       0x08
#define DEVICE_ID_ENIGMA_X1                     0x09
#define DEVICE_ID_ENIGMA_X2                     0x0A
#define DEVICE_ID_PCIESCREAMER_M2_X4            0x0B
#define DEVICE_ID_PCIESQUIRREL                  0x0C
#define DEVICE_ID_DEVICE13N                     0x0D
#define DEVICE_ID_DEVICE14T                     0x0E
#define DEVICE_ID_DEVICE15N                     0x0F
#define DEVICE_ID_DEVICE16T                     0x10
#define DEVICE_ID_MAX                           0x10

const DEVICE_PERFORMANCE PERFORMANCE_PROFILES[DEVICE_ID_MAX + 1] = {
    { .SZ_DEVICE_NAME = "SP605 / FT601",         .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0x8000, .MAX_SIZE_RX = 0x1f000, .MAX_SIZE_TX = 0x2000, .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 0,   .DELAY_WRITE = 175, .DELAY_READ = 400, .RETRY_ON_ERROR = 0, .F_TINY = 0 },
    // The PCIeScreamer R1 have a problem with the PCIe link stability which results on lost or delayed TLPS - workarounds are in place to retry after a delay.
    { .SZ_DEVICE_NAME = "PCIeScreamer R1",       .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x1c000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 1000, .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 0,   .DELAY_READ = 500, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "AC701 / FT601",         .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x1c000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 0,   .DELAY_WRITE = 0,   .DELAY_READ = 300, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "PCIeScreamer R2",       .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x1c000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 750,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 0,   .DELAY_READ = 400, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "ScreamerM2",            .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x1c000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 25,  .DELAY_READ = 300, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "NeTV2 RawUDP",          .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x1c000, .MAX_SIZE_TX = 0x400,  .DELAY_PROBE_READ = 0,    .DELAY_PROBE_WRITE = 0,   .DELAY_WRITE = 0,   .DELAY_READ = 0,   .RETRY_ON_ERROR = 0, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "Unsupported",           .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x14000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 35,  .DELAY_READ = 350, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "Unsupported",           .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x14000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 35,  .DELAY_READ = 350, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "FT2232H #1",            .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x30000, .MAX_SIZE_TX = 0x8000, .DELAY_PROBE_READ = 1000, .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 0,   .DELAY_READ = 0,   .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "Enigma X1",             .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x3c000, .MAX_SIZE_TX = 0x13f0, .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 10,  .DELAY_READ = 250, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "Enigma X1 (FutureUse)", .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x30000, .MAX_SIZE_TX = 0x13f0, .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 10,  .DELAY_READ = 250, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "ScreamerM2x4",          .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x14000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 25,  .DELAY_READ = 300, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "PCIeSquirrel",          .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x1c000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 25,  .DELAY_READ = 300, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "Device #13N",           .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x14000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 35,  .DELAY_READ = 350, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "Device #14T",           .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x14000, .MAX_SIZE_TX = 0x3f0,  .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 35,  .DELAY_READ = 350, .RETRY_ON_ERROR = 1, .F_TINY = 1 },
    { .SZ_DEVICE_NAME = "Device #15N",           .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x30000, .MAX_SIZE_TX = 0x13f0, .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 20,  .DELAY_READ = 300, .RETRY_ON_ERROR = 1, .F_TINY = 0 },
    { .SZ_DEVICE_NAME = "Device #16T",           .PROBE_MAXPAGES = 0x400, .RX_FLUSH_LIMIT = 0,      .MAX_SIZE_RX = 0x30000, .MAX_SIZE_TX = 0x13f0, .DELAY_PROBE_READ = 500,  .DELAY_PROBE_WRITE = 150, .DELAY_WRITE = 20,  .DELAY_READ = 300, .RETRY_ON_ERROR = 1, .F_TINY = 1 },
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
    BOOL fRestartDevice;
    QWORD qwDeviceIndex;
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
        BOOL f2232h;
        union {
            HANDLE hFTDI;
            SOCKET SocketUDP;
        };
        ULONG(WINAPI *pfnFT_Create)(
            PVOID pvArg,
            DWORD dwFlags,
            HANDLE *pftHandle
            );
        ULONG(WINAPI *pfnFT_Close)(
            HANDLE ftHandle
            );
        ULONG(WINAPI *pfnFT_WritePipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID,
            PUCHAR pucBuffer,
            ULONG ulBufferLength,
            PULONG pulBytesTransferred,
            LPOVERLAPPED pOverlapped
            );
        ULONG(WINAPI *pfnFT_ReadPipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID,
            PUCHAR pucBuffer,
            ULONG ulBufferLength,
            PULONG pulBytesTransferred,
            LPOVERLAPPED pOverlapped
            );
        ULONG(WINAPI *pfnFT_AbortPipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID
            );
        ULONG(WINAPI *pfnFT_GetOverlappedResult)(
            HANDLE ftHandle,
            LPOVERLAPPED pOverlapped,
            PULONG pulLengthTransferred,
            BOOL bWait
            );
        ULONG(WINAPI *pfnFT_InitializeOverlapped)(
            HANDLE ftHandle,
            LPOVERLAPPED pOverlapped
            );
        ULONG(WINAPI *pfnFT_ReleaseOverlapped)(
            HANDLE ftHandle,
            LPOVERLAPPED pOverlapped
        );
    } dev;
    struct {
        BOOL fEnabled;
        OVERLAPPED oOverlapped;
    } async;
    PVOID pMRdBufferX; // NULL || PTLP_CALLBACK_BUF_MRd || PTLP_CALLBACK_BUF_MRd_2
    VOID(*hRxTlpCallbackFn)(_Inout_ PVOID pBufferMrd, _In_ PBYTE pb, _In_ DWORD cb);
    BYTE RxEccBit;
    struct {
        // optional user-settable tlp read callback function:
        PVOID ctx;
        PLC_TLP_READ_FUNCTION_CALLBACK pfn;
        BOOL fInfo;
        BOOL fNoCpl;
        BOOL fThread;
    } read_callback;
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
// TLP defines and functionality below:
//-------------------------------------------------------------------------------

#define TLP_MRd32       0x00
#define TLP_MRd64       0x20
#define TLP_MRdLk32     0x01
#define TLP_MRdLk64     0x21
#define TLP_MWr32       0x40
#define TLP_MWr64       0x60
#define TLP_IORd        0x02
#define TLP_IOWr        0x42
#define TLP_CfgRd0      0x04
#define TLP_CfgRd1      0x05
#define TLP_CfgWr0      0x44
#define TLP_CfgWr1      0x45
#define TLP_Cpl         0x0A
#define TLP_CplD        0x4A
#define TLP_CplLk       0x0B
#define TLP_CplDLk      0x4B

typedef struct tdTLP_HDR {
    WORD Length : 10;
    WORD _AT : 2;
    WORD _Attr : 2;
    WORD _EP : 1;
    WORD _TD : 1;
    BYTE _R1 : 4;
    BYTE _TC : 3;
    BYTE _R2 : 1;
    BYTE TypeFmt;
} TLP_HDR, *PTLP_HDR;

typedef struct tdTLP_HDR_MRdWr32 {
    TLP_HDR h;
    BYTE FirstBE : 4;
    BYTE LastBE : 4;
    BYTE Tag;
    WORD RequesterID;
    DWORD Address;
} TLP_HDR_MRdWr32, *PTLP_HDR_MRdWr32;

typedef struct tdTLP_HDR_MRdWr64 {
    TLP_HDR h;
    BYTE FirstBE : 4;
    BYTE LastBE : 4;
    BYTE Tag;
    WORD RequesterID;
    DWORD AddressHigh;
    DWORD AddressLow;
} TLP_HDR_MRdWr64, *PTLP_HDR_MRdWr64;

typedef struct tdTLP_HDR_CplD {
    TLP_HDR h;
    WORD ByteCount : 12;
    WORD _BCM : 1;
    WORD Status : 3;
    WORD CompleterID;
    BYTE LowerAddress : 7;
    BYTE _R1 : 1;
    BYTE Tag;
    WORD RequesterID;
} TLP_HDR_CplD, *PTLP_HDR_CplD;

typedef struct tdTLP_HDR_Cfg {
    TLP_HDR h;
    BYTE FirstBE : 4;
    BYTE LastBE : 4;
    BYTE Tag;
    WORD RequesterID;
    BYTE _R1 : 2;
    BYTE RegNum : 6;
    BYTE ExtRegNum : 4;
    BYTE _R2 : 4;
    BYTE FunctionNum : 3;
    BYTE DeviceNum : 5;
    BYTE BusNum;
} TLP_HDR_Cfg, *PTLP_HDR_Cfg;

typedef struct tdTLP_CALLBACK_BUF_MRd {
    DWORD cbMax;
    DWORD cb;
    PBYTE pb;
} TLP_CALLBACK_BUF_MRd, *PTLP_CALLBACK_BUF_MRd;

typedef struct tdTLP_CALLBACK_BUF_MRd_SCATTER {
    PPMEM_SCATTER pph;              // pointer to pointer-table to DMA_READ_SCATTER_HEADERs.
    DWORD cph;                      // entry count of pph array.
    DWORD cbReadTotal;              // total bytes read.
    BOOL fTiny;                     // "tiny" algorithm i.e. 128 byte/read.
    BYTE bEccBit;                   // alternating bit (Tlp.Tag[7]) for ECC.
} TLP_CALLBACK_BUF_MRd_SCATTER, *PTLP_CALLBACK_BUF_MRd_SCATTER;

/*
* Convert a TLP into human readable form.
* CALLER DECREF: *pszTlpText
* -- pbTlp = complete TLP packet (header+data)
* -- cbTlp = length in bytes of TLP packet.
* -- pszTlpText = pointer to receive function allocated TLP.
* -- pcbTlpText = pointer to receive byte length of *pszTlp incl. null terminator.
* -- return
*/
_Success_(return)
BOOL TLP_ToString(_In_ PBYTE pbTlp, _In_ DWORD cbTlp, _Out_ LPSTR *pszTlpText, _Out_opt_ PDWORD pcbTlpText)
{
    DWORD i, iMax, cbHexAscii, cchHdr, cbResult;
    CHAR szHdr[MAX_PATH];
    LPSTR szResult, tp = "";
    DWORD hdrDwBuf[4];
    PTLP_HDR hdr = (PTLP_HDR)hdrDwBuf;
    PTLP_HDR_CplD hdrC;
    PTLP_HDR_MRdWr32 hdrM32;
    PTLP_HDR_MRdWr64 hdrM64;
    PTLP_HDR_Cfg hdrCfg;
    if((cbTlp < 12) || (cbTlp > 16 + 1024) || (cbTlp & 0x3)) { return FALSE; }
    for(i = 0, iMax = min(16, cbTlp); i < iMax; i += 4) {
        hdrDwBuf[i >> 2] = _byteswap_ulong(*(PDWORD)(pbTlp + i));
    }
    if((hdr->TypeFmt == TLP_Cpl) || (hdr->TypeFmt == TLP_CplD) || (hdr->TypeFmt == TLP_CplLk) || (hdr->TypeFmt == TLP_CplDLk)) {
        if(hdr->TypeFmt == TLP_Cpl)    { tp = "Cpl:   "; }
        if(hdr->TypeFmt == TLP_CplD)   { tp = "CplD:  "; }
        if(hdr->TypeFmt == TLP_CplLk)  { tp = "CplLk: "; }
        if(hdr->TypeFmt == TLP_CplDLk) { tp = "CplDLk:"; }
        hdrC = (PTLP_HDR_CplD)hdr;
        cchHdr = _snprintf_s(szHdr, _countof(szHdr), _TRUNCATE,
            "%s Len: %03x ReqID: %04x CplID: %04x Status: %01x BC: %03x Tag: %02x LowAddr: %02x",
            tp,
            hdr->Length,
            hdrC->RequesterID,
            hdrC->CompleterID,
            hdrC->Status,
            hdrC->ByteCount,
            hdrC->Tag,
            hdrC->LowerAddress
        );
    } else if((hdr->TypeFmt == TLP_MRd32) || (hdr->TypeFmt == TLP_MWr32)) {
        hdrM32 = (PTLP_HDR_MRdWr32)hdr;
        cchHdr = _snprintf_s(szHdr, _countof(szHdr), _TRUNCATE,
            "%s Len: %03x ReqID: %04x BE_FL: %01x%01x Tag: %02x Addr: %08x",
            (hdr->TypeFmt == TLP_MRd32) ? "MRd32: " : "MWr32: ",
            hdr->Length,
            hdrM32->RequesterID,
            hdrM32->FirstBE,
            hdrM32->LastBE,
            hdrM32->Tag,
            hdrM32->Address);
    } else if((hdr->TypeFmt == TLP_MRd64) || (hdr->TypeFmt == TLP_MWr64)) {
        hdrM64 = (PTLP_HDR_MRdWr64)hdr;
        cchHdr = _snprintf_s(szHdr, _countof(szHdr), _TRUNCATE,
            "%s Len: %03x ReqID: %04x BE_FL: %01x%01x Tag: %02x Addr: %016llx",
            (hdr->TypeFmt == TLP_MRd64) ? "MRd64: " : "MWr64: ",
            hdr->Length,
            hdrM64->RequesterID,
            hdrM64->FirstBE,
            hdrM64->LastBE,
            hdrM64->Tag,
            ((QWORD)hdrM64->AddressHigh << 32) + hdrM64->AddressLow
        );
    } else if((hdr->TypeFmt == TLP_IORd) || (hdr->TypeFmt == TLP_IOWr)) {
        hdrM32 = (PTLP_HDR_MRdWr32)hdr; // same format for IO Rd/Wr
        cchHdr = _snprintf_s(szHdr, _countof(szHdr), _TRUNCATE,
            "%s Len: %03x ReqID: %04x BE_FL: %01x%01x Tag: %02x Addr: %08x",
            (hdr->TypeFmt == TLP_IORd) ? "IORd:  " : "IOWr:  ",
            hdr->Length,
            hdrM32->RequesterID,
            hdrM32->FirstBE,
            hdrM32->LastBE,
            hdrM32->Tag,
            hdrM32->Address
        );
    } else if((hdr->TypeFmt == TLP_CfgRd0) || (hdr->TypeFmt == TLP_CfgRd1) || (hdr->TypeFmt == TLP_CfgWr0) || (hdr->TypeFmt == TLP_CfgWr1)) {
        if(hdr->TypeFmt == TLP_CfgRd0) { tp = "CfgRd0:"; }
        if(hdr->TypeFmt == TLP_CfgRd1) { tp = "CfgRd1:"; }
        if(hdr->TypeFmt == TLP_CfgWr0) { tp = "CfgWr0:"; }
        if(hdr->TypeFmt == TLP_CfgWr1) { tp = "CfgWr1:"; }
        hdrCfg = (PTLP_HDR_Cfg)hdr;
        cchHdr = _snprintf_s(szHdr, _countof(szHdr), _TRUNCATE,
            "%s Len: %03x ReqID: %04x BE_FL: %01x%01x Tag: %02x Dev: %i:%i.%i ExtRegNum: %01x RegNum: %02x",
            tp,
            hdr->Length,
            hdrCfg->RequesterID,
            hdrCfg->FirstBE,
            hdrCfg->LastBE,
            hdrCfg->Tag,
            hdrCfg->BusNum,
            hdrCfg->DeviceNum,
            hdrCfg->FunctionNum,
            hdrCfg->ExtRegNum,
            hdrCfg->RegNum
        );
    } else {
        cchHdr = _snprintf_s(szHdr, _countof(szHdr), _TRUNCATE,
            "TLP???: TypeFmt: %02x dwLen: %03x",
            hdr->TypeFmt,
            hdr->Length
        );
    }
    Util_FillHexAscii(pbTlp, cbTlp, 0, NULL, &cbHexAscii);
    cbResult = cchHdr + 1 + cbHexAscii;
    if(!(szResult = LocalAlloc(0, cbResult))) { return FALSE; }
    memcpy(szResult, szHdr, cchHdr);
    szResult[cchHdr] = '\n';
    Util_FillHexAscii(pbTlp, cbTlp, 0, szResult + cchHdr + 1, &cbHexAscii);
    *pszTlpText = szResult;
    if(pcbTlpText) { *pcbTlpText = cbResult; }
    return TRUE;
}

/*
* Print a PCIe TLP packet on the screen in a human readable format.
* -- ctxLC
* -- pbTlp = complete TLP packet (header+data)
* -- cbTlp = length in bytes of TLP packet.
* -- fTx = TRUE == packet is transmited, FALSE == packet is received.
*/
VOID TLP_Print(_In_ PLC_CONTEXT ctxLC, _In_ PBYTE pbTlp, _In_ DWORD cbTlp, _In_ BOOL fTx)
{
    LPSTR szTlpText;
    DWORD cbTlpText;
    if(TLP_ToString(pbTlp, cbTlp, &szTlpText, &cbTlpText)) {
        lcprintf(ctxLC, "\n%s: %s", (fTx ? "TX" : "RX"), szTlpText);
        LocalFree(szTlpText);
    }
}

/*
* Generic callback function that may be used by TLP capable devices to aid the
* collection of completions from the probe function. Receives single TLP packet.
* -- pBufferMrd
* -- pb
* -- cb
*/
VOID TLP_CallbackMRdProbe(_Inout_ PTLP_CALLBACK_BUF_MRd pBufferMRd, _In_ PBYTE pb, _In_ DWORD cb)
{
    PTLP_HDR_CplD hdrC = (PTLP_HDR_CplD)pb;
    PDWORD buf = (PDWORD)pb;
    DWORD i;
    if(cb < 16) { return; } // min size CplD = 16 bytes.
    buf[0] = _byteswap_ulong(buf[0]);
    buf[1] = _byteswap_ulong(buf[1]);
    buf[2] = _byteswap_ulong(buf[2]);
    if((hdrC->h.TypeFmt == TLP_CplD) && pBufferMRd) {
        // 5 low address bits coded into the dword read, 8 high address bits coded into tag.
        i = ((DWORD)hdrC->Tag << 5) + ((hdrC->LowerAddress >> 2) & 0x1f);
        if(i < pBufferMRd->cbMax) {
            pBufferMRd->pb[i] = 1;
            pBufferMRd->cb++;
        }
    }
}

/*
* Generic callback function that may be used by TLP capable devices to aid the
* collection of memory read completions. Receives single TLP packet.
* -- pBufferMrd_Scatter
* -- pb
* -- cb
*/
VOID TLP_CallbackMRd_Scatter(_Inout_ PTLP_CALLBACK_BUF_MRd_SCATTER pBufferMrd_Scatter, _In_ PBYTE pb, _In_ DWORD cb)
{
    PTLP_HDR_CplD hdrC = (PTLP_HDR_CplD)pb;
    PTLP_HDR hdr = (PTLP_HDR)pb;
    PDWORD buf = (PDWORD)pb;
    DWORD o, c, i;
    PMEM_SCATTER pMEM;
    buf[0] = _byteswap_ulong(buf[0]);
    buf[1] = _byteswap_ulong(buf[1]);
    buf[2] = _byteswap_ulong(buf[2]);
    if(cb < ((DWORD)hdr->Length << 2) + 12) { return; }
    if(pBufferMrd_Scatter->bEccBit != (hdrC->Tag >> 7)) { return; }   // ECC bit mismatch
    if(hdr->TypeFmt == TLP_CplD) {
        if(pBufferMrd_Scatter->fTiny) {
            // Algoritm: Multiple MRd of size 128 bytes
            i = (hdrC->Tag >> 5) & 0x03;
            if(i >= pBufferMrd_Scatter->cph) { return; }
            pMEM = pBufferMrd_Scatter->pph[i];
            if(pMEM->cb == 0x1000) {
                if(hdrC->ByteCount > 0x80) { return; }
                o = ((hdrC->Tag & 0x1f) << 7) + 0x80 - hdrC->ByteCount;
            } else {
                // TODO: Fix CplD BC
                o = (DWORD)MEM_SCATTER_STACK_PEEK(pMEM, 1);
            }
        } else {
            // Algoritm: Single MRd of page (0x1000) or less, multiple CplD.
            i = hdrC->Tag & 0x7f;
            if(i >= pBufferMrd_Scatter->cph) { return; }
            pMEM = pBufferMrd_Scatter->pph[i];
            if(pMEM->cb == 0x1000) {
                o = 0x1000 - (hdrC->ByteCount ? hdrC->ByteCount : 0x1000);
            } else {
                // TODO: Fix CplD BC
                o = (DWORD)MEM_SCATTER_STACK_PEEK(pMEM, 1);
            }
        }
        c = (DWORD)hdr->Length << 2;
        if(o + c > pMEM->cb) { return; }
        memcpy(pMEM->pb + o, pb + 12, c);
        MEM_SCATTER_STACK_ADD(pMEM, 1, c);
        pBufferMrd_Scatter->cbReadTotal += c;
    }
    if((hdr->TypeFmt == TLP_Cpl) && hdrC->Status) {
        pBufferMrd_Scatter->cbReadTotal += (hdrC->ByteCount ? hdrC->ByteCount : 0x1000);
    }
}



//-------------------------------------------------------------------------------
// UDP connectivity implementation below:
//-------------------------------------------------------------------------------

/*
* Emulate the FT601 Close function by closing socket.
*/
ULONG WINAPI DeviceFPGA_UDP_FT60x_FT_Close(HANDLE ftHandle)
{
    FPGA_HANDLESOCKET hs;
    hs.h = ftHandle;
    closesocket(hs.Socket);
    return 0;
}

/*
* Dummy function to keep compatibility with FT601 calls when using UDP.
*/
ULONG WINAPI DeviceFPGA_UDP_FT60x_FT_AbortPipe(HANDLE ftHandle, UCHAR ucPipeID)
{
    return 0;
}

/*
* Emulate the FT601 WritePipe function when writing UDP packets to keep
* function call compatibility for the FPGA device module.
*/
ULONG WINAPI DeviceFPGA_UDP_FT60x_FT_WritePipe(HANDLE ftHandle, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
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
ULONG WINAPI DeviceFPGA_UDP_FT60x_FT_ReadPipe(HANDLE ftHandle, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
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
#ifdef _WIN32
    u_long mode = 1;  // 1 == non-blocking socket - Windows only ???
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
// FT601/FT245 connectivity implementation below:
//-------------------------------------------------------------------------------

// Helper functions to avoid multiple connections in parallel on
// linux systems resulting in potential segfault errors. On Windows
// this is handled transparantly by the driver.
static BOOL g_fDeviceFpgaMultiHandleLock[0x10] = { 0 };

BOOL DeviceFPGA_Initialize_LinuxMultiHandle_LockCheck(_In_ QWORD qwDeviceIndex)
{
#ifdef LINUX
    if(g_fDeviceFpgaMultiHandleLock[min(0x10 - 1, qwDeviceIndex)]) { return TRUE; }
#endif /* LINUX */
    return FALSE;
}

VOID DeviceFPGA_Initialize_LinuxMultiHandle_LockAcquire(_In_ QWORD qwDeviceIndex)
{
    g_fDeviceFpgaMultiHandleLock[min(0x10 - 1, qwDeviceIndex)] = TRUE;
}

VOID DeviceFPGA_Initialize_LinuxMultiHandle_LockRelease(_In_ QWORD qwDeviceIndex)
{
    g_fDeviceFpgaMultiHandleLock[min(0x10 - 1, qwDeviceIndex)] = FALSE;
}


LPSTR DeviceFPGA_InitializeFT601(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    LPSTR szErrorReason;
    CHAR c, szModuleFTDI[MAX_PATH + 1] = { 0 };
    DWORD status;
    ULONG(WINAPI *pfnFT_GetChipConfiguration)(HANDLE ftHandle, PVOID pvConfiguration);
    ULONG(WINAPI *pfnFT_SetChipConfiguration)(HANDLE ftHandle, PVOID pvConfiguration);
    ULONG(WINAPI *pfnFT_SetSuspendTimeout)(HANDLE ftHandle, ULONG Timeout);
    FT_60XCONFIGURATION oCfgNew, oCfgOld;
    if(DeviceFPGA_Initialize_LinuxMultiHandle_LockCheck(ctx->qwDeviceIndex)) {
        szErrorReason = "FPGA linux handle already open";
        goto fail;
    }
    // Load FTDI Library
    ctx->dev.hModule = LoadLibraryA("FTD3XX.dll");
    if(!ctx->dev.hModule) {
        Util_GetPathLib(szModuleFTDI);
        strcat_s(szModuleFTDI, sizeof(szModuleFTDI) - 1, "FTD3XX.dll");
        ctx->dev.hModule = LoadLibraryA(szModuleFTDI);
    }
    if(!ctx->dev.hModule) {
        szErrorReason = "Unable to load FTD3XX.dll";
        goto fail;
    }
    ctx->dev.pfnFT_AbortPipe = (ULONG(WINAPI *)(HANDLE, UCHAR))
        GetProcAddress(ctx->dev.hModule, "FT_AbortPipe");
    ctx->dev.pfnFT_Create = (ULONG(WINAPI *)(PVOID, DWORD, HANDLE*))
        GetProcAddress(ctx->dev.hModule, "FT_Create");
    ctx->dev.pfnFT_Close = (ULONG(WINAPI *)(HANDLE))
        GetProcAddress(ctx->dev.hModule, "FT_Close");
    ctx->dev.pfnFT_ReadPipe = (ULONG(WINAPI *)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_ReadPipeEx");
    if(!ctx->dev.pfnFT_ReadPipe) {
        ctx->dev.pfnFT_ReadPipe = (ULONG(WINAPI *)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
            GetProcAddress(ctx->dev.hModule, "FT_ReadPipe");
    }
    ctx->dev.pfnFT_WritePipe = (ULONG(WINAPI *)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_WritePipeEx");
    if(!ctx->dev.pfnFT_WritePipe) {
        ctx->dev.pfnFT_WritePipe = (ULONG(WINAPI *)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
            GetProcAddress(ctx->dev.hModule, "FT_WritePipe");
    }
    ctx->dev.pfnFT_GetOverlappedResult = (ULONG(WINAPI *)(HANDLE, LPOVERLAPPED, PULONG, BOOL))
        GetProcAddress(ctx->dev.hModule, "FT_GetOverlappedResult");
    ctx->dev.pfnFT_InitializeOverlapped = (ULONG(WINAPI *)(HANDLE, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_InitializeOverlapped");
    ctx->dev.pfnFT_ReleaseOverlapped = (ULONG(WINAPI *)(HANDLE, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_ReleaseOverlapped");
    pfnFT_GetChipConfiguration = (ULONG(WINAPI *)(HANDLE, PVOID))GetProcAddress(ctx->dev.hModule, "FT_GetChipConfiguration");
    pfnFT_SetChipConfiguration = (ULONG(WINAPI *)(HANDLE, PVOID))GetProcAddress(ctx->dev.hModule, "FT_SetChipConfiguration");
    pfnFT_SetSuspendTimeout = (ULONG(WINAPI *)(HANDLE, ULONG))GetProcAddress(ctx->dev.hModule, "FT_SetSuspendTimeout");
    if(!ctx->dev.pfnFT_Create || !ctx->dev.pfnFT_ReadPipe || !ctx->dev.pfnFT_WritePipe) {
        szErrorReason = ctx->dev.pfnFT_ReadPipe ?
            "Unable to retrieve required functions from FTD3XX.dll" :
            "Unable to retrieve required functions from FTD3XX.dll v1.3.0.4 or later";
        goto fail;
    }
    // Open FTDI
    status = ctx->dev.pfnFT_Create((PVOID)ctx->qwDeviceIndex, 0x10 /*FT_OPEN_BY_INDEX*/, &ctx->dev.hFTDI);
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
        return DeviceFPGA_InitializeFT601(ctx);
    }
    ctx->async.fEnabled =
        ctx->dev.pfnFT_GetOverlappedResult && ctx->dev.pfnFT_InitializeOverlapped && ctx->dev.pfnFT_ReleaseOverlapped &&
        !ctx->dev.pfnFT_InitializeOverlapped(ctx->dev.hFTDI, &ctx->async.oOverlapped);
    ctx->dev.fInitialized = TRUE;
    DeviceFPGA_Initialize_LinuxMultiHandle_LockAcquire(ctx->qwDeviceIndex);
    return NULL;
fail:
    if(ctx->dev.hFTDI && ctx->dev.pfnFT_Close) { ctx->dev.pfnFT_Close(ctx->dev.hFTDI); }
    if(ctx->dev.hModule) { FreeLibrary(ctx->dev.hModule); }
    ctx->dev.hModule = NULL;
    ctx->dev.hFTDI = NULL;
    return szErrorReason;
}

//-------------------------------------------------------------------------------
// FT2232H/FT245 connectivity implementation below:
//-------------------------------------------------------------------------------

typedef struct tdFT2232H_HANDLE {
    HANDLE ftHandle;
    ULONG(WINAPI *pfnFT_Close)(HANDLE ftHandle);
    ULONG(WINAPI *pfnFT_GetStatus)(HANDLE ftHandle, DWORD *dwRxBytes, DWORD *dwTxBytes, DWORD *dwEventDWord);
    ULONG(WINAPI *pfnFT_Read)(HANDLE ftHandle, PVOID lpBuffer, DWORD dwBytesToRead, LPDWORD lpBytesReturned);
    ULONG(WINAPI *pfnFT_Write)(HANDLE ftHandle, PVOID lpBuffer, DWORD dwBytesToWrite, LPDWORD lpBytesWritten);
} FT2232H_HANDLE, *PFT2232H_HANDLE;

/*
* Emulate FT601 Close for FT2232H.
*/
ULONG WINAPI DeviceFPGA_FT2232_FT60x_FT_Close(HANDLE ftHandleEx)
{
    PFT2232H_HANDLE hFT2232H = (PFT2232H_HANDLE)ftHandleEx;
    ULONG status = hFT2232H->pfnFT_Close(hFT2232H->ftHandle);
    LocalFree(ftHandleEx);
    return status;
}

/*
* Dummy function to keep compatibility with FT601 calls.
*/
ULONG WINAPI DeviceFPGA_FT2232_FT60x_FT_AbortPipe(HANDLE ftHandleEx, UCHAR ucPipeID)
{
    return 0;
}

/*
* Emulate FT601 ReadPipe for FT2232H.
*/
ULONG WINAPI DeviceFPGA_FT2232_FT60x_FT_ReadPipe(HANDLE ftHandleEx, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
{
    PFT2232H_HANDLE hFT2232H = (PFT2232H_HANDLE)ftHandleEx;
    ULONG iRetry, status = 0, cbRead = 0, cbReadTotal = 0, cbRx, cbTx, dwEventStatus;
    *pulBytesTransferred = 0;
    if(ulBufferLength == 0x00103000) {
        // "fake" ASYNC MODE always calls with a 0x103 page buffer in FT2232H mode.
        status = hFT2232H->pfnFT_GetStatus(hFT2232H->ftHandle, &cbRx, &cbTx, &dwEventStatus);
        if(status) { return status; }
        if(cbRx) {
            return hFT2232H->pfnFT_Read(hFT2232H->ftHandle, pucBuffer, min(cbRx, ulBufferLength), pulBytesTransferred);
        }
        usleep(125);
        return 0;
    }
    // "NORMAL" MODE:
    while(TRUE) {
        cbRx = 0;
        iRetry = 0;
        while(!cbRx) {
            status = hFT2232H->pfnFT_GetStatus(hFT2232H->ftHandle, &cbRx, &cbTx, &dwEventStatus);
            if(cbRx) { break; }
            if(status || iRetry > 15) { break; }
            iRetry++;
            usleep(120);
        }
        status = hFT2232H->pfnFT_Read(hFT2232H->ftHandle, pucBuffer + cbReadTotal, min(cbRx, ulBufferLength - cbReadTotal), &cbRead);
        if(status || !cbRead) { break; }
        cbReadTotal += cbRead;
        if(cbReadTotal >= ulBufferLength) { break; }
    }
    *pulBytesTransferred = cbReadTotal;
    return status;
}

/*
* Emulate FT601 WritePipe for FT2232H.
*/
ULONG WINAPI DeviceFPGA_FT2232_FT60x_FT_WritePipe(HANDLE ftHandleEx, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
{
    PFT2232H_HANDLE hFT2232H = (PFT2232H_HANDLE)ftHandleEx;
    return hFT2232H->pfnFT_Write(hFT2232H->ftHandle, pucBuffer, ulBufferLength, pulBytesTransferred);
}

/*
* Initialize FT2232H with FT245 synchrouous FIFO.
*/
LPSTR DeviceFPGA_InitializeFT2232(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DWORD status;
    LPSTR szErrorReason;
    CHAR szModuleFTDI[MAX_PATH + 1] = { 0 };
    UCHAR ucMask = 0xff, ucMode0 = 0, ucMode1 = 0x40;
    PFT2232H_HANDLE hFT2232H = NULL;
    ULONG(WINAPI *pfnFT_Open)(int deviceNumber, HANDLE *pHandle);
    ULONG(WINAPI *pfnFT_ResetDevice)(HANDLE ftHandle);
    ULONG(WINAPI *pfnFT_SetBitMode)(HANDLE ftHandle, UCHAR ucMask, UCHAR ucEnable);
    ULONG(WINAPI *pfnFT_SetLatencyTimer)(HANDLE ftHandle, UCHAR ucLatency);
    ULONG(WINAPI *pfnFT_SetUSBParameters)(HANDLE ftHandle, ULONG ulInTransferSize, ULONG ulOutTransferSize);
    ULONG(WINAPI *pfnFT_SetFlowControl)(HANDLE ftHandle, USHORT FlowControl, UCHAR XonChar, UCHAR XoffChar);
    if(DeviceFPGA_Initialize_LinuxMultiHandle_LockCheck(ctx->qwDeviceIndex)) {
        szErrorReason = "FPGA linux handle already open";
        goto fail;
    }
    // Load FTDI Library
    ctx->dev.hModule = LoadLibraryA("FTD2XX.dll");
    if(!ctx->dev.hModule) {
        Util_GetPathLib(szModuleFTDI);
        strcat_s(szModuleFTDI, sizeof(szModuleFTDI) - 1, "FTD2XX.dll / libftd2xx.so");
        ctx->dev.hModule = LoadLibraryA(szModuleFTDI);
    }
    if(!ctx->dev.hModule) {
        szErrorReason = "Unable to load FTD2XX.dll / libftd2xx.so";
        goto fail;
    }
    // Assign FT601 compatibility functions to device object:
    ctx->dev.pfnFT_AbortPipe = DeviceFPGA_FT2232_FT60x_FT_AbortPipe;
    ctx->dev.pfnFT_Close = DeviceFPGA_FT2232_FT60x_FT_Close;
    ctx->dev.pfnFT_ReadPipe = DeviceFPGA_FT2232_FT60x_FT_ReadPipe;
    ctx->dev.pfnFT_WritePipe = DeviceFPGA_FT2232_FT60x_FT_WritePipe;
    // Allocate and assign "extended" ftHandle to device object [free by pfnFT_Close()].
    // Also assign required function pointers.
    if(!(hFT2232H = LocalAlloc(LMEM_ZEROINIT, sizeof(FT2232H_HANDLE)))) {
        szErrorReason = "OOM";
        goto fail;
    }
    ctx->dev.hFTDI = (HANDLE)hFT2232H;
    hFT2232H->pfnFT_GetStatus = (ULONG(WINAPI *)(HANDLE, DWORD*, DWORD*, DWORD*))
        GetProcAddress(ctx->dev.hModule, "FT_GetStatus");
    hFT2232H->pfnFT_Read = (ULONG(WINAPI *)(HANDLE, PVOID, DWORD, LPDWORD))
        GetProcAddress(ctx->dev.hModule, "FT_Read");
    hFT2232H->pfnFT_Write = (ULONG(WINAPI *)(HANDLE, PVOID, DWORD, LPDWORD))
        GetProcAddress(ctx->dev.hModule, "FT_Write");
    hFT2232H->pfnFT_Close = (ULONG(WINAPI *)(HANDLE))
        GetProcAddress(ctx->dev.hModule, "FT_Close");
    if(!hFT2232H->pfnFT_GetStatus || !hFT2232H->pfnFT_Read || !hFT2232H->pfnFT_Write || !hFT2232H->pfnFT_Close) {
        szErrorReason = "Unable to retrieve required functions from FTD2XX.dll";
        goto fail;
    }
    // Retrieve required function-local function pointers from FTDI library:
    pfnFT_Open = (ULONG(WINAPI *)(int, HANDLE*))
        GetProcAddress(ctx->dev.hModule, "FT_Open");
    pfnFT_ResetDevice = (ULONG(WINAPI *)(HANDLE))
        GetProcAddress(ctx->dev.hModule, "FT_ResetDevice");
    pfnFT_SetBitMode = (ULONG(WINAPI *)(HANDLE, UCHAR, UCHAR))
        GetProcAddress(ctx->dev.hModule, "FT_SetBitMode");
    pfnFT_SetLatencyTimer = (ULONG(WINAPI *)(HANDLE, UCHAR))
        GetProcAddress(ctx->dev.hModule, "FT_SetLatencyTimer");
    pfnFT_SetUSBParameters = (ULONG(WINAPI *)(HANDLE, ULONG, ULONG))
        GetProcAddress(ctx->dev.hModule, "FT_SetUSBParameters");
    pfnFT_SetFlowControl = (ULONG(WINAPI *)(HANDLE, USHORT, UCHAR, UCHAR))
        GetProcAddress(ctx->dev.hModule, "FT_SetFlowControl");
    if(!pfnFT_Open || !pfnFT_ResetDevice || !pfnFT_SetBitMode || !pfnFT_SetLatencyTimer || !pfnFT_SetUSBParameters || !pfnFT_SetFlowControl) {
        szErrorReason = "Unable to retrieve required functions from FTD2XX.dll";
        goto fail;
    }
    // Open FTDI
    status = pfnFT_Open((int)ctx->qwDeviceIndex, &hFT2232H->ftHandle);
    if(status || !hFT2232H->ftHandle) {
        szErrorReason = "Unable to connect to USB/FT2232H device";
        goto fail;
    }
    // Reset, set FT245 mode and performance options:
    if(pfnFT_ResetDevice(hFT2232H->ftHandle)) {
        szErrorReason = "FT_ResetDevice failed.";
        goto fail;
    }
    pfnFT_SetBitMode(hFT2232H->ftHandle, ucMask, ucMode0);
    if(pfnFT_SetBitMode(hFT2232H->ftHandle, ucMask, ucMode1)) {
        szErrorReason = "FT_SetBitMode failed.";
        goto fail;
    }
    if(pfnFT_SetLatencyTimer(hFT2232H->ftHandle, 2)) {
        szErrorReason = "FT_SetLatencyTimer failed.";
        goto fail;
    }
    if(pfnFT_SetUSBParameters(hFT2232H->ftHandle, 0x10000, 0x10000)) {
        szErrorReason = "FT_SetUSBParameters failed.";
        goto fail;
    }
    if(pfnFT_SetFlowControl(hFT2232H->ftHandle, 0x0100 /* FT_FLOW_RTS_CTS */, 0x0, 0x0)) {
        szErrorReason = "FT_SetFlowControl failed.";
        goto fail;
    }
    ctx->dev.f2232h = TRUE;
    ctx->async.fEnabled = TRUE;
    ctx->dev.fInitialized = TRUE;
    DeviceFPGA_Initialize_LinuxMultiHandle_LockAcquire(ctx->qwDeviceIndex);
    return NULL;
fail:
    if(ctx->dev.hFTDI && ctx->dev.pfnFT_Close) { ctx->dev.pfnFT_Close(ctx->dev.hFTDI); }
    if(ctx->dev.hModule) { FreeLibrary(ctx->dev.hModule); }
    ctx->dev.hModule = NULL;
    ctx->dev.hFTDI = NULL;
    return szErrorReason;
}

//-------------------------------------------------------------------------------
// FPGA implementation below:
//-------------------------------------------------------------------------------

VOID DeviceFPGA_ReInitializeFTDI(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    // called to try to recover link in case of unstable devices.
    if(ctx->dev.pfnFT_Create) {
        ctx->dev.pfnFT_Close(ctx->dev.hFTDI);
        ctx->dev.hFTDI = NULL;
        Sleep(250);
        ctx->dev.pfnFT_Create((PVOID)ctx->qwDeviceIndex, 0x10 /*FT_OPEN_BY_INDEX*/, &ctx->dev.hFTDI);
    }
}

VOID DeviceFPGA_Close(_Inout_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    DWORD cbTMP;
    if(!ctx) { return; }
    if(ctx->async.fEnabled && ctx->dev.pfnFT_GetOverlappedResult) {
        ctx->dev.pfnFT_GetOverlappedResult(ctx->dev.hFTDI, &ctx->async.oOverlapped, &cbTMP, TRUE);
    }
    if(ctx->dev.pfnFT_ReleaseOverlapped && ctx->async.fEnabled) {
        ctx->dev.pfnFT_ReleaseOverlapped(ctx->dev.hFTDI, &ctx->async.oOverlapped);
    }
#ifdef WIN32
    __try {
#endif /* WIN32 */
        if(ctx->dev.hFTDI) {
            ctx->dev.pfnFT_Close(ctx->dev.hFTDI);
            DeviceFPGA_Initialize_LinuxMultiHandle_LockRelease(ctx->qwDeviceIndex);
        }
        if(ctx->dev.hModule) { FreeLibrary(ctx->dev.hModule); }
#ifdef WIN32
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
#endif /* WIN32 */
    LocalFree(ctx->rxbuf.pb);
    LocalFree(ctx->txbuf.pb);
    LocalFree(ctx);
    ctxLC->hDevice = 0;
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
    if(!cb || (wBaseAddr + cb > 0x1000)) { goto fail; }
    if(!(pbRxTx = LocalAlloc(LMEM_ZEROINIT, 0x20000))) { goto fail; }
    // WRITE requests
    for(wAddr = wBaseAddr & 0xfffe; wAddr < wBaseAddr + cb; wAddr += 2) {
        pbRxTx[cbRxTx + 4] = (wAddr | (flags & 0xC000)) >> 8;
        pbRxTx[cbRxTx + 5] = wAddr & 0xff;
        pbRxTx[cbRxTx + 6] = 0x10 | (flags & 0x03);
        pbRxTx[cbRxTx + 7] = 0x77;
        cbRxTx += 8;
        if(cbRxTx >= 0x3f0) {
            status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbRxTx, cbRxTx, &cbRxTx, NULL);
            if(status) { goto fail; }
            cbRxTx = 0;
        }
    }
    if(cbRxTx) {
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbRxTx, cbRxTx, &cbRxTx, NULL);
        if(status) { goto fail; }
    }
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
            wAddr -= (flags & 0xC000) + wBaseAddr;  // adjust for base address and read-write config memory
            if(wAddr == 0xffff) {   // 1st unaligned byte
                *pb = (dwData >> 24) & 0xff;
            }
            if(wAddr >= cb) { continue; }           // address read is out of range
            if(wAddr == cb - 1) {   // last byte
                *(PBYTE)(pb + wAddr) = (dwData >> 16) & 0xff;
            } else {                // normal two-bytes
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
    pbTx[4] = (wBaseAddr | (flags & 0xc000)) >> 8;  // [4] = addr_high = bit[6:0], write_regbank = bit[7]
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
    BYTE pbTx[0x800];
    DWORD status, cbTx = 0;
    WORD i = 0, wAddr;
    if(!cb || (wBaseAddr + cb > 0x1000)) { return FALSE; }
    // BYTE ALIGN (if required)
    if(wBaseAddr % 2) {
        wAddr = (wBaseAddr - 1) | (flags & 0xC000);
        pbTx[cbTx + 0] = 0x00;                          // [0] = byte_value = not valid
        pbTx[cbTx + 1] = pb[0];                         // [1] = byte_value_addr[0]
        pbTx[cbTx + 2] = 0x00;                          // [2] = mask_addr = not valid
        pbTx[cbTx + 3] = 0xff;                          // [3] = byte_mask_addr[0]
        pbTx[cbTx + 4] = wAddr >> 8;                    // [4] = addr_high = bit[5:0], write_regbank = bit[7], shadowpciecfgspace = bit[6]
        pbTx[cbTx + 5] = wAddr & 0xff;                  // [5] = addr_low
        pbTx[cbTx + 6] = 0x20 | (flags & 0x03);         // [6] = target = bit[0:1], read = bit[4], write = bit[5]
        pbTx[cbTx + 7] = 0x77;                          // [7] = MAGIC 0x77
        cbTx += 8;
        i++;
    }
    // WRITE requests
    for(; i < cb; i += 2) {
        wAddr = (wBaseAddr + i) | (flags & 0xC000);
        pbTx[cbTx + 0] = pb[i];                         // [0] = byte_value_addr
        pbTx[cbTx + 1] = (cb == i + 1) ? 0 : pb[i + 1]; // [1] = byte_value_addr+1
        pbTx[cbTx + 2] = 0xff;                          // [2] = byte_mask_addr
        pbTx[cbTx + 3] = (cb == i + 1) ? 0 : 0xff;      // [3] = byte_mask_addr+1
        pbTx[cbTx + 4] = wAddr >> 8;                    // [4] = addr_high = bit[5:0], write_regbank = bit[7], shadowpciecfgspace = bit[6]
        pbTx[cbTx + 5] = wAddr & 0xff;                  // [5] = addr_low
        pbTx[cbTx + 6] = 0x20 | (flags & 0x03);         // [6] = target = bit[0:1], read = bit[4], write = bit[5]
        pbTx[cbTx + 7] = 0x77;                          // [7] = MAGIC 0x77
        cbTx += 8;
        if(cbTx >= 0x3f0) {
            status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, cbTx, &cbTx, NULL);
            if(status) { return FALSE; }
            cbTx = 0;
        }
    }
    if(cbTx) {
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, cbTx, &cbTx, NULL);
        if(status) { return FALSE; }
    }
    return TRUE;
}

/*
* Read from the device PCIe configuration space. Only the values used by the
* xilinx ip core itself is read. Custom "shadow" user-provided configuration
* space is read with DeviceFPGA_ConfigWrite(). Please use "lspci" on target
* system to see result of xilinx + custom "shadow" config space.
* -- ctx
* -- pb = only the 1st 0x200 bytes are read
* -- raSingleDW = Config space register address (in DWORD) to read single DWORD
*                 value from; to read 0x0; enable by set topmost bit.
* -- return
*/
_Success_(return)
BOOL DeviceFPGA_PCIeCfgSpaceCoreRead(_In_ PDEVICE_CONTEXT_FPGA ctx, _Out_writes_(0x200) PBYTE pb, _In_opt_ DWORD raSingleDW)
{
    BYTE pbTxLockEnable[]   = { 0x04, 0x00, 0x04, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxLockDisable[]  = { 0x00, 0x00, 0x04, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxReadEnable[]   = { 0x01, 0x00, 0x01, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxAddress[]      = { 0x00, 0x00, 0xff, 0x03, 0x80, 0x14, 0x21, 0x77 };
    BYTE pbTxResultMeta[]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x11, 0x77 };
    BYTE pbTxResultDataLo[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x11, 0x77 };
    BYTE pbTxResultDataHi[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x11, 0x77 };
    BOOL f;
    BYTE oAddr, pbRxTx[0x1000];
    DWORD i, j, status, dwStatus, dwData, cbRxTx;
    PDWORD pdwData;
    WORD wDWordAddr, oDWord, wAddr = 0;
    ZeroMemory(pb, 0x200);
    for(wDWordAddr = 0; wDWordAddr < 0x80; wDWordAddr += 32) {  // 0x80 * sizeof(DWORD) == 0x200
        // enable read/write lock (instruction serialization)
        cbRxTx = 0;
        memcpy(pbRxTx + cbRxTx, pbTxLockEnable, 8); cbRxTx += 8;
        for(oDWord = 0; oDWord < 32; oDWord++) {
            // NB! read config space DWORD _TWO_ times on 1st read in
            //     batch required to clear any lingering register data.
            for(i = 0; (i < 2) && (!i || !oDWord); i++) {
                // WRITE request setup (address)
                if(raSingleDW) {
                    // set address: single dword read
                    pbTxAddress[0] = raSingleDW & 0xff;
                    pbTxAddress[1] = (raSingleDW >> 8) & 0x03;
                } else {
                    // set address: normal (full config space read)
                    pbTxAddress[0] = (wDWordAddr + oDWord) & 0xff;
                    pbTxAddress[1] = ((wDWordAddr + oDWord) >> 8) & 0x03;
                }
                memcpy(pbRxTx + cbRxTx, pbTxAddress, 8); cbRxTx += 8;
                // WRITE read enable bit
                memcpy(pbRxTx + cbRxTx, pbTxReadEnable, 8); cbRxTx += 8;
            }
            // READ result
            memcpy(pbRxTx + cbRxTx, pbTxResultMeta, 8); cbRxTx += 8;
            memcpy(pbRxTx + cbRxTx, pbTxResultDataLo, 8); cbRxTx += 8;
            memcpy(pbRxTx + cbRxTx, pbTxResultDataHi, 8); cbRxTx += 8;
            if(raSingleDW) { break; }
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
        if(raSingleDW) { break; }
    }
    return TRUE;
}

/*
* Read a single DWORD from the device PCIe configuration space controlled by
* the Xilinx PCIe IP core.
* -- ctx
* -- dwaSingleDW = byte address to read; DWORD aligned; max 0x200.
* -- pdwResultDW
* -- return
*/
_Success_(return)
BOOL DeviceFPGA_PCIeCfgSpaceCoreReadDWORD(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ DWORD dwaSingleDW, _Out_ PDWORD pdwResultDW)
{
    BYTE pb[0x200];
    if((dwaSingleDW % 4) || dwaSingleDW >= 0x200) { return FALSE; }
    if(!DeviceFPGA_PCIeCfgSpaceCoreRead(ctx, pb, 0x80000000 | (dwaSingleDW >> 2))) { return FALSE; }
    *pdwResultDW = *(PDWORD)(pb + dwaSingleDW);
    return TRUE;
}

/*
* Write a single DWORD from the device PCIe configuration space controlled by
* the Xilinx PCIe IP core.
* -- ctx
* -- dwaSingleDW = byte address to write; DWORD aligned; max 0x200.
* -- dwByteEnable = byte enable of dwDWORD (set to '0x01010101') to enable all.
* -- dwValue
* -- return
*/
_Success_(return)
BOOL DeviceFPGA_PCIeCfgSpaceCoreWriteDWORD(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ DWORD dwaSingleDW, _In_ DWORD dwByteEnable, _In_ DWORD dwValue)
{
    BYTE pbRxTx[0x1000];
    DWORD status, cbRxTx = 0;
    BYTE pbTxLockEnable[]   = { 0x04, 0x00, 0x04, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxLockDisable[]  = { 0x00, 0x00, 0x04, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxWriteEnable[]  = { 0x02, 0x00, 0x02, 0x00, 0x80, 0x02, 0x21, 0x77 };
    BYTE pbTxAddress[]      = { 0x00, 0x00, 0xff, 0xff, 0x80, 0x14, 0x21, 0x77 };
    BYTE pbTxDataLo[]       = { 0x00, 0x00, 0xff, 0xff, 0x80, 0x10, 0x21, 0x77 };
    BYTE pbTxDataHi[]       = { 0x00, 0x00, 0xff, 0xff, 0x80, 0x12, 0x21, 0x77 };
    if((dwaSingleDW % 4) || dwaSingleDW >= 0x200) { return FALSE; }
    pbTxAddress[0] = (dwaSingleDW >> 2) & 0xff;
    pbTxAddress[1] = ((dwaSingleDW >> 10) & 0x03) | (dwByteEnable & 0x80000000 ? 0x08 : 0) |
        (dwByteEnable & 0x000000ff ? 0x10 : 0) | (dwByteEnable & 0x0000ff00 ? 0x20 : 0) |
        (dwByteEnable & 0x00ff0000 ? 0x40 : 0) | (dwByteEnable & 0x7f000000 ? 0x80 : 0);
    pbTxDataLo[0] = (BYTE)(dwValue >> 0);
    pbTxDataLo[1] = (BYTE)(dwValue >> 8);
    pbTxDataHi[0] = (BYTE)(dwValue >> 12);
    pbTxDataHi[1] = (BYTE)(dwValue >> 16);
    memcpy(pbRxTx + cbRxTx, pbTxLockEnable, 8); cbRxTx += 8;    // enable read/write lock
    memcpy(pbRxTx + cbRxTx, pbTxDataLo, 8); cbRxTx += 8;        // data lo
    memcpy(pbRxTx + cbRxTx, pbTxDataHi, 8); cbRxTx += 8;        // data hi
    memcpy(pbRxTx + cbRxTx, pbTxAddress, 8); cbRxTx += 8;       // address & byte_enable
    memcpy(pbRxTx + cbRxTx, pbTxWriteEnable, 8); cbRxTx += 8;   // write/enable bit
    memcpy(pbRxTx + cbRxTx, pbTxLockDisable, 8); cbRxTx += 8;   // disable read/write lock
    // WRITE TxData
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbRxTx, cbRxTx, &cbRxTx, NULL);
    return status ? FALSE : TRUE;
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
    BOOL f;
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

VOID DeviceFPGA_ConfigPrint(_In_ PLC_CONTEXT ctxLC, _In_ PDEVICE_CONTEXT_FPGA ctx)
{
    WORD flags[] = {
        FPGA_REG_CORE | FPGA_REG_READONLY,
        FPGA_REG_CORE | FPGA_REG_READWRITE,
        FPGA_REG_PCIE | FPGA_REG_READONLY,
        FPGA_REG_PCIE | FPGA_REG_READWRITE };
    LPSTR szNAME[] = { "CORE-READ-ONLY ", "CORE-READ-WRITE", "PCIE-READ-ONLY ", "PCIE-READ-WRITE" };
    BYTE pb[0x1000];
    WORD i, cb;
    if(ctx->wFpgaVersionMajor < 4) { return; }
    for(i = 0; i < 4; i++) {
        if(DeviceFPGA_ConfigRead(ctx, 0x0004, (PBYTE)&cb, 2, flags[i])) {
            lcprintf(ctxLC, "\n----- FPGA DEVICE CONFIG REGISTERS: %s    SIZE: %i BYTES -----\n", szNAME[i], cb);
            cb = min(cb, sizeof(pb));
            DeviceFPGA_ConfigRead(ctx, 0x0000, pb, cb, flags[i]);
            Util_PrintHexAscii(ctxLC, pb, cb, 0);
        }
    }
    if(DeviceFPGA_PCIeDrpRead(ctx, pb)) {
        lcprintf(ctxLC, "\n----- PCIe CORE Dynamic Reconfiguration Port (DRP)  SIZE: 0x100 BYTES -----\n");
        Util_PrintHexAscii(ctxLC, pb, 0x100, 0);
    }
    if(DeviceFPGA_PCIeCfgSpaceCoreRead(ctx, pb, 0)) {
        lcprintf(ctxLC, "\n----- PCIe CONFIGURATION SPACE (no user set values) SIZE: 0x200 BYTES -----\n");
        Util_PrintHexAscii(ctxLC, pb, 0x200, 0);
    }
    if(DeviceFPGA_ConfigRead(ctx, 0x0000, pb, 0x1000, FPGA_REG_CORE | FPGA_REG_SHADOWCFGSPACE)) {
        lcprintf(ctxLC, "\n----- PCIe SHADOW CONFIGURATION SPACE (only user set values) SIZE: 0x1000 BYTES -----\n");
        Util_PrintHexAscii(ctxLC, pb, 0x1000, 0);
    }
    lcprintf(ctxLC, "\n");
}

_Success_(return)
BOOL DeviceFPGA_GetPHYv4(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    return
        DeviceFPGA_ConfigRead(ctx, 0x0016, (PBYTE)&ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_REG_PCIE | FPGA_REG_READWRITE) &&
        DeviceFPGA_ConfigRead(ctx, 0x000a, (PBYTE)&ctx->phy.rd, sizeof(ctx->phy.rd), FPGA_REG_PCIE | FPGA_REG_READONLY);
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
        DeviceFPGA_ConfigWrite(ctx, 0x0016, (PBYTE)&ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_REG_PCIE | FPGA_REG_READWRITE);
        for(i = 0; i < 32; i++) {
            if(!DeviceFPGA_GetPHYv4(ctx) || ctx->phy.rd.pl_directed_change_done) { break; }
            Sleep(10);
        }
        ctx->phy.wr.pl_directed_link_auton = 0;
        ctx->phy.wr.pl_directed_link_speed = 0;
        ctx->phy.wr.pl_directed_link_change = 0;
        DeviceFPGA_ConfigWrite(ctx, 0x0016, (PBYTE)&ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_REG_PCIE | FPGA_REG_READWRITE);
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
    BYTE pbCoreResetSYS[] = { 0x00, 0x80 };
    BYTE pbTX_Dummy[] = {
        // dword->qword resynch v4.5+
        0x66, 0x66, 0x55, 0x55,  0x66, 0x66, 0x55, 0x55,
        0x66, 0x66, 0x55, 0x55,  0x66, 0x66, 0x55, 0x55,
        // cmd msg: FPGA bitstream version (major.minor)    v4
        0x00, 0x00, 0x00, 0x00,  0x00, 0x08, 0x13, 0x77,
        // cmd msg: FPGA bitstream version (major)          v3
        0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x03, 0x77,
    };
    if(ctx->fRestartDevice) {
        ctx->fRestartDevice = FALSE;
        DeviceFPGA_ConfigWriteEx(ctx, 0x0002, pbCoreResetSYS, pbCoreResetSYS, FPGA_REG_CORE | FPGA_REG_READWRITE);
        Sleep(1000);
        DeviceFPGA_ReInitializeFTDI(ctx);
    }
    if(!(pbRX = LocalAlloc(0, 0x00100000))) { return; }
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTX_Dummy, sizeof(pbTX_Dummy), &cbTX, NULL);
    if(status) { goto fail; }
    Sleep(25);
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, 0x1000, &cbRX, NULL);
    if(status) { goto fail; }
    if(cbRX >= 0x1000) {
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, 0x00100000, &cbRX, NULL);
        if(!status && cbRX == 0x00100000) {
            // Sometimes the PCIe core locks up at unclean exits from PCILeech
            // causing things to stop work - including spamming output FIFOs
            // with trash data. Solution is to issue a "Global System Reset" of
            // the FPGA (supported on v4.6+ bitstreams). After the core and the
            // FT601 is back online try re-initialize the USB connection.
            DeviceFPGA_ConfigWriteEx(ctx, 0x0002, pbCoreResetSYS, pbCoreResetSYS, FPGA_REG_CORE | FPGA_REG_READWRITE);
            Sleep(1000);
            DeviceFPGA_ReInitializeFTDI(ctx);
        }
    }
fail:
    LocalFree(pbRX);
}

VOID DeviceFPGA_HotResetV4(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DeviceFPGA_GetPHYv4(ctx);
    ctx->phy.wr.pl_transmit_hot_rst = 1;
    DeviceFPGA_ConfigWrite(ctx, 0x0016, (PBYTE)&ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_REG_PCIE | FPGA_REG_READWRITE);
    Sleep(250);     // sloppy w/ sleep instead of poll pl_ltssm_state - but 250ms should be plenty of time ...
    ctx->phy.wr.pl_transmit_hot_rst = 0;
    DeviceFPGA_ConfigWrite(ctx, 0x0016, (PBYTE)& ctx->phy.wr, sizeof(ctx->phy.wr), FPGA_REG_PCIE | FPGA_REG_READWRITE);
}

_Success_(return)
BOOL DeviceFPGA_GetDeviceID_FpgaVersionV4(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    WORD wbsDeviceId, wMagicPCIe;
    DWORD dwInactivityTimer = 0x000186a0;       // set inactivity timer to 1ms ( 0x0186a0 * 100MHz ) [only later activated on UDP bitstreams]
    if(!DeviceFPGA_ConfigRead(ctx, 0x0008, (PBYTE)&ctx->wFpgaVersionMajor, 1, FPGA_REG_CORE | FPGA_REG_READONLY) || ctx->wFpgaVersionMajor < 4) { return FALSE; }
    DeviceFPGA_ConfigRead(ctx, 0x0009, (PBYTE)&ctx->wFpgaVersionMinor, 1, FPGA_REG_CORE | FPGA_REG_READONLY);
    DeviceFPGA_ConfigRead(ctx, 0x000a, (PBYTE)&ctx->wFpgaID, 1, FPGA_REG_CORE | FPGA_REG_READONLY);
    DeviceFPGA_ConfigWrite(ctx, 0x0008, (PBYTE)&dwInactivityTimer, 4, FPGA_REG_CORE | FPGA_REG_READWRITE);
    // PCIe
    DeviceFPGA_ConfigRead(ctx, 0x0008, (PBYTE)&wbsDeviceId, 2, FPGA_REG_PCIE | FPGA_REG_READONLY);
    if(!wbsDeviceId && DeviceFPGA_ConfigRead(ctx, 0x0000, (PBYTE)&wMagicPCIe, 2, FPGA_REG_PCIE | FPGA_REG_READWRITE) && (wMagicPCIe == 0x6745)) {
        // failed getting device id - assume device is connected -> try recover the bad link with hot-reset.
        DeviceFPGA_HotResetV4(ctx);
        DeviceFPGA_ConfigRead(ctx, 0x0008, (PBYTE)&wbsDeviceId, 2, FPGA_REG_PCIE | FPGA_REG_READONLY);
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

#define FT_IO_PENDING           24
#define TLP_RX_MAX_SIZE         (16+1024)

_Success_(return)
BOOL DeviceFPGA_TxTlp(_In_ PLC_CONTEXT ctxLC, _In_ PDEVICE_CONTEXT_FPGA ctx, _In_reads_(cbTlp) PBYTE pbTlp, _In_ DWORD cbTlp, _In_ BOOL fRdKeepalive, _In_ BOOL fFlush)
{
    DWORD status;
    PBYTE pbTx;
    QWORD i;
    DWORD cbTx, cbTxed = 0;
    if(cbTlp & 0x3) { return FALSE; }
    if(cbTlp > 4 * 4 + 128) { return FALSE; }
    if(cbTlp && (ctx->txbuf.cb + (cbTlp << 1) + (fFlush ? 8 : 0) >= ctx->perf.MAX_SIZE_TX)) {
        if(!DeviceFPGA_TxTlp(ctxLC, ctx, NULL, 0, FALSE, TRUE)) { return FALSE; }
    }
    if(ctxLC->fPrintf[LC_PRINTF_VVV] && cbTlp) {
        TLP_Print(ctxLC, pbTlp, cbTlp, TRUE);
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
    if((ctx->txbuf.cb >= ctx->perf.MAX_SIZE_TX) || (fFlush && ctx->txbuf.cb)) {
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, ctx->txbuf.pb, ctx->txbuf.cb, &cbTxed, NULL);
        if(status == 0x20) {
            DeviceFPGA_ReInitializeFTDI(ctx); // try recovery if possible.
            status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, ctx->txbuf.pb, ctx->txbuf.cb, &cbTxed, NULL);
        }
        ctx->txbuf.cb = 0;
        usleep(ctx->perf.DELAY_WRITE);
        return (0 == status);
    }
    return TRUE;
}

/*
* Prepare a single TLP for the user-set custom callback function and dispatch.
*/
VOID DeviceFPGA_RxTlp_UserCallback(_In_ PLC_CONTEXT ctxLC, _In_ PDEVICE_CONTEXT_FPGA ctx, PBYTE pbTlp, DWORD cbTlp)
{
    LPSTR szTlpText = NULL;
    DWORD hdrDwBuf, cbTlpText = 0;
    PTLP_HDR hdr = (PTLP_HDR)&hdrDwBuf;
    if(ctx->read_callback.fNoCpl && ctx->hRxTlpCallbackFn && (cbTlp >= 4)) {
        hdrDwBuf = _byteswap_ulong(*(PDWORD)pbTlp);
        if((hdr->TypeFmt == TLP_Cpl) || (hdr->TypeFmt == TLP_CplD) || (hdr->TypeFmt == TLP_CplLk) || (hdr->TypeFmt == TLP_CplDLk)) {
            return;
        }
    }
    if(ctx->read_callback.fInfo) {
        TLP_ToString(pbTlp, cbTlp, &szTlpText, &cbTlpText);
    }
    ctx->read_callback.pfn(ctx->read_callback.ctx, cbTlp, pbTlp, cbTlpText, szTlpText);
    if(szTlpText) { LocalFree(szTlpText); }
}

/*
* Extract the first TLP out of a byte buffer received from the FPGA and forward
* the TLP for processing.
* -- ctxLC
* -- ctx
* -- cdwData = number of DWORDs in FPGA data pdwData
* -- pdwData = FPGA data
* -- return = the number of DWORDs successfully consumed.
*/
DWORD DeviceFPGA_RxTlpAsynchronous_Tlp(_In_ PLC_CONTEXT ctxLC, _In_ PDEVICE_CONTEXT_FPGA ctx, _In_ DWORD cdwData, _In_ PDWORD pdwData)
{
    BYTE pbTlp[TLP_RX_MAX_SIZE];
    PDWORD pdwTlp = (PDWORD)pbTlp;
    DWORD i = 0, j, dwStatus, cdwTlp = 0, iStartWord;
    // skip over initial ftdi workaround dummy fillers / non valid octa-dwords
    while((i < cdwData) && ((pdwData[i] == 0x55556666) || ((pdwData[i] & 0xf0000000) != 0xe0000000))) {
        i++;
    }
    if(i) { return i; }
    // fetch and process next complete and valid tlp (if possible)
    while(i <= cdwData - 8) {
        iStartWord = i;
        dwStatus = pdwData[i++];
        if((dwStatus & 0xf0000000) != 0xe0000000) {
            continue;
        }
        for(j = 0; j < 7; j++, i++) {
            if((dwStatus & 0x03) == 0x00) { // PCIe TLP
                if(cdwTlp >= TLP_RX_MAX_SIZE / sizeof(DWORD)) {
                    // TODO: malformed TLP
                    pdwData[iStartWord] = pdwData[iStartWord] | (0xffffffff >> (28 - (j << 2)));
                    return iStartWord;
                }
                pdwTlp[cdwTlp++] = pdwData[i];
            }
            if((dwStatus & 0x07) == 0x04) { // PCIe TLP and LAST
                if(cdwTlp < 3) {
                    printf("Device Info: FPGA: Bad PCIe TLP received! Should not happen!\n");
                    pdwData[iStartWord] = pdwData[iStartWord] | (0xffffffff >> (28 - (j << 2)));
                    return iStartWord;
                }
                if(ctxLC->fPrintf[LC_PRINTF_VVV]) {
                    TLP_Print(ctxLC, pbTlp, cdwTlp << 2, FALSE);
                }
                if(ctx->read_callback.pfn) {
                    DeviceFPGA_RxTlp_UserCallback(ctxLC, ctx, pbTlp, cdwTlp << 2);
                }
                if(ctx->hRxTlpCallbackFn) {
                    ctx->hRxTlpCallbackFn(ctx->pMRdBufferX, pbTlp, cdwTlp << 2);
                }
                pdwData[iStartWord] = pdwData[iStartWord] | (0xffffffff >> (28 - (j << 2)));
                return iStartWord;
            }
            dwStatus >>= 4;
        }
    }
    return -1;
}

/*
* Read memory using an asynchronous approach. In most aspects it should work
* better than the synchronous approach. Async is however not supported on the
* Linux drivers and may also have other advantages - so keep old function too.
* -- ctxLC
* -- ctx
* -- cbBytesToRead
*/
VOID DeviceFPGA_RxTlpAsynchronous(_In_ PLC_CONTEXT ctxLC, _In_ PDEVICE_CONTEXT_FPGA ctx, _In_opt_ DWORD cbBytesToRead)
{
    DWORD status, cbRead, cdwTlpDataConsumed, cbReadMax = 0x10000;
    DWORD cbBuffer = 0, oBuffer = 0, cEmptyRead = 0;
    PBYTE pbBuffer = NULL;
    BOOL fAsync = cbBytesToRead > 0x4000;
    PTLP_CALLBACK_BUF_MRd_SCATTER prxbuf = ctx->pMRdBufferX;
    pbBuffer = ctx->rxbuf.pb;
    if(prxbuf) {
        cbReadMax = min(0x10000, max(0x1000, (cbBytesToRead - prxbuf->cbReadTotal) << 1));
    }
    if(ctx->dev.f2232h) {
        cbReadMax = 0x00103000; // "fake" async buffer magic value in FT2232H mode
        fAsync = FALSE;
    }
    usleep(25);
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbBuffer, cbReadMax, &cbRead, NULL);
    if(status && (status != FT_IO_PENDING)) { return; }
    while(TRUE) {
        cEmptyRead = ((cbRead == 0) || (cbRead == 0x14)) ? cEmptyRead + 1 : 0;
        if(cEmptyRead >= 0x30) { break; }
        cbBuffer += cbRead;
        // 1: submit async read (if target read is large enough to gain from it)
        if(fAsync) {
            status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbBuffer + cbBuffer, cbReadMax, &cbRead, &ctx->async.oOverlapped);
            if(status && (status != FT_IO_PENDING)) {
                break;
            }
        }
        // 2: process (partial) tlp result
        while(oBuffer + 32 <= cbBuffer) {
            cdwTlpDataConsumed = DeviceFPGA_RxTlpAsynchronous_Tlp(ctxLC, ctx, (cbBuffer - oBuffer) >> 2, (PDWORD)(pbBuffer + oBuffer));
            if(cdwTlpDataConsumed == (DWORD)-1) { break; }
            oBuffer += cdwTlpDataConsumed << 2;
        }
        if(prxbuf) {
            cbReadMax = min(0x10000, max(0x1000, (cbBytesToRead - prxbuf->cbReadTotal) << 1));
        }
        // 3: check exit criteria
        if(cbBuffer > 0x00f00000) { break; }
        if(prxbuf && (cbBytesToRead <= prxbuf->cbReadTotal)) { break; }
        // 3: read overlapped
        status = fAsync ?
            ctx->dev.pfnFT_GetOverlappedResult(ctx->dev.hFTDI, &ctx->async.oOverlapped, &cbRead, TRUE) :
            ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbBuffer + cbBuffer, cbReadMax, &cbRead, NULL);
        if(status) {
            break;
        }
    }
}

VOID DeviceFPGA_RxTlpSynchronous(_In_ PLC_CONTEXT ctxLC, _In_ PDEVICE_CONTEXT_FPGA ctx, _In_opt_ DWORD dwBytesToRead)
{
    DWORD status;
    DWORD i, j, cdwTlp = 0, cbReadRxBuf;
    BYTE pbTlp[TLP_RX_MAX_SIZE];
    PDWORD pdwTlp = (PDWORD)pbTlp;
    DWORD dwStatus, *pdwData;
    // larger read buffer slows down FT_ReadPipe so set it fairly tight if possible.
    cbReadRxBuf = ctx->dev.f2232h ? ctx->rxbuf.cbMax :
        min(ctx->rxbuf.cbMax, dwBytesToRead ? max(0x4000, (0x1000 + dwBytesToRead + (dwBytesToRead >> 1))) : (DWORD)-1);
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, ctx->rxbuf.pb, cbReadRxBuf, &ctx->rxbuf.cb, NULL);
    if(status == 0x20 && ctx->perf.RETRY_ON_ERROR) {
        DeviceFPGA_ReInitializeFTDI(ctx); // try recovery if possible.
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, ctx->rxbuf.pb, ctx->rxbuf.cbMax, &ctx->rxbuf.cb, NULL);
    }
    if(status) {
        ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x82);
        return;
    }
    for(i = 0; i < ctx->rxbuf.cb; i += 32) { // index in 32-bit (DWORD)
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
                    if(ctxLC->fPrintf[LC_PRINTF_VVV]) {
                        TLP_Print(ctxLC, pbTlp, cdwTlp << 2, FALSE);
                    }
                    if(ctx->read_callback.pfn) {
                        DeviceFPGA_RxTlp_UserCallback(ctxLC, ctx, pbTlp, cdwTlp << 2);
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

/*
* Background thread to make periodic reads of TLPs from the FPGA when there is
* little or no other traffic. Thread operates outside the device lock and must
* lock the device before doing any actions.
*/
DWORD DeviceFPGA_RxTlp_UserCallback_ThreadProc(_In_ PLC_CONTEXT ctxLC)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    if(!ctx->read_callback.fThread) { return 1; }
    InterlockedIncrement(&ctxLC->dwHandleCount);    // increment device handle count
    while((ctxLC->dwHandleCount > 1) && ctx->read_callback.fThread) {
        SwitchToThread();
        usleep(ctx->perf.DELAY_READ);
        EnterCriticalSection(&ctxLC->Lock);
        if((ctxLC->dwHandleCount > 1) && ctx->read_callback.fThread) {
            if(ctx->async.fEnabled) {
                DeviceFPGA_RxTlpAsynchronous(ctxLC, ctx, ctx->perf.MAX_SIZE_RX);
            } else {
                DeviceFPGA_RxTlpSynchronous(ctxLC, ctx, ctx->perf.MAX_SIZE_RX);
            }
        }
        LeaveCriticalSection(&ctxLC->Lock);
    }
    ctx->read_callback.fThread = FALSE;
    LcClose(ctxLC);     // decrement handle count (and close if required)
    return 1;
}

VOID DeviceFPGA_ReadScatter_Impl(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    TLP_CALLBACK_BUF_MRd_SCATTER rxbuf;
    DWORD tx[4] = { 0 };
    DWORD o, i, j, cb, cbFlush, cbTotalInCycle = 0;
    BOOL is32, fTiny = ctx->fAlgorithmReadTiny;
    PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
    PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
    PMEM_SCATTER pDMA;
    BYTE bTag;
    i = 0;
    ctx->pMRdBufferX = &rxbuf;
    ctx->hRxTlpCallbackFn = (VOID(*)(PVOID, PBYTE, DWORD))TLP_CallbackMRd_Scatter;
    rxbuf.fTiny = fTiny;
    while(i < cMEMs) {
        // Prepare callback buffer
        ctx->RxEccBit = ctx->RxEccBit ? 0 : 1;
        rxbuf.bEccBit = ctx->RxEccBit;
        rxbuf.cbReadTotal = 0;
        rxbuf.cph = cMEMs - i;
        rxbuf.pph = ppMEMs + i;
        // Transmit TLPs
        cbFlush = 0;
        cbTotalInCycle = 0;
        bTag = ctx->RxEccBit ? 0x80 : 0;
        for(; i < cMEMs; i++) {
            pDMA = *(ppMEMs + i);
            if(pDMA->f || !pDMA->cb || (pDMA->cb % 8) || ((pDMA->qwA & 0xfff) + pDMA->cb > 0x1000) || MEM_SCATTER_ADDR_ISINVALID(pDMA)) { // already completed, unsupported size, not in memmap -> skip over
                bTag = fTiny ? ((bTag + 0x20) & 0xe0) : (bTag + 1);
                if(!(bTag & 0x7f)) { break; }
                continue;
            }
            if(cbTotalInCycle >= ctx->perf.MAX_SIZE_RX) { break; }  // over max size -> break loop and read result
            cbTotalInCycle += pDMA->cb;
            o = 0;
            while(o < pDMA->cb) {
                cb = fTiny ? min(0x80, pDMA->cb - o) : pDMA->cb;
                is32 = pDMA->qwA < 0x100000000;
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
                if(ctx->perf.RX_FLUSH_LIMIT && (cbFlush >= (ctx->fAlgorithmReadTiny ? 0x1000 : ctx->perf.RX_FLUSH_LIMIT))) {
                    // flush is only used by the SP605.
                    DeviceFPGA_TxTlp(ctxLC, ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, TRUE);
                    usleep(ctx->perf.DELAY_WRITE);
                    cbFlush = 0;
                } else {
                    DeviceFPGA_TxTlp(ctxLC, ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, FALSE);
                }
                o += cb;
                bTag++;
            }
            if(fTiny && (bTag & 0x1f)) {
                bTag = (bTag + 0x20) & 0xe0;
            }
            if(!(bTag & 0x7f)) {
                i++;
                break;
            }
        }
        // Receive TLPs
        if(cbTotalInCycle) {
            DeviceFPGA_TxTlp(ctxLC, ctx, NULL, 0, TRUE, TRUE);
            if(ctx->async.fEnabled) {
                DeviceFPGA_RxTlpAsynchronous(ctxLC, ctx, cbTotalInCycle);
            } else {
                usleep(ctx->perf.DELAY_READ);
                DeviceFPGA_RxTlpSynchronous(ctxLC, ctx, cbTotalInCycle);
            }
        }
    }
    ctx->hRxTlpCallbackFn = NULL;
    ctx->pMRdBufferX = NULL;
}

VOID DeviceFPGA_ReadScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    DWORD i, iRetry;
    BOOL fRetry;
    PMEM_SCATTER pMEM;
    if(!ctx->wDeviceId) { return; }
    for(iRetry = 0, fRetry = TRUE; (fRetry && (iRetry <= ctx->perf.RETRY_ON_ERROR)); iRetry++) {
        fRetry = FALSE;
        for(i = 0; i < cMEMs; i++) {
            pMEM = ppMEMs[i];
            if(!pMEM->f && MEM_SCATTER_ADDR_ISVALID(pMEM)) {
                MEM_SCATTER_STACK_PUSH(pMEM, 0);
            }
        }
        DeviceFPGA_ReadScatter_Impl(ctxLC, cMEMs, ppMEMs);
        for(i = 0; i < cMEMs; i++) {
            pMEM = ppMEMs[i];
            if(!pMEM->f && MEM_SCATTER_ADDR_ISVALID(pMEM)) {
                pMEM->f = pMEM->cb == MEM_SCATTER_STACK_POP(pMEM);
                fRetry = fRetry || !pMEM->f;
            }
        }
    }
}

VOID DeviceFPGA_ProbeMEM_Impl(_In_ PLC_CONTEXT ctxLC, _In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_updates_bytes_(cPages) PBYTE pbResultMap)
{
    QWORD i;
    DWORD j, cTxTlp = 0;
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    TLP_CALLBACK_BUF_MRd bufMRd;
    DWORD tx[4];
    BOOL is32, isFlush;
    PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
    PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
    // split probe into processing chunks if too large...
    while(cPages > ctx->perf.PROBE_MAXPAGES) {
        DeviceFPGA_ProbeMEM_Impl(ctxLC, qwAddr, ctx->perf.PROBE_MAXPAGES, pbResultMap);
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
            DeviceFPGA_TxTlp(ctxLC, ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, TRUE);
            usleep(ctx->perf.DELAY_PROBE_WRITE);
        } else {
            DeviceFPGA_TxTlp(ctxLC, ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, FALSE);
        }
    }
    DeviceFPGA_TxTlp(ctxLC, ctx, NULL, 0, TRUE, TRUE);
    usleep(ctx->perf.DELAY_PROBE_READ);
    DeviceFPGA_RxTlpSynchronous(ctxLC, ctx, 0);
    ctx->hRxTlpCallbackFn = NULL;
    ctx->pMRdBufferX = NULL;
}

VOID DeviceFPGA_ProbeMEM(_In_ PLC_CONTEXT ctxLC, _In_ QWORD pa, _In_ DWORD cPages, _Inout_updates_bytes_(cPages) PBYTE pbResultMap)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    DWORD i;
    DeviceFPGA_ProbeMEM_Impl(ctxLC, pa, cPages, pbResultMap);
    if(ctx->perf.RETRY_ON_ERROR) {
        for(i = 0; i < cPages; i++) {
            if(0 == pbResultMap[i]) {
                Sleep(100);
                DeviceFPGA_ProbeMEM_Impl(ctxLC, pa, cPages, pbResultMap);
                return;
            }
        }
    }
}

// write max 128 byte packets.
_Success_(return) LINUX_NO_OPTIMIZE
BOOL DeviceFPGA_WriteMEM_TXP(_In_ PLC_CONTEXT ctxLC, _Inout_ PDEVICE_CONTEXT_FPGA ctx, _In_ QWORD pa, _In_ BYTE bFirstBE, _In_ BYTE bLastBE, _In_ PBYTE pb, _In_ DWORD cb)
{
    static BYTE bTag = 0;
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
        hdrWr32->Tag = bTag++;
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
        hdrWr64->Tag = bTag++;
        hdrWr64->RequesterID = ctx->wDeviceId;
        hdrWr64->AddressHigh = (DWORD)(pa >> 32);
        hdrWr64->AddressLow = (DWORD)pa;
        for(i = 0; i < 4; i++) {
            ENDIAN_SWAP_DWORD(txbuf[i]);
        }
        memcpy(pbTlp + 16, pb, cb);
        cbTlp = (16 + cb + 3) & ~0x3;
    }
    return DeviceFPGA_TxTlp(ctxLC, ctx, pbTlp, cbTlp, FALSE, FALSE);
}

VOID DeviceFPGA_WriteScatter(_In_ PLC_CONTEXT ctxLC, _In_ DWORD cpMEMs, _Inout_ PPMEM_SCATTER ppMEMs)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    BOOL result = TRUE;
    BYTE *pb, be, pbb[4];
    DWORD cb, iMEM, cbtx;
    QWORD pa;
    PMEM_SCATTER pMEM;
    if(!ctx->wDeviceId) { return; }
    for(iMEM = 0; iMEM < cpMEMs; iMEM++) {
        pMEM = ppMEMs[iMEM];
        if(pMEM->f || (pMEM->qwA == (QWORD)-1)) { continue; }
        pa = pMEM->qwA;
        cb = pMEM->cb;
        pb = pMEM->pb;
        // TX 1st dword if not aligned
        if(cb && (pa & 0x3)) {
            be = (cb < 3) ? (0xf >> (4 - cb)) : 0xf;
            be <<= pa & 0x3;
            cbtx = min(cb, 4 - (pa & 0x3));
            memcpy(pbb + (pa & 0x3), pb, cbtx);
            result = DeviceFPGA_WriteMEM_TXP(ctxLC, ctx, pa & ~0x3, be, 0, pbb, 4);
            pb += cbtx;
            cb -= cbtx;
            pa += cbtx;
        }
        // TX as 128-byte packets (aligned to 128-byte boundaries)
        while(result && cb) {
            cbtx = min(128 - (pa & 0x7f), cb);
            be = (cbtx & 0x3) ? (0xf >> (4 - (cbtx & 0x3))) : 0xf;
            result = (cbtx <= 4) ?
                DeviceFPGA_WriteMEM_TXP(ctxLC, ctx, pa, be, 0, pb, 4) :
                DeviceFPGA_WriteMEM_TXP(ctxLC, ctx, pa, 0xf, be, pb, cbtx);
            pb += cbtx;
            cb -= cbtx;
            pa += cbtx;
        }
        pMEM->f = TRUE;
    }
    DeviceFPGA_TxTlp(ctxLC, ctx, NULL, 0, FALSE, TRUE) && result; // Flush and Return.
}

_Success_(return)
BOOL DeviceFPGA_ListenTlp(_In_ PLC_CONTEXT ctxLC, _In_ DWORD dwTime)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    QWORD tmStart = GetTickCount64();
    ctx->hRxTlpCallbackFn = NULL;
    while(GetTickCount64() - tmStart < dwTime) {
        DeviceFPGA_TxTlp(ctxLC, ctx, NULL, 0, TRUE, TRUE);
        Sleep(10);
        DeviceFPGA_RxTlpSynchronous(ctxLC, ctx, 0);
    }
    return TRUE;
}

_Success_(return)
BOOL DeviceFPGA_WriteTlp(_In_ PLC_CONTEXT ctxLC, _In_ PBYTE pbTlp, _In_ DWORD cbTlp)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    return DeviceFPGA_TxTlp(ctxLC, ctx, pbTlp, cbTlp, FALSE, TRUE);
}

_Success_(return)
BOOL DeviceFPGA_Command(
    _In_ PLC_CONTEXT ctxLC,
    _In_ QWORD fOption,
    _In_ DWORD cbDataIn,
    _In_reads_opt_(cbDataIn) PBYTE pbDataIn,
    _Out_opt_ PBYTE *ppbDataOut,
    _Out_opt_ PDWORD pcbDataOut
) {
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    QWORD i, c, qwOptionHi, qwOptionLo;
    WORD fCfgRegConfig;
    PLC_TLP pTLP;
    PBYTE pb;
    qwOptionLo = fOption & 0x00000000ffffffff;
    qwOptionHi = fOption & 0xffffffff00000000;
    if(ppbDataOut) { *ppbDataOut = NULL; }
    if(pcbDataOut) { *pcbDataOut = 0; }
    switch(qwOptionHi) {
        case LC_CMD_FPGA_WRITE_TLP:
        case LC_CMD_FPGA_TLP_WRITE_SINGLE:
            return (cbDataIn >= 12) && !(cbDataIn % 4) && pbDataIn && DeviceFPGA_WriteTlp(ctxLC, pbDataIn, cbDataIn);
        case LC_CMD_FPGA_TLP_WRITE_MULTIPLE:
            if(!pbDataIn || (cbDataIn % sizeof(LC_TLP))) { return FALSE; }
            for(i = 0, c = cbDataIn / sizeof(LC_TLP); i < c; i++) {
                pTLP = ((PLC_TLP)pbDataIn) + i;
                if((pTLP->cb >= 12) && !(pTLP->cb % 4)) {
                    DeviceFPGA_TxTlp(ctxLC, ctx, pTLP->pb, pTLP->cb, FALSE, (i == c - 1));
                }
            }
            return TRUE;
        case LC_CMD_FPGA_LISTEN_TLP:
            return (cbDataIn == 4) && !(cbDataIn % 4) && pbDataIn && DeviceFPGA_ListenTlp(ctxLC, *(PDWORD)pbDataIn);
        case LC_CMD_FPGA_TLP_TOSTRING:
            if(!ppbDataOut || !pbDataIn || (cbDataIn % 4)) { return FALSE; }
            return TLP_ToString(pbDataIn, cbDataIn, (LPSTR*)ppbDataOut, pcbDataOut);
        case LC_CMD_FPGA_TLP_READ_FUNCTION_CALLBACK:
            if(!pbDataIn && !cbDataIn) {
                ctx->read_callback.ctx = NULL;
                ctx->read_callback.pfn = NULL;
                return TRUE;
            }
            if(!pbDataIn || (cbDataIn != sizeof(LC_TLP_CALLBACK))) { return FALSE; }
            ctx->read_callback.ctx = ((PLC_TLP_CALLBACK)pbDataIn)->ctx;
            ctx->read_callback.pfn = ((PLC_TLP_CALLBACK)pbDataIn)->pfn;
            if(ctx->read_callback.pfn) {
                if(ctx->async.fEnabled) {
                    DeviceFPGA_RxTlpAsynchronous(ctxLC, ctx, ctx->perf.MAX_SIZE_RX);
                } else {
                    DeviceFPGA_RxTlpSynchronous(ctxLC, ctx, ctx->perf.MAX_SIZE_RX);
                }
            }
            return TRUE;
        case LC_CMD_FPGA_PCIECFGSPACE:
            if(!ppbDataOut || (ctx->wFpgaVersionMajor < 4)) { return FALSE; }
            if(!(*ppbDataOut = LocalAlloc(LMEM_ZEROINIT, 0x1000))) { return FALSE; }
            if(pcbDataOut) { *pcbDataOut = 0x1000; };
            return DeviceFPGA_PCIeCfgSpaceCoreRead(ctx, *ppbDataOut, 0);
        case LC_CMD_FPGA_CFGREGCFG:
        case LC_CMD_FPGA_CFGREGPCIE:
            if(ctx->wFpgaVersionMajor < 4) { return FALSE; }
            if(pbDataIn && (cbDataIn > 0x100)) { return FALSE; }
            fCfgRegConfig =
                ((qwOptionHi == LC_CMD_FPGA_CFGREGCFG) ? FPGA_REG_CORE : FPGA_REG_PCIE) |
                ((qwOptionLo & 0x8000) ? FPGA_REG_READWRITE : FPGA_REG_READONLY);
            if(pbDataIn) {
                DeviceFPGA_ConfigWrite(ctx, qwOptionLo & 0x3fff, pbDataIn, (WORD)cbDataIn, fCfgRegConfig);
            }
            if(ppbDataOut) {
                if(!(pb = LocalAlloc(LMEM_ZEROINIT, 0x100))) { return FALSE; }
                DeviceFPGA_ConfigRead(ctx, qwOptionLo & 0x3fff, pb, 0x100, fCfgRegConfig);
                if(pcbDataOut) { *pcbDataOut = min(0x100, *(PDWORD)(pb + 4)); }
                *ppbDataOut = pb;
            }
            return TRUE;
        case LC_CMD_FPGA_CFGREGDRP:
            if(!ppbDataOut || (ctx->wFpgaVersionMajor < 4)) { return FALSE; }
            if(!(*ppbDataOut = LocalAlloc(LMEM_ZEROINIT, 0x100))) { return FALSE; }
            if(pcbDataOut) { *pcbDataOut = 0x100; }
            return DeviceFPGA_PCIeDrpRead(ctx, *ppbDataOut);;
        case LC_CMD_FPGA_CFGREGCFG_MARKWR:
        case LC_CMD_FPGA_CFGREGPCIE_MARKWR:
            if(ctx->wFpgaVersionMajor < 4) { return FALSE; }
            if(!pbDataIn || (cbDataIn != 4)) { return FALSE; }
            fCfgRegConfig =
                ((qwOptionHi == LC_CMD_FPGA_CFGREGCFG_MARKWR) ? FPGA_REG_CORE : FPGA_REG_PCIE) |
                FPGA_REG_READWRITE;
            return DeviceFPGA_ConfigWriteEx(ctx, qwOptionLo & 0x3fff, pbDataIn, pbDataIn + 2, fCfgRegConfig);
        case LC_CMD_FPGA_CFGSPACE_SHADOW_RD:
            if(!ppbDataOut || (ctx->wFpgaVersionMinor < 8)) { return FALSE; }
            if(!(*ppbDataOut = LocalAlloc(LMEM_ZEROINIT, 0x1000))) { return FALSE; }
            if(pcbDataOut) { *pcbDataOut = 0x1000; }
            return DeviceFPGA_ConfigRead(ctx, 0, *ppbDataOut, 0x1000, FPGA_REG_CORE | FPGA_REG_SHADOWCFGSPACE);
        case LC_CMD_FPGA_CFGSPACE_SHADOW_WR:
            if(!pbDataIn || (ctx->wFpgaVersionMinor < 8)) { return FALSE; }
            return DeviceFPGA_ConfigWrite(ctx, (WORD)qwOptionLo, pbDataIn, (WORD)cbDataIn, FPGA_REG_CORE | FPGA_REG_SHADOWCFGSPACE);
        case LC_CMD_FPGA_CFGREG_DEBUGPRINT:
            DeviceFPGA_ConfigPrint(ctxLC, ctx);
            return TRUE;
        case LC_CMD_FPGA_PROBE:
            if(!pbDataIn || !ppbDataOut || (cbDataIn != 8) || (0x01000000 < qwOptionLo /* cPages */)) { return FALSE; }
            if(!(*ppbDataOut = LocalAlloc(LMEM_ZEROINIT, (SIZE_T)qwOptionLo))) { return FALSE; }
            DeviceFPGA_ProbeMEM(ctxLC, *(PQWORD)pbDataIn, (DWORD)qwOptionLo, *ppbDataOut);
            if(pcbDataOut) { *pcbDataOut = (DWORD)qwOptionLo; }
            return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL DeviceFPGA_GetOption(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _Out_ PQWORD pqwValue)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    PDEVICE_PERFORMANCE perf = &ctx->perf;
    if(!pqwValue) { return FALSE; }
    switch(fOption & 0xffffffff00000000) {
        case LC_OPT_FPGA_PROBE_MAXPAGES:
            *pqwValue = perf->PROBE_MAXPAGES;
            return TRUE;
        case LC_OPT_FPGA_MAX_SIZE_RX:
            *pqwValue = perf->MAX_SIZE_RX;
            return TRUE;
        case LC_OPT_FPGA_MAX_SIZE_TX:
            *pqwValue = perf->MAX_SIZE_TX;
            return TRUE;
        case LC_OPT_FPGA_DELAY_PROBE_READ:
            *pqwValue = perf->DELAY_PROBE_READ;
            return TRUE;
        case LC_OPT_FPGA_DELAY_PROBE_WRITE:
            *pqwValue = perf->DELAY_PROBE_WRITE;
            return TRUE;
        case LC_OPT_FPGA_DELAY_WRITE:
            *pqwValue = perf->DELAY_WRITE;
            return TRUE;
        case LC_OPT_FPGA_DELAY_READ:
            *pqwValue = perf->DELAY_READ;
            return TRUE;
        case LC_OPT_FPGA_RETRY_ON_ERROR:
            *pqwValue = perf->RETRY_ON_ERROR;
            return TRUE;
        case LC_OPT_FPGA_DEVICE_ID:
            *pqwValue = ctx->wDeviceId;
            return TRUE;
        case LC_OPT_FPGA_FPGA_ID:
            *pqwValue = ctx->wFpgaID;
            return TRUE;
        case LC_OPT_FPGA_VERSION_MAJOR:
            *pqwValue = ctx->wFpgaVersionMajor;
            return TRUE;
        case LC_OPT_FPGA_VERSION_MINOR:
            *pqwValue = ctx->wFpgaVersionMinor;
            return TRUE;
        case LC_OPT_FPGA_ALGO_TINY:
            *pqwValue = ctx->fAlgorithmReadTiny ? 1 : 0;
            return TRUE;
        case LC_OPT_FPGA_ALGO_SYNCHRONOUS:
            *pqwValue = ctx->async.fEnabled ? 1 : 0;
            return TRUE;
        case LC_OPT_FPGA_CFGSPACE_XILINX:
            *pqwValue = 0;
            return DeviceFPGA_PCIeCfgSpaceCoreReadDWORD(ctx, (DWORD)fOption, (PDWORD)pqwValue);
        case LC_OPT_FPGA_TLP_READ_CB_WITHINFO:
            *pqwValue = ctx->read_callback.fInfo ? 1 : 0;
            return TRUE;
        case LC_OPT_FPGA_TLP_READ_CB_FILTERCPL:
            *pqwValue = ctx->read_callback.fNoCpl ? 1 : 0;
            return TRUE;
        case LC_OPT_FPGA_TLP_READ_CB_BACKGROUND_THREAD:
            *pqwValue = ctx->read_callback.fThread ? 1 : 0;
            return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL DeviceFPGA_SetOption(_In_ PLC_CONTEXT ctxLC, _In_ QWORD fOption, _In_ QWORD qwValue)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxLC->hDevice;
    PDEVICE_PERFORMANCE perf = &ctx->perf;
    HANDLE hThread;
    switch(fOption & 0xffffffff00000000) {
        case  LC_OPT_FPGA_PROBE_MAXPAGES:
            perf->PROBE_MAXPAGES = (DWORD)qwValue;
            return TRUE;
        case LC_OPT_FPGA_MAX_SIZE_RX:
            perf->MAX_SIZE_RX = (DWORD)qwValue;
            return TRUE;
        case LC_OPT_FPGA_MAX_SIZE_TX:
            perf->MAX_SIZE_TX = (DWORD)qwValue;
            return TRUE;
        case LC_OPT_FPGA_DELAY_PROBE_READ:
            perf->DELAY_PROBE_READ = (DWORD)qwValue;
            return TRUE;
        case LC_OPT_FPGA_DELAY_PROBE_WRITE:
            perf->DELAY_PROBE_WRITE = (DWORD)qwValue;
            return TRUE;
        case LC_OPT_FPGA_DELAY_WRITE:
            perf->DELAY_WRITE = (DWORD)qwValue;
            return TRUE;
        case LC_OPT_FPGA_DELAY_READ:
            perf->DELAY_READ = (DWORD)qwValue;
            return TRUE;
        case LC_OPT_FPGA_RETRY_ON_ERROR:
            perf->RETRY_ON_ERROR = qwValue ? 1 : 0;
            return TRUE;
        case LC_OPT_FPGA_DEVICE_ID:
            ctx->wDeviceId  = (WORD)qwValue;
            return TRUE;
        case LC_OPT_FPGA_ALGO_TINY:
            ctx->fAlgorithmReadTiny = qwValue ? TRUE : FALSE;
            return TRUE;
        case LC_OPT_FPGA_ALGO_SYNCHRONOUS:
            ctx->async.fEnabled =  (qwValue && ctx->dev.pfnFT_ReleaseOverlapped) ? TRUE : FALSE;
            return TRUE;
        case LC_OPT_FPGA_CFGSPACE_XILINX:
            return DeviceFPGA_PCIeCfgSpaceCoreWriteDWORD(ctx, (DWORD)fOption, qwValue >> 32, (DWORD)qwValue);
        case LC_OPT_FPGA_TLP_READ_CB_WITHINFO:
            ctx->read_callback.fInfo = qwValue ? TRUE : FALSE;
            return TRUE;
        case LC_OPT_FPGA_TLP_READ_CB_FILTERCPL:
            ctx->read_callback.fNoCpl = qwValue ? TRUE : FALSE;
            return TRUE;
        case LC_OPT_FPGA_TLP_READ_CB_BACKGROUND_THREAD:
            if(ctx->read_callback.fThread) {
                ctx->read_callback.fThread = qwValue ? TRUE : FALSE;
                return TRUE;
            }
            if(qwValue) {
                if(!ctx->read_callback.pfn) { return FALSE; }
                ctx->read_callback.fThread = TRUE;
                if((hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DeviceFPGA_RxTlp_UserCallback_ThreadProc, ctxLC, 0, NULL))) {
                    CloseHandle(hThread);
                    Sleep(10);
                }
            }
            return TRUE;
    }
    return FALSE;
}

#define FPGA_PARAMETER_UDP_ADDRESS     "ip"
#define FPGA_PARAMETER_FT2232H         "ft2232h"
#define FPGA_PARAMETER_PCIE            "pciegen"
#define FPGA_PARAMETER_PCIE_NOCONNECT  "pcienotconnected"
#define FPGA_PARAMETER_RESTART_DEVICE  "devreload"
#define FPGA_PARAMETER_DELAY_READ      "tmread"
#define FPGA_PARAMETER_DELAY_WRITE     "tmwrite"
#define FPGA_PARAMETER_DELAY_PROBE     "tmprobe"
#define FPGA_PARAMETER_READ_ALGORITHM  "algo"
#define FPGA_PARAMETER_READ_SIZE       "readsize"
#define FPGA_PARAMETER_READ_RETRY      "readretry"
#define FPGA_PARAMETER_DEVICE_INDEX    "devindex"
#define FPGA_PARAMETER_DEVICE_ID       "bdf"

#define FPGA_PARAMETER_ALGO_TINY        0x01
#define FPGA_PARAMETER_ALGO_SYNCHRONOUS 0x02

_Success_(return)
BOOL DeviceFPGA_Open(_Inout_ PLC_CONTEXT ctxLC, _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo)
{
    DWORD dwIpAddr;
    QWORD v;
    LPSTR szDeviceError;
    PDEVICE_CONTEXT_FPGA ctx;
    PLC_DEVICE_PARAMETER_ENTRY pParam;
    if(ppLcCreateErrorInfo) { *ppLcCreateErrorInfo = NULL; }
    ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FPGA));
    if(!ctx) { return FALSE; }
    ctxLC->hDevice = (HANDLE)ctx;
    if((pParam = LcDeviceParameterGet(ctxLC, FPGA_PARAMETER_UDP_ADDRESS)) && pParam->szValue) {
        dwIpAddr = inet_addr(pParam->szValue);
        szDeviceError = ((dwIpAddr == 0) || (dwIpAddr == (DWORD)-1)) ?
            "Bad IPv4 address" :
            DeviceFPGA_InitializeUDP(ctx, dwIpAddr);
    } else if((pParam = LcDeviceParameterGet(ctxLC, FPGA_PARAMETER_FT2232H)) && pParam->szValue) {
        ctx->qwDeviceIndex = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_DEVICE_INDEX);
        szDeviceError = DeviceFPGA_InitializeFT2232(ctx);
    } else {
        ctx->qwDeviceIndex = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_DEVICE_INDEX);
        szDeviceError = DeviceFPGA_InitializeFT601(ctx);
    }
    if(szDeviceError) { goto fail; }
    ctx->fRestartDevice = (1 == LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_RESTART_DEVICE));
    DeviceFPGA_GetDeviceID_FpgaVersion(ctx);
    if(!ctx->wFpgaVersionMajor) {
        szDeviceError = "Unable to connect to FPGA device";
        goto fail;
    }
    // verify parameters and set version&speed
    DeviceFPGA_SetSpeedPCIeGen(ctx, (DWORD)LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_PCIE));
    if(!ctx->wDeviceId && !LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_PCIE_NOCONNECT)) {
        szDeviceError = "Unable to retrieve required Device PCIe ID";
        goto fail;
    }
    DeviceFPGA_SetPerformanceProfile(ctx);
    ctx->rxbuf.cbMax = ctx->dev.f2232h ? 0x01000000 : (DWORD)(1.30 * ctx->perf.MAX_SIZE_RX + 0x2000);  // buffer size tuned to lowest possible (+margin) for performance (FT601).
    ctx->rxbuf.pb = LocalAlloc(0, 0x01000000);
    if(!ctx->rxbuf.pb) { goto fail; }
    ctx->txbuf.cbMax = ctx->perf.MAX_SIZE_TX + 0x10000;
    ctx->txbuf.pb = LocalAlloc(0, ctx->txbuf.cbMax);
    if(!ctx->txbuf.pb) { goto fail; }
    // set callback functions and fix up config
    ctxLC->Config.fVolatile = TRUE;
    ctxLC->pfnClose = DeviceFPGA_Close;
    ctxLC->pfnReadScatter = DeviceFPGA_ReadScatter;
    ctxLC->pfnWriteScatter = DeviceFPGA_WriteScatter;
    ctxLC->pfnGetOption = DeviceFPGA_GetOption;
    ctxLC->pfnSetOption = DeviceFPGA_SetOption;
    ctxLC->pfnCommand = DeviceFPGA_Command;
    if((v = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_DELAY_READ)))  { ctx->perf.DELAY_READ = (DWORD)v; }
    if((v = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_DELAY_WRITE))) { ctx->perf.DELAY_WRITE = (DWORD)v; }
    if((v = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_DELAY_PROBE))) { ctx->perf.DELAY_PROBE_READ = (DWORD)v; }
    if((v = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_READ_RETRY)))  { ctx->perf.RETRY_ON_ERROR = (DWORD)v; }
    if((v = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_READ_SIZE)))   { ctx->perf.MAX_SIZE_RX = min(ctx->perf.MAX_SIZE_RX, (DWORD)v & ~0xfff); }
    if((v = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_DEVICE_ID)))   { ctx->wDeviceId = (WORD)v; }
    v = LcDeviceParameterGetNumeric(ctxLC, FPGA_PARAMETER_READ_ALGORITHM);
    ctx->fAlgorithmReadTiny = ((v & FPGA_PARAMETER_ALGO_TINY) ? TRUE : FALSE) || ctx->perf.F_TINY;
    ctx->async.fEnabled = ctx->async.fEnabled && !(v & FPGA_PARAMETER_ALGO_SYNCHRONOUS);
    // return
    lcprintfv(ctxLC, 
        "DEVICE: FPGA: %s PCIe gen%i x%i [%i,%i,%i] [v%i.%i,%04x] [%s,%s]\n",
        ctx->perf.SZ_DEVICE_NAME,
        DeviceFPGA_PHY_GetPCIeGen(ctx),
        DeviceFPGA_PHY_GetLinkWidth(ctx),
        ctx->perf.DELAY_READ,
        ctx->perf.DELAY_WRITE,
        ctx->perf.DELAY_PROBE_READ,
        ctx->wFpgaVersionMajor,
        ctx->wFpgaVersionMinor,
        ctx->wDeviceId,
        (ctx->async.fEnabled ? "ASYNC" : "SYNC"),
        (ctx->fAlgorithmReadTiny ? "TINY" : "NORM")
        );
    if(ctxLC->fPrintf[LC_PRINTF_VV]) {
        DeviceFPGA_ConfigPrint(ctxLC, ctx);
    }
    return TRUE;
fail:
    if(ctxLC->fPrintf[LC_PRINTF_VV] && ctx->dev.fInitialized) {
        DeviceFPGA_ConfigPrint(ctxLC, ctx);
    }
    if(szDeviceError && ctxLC->fPrintf[LC_PRINTF_V]) {
        lcprintfv(ctxLC,
            "DEVICE: FPGA: ERROR: %s [%i,v%i.%i,%04x]\n",
            szDeviceError,
            ctx->wFpgaID,
            ctx->wFpgaVersionMajor,
            ctx->wFpgaVersionMinor,
            ctx->wDeviceId);
    }
    DeviceFPGA_Close(ctxLC);
    return FALSE;
}
