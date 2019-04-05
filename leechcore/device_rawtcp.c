// Contribution by Synacktiv - www.synacktiv.com
// https://www.synacktiv.com/posts/exploit/using-your-bmc-as-a-dma-device-plugging-pcileech-to-hpe-ilo-4.html
//
//
// devicerawtcp.c : implementation related to dummy device backed by a TCP service.
//

#ifdef _WIN32

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

#endif /* _WIN32 */
#ifdef LINUX

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define SOCKET int
#define closesocket(_s_) close((_s_))
#define INVALID_SOCKET	-1
#define SOCKET_ERROR	-1

#endif /* LINUX */

#include "device_rawtcp.h"
#include "device.h"
#include "memmap.h"
#include "util.h"

#define RAWTCP_MAX_SIZE_RX      0x01000000
#define RAWTCP_MAX_SIZE_TX      0x00100000
#define RAWTCP_DEFAULT_PORT           8888

typedef struct tdDEVICE_CONTEXT_RAWTCP {
    DWORD TcpAddr;
    WORD TcpPort;
	SOCKET Sock;
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
    BYTE pbBufferScatterGather[RAWTCP_MAX_SIZE_RX];
} DEVICE_CONTEXT_RAWTCP, *PDEVICE_CONTEXT_RAWTCP;

typedef struct tdRAWTCP_PROTO_PACKET {
	RawTCPCmd cmd;
	QWORD addr;
	QWORD cb;
} RAWTCP_PROTO_PACKET, *PRAWTCP_PROTO_PACKET;

SOCKET DeviceRawTCP_Connect(_In_ DWORD Addr, _In_ WORD Port)
{
	SOCKET Sock = 0;
	struct sockaddr_in sAddr;
	sAddr.sin_family = AF_INET;
	sAddr.sin_port = htons(Port);
	sAddr.sin_addr.s_addr = Addr;
	if ((Sock = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET) {
		if (connect(Sock, (struct sockaddr *)&sAddr, sizeof(sAddr)) != SOCKET_ERROR) { return Sock; }
        vprintf("RAWTCP: ERROR: connect() fails\n");
		closesocket(Sock);
	}
	else {
        vprintf("RAWTCP: ERROR: socket() fails\n");
	}
	return 0;
}

BOOL DeviceRawTCP_Status(_In_ PDEVICE_CONTEXT_RAWTCP ctxrawtcp)
{
	RAWTCP_PROTO_PACKET Rx = {0}, Tx = {0};
	DWORD cbRead;
	BYTE ready;
	DWORD len;

	Tx.cmd = STATUS;

	if (send(ctxrawtcp->Sock, (const char *)&Tx, sizeof(Tx), 0) != sizeof(Tx)) {
        vprintf("RAWTCP: ERROR: send() fails\n");
		return 0;
	}

	cbRead = 0;
	while (cbRead < sizeof(Rx)) {
		len = recv(ctxrawtcp->Sock, (char *)&Rx + cbRead, sizeof(Rx) - cbRead, 0);
		if (len == SOCKET_ERROR || len == 0) {
            vprintf("RAWTCP: ERROR: recv() fails\n");
			return 0;
		}
		cbRead += len;
	}
	
	len = recv(ctxrawtcp->Sock, (char *)&ready, sizeof(ready), 0);
	if (len == SOCKET_ERROR || len != sizeof(ready)) {
        vprintf("RAWTCP: ERROR: recv() fails\n");
		return 0;
	}

	if (Rx.cmd != STATUS || Rx.cb != sizeof(ready)) {
        vprintf("RAWTCP: ERROR: Fail getting device status\n");
	}

	return ready != 0;
}

VOID DeviceRawTCP_Close()
{
    PDEVICE_CONTEXT_RAWTCP ctx = (PDEVICE_CONTEXT_RAWTCP)ctxDeviceMain->hDevice;
	if (!ctx) { return; }
	if (ctx->Sock) { closesocket(ctx->Sock); }
	if (ctx->rxbuf.pb) { LocalFree(ctx->rxbuf.pb); }
	if (ctx->txbuf.pb) { LocalFree(ctx->txbuf.pb); }
	LocalFree(ctx);
    ctxDeviceMain->hDevice = 0;
}

BOOL DeviceRawTCP_ReadDMA(_In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
    PDEVICE_CONTEXT_RAWTCP ctxrawtcp = (PDEVICE_CONTEXT_RAWTCP)ctxDeviceMain->hDevice;
	RAWTCP_PROTO_PACKET Rx = {0}, Tx = {0};
	DWORD cbRead;
	DWORD len;

	if (cb > RAWTCP_MAX_SIZE_RX) { return FALSE; }
	if (qwAddr % 0x1000) { return FALSE; }
	if ((cb >= 0x1000) && (cb % 0x1000)) { return FALSE; }
	if ((cb < 0x1000) && (cb % 0x8)) { return FALSE; }
	
	Tx.cmd = MEM_READ;
	Tx.addr = qwAddr;
	Tx.cb = cb;

	if (send(ctxrawtcp->Sock, (const char *)&Tx, sizeof(Tx), 0) != sizeof(Tx)) {
        vprintf("RAWTCP: ERROR: send() fails\n");
		return 0;
	}

	cbRead = 0;
	while (cbRead < sizeof(Rx)) {
		len = recv(ctxrawtcp->Sock, (char *)&Rx + cbRead, sizeof(Rx) - cbRead, 0);
		if (len == SOCKET_ERROR || len == 0) {
            vprintf("RAWTCP: ERROR: recv() fails\n");
			return 0;
		}
		cbRead += len;
	}


	cbRead = 0;
	while (cbRead < Rx.cb) {
		len = recv(ctxrawtcp->Sock, (char *)pb + cbRead, (int)(Rx.cb - cbRead), 0);
		if (len == SOCKET_ERROR || len == 0) {
            vprintf("RAWTCP: ERROR: recv() fails\n");
			return 0;
		}
		cbRead += len;
	}

	if (Rx.cmd != MEM_READ) {
        vprintf("RAWTCP: ERROR: Memory read fail (0x%x bytes read)\n", cbRead);
	}
	
	return Rx.cb >= cb;
}

VOID DeviceRawTCP_ReadScatterGather_ReadRegion(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ QWORD pa, _In_ DWORD cb)
{
    BOOL result;
    PDEVICE_CONTEXT_RAWTCP ctx = (PDEVICE_CONTEXT_RAWTCP)ctxDeviceMain->hDevice;
    DWORD iMEM, cbMEM;
    ZeroMemory(ctx->pbBufferScatterGather, cb);
    result = DeviceRawTCP_ReadDMA(pa, ctx->pbBufferScatterGather, cb);
    if(result) {
        // fill successful mem reads
        for(iMEM = 0, cbMEM = 0; iMEM < cpMEMs; iMEM++) {
            ppMEMs[iMEM]->cb = ppMEMs[iMEM]->cbMax;
            memcpy(ppMEMs[iMEM]->pb, ctx->pbBufferScatterGather + cbMEM, ppMEMs[iMEM]->cb);
            cbMEM += ppMEMs[iMEM]->cb;
        }
    }
}

VOID DeviceRawTCP_ReadScatterGather(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
    PDEVICE_CONTEXT_RAWTCP ctx = (PDEVICE_CONTEXT_RAWTCP)ctxDeviceMain->hDevice;
    PMEM_IO_SCATTER_HEADER pMEM;
    QWORD paBase = 0;
    DWORD i, c = 0, iBase = 0, cbCurrent = 0;
    for(i = 0; i < cpMEMs; i++) {
        pMEM = ppMEMs[i];
        if(!MemMap_VerifyTranslateMEM(pMEM, NULL)) { continue; }
        if(c == 0) {
            if(pMEM->cbMax && (pMEM->cb != pMEM->cbMax)) {
                c = 1;
                iBase = i;
                paBase = pMEM->qwA;
                cbCurrent = pMEM->cbMax;
            }
        } else if((paBase + cbCurrent == pMEM->qwA) && (cbCurrent + pMEM->cbMax <= RAWTCP_MAX_SIZE_RX)) {
            c++;
            cbCurrent += pMEM->cbMax;
        } else {
            DeviceRawTCP_ReadScatterGather_ReadRegion(ppMEMs + iBase, c, paBase, cbCurrent);
            c = 0;
            if(pMEM->cbMax && (pMEM->cb != pMEM->cbMax)) {
                c = 1;
                iBase = i;
                paBase = pMEM->qwA;
                cbCurrent = pMEM->cbMax;
            }
        }
    }
    if(c) {
        DeviceRawTCP_ReadScatterGather_ReadRegion(ppMEMs + iBase, c, paBase, cbCurrent);
    }
}

BOOL DeviceRawTCP_WriteDMA(_In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
	PDEVICE_CONTEXT_RAWTCP ctxrawtcp = (PDEVICE_CONTEXT_RAWTCP)ctxDeviceMain->hDevice;
	RAWTCP_PROTO_PACKET Rx = {0}, Tx = {0};
	DWORD cbRead, cbWritten;
	DWORD len;

    while(cb > RAWTCP_MAX_SIZE_TX) {
        if(!DeviceRawTCP_WriteDMA(qwAddr, pb, RAWTCP_MAX_SIZE_TX)) {
            return FALSE;
        }
        qwAddr += RAWTCP_MAX_SIZE_TX;
        pb = pb + RAWTCP_MAX_SIZE_TX;
        cb -= RAWTCP_MAX_SIZE_TX;
    }
	
	Tx.cmd = MEM_WRITE;
	Tx.addr = qwAddr;
	Tx.cb = cb;

	if (send(ctxrawtcp->Sock, (const char *)&Tx, sizeof(Tx), 0) != sizeof(Tx)) {
        vprintf("RAWTCP: ERROR: send() fails\n");
		return FALSE;
	}

	cbWritten = 0;
	while (cbWritten < cb) {
		len = send(ctxrawtcp->Sock, (char *)pb + cbWritten, cb - cbWritten, 0);
		if (len == SOCKET_ERROR || len == 0) {
            vprintf("RAWTCP: ERROR: send() fails\n");
			return FALSE;
		}
		cbWritten += len;
	}


	cbRead = 0;
	while (cbRead < sizeof(Rx)) {
		len = recv(ctxrawtcp->Sock, (char *)&Rx + cbRead, sizeof(Rx) - cbRead, 0);
		if (len == SOCKET_ERROR || len == 0) {
            vprintf("RAWTCP: ERROR: recv() fails\n");
			return FALSE;
		}
		cbRead += len;
	}

	if (Rx.cmd != MEM_WRITE) {
		vprintf("RAWTCP: ERROR: Memory write fail\n");
	}
	
	return cbWritten >= cb;
}

BOOL DeviceRawTCP_Open()
{
    PDEVICE_CONTEXT_RAWTCP ctx;
    CHAR _szBuffer[MAX_PATH];
    LPSTR szAddress = NULL, szPort = NULL;
#ifdef _WIN32

    WSADATA WsaData;
    WSAStartup(MAKEWORD(2, 2), &WsaData);

#endif /* _WIN32 */
    ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_RAWTCP));
    if(!ctx) { return FALSE; }
    ctxDeviceMain->hDevice = (HANDLE)ctx;
    // retrieve address and optional port from device string rawtcp://<host>[:port]
    Util_Split2(ctxDeviceMain->cfg.szDevice + 9, ':', _szBuffer, &szAddress, &szPort);
    ctx->TcpAddr = inet_addr(szAddress);
    ctx->TcpPort = atoi(szPort);
    if(!ctx->TcpAddr || (ctx->TcpAddr == (DWORD)-1)) {
        vprintf("RAWTCP: ERROR: cannot resolve IP-address: '%s'\n", szAddress);
        return FALSE;
    }
    if(!ctx->TcpPort) {
        ctx->TcpPort = RAWTCP_DEFAULT_PORT;
    }
	// open device connection
	ctx->Sock = DeviceRawTCP_Connect(ctx->TcpAddr, ctx->TcpPort);
	if (!ctx->Sock) { goto fail; }	
	if(!DeviceRawTCP_Status(ctx)) { vprintf("RAWTCP: ERROR: remote service is not ready.\n"); goto fail; }
	ctx->rxbuf.cbMax = RAWTCP_MAX_SIZE_RX;
	ctx->rxbuf.pb = LocalAlloc(0, ctx->rxbuf.cbMax);
	if (!ctx->rxbuf.pb) { goto fail; }
	ctx->txbuf.cbMax = RAWTCP_MAX_SIZE_TX;
	ctx->txbuf.pb = LocalAlloc(0, ctx->txbuf.cbMax);
	if (!ctx->txbuf.pb) { goto fail; }
	// set callback functions and fix up config
    ctxDeviceMain->cfg.tpDevice = LEECHCORE_DEVICE_RAWTCP;
    ctxDeviceMain->cfg.fVolatile = TRUE;
    ctxDeviceMain->cfg.cbMaxSizeMemIo = ctxDeviceMain->cfg.cbMaxSizeMemIo ? min(ctxDeviceMain->cfg.cbMaxSizeMemIo, RAWTCP_MAX_SIZE_RX) : RAWTCP_MAX_SIZE_RX; // RAWTCP_MAX_SIZE_RX (or lower user-value)
    ctxDeviceMain->cfg.paMaxNative = 0x0000ffffffffffff;
    ctxDeviceMain->pfnClose = DeviceRawTCP_Close;
    ctxDeviceMain->pfnReadScatterMEM = DeviceRawTCP_ReadScatterGather;
    ctxDeviceMain->pfnWriteMEM = DeviceRawTCP_WriteDMA;
    // return
    vprintfv("Device Info: Raw TCP.\n");
	return TRUE;
fail:
	DeviceRawTCP_Close();
	return FALSE;
}
