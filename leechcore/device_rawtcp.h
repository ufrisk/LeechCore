// Contribution by Synacktiv - www.synacktiv.com
// https://www.synacktiv.com/posts/exploit/using-your-bmc-as-a-dma-device-plugging-pcileech-to-hpe-ilo-4.html
//
//
// devicerawtcp.h : implementation related to dummy device backed by a TCP service.
//

#ifndef __DEVICE_RAWTCP_H__
#define __DEVICE_RAWTCP_H__
#include "leechcore.h"

BOOL DeviceRawTCP_Open();

typedef enum tdRawTCPCmd {
	STATUS,
	MEM_READ,
	MEM_WRITE
} RawTCPCmd;

#endif /* __DEVICE_RAWTCP_H__ */
