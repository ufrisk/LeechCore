The LeechCore Physical Memory Acquisition Library:
=========================================
The LeechCore Memory Acquisition Library focuses on Physical Memory Acquisition using various hardware and software based methods.

Connect to a remote LeechCore instance hosted by a LeechService to acquire physical memory remotely. The connection is by default compressed and secured with mutually authenticated kerberos - making it ideal in incident response when combined with live memory capture using Comae DumpIt or WinPMEM - even over medium latency low-bandwidth connections!

The LeechCore library is used for memory acquisition by [The Memory Process File System](https://github.com/ufrisk/MemProcFS).

The LeechCore library is supported on both **Windows** (`.dll`) and **Linux** (`.so`). No executable exists for LeechCore - the library is always loaded by other applications using it - such as The Memory Process File System `MemProcFS.exe` or the LeechService `LeechSvc.exe`.

For detailed information about individual memory acquisition methods or the LeechCore API please check out the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki).

Memory Acquisition Methods:
===========================
**Software based memory aqusition methods:**

Please find a summary of the supported software based memory acquisition methods listed below. Please note that the LeechService only provides a network connection to a remote LeechCore library. It's possible to use both hardware and software based memory acquisition once connected.

| Device                     | Type             | Linux Support |
| -------------------------- | ---------------- | ------------- |
| [RAW physical memory dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)         | File             | Yes |
| [Full Microsoft Crash Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)        | File             | Yes |
| [Hyper-V Saved State](https://github.com/ufrisk/LeechCore/wiki/Device_HyperV_SavedState) | File             | No  |
| [TotalMeltdown](https://github.com/ufrisk/LeechCore/wiki/Device_Totalmeltdown)           | CVE-2018-1038    | No  |
| [DumpIt /LIVEKD](https://github.com/ufrisk/LeechCore/wiki/Device_DumpIt)                 | Live&nbsp;Memory | No  |
| [WinPMEM](https://github.com/ufrisk/LeechCore/wiki/Device_WinPMEM)                       | Live&nbsp;Memory | No  |
| [LeechService*](https://github.com/ufrisk/LeechCore/wiki/Device_Remote)                  | Remote           | No  |

**Hardware based memory aqusition methods:**

Please find a summary of the supported hardware based memory acquisition methods listed below. All hardware based memory acquisition methods are supported on both Windows and Linux. The FPGA based methods however sports a slight performance penalty on Linux and will max out at approx: 90MB/s compared to 150MB/s on Windows.

| Device                                    | Type | Interface | Speed | 64-bit memory access | PCIe TLP access |
| ------------------------------------------------------------ | ------- | ---- | ------- | ----------------- | --- |
| [AC701/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)    | FPGA    | USB3 | 150MB/s | Yes | Yes |
| [PCIeScreamer](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)   | FPGA    | USB3 | 100MB/s | Yes | Yes |
| [SP605/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)    | FPGA    | USB3 |  75MB/s | Yes | Yes |
| [SP605/TCP](https://github.com/ufrisk/LeechCore/wiki/Device_SP605TCP)  | FPGA  | TCP/IP | 100kB/s | Yes | Yes |
| [USB3380-EVB](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380) | USB3380 | USB3 | 150MB/s | No  | No  |
| [PP3380](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380)      | USB3380 | USB3 | 150MB/s | No  | No  |
| [DMA patched HP iLO](https://github.com/ufrisk/LeechCore/wiki/Device_iLO) | TCP/IP | TCP | 1MB/s  | Yes | No  |

The LeechService Memory Acquisition Service:
============================================
The LeechService Memory Acquisition Service exists for Windows only. It allows users of the LeechCore library to connect to a remote instance of the LeechCore library (loaded by the LeechService). The connection takes place by default over mutually authenticated encrypted kerberos (if in service mode in an active directory domain).

If running as a service LeechService authenticates all incoming connections against membership in the Local Administrators group. The clients must also authenticate the service itself against the SPN used by the service - please check the Application Event Log for information about the SPN and also successful authentication events against the service.

There is also a possibility to run the LeechService in interactive mode (as a normal program). If run in interactive mode a user may also start the LeechService in "insecure" mode - which means no authentication or logging at all.

The LeechService listens on the port `28473` - please ensure network connectivity for this port in the firewall. Also, if doing live capture ensure that LeechService (if running in interactive mode) is started as an administrator.

For more information please check the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki) and the [blog entry](https://blog.frizk.net/2019/01/remote-live-memory-analysis.html) about remote live memory capture.

**Examples:**

Installing the LeechService (run as elevated administrator)'. Please ensure that the LeechSvc.exe is on the local C: drive before installing the service. Please also ensure that dependencies such as required `.dll` and/or `.sys` files are put in the same directory as the service before running the install command.
* `LeechSvc.exe install`

Uninstall an existing LeechService:
* `LeechSvc.exe uninstall`

Start the LeechService in interactive mode only accepting connections from administative users over kerberos-secured connections. Remember to start as elevated administrator if clients accessing LeechSvc should load WinPMEM to access live memory.
* `LeechSvc.exe interactive`

Start the LeechService in interactive mode with DumpIt LIVEKD to allow connecting clients to access live memory. Start as elevated administrator. Only accept connections from administative users over kerberos-secured connections. 
* `DumpIt.exe /LIVEKD /A LeechSvc.exe /C interactive`

Start the LeevhService in interactive mode with DumpIt LIVEKD to allow connecting clients to access live memory. Start as elevated administrator. Accept connections from all clients with access to port `tcp/28473` without any form of authentication.
* `DumpIt.exe /LIVEKD /A LeechSvc.exe /C "interactive insecure"`



Links:
======
* Blog: http://blog.frizk.net
* Twitter: https://twitter.com/UlfFrisk
* PCILeech: https://github.com/ufrisk/pcileech/
* The Memory Process File System: https://github.com/ufrisk/MemProcFS/

Changelog:
===================
v1.0
* Initial Release.
