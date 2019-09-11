The LeechCore Physical Memory Acquisition Library:
=========================================
The LeechCore Memory Acquisition Library focuses on Physical Memory Acquisition using various hardware and software based methods.

Use the LeechCore library locally or connect to, over the network, a LeechAgent to acquire physical memory or run commands remotely. The connection is by default compressed and secured with mutually authenticated kerberos - making it ideal in incident response when combined with analysis and live memory capture using Comae DumpIt or WinPMEM - even over high latency low-bandwidth connections!

The LeechCore library is used by [PCILeech](https://github.com/ufrisk/pcileech) and [The Memory Process File System (MemProcFS)](https://github.com/ufrisk/MemProcFS).

The LeechCore library is supported on 32/64-bit **Windows** (`.dll`) and 64-bit **Linux** (`.so`). No executable exists for LeechCore - the library is always loaded by other applications using it - such as PCILeech and The Memory Process File System `MemProcFS.exe`.

For detailed information about individual memory acquisition methods or the LeechCore API please check out the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki).

Memory Acquisition Methods:
===========================
### Software based memory aqusition methods:

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

### Hardware based memory aqusition methods:

Please find a summary of the supported hardware based memory acquisition methods listed below. All hardware based memory acquisition methods are supported on both Windows and Linux. The FPGA based methods however sports a slight performance penalty on Linux and will max out at approx: 90MB/s compared to 150MB/s on Windows.

| Device                                    | Type | Interface | Speed | 64-bit memory access | PCIe TLP access |
| ---------------------------------------------------------------------- | ------- | ---- | ------- | --- | --- |
| [AC701/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)    | FPGA    | USB3 | 150MB/s | Yes | Yes |
| [PCIeScreamer](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)   | FPGA    | USB3 | 100MB/s | Yes | Yes |
| [SP605/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)    | FPGA    | USB3 |  75MB/s | Yes | Yes |
| [SP605/TCP](https://github.com/ufrisk/LeechCore/wiki/Device_SP605TCP)  | FPGA  | TCP/IP | 100kB/s | Yes | Yes |
| [USB3380-EVB](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380) | USB3380 | USB3 | 150MB/s | No  | No  |
| [PP3380](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380)      | USB3380 | USB3 | 150MB/s | No  | No  |
| [DMA patched HP iLO](https://github.com/ufrisk/LeechCore/wiki/Device_iLO) | TCP/IP | TCP | 1MB/s  | Yes | No  |

The LeechAgent Memory Acquisition and Analysis Agent:
=====================================================
The LeechAgent Memory Acquisition and Analysis Agent exists for Windows only. It allows users of the LeechCore library (PCILeech and MemProcFS) to connect to remotely installed LeechAgents over the network. The connection is secured, by default, with mutually authenticated encrypted kerberos.

Once connected physical memory may be acquired over the secure compressed connection. Memory analysis scripts, written in Python, may also be submitted for remote processing by the LeechAgent.

The LeechAgent authenticates all incoming connections against membership in the Local Administrators group. The clients must also authenticate the agent itself against the SPN used by the agent - please check the Application Event Log for information about the SPN and also successful authentication events against the agent.

There is also a possibility to run the LeechAgent in interactive mode (as a normal program). If run in interactive mode a user may also start the LeechAgent in "insecure" mode - which means no authentication or logging at all.

The LeechAgent listens on the port `tcp/28473` - please ensure network connectivity for this port in the firewall. Also, if doing live capture ensure that LeechAgent (if running in interactive mode) is started as an administrator.

For more information please check the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki) and the [blog entry](http://blog.frizk.net/2019/04/LeechAgent.html) about remote live memory capture with the LeechAgent.

The video below shows the process of installing the LeechAgent to a remote computer, connecting to it with MemProcFS to analyze and dump the memory while also connecting to it in parallel with PCILecch to submit a Python memory analysis script that make use of the MemProcFS API to analyze the remote CPU page tables for rwx-sections. Click on the video to open a higher-quality version on Youtube.
<p align="center"><a href="https://www.youtube.com/watch?v=UIsNWJ5KTvQ" alt="Installing the LeechAgent, Dumping remote memory and running remote Python analysis scripts." target="_new"><img src="https://raw.githubusercontent.com/wiki/ufrisk/LeechCore/resources/agent-anim.gif"/></a></p>

**Examples:**

Installing the LeechAgent on the local system (run as elevated administrator)'. Please ensure that the LeechAgent.exe is on the local C: drive before installing the agent service. Please also ensure that dependencies such as required `.dll` and/or `.sys` files (and optional Python sub-subfolder) are put in the same directory as the LeechAgent before running the install command.
* `LeechAgent.exe -install`

Installing the LeechAgent on a remote system (or on the local system) in the `Program Files\LeechAgent` folder. An Actice Directory environment with remote access to the Service Manager of the target system is required. For additional information see the [wiki entry](https://github.com/ufrisk/LeechCore/wiki/LeechAgent_Install) about installing LeechAgent.
* `LeechSvc.exe -remoteinstall <remotecomputer.contoso.com>`

Uninstall an existing, locally installed, LeechAgent. The agent service will be uninstalled but any files will remain.
* `LeechAgent.exe -uninstall`

Uninstall a LeechAgent from a remote system and delete the `Program Files\LeechAgent` folder.
* `LeechAgent.exe -remoteuninstall <remotecomputer.contoso.com>`

Start the LeechAgent in interactive mode only accepting connections from administative users over kerberos-secured connections. Remember to start as elevated administrator if clients accessing LeechAgent should load WinPMEM to access live memory.
* `LeechAgent.exe -interactive`

Start the LeechAgent in interactive insecure mode - accepting connections from all clients with access to port `tcp/28473`. NB! unauthenticated clients may dump memory and submit Python scripts running as SYSTEM. Use with care for testing only!
* `LeechAgent.exe -interactive -insecure`

Start the LeechAgent in interactive mode with DumpIt LIVEKD to allow connecting clients to access live memory. Start as elevated administrator. Only accept connections from administative users over kerberos-secured connections. 
* `DumpIt.exe /LIVEKD /A LeechAgent.exe /C -interactive`

Start the LeevhAgent in interactive mode with DumpIt LIVEKD to allow connecting clients to access live memory. Start as elevated administrator. Accept connections from all clients with access to port `tcp/28473` without any form of authentication.
* `DumpIt.exe /LIVEKD /A LeechAgent.exe /C "-interactive -insecure"`

Building:
=========
Pre-built binaries are found together with other supporting files in the files folder. Build instructions are found in the [Wiki](https://github.com/ufrisk/LeechCore/wiki) in the [Building](https://github.com/ufrisk/LeechCore/wiki/Dev_Building) section.

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

v1.1
* Multiple bug fixes including pmem device.
* LeechService: Multiple parallel connections and connection timeouts supported.

v1.2
* Project upgrade to Visual Studio 2019.
* Release of the LeechAgent - remote memory acquisition and remote physical memory analysis.
* LeechCore Windows x86 support. Now Windows x86/x64 and Linux x64 is supported.
* Bug fixes and additional functionality to support LeechAgent.

v1.3
* Bug fixes.
* Use libusb for FPGA USB access. Contribution by: [Jérémie Boutoille / Synacktiv](https://github.com/tlk-synacktiv).
