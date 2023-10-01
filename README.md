The LeechCore Physical Memory Acquisition Library:
=========================================
The LeechCore Memory Acquisition Library focuses on Physical Memory Acquisition using various hardware and software based methods.

LeechCore provides API-based access to various hardware and software based memory sources via its `C/C++`, `Python` and `C#` APIs. Download the latest [release](https://github.com/ufrisk/LeechCore/releases/latest) of the library here on Github. If using Python it's recommended to install the [`leechcorepyc`](https://pypi.org/project/leechcorepyc/) **python pip** package which is available for 64-bit Linux and Windows.

Use the LeechCore library locally or connect to, over the network, a LeechAgent to acquire physical memory or run commands remotely. The connection is by default compressed and secured with mutually authenticated kerberos - making it ideal in incident response when combined with analysis and live memory capture using Comae DumpIt or WinPMEM - even over high latency low-bandwidth connections!

The LeechCore library is used by [PCILeech](https://github.com/ufrisk/pcileech) and [The Memory Process File System (MemProcFS)](https://github.com/ufrisk/MemProcFS).

The LeechCore library is supported on 32/64-bit **Windows** (`.dll`) and 64-bit **Linux** (`.so`). No executable exists for LeechCore - the library is always loaded by other applications using it - such as PCILeech and The Memory Process File System `MemProcFS.exe`.

For detailed information about individual memory acquisition methods, the API and related examples please check out the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki).


Memory Acquisition Methods:
===========================
### Software based memory aqusition methods:

Please find a summary of the supported software based memory acquisition methods listed below. Please note that the LeechAgent only provides a network connection to a remote LeechCore library. It's possible to use both hardware and software based memory acquisition once connected.

| Device                     | Type             | Volatile | Write | Linux Support | Plugin |
| ---------------------------------------------------------------------------------------- | ---------------- | -------- | ----- | ------------- | ------ |
| [RAW physical memory dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)         | File             | No  | No  | Yes | No  |
| [Full Microsoft Crash Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)        | File             | No  | No  | Yes | No  |
| [Full ELF Core Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)               | File             | No  | No  | Yes | No  |
| [QEMU](https://github.com/ufrisk/LeechCore/wiki/Device_QEMU)                             | Live&nbsp;Memory | Yes | Yes | No  | No  |
| [VMware](https://github.com/ufrisk/LeechCore/wiki/Device_VMWare)                         | Live&nbsp;Memory | Yes | Yes | No  | No  |
| [VMware memory save file](https://github.com/ufrisk/LeechCore/wiki/Device_File)          | File             | No  | No  | Yes | No  |
| [TotalMeltdown](https://github.com/ufrisk/LeechCore/wiki/Device_Totalmeltdown)           | CVE-2018-1038    | Yes | Yes | No  | No  |
| [DumpIt /LIVEKD](https://github.com/ufrisk/LeechCore/wiki/Device_DumpIt)                 | Live&nbsp;Memory | Yes | No  | No  | No  |
| [WinPMEM](https://github.com/ufrisk/LeechCore/wiki/Device_WinPMEM)                       | Live&nbsp;Memory | Yes | No  | No  | No  |
| [LiveKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveKd)                         | Live&nbsp;Memory | Yes | No  | No  | No  |
| [LiveCloudKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd)               | Live&nbsp;Memory | Yes | Yes | No  | Yes |
| [libmicrovmi](https://github.com/ufrisk/LeechCore-plugins#leechcore_device_microvmi)     | Live&nbsp;Memory | Yes | Yes | Yes | Yes |
| [Hyper-V Saved State](https://github.com/ufrisk/LeechCore/wiki/Device_HyperV_SavedState) | File             | No  | No  | No  | Yes |
| [LeechAgent*](https://github.com/ufrisk/LeechCore/wiki/Device_Remote)                    | Remote           |     |     | No  | No  |

### Hardware based memory aqusition methods:

Please find a summary of the supported hardware based memory acquisition methods listed below. All hardware based memory acquisition methods are supported on both Windows and Linux. The FPGA based methods however have a performance penalty on Linux and will max out at approx: 90MB/s compared to 150MB/s on Windows due to less optimized drivers.
| Device                                                                         | Type | Interface | Speed | 64-bit memory access | PCIe TLP access | Plugin | Project<br>Sponsor |
| -------------------------------------------------------------------------------| ---- | --------- | ----- | -------------------- | --------------- | ------ | ------------------ |
| [Screamer PCIe Squirrel](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA) | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/PCIeSquirrel) | USB-C | 190MB/s | Yes | Yes | No  | 💖 |
| [LeetDMA](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)                | [FPGA](https://github.com/ufrisk/pcileech-fpga)                          | USB-C | 190MB/s | Yes | Yes | No  | 💖 |
| [Enigma X1](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)              | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/EnigmaX1)     | USB-C | 200MB/s | Yes | Yes | No  | 💖 |
| [PCIeScreamerR04](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)        | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/ScreamerM2)   | USB-C | 190MB/s | Yes | Yes | No  | 💖 |
| [ScreamerM2](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)             | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/ScreamerM2)   | USB3  | 190MB/s | Yes | Yes | No  | 💖 |
| [AC701/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)            | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/ac701_ft601)  | USB3  | 190MB/s | Yes | Yes | No  |    |
| [PCIeScreamer](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)           | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/pciescreamer) | USB3  | 100MB/s | Yes | Yes | No  |    |
| [SP605/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)            | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/sp605_ft601)  | USB3  |  75MB/s | Yes | Yes | No  |    |
| [Acorn/FT2232H](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)          | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/acorn_ft2232h)| USB2  |  25MB/s | Yes | Yes | No  |    |
| [NeTV2/UDP](https://github.com/ufrisk/LeechCore/wiki/Device_RawUDP)            | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/NeTV2)        | UDP   |   7MB/s | Yes | Yes | No  |    |
| [USB3380-EVB](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380)         | USB3380 | USB3 | 150MB/s | No  | No  | No  |    |
| [PP3380](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380)              | USB3380 | USB3 | 150MB/s | No  | No  | No  |    |
| [DMA patched HP iLO](https://github.com/ufrisk/LeechCore/wiki/Device_RawTCP)   | BMC     | TCP  |   1MB/s | Yes | No  | Yes |    |


The LeechAgent Memory Acquisition and Analysis Agent:
=====================================================
The LeechAgent Memory Acquisition and Analysis Agent exists for Windows only. It allows users of the LeechCore library (PCILeech and MemProcFS) to connect to remotely installed LeechAgents over the network. The connection is secured, by default, with mutually authenticated encrypted kerberos.

Once connected physical memory may be acquired over the secure compressed connection. Memory analysis scripts, written in Python, may also be submitted for remote processing by the LeechAgent.

The LeechAgent authenticates all incoming connections against membership in the Local Administrators group. The clients must also authenticate the agent itself against the SPN used by the agent - please check the Application Event Log for information about the SPN and also successful authentication events against the agent.

There is also a possibility to run the LeechAgent in interactive mode (as a normal program). If run in interactive mode a user may also start the LeechAgent in "insecure" mode - which means no authentication or logging at all.

The LeechAgent listens on the port `tcp/28473` - please ensure network connectivity for this port in the firewall. Also, if doing live capture ensure that LeechAgent (if running in interactive mode) is started as an administrator.

For more information please check the [LeechCore wiki](https://github.com/ufrisk/LeechCore/wiki) and the [blog entry](http://blog.frizk.net/2019/04/LeechAgent.html) about remote live memory capture with the LeechAgent.

The videos below shows the process of installing the LeechAgent to a remote computer, connecting to it with MemProcFS to analyze and dump the memory while also connecting to it in parallel with PCILecch to submit a Python memory analysis script that make use of the MemProcFS API to analyze the remote CPU page tables for rwx-sections. Click on the video to open a higher-quality version on Youtube.
<p align="center"><a href="https://www.youtube.com/watch?v=UIsNWJ5KTvQ" alt="Installing the LeechAgent, Dumping remote memory and running remote Python analysis scripts." target="_new"><img src="https://raw.githubusercontent.com/wiki/ufrisk/LeechCore/resources/agent-anim.gif"/></a>&nbsp;&nbsp;<a href="https://www.youtube.com/watch?v=Mij6LY1z4SY" alt="Demo: Remote memory analysis with MemProcFS and PCILeech" target="_new"><img src="http://img.youtube.com/vi/Mij6LY1z4SY/0.jpg" height="285"/></a></p>

**Examples:**

Installing the LeechAgent on the local system (run as elevated administrator)'. Please ensure that the LeechAgent.exe is on the local C: drive before installing the agent service. Please also ensure that dependencies such as required `.dll` and/or `.sys` files (and optional Python sub-subfolder) are put in the same directory as the LeechAgent before running the install command.
* `LeechAgent.exe -install`

Installing the LeechAgent on a remote system (or on the local system) in the `Program Files\LeechAgent` folder. An Actice Directory environment with remote access to the Service Manager of the target system is required. For additional information see the [wiki entry](https://github.com/ufrisk/LeechCore/wiki/LeechAgent_Install) about installing LeechAgent.
* `LeechAgent.exe -remoteinstall <remotecomputer.contoso.com>`

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

Start the LeechAgent in interactive mode with DumpIt LIVEKD to allow connecting clients to access live memory. Start as elevated administrator. Accept connections from all clients with access to port `tcp/28473` without any form of authentication.
* `DumpIt.exe /LIVEKD /A LeechAgent.exe /C "-interactive -insecure"`


Building:
=========
<b>Pre-built [binaries, modules and configuration files](https://github.com/ufrisk/LeechCore/releases/latest) are found in the latest release.</b> Build instructions are found in the [Wiki](https://github.com/ufrisk/LeechCore/wiki) in the [Building](https://github.com/ufrisk/LeechCore/wiki/Dev_Building) section.


Contributing:
=============
PCILeech, MemProcFS and LeechCore are open source but not open contribution. PCILeech, MemProcFS and LeechCore offers a highly flexible plugin architecture that will allow for contributions in the form of plugins. If you wish to make a contribution, other than a plugin, to the core projects please contact me before starting to develop.


Links:
======
* Twitter: [![Twitter](https://img.shields.io/twitter/follow/UlfFrisk?label=UlfFrisk&style=social)](https://twitter.com/intent/follow?screen_name=UlfFrisk)
* Discord: [![Discord | PCILeech/MemProcFS](https://img.shields.io/discord/1155439643395883128.svg?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/BCmfBhDPXX)
* PCILeech: https://github.com/ufrisk/pcileech
* PCILeech FPGA: https://github.com/ufrisk/pcileech-fpga
* LeechCore: https://github.com/ufrisk/LeechCore
* MemProcFS: https://github.com/ufrisk/MemProcFS
* YouTube: https://www.youtube.com/channel/UC2aAi-gjqvKiC7s7Opzv9rg
* Blog: http://blog.frizk.net


Support PCILeech/MemProcFS development:
=======================================
PCILeech and MemProcFS is free and open source!

I put a lot of time and energy into PCILeech and MemProcFS and related research to make this happen. Some aspects of the projects relate to hardware and I put quite some money into my projects and related research. If you think PCILeech and/or MemProcFS are awesome tools and/or if you had a use for them it's now possible to contribute by becoming a sponsor! 
 
If you like what I've created with PCIleech and MemProcFS with regards to DMA, Memory Analysis and Memory Forensics and would like to give something back to support future development please consider becoming a sponsor at: [`https://github.com/sponsors/ufrisk`](https://github.com/sponsors/ufrisk)

To all my sponsors, Thank You 💖 

All sponsorships are welcome, no matter how large or small. I especially wish to thank my **bronze sponsors**: [grandprixgp](https://github.com/grandprixgp).


Changelog:
===================
<details><summary>Previous releases (click to expand):</summary>
v1.0-1.8
* Initial Release and various updates. Please see individual relases for more information.

[v2.0](https://github.com/ufrisk/LeechCore/releases/tag/v2.0)
* API: New handle based API to support multiple concurrent open devices.<br>
  NB! API contains breaking changes compared to v1.x API versions.
* FPGA related performance improvements and bug fixes.
* New features:
  - AMD support.
  - User-settable physical memory map.
  - External device plugins - see the [LeechCore-plugin](https://github.com/ufrisk/LeechCore-plugins) project for details.
  - Sysinternals LiveKd Hyper-V VM-introspection (slow).

[v2.1](https://github.com/ufrisk/LeechCore/releases/tag/v2.1)
* Bug fixes.
* Support for [LiveCloudKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd).

[v2.2](https://github.com/ufrisk/LeechCore/releases/tag/v2.2)
* Bug fixes.
* Minor API additions.

[v2.3](https://github.com/ufrisk/LeechCore/releases/tag/v2.3)
* FPGA: R/W "shadow" config space (requires v4.9+ bitstream).
* LeechAgent: Full multi-device support.

[v2.4](https://github.com/ufrisk/LeechCore/releases/tag/v2.4)
* Bug fixes.
* Remake of Python package `leechcorepyc` now also available on [pip](https://pypi.org/project/leechcorepyc/).

[v2.5](https://github.com/ufrisk/LeechCore/releases/tag/v2.5)
* Bug fixes.
* Read/Write PCI Express Transaction Layer Packets, PCIe TLPs, FPGA devices only.

[v2.6](https://github.com/ufrisk/LeechCore/releases/tag/v2.6)
* Bug fixes.
* Updates to support MemProcFS v4.
* Separate releases for Windows and Linux.

[v2.7](https://github.com/ufrisk/LeechCore/releases/tag/v2.7)
* Bug fixes.
* Remote LeechAgent support for MemProcFS.
* VMWare live memory VM introspection (Windows host only).

[v2.8](https://github.com/ufrisk/LeechCore/releases/tag/v2.8)
* Bug fixes.
* 32-bit support.
* Support for Active Memory and Full Bitmap Microsoft Crash Dump files.

[v2.9](https://github.com/ufrisk/LeechCore/releases/tag/v2.9)
* Support for the FT2232H USB2 chip.

[v2.10](https://github.com/ufrisk/LeechCore/releases/tag/v2.10)
* Support for [Enigma X1](https://github.com/ufrisk/pcileech-fpga/tree/master/EnigmaX1) hardware.
* [Plugin support](https://github.com/ufrisk/LeechCore-plugins/blob/master/README.md#leechcore_device_microvmi) for [libmicrovmi](https://github.com/Wenzel/libmicrovmi):
  - Support for Xen, KVM, VirtualBox, QEMU on Linux.
  - Pre-bundled on Linux x64 (libmicrovmi)
  - Thank you [Wenzel](https://github.com/Wenzel/) for this contribution.

[v2.11](https://github.com/ufrisk/LeechCore/releases/tag/v2.11)
* Bug fixes.
* Visual Studio 2022 Support.
* New write fpga algorithm.
</details>

[v2.12](https://github.com/ufrisk/LeechCore/releases/tag/v2.12)
* Support for MemProcFS v5.

[v2.13](https://github.com/ufrisk/LeechCore/releases/tag/v2.13)
* FPGA performance improvements.
* ARM64 Windows support.

[v2.14](https://github.com/ufrisk/LeechCore/releases/tag/v2.14)
* VMM loopback device.

[v2.15](https://github.com/ufrisk/LeechCore/releases/tag/v2.15)
* Multi-threaded file access.
* Volatile memory file support.
* Support for LiME memory dump files.
* Improved FPGA performance for smaller reads.
* QEMU support on Linux (VM live memory introspection).
* Improved [MemProcFS remoting](https://github.com/ufrisk/MemProcFS/wiki/_Remoting) via a remote [LeechAgent](https://github.com/ufrisk/LeechCore/wiki/LeechAgent). Full MemProcFS remote support over SMB - tcp/445. Perfect for memory forensics Incident Response (IR)!

[v2.16](https://github.com/ufrisk/LeechCore/releases/tag/v2.16)
* PCIe BAR information and user callback (easier implementation of custom devices).
* ARM64 memory dump (.dmp) and VMWare Fusion (.vmem/.vmsn) support.
* Improved handling of PCIe TLP user callback.

Latest:
* Bug fixes.
* I/O BAR support.
* Linux PCIe FPGA performance improvements.
* Linux PCIe FPGA multiple devices (devindex) supported.
