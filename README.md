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

Please find a summary of the supported software based memory acquisition methods listed below. Please note that the LeechAgent only provides a network connection to a remote LeechCore library. It's possible to use both hardware and software based memory acquisition once connected.

| Device                     | Type             | Volatile | Write | Linux Support | Plugin |
| -------------------------- | ---------------- | -------- | ----- | ------------- | ------ |
| [RAW physical memory dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)         | File             | No  | No  | Yes | No  |
| [Full Microsoft Crash Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)        | File             | No  | No  | Yes | No  |
| [Full ELF Core Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)               | File             | No  | No  | Yes | No  |
| [VMware memory save file](https://github.com/ufrisk/LeechCore/wiki/Device_File)          | File             | No  | No  | Yes | No  |
| [TotalMeltdown](https://github.com/ufrisk/LeechCore/wiki/Device_Totalmeltdown)           | CVE-2018-1038    | Yes | Yes | No  | No  |
| [DumpIt /LIVEKD](https://github.com/ufrisk/LeechCore/wiki/Device_DumpIt)                 | Live&nbsp;Memory | Yes | No  | No  | No  |
| [WinPMEM](https://github.com/ufrisk/LeechCore/wiki/Device_WinPMEM)                       | Live&nbsp;Memory | Yes | No  | No  | No  |
| [LiveKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveKd)                         | Live&nbsp;Memory | Yes | No  | No  | No  |
| [LiveCloudKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd)               | Live&nbsp;Memory | Yes | No  | No  | Yes |
| [Hyper-V Saved State](https://github.com/ufrisk/LeechCore/wiki/Device_HyperV_SavedState) | File             | No  | No  | No  | Yes |
| [LeechAgent*](https://github.com/ufrisk/LeechCore/wiki/Device_Remote)                    | Remote           |     |     | No  | No  |

### Hardware based memory aqusition methods:

Please find a summary of the supported hardware based memory acquisition methods listed below. All hardware based memory acquisition methods are supported on both Windows and Linux. The FPGA based methods however have a performance penalty on Linux and will max out at approx: 90MB/s compared to 150MB/s on Windows due to less optimized drivers.
| Device                                                                 | Type | Interface | Speed | 64-bit memory access | PCIe TLP access | Plugin |
| -----------------------------------------------------------------------| ---- | --------- | ----- | -------------------- | --------------- | ------ |
| [AC701/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)    | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/ac701_ft601) | USB3 | 150MB/s | Yes | Yes | No  |
| [ScreamerM2](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)     | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/ScreamerM2)  | USB3 | 150MB/s | Yes | Yes | No  |
| [PCIeScreamer](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)   | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/pciescreamer)| USB3 | 100MB/s | Yes | Yes | No  |
| [SP605/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)    | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/sp605_ft601) | USB3 |  75MB/s | Yes | Yes | No  |
| [NeTV2/UDP](https://github.com/ufrisk/LeechCore/wiki/Device_RawUDP)    | [FPGA](https://github.com/ufrisk/pcileech-fpga/tree/master/NeTV2)       | UDP  |   7MB/s | Yes | Yes | No  |
| [USB3380-EVB](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380) | USB3380 | USB3 | 150MB/s | No  | No  | No  |
| [PP3380](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380)      | USB3380 | USB3 | 150MB/s | No  | No  | No  |
| [SP605/TCP](https://github.com/ufrisk/LeechCore/wiki/Device_SP605TCP)  | FPGA    | TCP  | 100kB/s | Yes | Yes | Yes |
| [DMA patched HP iLO](https://github.com/ufrisk/LeechCore/wiki/Device_RawTCP) | BMC | TCP |  1MB/s | Yes | No  | Yes |

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

Support PCILeech/MemProcFS development:
=======================================
PCILeech and MemProcFS are hobby projects of mine. I put a lot of time and energy into my projects. The time being most of my spare time - since I'm not able to work with this. Unfortunately since some aspects also relate to hardware I also put quite some of money into my projects. If you think PCILeech and/or MemProcFS are awesome tools and/or if you had a use for them it's now possible to contribute.

Please do note that PCILeech and MemProcFS are free and open source - as such I'm not expecting donations; even though a donation would be very much appreciated. I'm also not able to promise product features, consultancy or other things in return for a donation. A donation will have to stay donation and no more.  I'll set up the Github sponsors as soon as I'm able to; but for now it's possible to contribute with:

 - Paypal: `paypal@ulffrisk.com` 
 - Bitcoin: `bc1q9kur5pym8wmh5yxkf65792rdqm0guncd2gl4tu`

Links:
======
* Twitter: [![Twitter](https://img.shields.io/twitter/follow/UlfFrisk?label=UlfFrisk&style=social)](https://twitter.com/intent/follow?screen_name=UlfFrisk)
* Discord: [![Discord | Porchetta Industries](https://img.shields.io/discord/736724457258745996.svg?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/sEkn3aa)
* PCILeech: https://github.com/ufrisk/pcileech
* PCILeech FPGA: https://github.com/ufrisk/pcileech-fpga
* LeechCore: https://github.com/ufrisk/LeechCore
* MemProcFS: https://github.com/ufrisk/MemProcFS
* YouTube: https://www.youtube.com/channel/UC2aAi-gjqvKiC7s7Opzv9rg
* Blog: http://blog.frizk.net

Support PCILeech/MemProcFS development:
=======================================
PCILeech and MemProcFS are hobby projects of mine. I put a lot of time and energy into my projects. The time being most of my spare time - since I'm not able to work with this. Unfortunately since some aspects also relate to hardware I also put quite some of money into my projects. If you think PCILeech and/or MemProcFS are awesome tools and/or if you had a use for them it's now possible to contribute.

Please do note that PCILeech and MemProcFS are free and open source - as such I'm not expecting sponsorships; even though a sponsorship would be very much appreciated. I'm also not able to promise product features, consultancy or other things in return for a donation. A sponsorship will have to stay a sponsorship and no more. It's possible to sponsor via Github Sponsors.

 - Github Sponsors: [`https://github.com/sponsors/ufrisk`](https://github.com/sponsors/ufrisk)

Changelog:
===================
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
