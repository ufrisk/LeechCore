// oscompatibility.h : LeechCore Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2017-2024
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OSCOMPATIBILITY_H__
#define __OSCOMPATIBILITY_H__
#include "leechcore.h"

#ifdef _WIN32

#include <Windows.h>
#include <stdio.h>
#include <winusb.h>
#include <setupapi.h>
#include <conio.h>

#define SOCK_NONBLOCK                       0

#pragma warning( disable : 4477)

#define LC_LIBRARY_FILETYPE                 ".dll"
#define LINUX_NO_OPTIMIZE
VOID usleep(_In_ DWORD us);

#endif /* _WIN32 */
#ifdef LINUX
#include <byteswap.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LC_LIBRARY_FILETYPE                 ".so"

typedef void                                VOID, *PVOID;
typedef void                                *HANDLE, **PHANDLE, *HMODULE, *FARPROC;
typedef uint32_t                            BOOL, *PBOOL;
typedef uint8_t                             BYTE, *PBYTE;
typedef uint8_t                             UCHAR, *PUCHAR;
typedef char                                CHAR, *PCHAR, *PSTR, *LPSTR;
typedef const char                          *LPCSTR;
typedef uint16_t                            WORD, *PWORD, USHORT, *PUSHORT;
typedef uint16_t                            WCHAR, *PWCHAR, *LPWSTR;
typedef const uint16_t                      *LPCWSTR;
typedef uint32_t                            DWORD, *PDWORD, ULONG, *PULONG;
typedef long long unsigned int              QWORD, *PQWORD, ULONG64, *PULONG64;
typedef uint64_t                            LARGE_INTEGER, *PLARGE_INTEGER, FILETIME;
typedef size_t                              SIZE_T, *PSIZE_T;
typedef void                                *OVERLAPPED, *LPOVERLAPPED;
typedef struct tdEXCEPTION_RECORD32         { CHAR sz[80]; } EXCEPTION_RECORD32;
typedef struct tdEXCEPTION_RECORD64         { CHAR sz[152]; } EXCEPTION_RECORD64;
#define TRUE                                1
#define FALSE                               0
#define MAX_PATH                            260
#define LMEM_ZEROINIT                       0x0040
#define INVALID_HANDLE_VALUE                ((HANDLE)-1)
#define STD_INPUT_HANDLE                    ((DWORD)-10)
#define STD_OUTPUT_HANDLE                   ((DWORD)-11)
#define GENERIC_WRITE                       (0x40000000L)
#define GENERIC_READ                        (0x80000000L)
#define FILE_SHARE_READ                     (0x00000001L)
#define CREATE_NEW                          (0x00000001L)
#define OPEN_EXISTING                       (0x00000003L)
#define FILE_ATTRIBUTE_NORMAL               (0x00000080L)
#define STILL_ACTIVE                        (0x00000103L)
#define CRYPT_STRING_HEX_ANY                (0x00000008L)
#define CRYPT_STRING_HEXASCIIADDR           (0x00000008L)
#define STILL_ACTIVE                        (0x00000103L)
#define INVALID_FILE_SIZE                   (0xffffffffL)
#define _TRUNCATE                           ((SIZE_T)-1LL)
#define LPTHREAD_START_ROUTINE              PVOID
#define WINUSB_INTERFACE_HANDLE             libusb_device_handle*
#define PIPE_TRANSFER_TIMEOUT               0x03
#define CONSOLE_SCREEN_BUFFER_INFO          PVOID    // TODO: remove this dummy
#define SOCKET                              int
#define INVALID_SOCKET	                    -1
#define SOCKET_ERROR	                    -1
#define WSAEWOULDBLOCK                      10035L
#define WAIT_OBJECT_0                       (0x00000000UL)
#define INFINITE                            (0xFFFFFFFFUL)
#define MAXIMUM_WAIT_OBJECTS                64

#define _In_
#define _In_z_
#define _Out_
#define _Inout_
#define _Inout_opt_
#define _In_opt_
#define _Out_opt_
#define _Check_return_opt_
#define _Frees_ptr_opt_
#define _Post_ptr_invalid_
#define _Printf_format_string_
#define _In_reads_(x)
#define _In_reads_opt_(x)
#define _Out_writes_(x)
#define __bcount(x)
#define _Inout_bytecount_(x)
#define _Inout_updates_opt_(x)
#define _Inout_updates_bytes_(x)
#define _Out_writes_opt_(x)
#define _Success_(x)
#define UNREFERENCED_PARAMETER(x)

#define max(a, b)                           (((a) > (b)) ? (a) : (b))
#define min(a, b)                           (((a) < (b)) ? (a) : (b))
#define _byteswap_ushort(v)                 (bswap_16(v))
#define _byteswap_ulong(v)                  (bswap_32(v))
#define _byteswap_uint64(v)                 (bswap_64(v))
#define _countof(_Array)                    (sizeof(_Array) / sizeof(_Array[0]))
#define sprintf_s(s, maxcount, ...)         (snprintf(s, maxcount, __VA_ARGS__))
#define strnlen_s(s, maxcount)              (strnlen(s, maxcount))
#define strcpy_s(dst, len, src)             (strncpy(dst, src, len))
#define strncpy_s(dst, len, src, srclen)    (strncpy(dst, src, min((QWORD)(max(1, len)) - 1, (QWORD)(srclen))))
#define strncat_s(dst, dstlen, src, srclen) (strncat(dst, src, min((((strlen(dst) + 1 >= (QWORD)(dstlen)) || ((QWORD)(dstlen) == 0)) ? 0 : ((QWORD)(dstlen) - strlen(dst) - 1)), (QWORD)(srclen))))
#define strcat_s(dst, dstlen, src)          (strncat_s(dst, dstlen, src, _TRUNCATE))
#define _vsnprintf_s(dst, len, cnt, fmt, a) (vsnprintf(dst, min((QWORD)(len), (QWORD)(cnt)), fmt, a))
#define _stricmp(s1, s2)                    (strcasecmp(s1, s2))
#define _strnicmp(s1, s2, maxcount)         (strncasecmp(s1, s2, maxcount))
#define strtok_s(s, d, c)                   (strtok_r(s, d, c))
#define _snprintf_s(s,l,c,...)              (snprintf(s,min((QWORD)(l), (QWORD)(c)),__VA_ARGS__))
#define sscanf_s(s, f, ...)                 (sscanf(s, f, __VA_ARGS__))
#define SwitchToThread()                    (sched_yield())
#define ExitThread(dwExitCode)              (pthread_exit(dwExitCode))
#define ExitProcess(c)                      (exit(c ? EXIT_SUCCESS : EXIT_FAILURE))
#define Sleep(dwMilliseconds)               (usleep(1000*dwMilliseconds))
#define fopen_s(ppFile, szFile, szAttr)     ((*ppFile = fopen(szFile, szAttr)) ? 0 : 1)
#define GetModuleFileNameA(m, f, l)         (readlink("/proc/self/exe", f, l))
#define ZeroMemory(pb, cb)                  (memset(pb, 0, cb))
#define WinUsb_SetPipePolicy(h, p, t, cb, pb)   // TODO: implement this for better USB2 performance.
#define WSAGetLastError()                   (WSAEWOULDBLOCK)    // TODO: remove this dummy when possible.
#define _ftelli64(f)                        (ftello(f))
#define _fseeki64(f, o, w)                  (fseeko(f, o, w))
#define _chsize_s(fd, cb)                   (ftruncate64(fd, cb))
#define _fileno(f)                          (fileno(f))
#define InterlockedAdd64(p, v)              (__sync_add_and_fetch(p, v))
#define InterlockedIncrement64(p)           (__sync_add_and_fetch(p, 1))
#define InterlockedIncrement(p)             (__sync_add_and_fetch_4(p, 1))
#define GetCurrentProcess()					((HANDLE)-1)
#define closesocket(s)                      close(s)

#ifndef _LINUX_DEF_CRITICAL_SECTION
#define _LINUX_DEF_CRITICAL_SECTION
typedef struct tdCRITICAL_SECTION {
    pthread_mutex_t mutex;
    pthread_mutexattr_t mta;
} CRITICAL_SECTION, *LPCRITICAL_SECTION;
#endif /* _LINUX_DEF_CRITICAL_SECTION */

VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct _WIN32_FIND_DATAA {
    CHAR __cExtension[5];
    CHAR cFileName[MAX_PATH];
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

HANDLE FindFirstFileA(LPSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes);
VOID LocalFree(HANDLE hMem);
QWORD GetTickCount64();
BOOL QueryPerformanceFrequency(_Out_ LARGE_INTEGER *lpFrequency);
BOOL QueryPerformanceCounter(_Out_ LARGE_INTEGER *lpPerformanceCount);
VOID GetLocalTime(LPSYSTEMTIME lpSystemTime);
DWORD InterlockedAdd(DWORD *Addend, DWORD Value);
BOOL IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);

HANDLE CreateThread(
    PVOID    lpThreadAttributes,
    SIZE_T    dwStackSize,
    PVOID    lpStartAddress,
    PVOID    lpParameter,
    DWORD    dwCreationFlags,
    PDWORD    lpThreadId
);

BOOL CloseHandle(_In_ HANDLE hObject);
BOOL ResetEvent(_In_ HANDLE hEvent);
BOOL SetEvent(_In_ HANDLE hEvent);
HANDLE CreateEvent(_In_opt_ PVOID lpEventAttributes, _In_ BOOL bManualReset, _In_ BOOL bInitialState, _In_opt_ PVOID lpName);
DWORD WaitForMultipleObjects(_In_ DWORD nCount, HANDLE *lpHandles, _In_ BOOL bWaitAll, _In_ DWORD dwMilliseconds);
DWORD WaitForSingleObject(_In_ HANDLE hHandle, _In_ DWORD dwMilliseconds);

// for some unexplainable reasons the gcc on -O2 will optimize out functionality
// and destroy the proper workings on some functions due to an unexplainable
// reason disable optimization on a function level resolves the issues ...
#define LINUX_NO_OPTIMIZE __attribute__((optimize("O0")))

#endif /* LINUX */

#endif /* __OSCOMPATIBILITY_H__ */
