// oscompatibility.c : LeechCore Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2017-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef _WIN32

#include "oscompatibility.h"

VOID usleep(_In_ DWORD us)
{
    QWORD tmFreq, tmStart, tmNow, tmThreshold;
    if(us == 0) { return; }
    QueryPerformanceFrequency((PLARGE_INTEGER)&tmFreq);
    tmThreshold = tmFreq * us / (1000 * 1000);  // dw_uS uS
    QueryPerformanceCounter((PLARGE_INTEGER)&tmStart);
    while(QueryPerformanceCounter((PLARGE_INTEGER)&tmNow) && ((tmNow - tmStart) < tmThreshold)) {
        ;
    }
}

_Success_(return)
BOOL Util_GetPathExe(_Out_writes_(MAX_PATH) PCHAR szPath)
{
    SIZE_T i;
    if(GetModuleFileNameA(NULL, szPath, MAX_PATH - 4)) {
        for(i = strlen(szPath) - 1; i > 0; i--) {
            if(szPath[i] == '/' || szPath[i] == '\\') {
                szPath[i + 1] = '\0';
                return TRUE;
            }
        }
    }
    return FALSE;
}

#endif /* _WIN32 */
#ifdef LINUX

#include "oscompatibility.h"
#include "util.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#define INTERNAL_HANDLE_TYPE_THREAD        0xdeadbeeffedfed01

typedef struct tdINTERNAL_HANDLE {
    QWORD type;
    HANDLE handle;
} INTERNAL_HANDLE, *PINTERNAL_HANDLE;

HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes)
{
    HANDLE h = malloc(uBytes);
    if(h && (uFlags & LMEM_ZEROINIT)) {
        memset(h, 0, uBytes);
    }
    return h;
}

VOID LocalFree(HANDLE hMem)
{
    free(hMem);
}

QWORD GetTickCount64()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / (1000 * 1000);
}

BOOL QueryPerformanceFrequency(_Out_ LARGE_INTEGER *lpFrequency)
{
    *lpFrequency = 1000 * 1000;
    return TRUE;
}

BOOL QueryPerformanceCounter(_Out_ LARGE_INTEGER *lpPerformanceCount)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    *lpPerformanceCount = (ts.tv_sec * 1000 * 1000) + (ts.tv_nsec / 1000);  // uS resolution
    return TRUE;
}

HANDLE CreateThread(
    PVOID     lpThreadAttributes,
    SIZE_T    dwStackSize,
    PVOID     lpStartAddress,
    PVOID     lpParameter,
    DWORD     dwCreationFlags,
    PDWORD    lpThreadId
) {
    PINTERNAL_HANDLE ph;
    pthread_t thread;
    int status;
    status = pthread_create(&thread, NULL, lpStartAddress, lpParameter);
    if(status) { return NULL;}
    ph = malloc(sizeof(INTERNAL_HANDLE));
    ph->type = INTERNAL_HANDLE_TYPE_THREAD;
    ph->handle = (HANDLE)thread;
    return ph;
}

VOID GetLocalTime(LPSYSTEMTIME lpSystemTime)
{
    time_t curtime;
    struct tm t = { 0 };
    curtime = time(NULL);
    localtime_r(&curtime, &t);
    lpSystemTime->wYear = t.tm_year;
    lpSystemTime->wMonth = t.tm_mon;
    lpSystemTime->wDayOfWeek = t.tm_wday;
    lpSystemTime->wDay = t.tm_mday;
    lpSystemTime->wHour = t.tm_hour;
    lpSystemTime->wMinute = t.tm_min;
    lpSystemTime->wSecond = t.tm_sec;
    lpSystemTime->wMilliseconds = 0;
}

HANDLE FindFirstFileA(LPSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    DWORD i;
    DIR *hDir;
    CHAR szDirName[MAX_PATH] = { 0 };
    strcpy_s(lpFindFileData->__cExtension, 5, lpFileName + strlen(lpFileName) - 3);
    strcpy_s(szDirName, MAX_PATH - 1, lpFileName);
    for(i = strlen(szDirName) - 1; i > 0; i--) {
        if(szDirName[i] == '/') {
            szDirName[i] = 0;
            break;
        }
    }
    hDir = opendir(szDirName);
    if(!hDir) { return NULL; }
    return FindNextFileA((HANDLE)hDir, lpFindFileData) ? (HANDLE)hDir : INVALID_HANDLE_VALUE;
}

BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    DIR *hDir = (DIR*)hFindFile;
    struct dirent *dir;
    char* sz;
    if(!hDir) { return FALSE; }
    while ((dir = readdir(hDir)) != NULL) {
        sz = dir->d_name;
        if((strlen(sz) > 3) && !strcasecmp(sz + strlen(sz) - 3, lpFindFileData->__cExtension)) {
            strcpy_s(lpFindFileData->cFileName, MAX_PATH, sz);
            return TRUE;
        }
    }
    closedir(hDir);
    return FALSE;
}

BOOL __WinUsb_ReadWritePipe(
    WINUSB_INTERFACE_HANDLE InterfaceHandle,
    UCHAR    PipeID,
    PUCHAR    Buffer,
    ULONG    BufferLength,
    PULONG    LengthTransferred,
    PVOID    Overlapped
) {
    int result, cbTransferred;
    result = libusb_bulk_transfer(
        InterfaceHandle,
        PipeID,
        Buffer,
        BufferLength,
        &cbTransferred,
        500);
    *LengthTransferred = (ULONG)cbTransferred;
    return result ? FALSE : TRUE;
}

BOOL WinUsb_Free(WINUSB_INTERFACE_HANDLE InterfaceHandle)
{
    if(!InterfaceHandle) { return TRUE; }
    libusb_release_interface(InterfaceHandle, 0);
    libusb_reset_device(InterfaceHandle);
    libusb_close(InterfaceHandle);
    return TRUE;
}

DWORD InterlockedAdd(DWORD *Addend, DWORD Value)
{
    return __sync_add_and_fetch(Addend, Value);
}

BOOL IsWow64Process(HANDLE hProcess, PBOOL Wow64Process)
{
    if(Wow64Process) {
        *Wow64Process = FALSE;
        return TRUE;
    }
    return FALSE;
}



// ----------------------------------------------------------------------------
// LoadLibrary / GetProcAddress facades (for FPGA functionality) below:
// ----------------------------------------------------------------------------

HMODULE LoadLibraryA(LPSTR lpFileName)
{
    CHAR szFileName[2 * MAX_PATH] = { 0 };
    if(lpFileName && (0 == memcmp(lpFileName, "FTD3XX.dll", 10))) {
        lpFileName = "leechcore_ft601_driver_linux.so";
    }
    if(lpFileName && (0 == memcmp(lpFileName, "FTD2XX.dll", 10))) {
        lpFileName = "libftd2xx.so";
    }
    if(lpFileName && (0 == memcmp(lpFileName, "vmm.dll", 7))) {
        lpFileName = "vmm.so";
    }
    strncat(szFileName, lpFileName, MAX_PATH);
    return dlopen(szFileName, RTLD_NOW);
}

BOOL FreeLibrary(_In_ HMODULE hLibModule)
{
    return 0 == dlclose(hLibModule);
}

FARPROC GetProcAddress(HMODULE hModule, LPSTR lpProcName)
{
    return dlsym(hModule, lpProcName);
}



// ----------------------------------------------------------------------------
// CRITICAL_SECTION functionality below:
// ----------------------------------------------------------------------------

VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    memset(lpCriticalSection, 0, sizeof(CRITICAL_SECTION));
    pthread_mutexattr_init(&lpCriticalSection->mta);
    pthread_mutexattr_settype(&lpCriticalSection->mta, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&lpCriticalSection->mutex, &lpCriticalSection->mta);
}

VOID DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    pthread_mutex_destroy(&lpCriticalSection->mutex);
    memset(lpCriticalSection, 0, sizeof(CRITICAL_SECTION));
}

VOID EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    pthread_mutex_lock(&lpCriticalSection->mutex);
}

BOOL TryEnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    return 0 == pthread_mutex_trylock(&lpCriticalSection->mutex);
}

VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    pthread_mutex_unlock(&lpCriticalSection->mutex);
}



// ----------------------------------------------------------------------------
// SRWLock functionality below:
// ----------------------------------------------------------------------------

static int futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

VOID InitializeSRWLock(PSRWLOCK SRWLock)
{
    ZeroMemory(SRWLock, sizeof(SRWLOCK));
}

BOOL AcquireSRWLockExclusive_Try(_Inout_ PSRWLOCK SRWLock)
{
    DWORD dwZero = 0;
    __sync_fetch_and_add_4(&SRWLock->c, 1);
    if(atomic_compare_exchange_strong(&SRWLock->xchg, &dwZero, 1)) {
        return TRUE;
    }
    __sync_sub_and_fetch_4(&SRWLock->c, 1);
    return FALSE;
}

VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK SRWLock)
{
    DWORD dwZero;
    __sync_fetch_and_add_4(&SRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong(&SRWLock->xchg, &dwZero, 1)) {
            return;
        }
        futex(&SRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0);
    }
}

_Success_(return)
BOOL AcquireSRWLockExclusive_Timeout(_Inout_ PSRWLOCK SRWLock, _In_ DWORD dwMilliseconds)
{
    DWORD dwZero;
    struct timespec ts;
    __sync_fetch_and_add_4(&SRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong(&SRWLock->xchg, &dwZero, 1)) {
            return TRUE;
        }
        if((dwMilliseconds != 0) && (dwMilliseconds != 0xffffffff)) {
            ts.tv_sec = dwMilliseconds / 1000;
            ts.tv_nsec = (dwMilliseconds % 1000) * 1000 * 1000;
            if((-1 == futex(&SRWLock->xchg, FUTEX_WAIT, 1, &ts, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&SRWLock->c, 1);
                return FALSE;
            }
        } else {
            if((-1 == futex(&SRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&SRWLock->c, 1);
                return FALSE;
            }
        }
    }
}

VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK SRWLock)
{
    DWORD dwOne = 1;
    if(atomic_compare_exchange_strong(&SRWLock->xchg, &dwOne, 0)) {
        if(__sync_sub_and_fetch_4(&SRWLock->c, 1)) {
            futex(&SRWLock->xchg, FUTEX_WAKE, 1, NULL, NULL, 0);
        }
    }
}



// ----------------------------------------------------------------------------
// EVENT AND CLOSE HANDLE functionality below:
// ----------------------------------------------------------------------------

#define OSCOMPATIBILITY_HANDLE_INTERNAL         0x35d91cca
#define OSCOMPATIBILITY_HANDLE_TYPE_EVENTFD     1

typedef struct tdHANDLE_INTERNAL {
    DWORD magic;
    DWORD type;
    BOOL fEventManualReset;
    int handle;
} HANDLE_INTERNAL, *PHANDLE_INTERNAL;

BOOL CloseHandle(_In_ HANDLE hObject)
{
    PHANDLE_INTERNAL hi = (PHANDLE_INTERNAL)hObject;
    if(hi->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) { return FALSE; }
    if(hi->type == OSCOMPATIBILITY_HANDLE_TYPE_EVENTFD) {
        close(hi->handle);
    }
    LocalFree(hi);
    return TRUE;
}

BOOL SetEvent(_In_ HANDLE hEvent)
{
    PHANDLE_INTERNAL hi = (PHANDLE_INTERNAL)hEvent;
    uint64_t v = 1;
    return -1 != write(hi->handle, &v, sizeof(v));
}

// function is not thread-safe, but use case in leechcore is single-threaded
BOOL ResetEvent(_In_ HANDLE hEvent)
{
    PHANDLE_INTERNAL hi = (PHANDLE_INTERNAL)hEvent;
    uint64_t v;
    struct pollfd fds[1];
    fds[0].fd = hi->handle;
    fds[0].events = POLLIN;
    while((poll(fds, 1, 0) > 0) && (fds[0].revents & POLLIN)) {
        read(fds[0].fd, &v, sizeof(v));
    }
    return TRUE;
}

HANDLE CreateEvent(_In_opt_ PVOID lpEventAttributes, _In_ BOOL bManualReset, _In_ BOOL bInitialState, _In_opt_ PVOID lpName)
{
    PHANDLE_INTERNAL pi;
    pi = malloc(sizeof(HANDLE_INTERNAL));
    pi->magic = OSCOMPATIBILITY_HANDLE_INTERNAL;
    pi->type = OSCOMPATIBILITY_HANDLE_TYPE_EVENTFD;
    pi->fEventManualReset = bManualReset;
    pi->handle = eventfd(0, 0);
    if(bInitialState) { SetEvent(pi); }
    return pi;
}

// function is limited and not thread-safe, but use case in leechcore is single-threaded
DWORD WaitForSingleObject(_In_ HANDLE hHandle, _In_ DWORD dwMilliseconds)
{
    PHANDLE_INTERNAL hi = (PHANDLE_INTERNAL)hHandle;
    uint64_t v;
    read(hi->handle, &v, sizeof(v));
    return 0;
}

// function is limited and not thread-safe, but use case in leechcore is single-threaded
DWORD WaitForMultipleObjects(_In_ DWORD nCount, HANDLE *lpHandles, _In_ BOOL bWaitAll, _In_ DWORD dwMilliseconds)
{
    struct pollfd fds[MAXIMUM_WAIT_OBJECTS];
    DWORD i;
    uint64_t v;
    if(bWaitAll) {
        for(i = 0; i < nCount; i++) {
            WaitForSingleObject(lpHandles[i], dwMilliseconds);
        }
        return -1;
    }
    for(i = 0; i < nCount; i++) {
        fds[i].fd = ((PHANDLE_INTERNAL)lpHandles[i])->handle;
        fds[i].events = POLLIN;
    }
    if(poll(fds, 1, -1) > 0) {
        for(i = 0; i < nCount; i++) {
            if((fds[0].revents & POLLIN)) {
                read(fds[i].fd, &v, sizeof(v));
                return i;
            }
        }
    }
    return -1;
}

#endif /* LINUX */
