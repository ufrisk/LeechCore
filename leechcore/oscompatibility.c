// oscompatibility.c : LeechCore Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2017-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef _WIN32

#include "oscompatibility.h"

VOID BusySleep(_In_ DWORD us)
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

#if defined(LINUX) || defined(MACOS)

#include "oscompatibility.h"
#include "util.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/ioctl.h>

// ----------------------------------------------------------------------------
// LocalAlloc/LocalFree BELOW:
// ----------------------------------------------------------------------------

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



// ----------------------------------------------------------------------------
// GENERAL HANDLES BELOW:
// ----------------------------------------------------------------------------

#define OSCOMPATIBILITY_HANDLE_INTERNAL         0x35d91cca
#define OSCOMPATIBILITY_HANDLE_TYPE_NA          0
#define OSCOMPATIBILITY_HANDLE_TYPE_THREAD      2
#define OSCOMPATIBILITY_HANDLE_TYPE_EVENT       3

typedef struct tdHANDLE_INTERNAL {
    DWORD magic;
    DWORD type;
} HANDLE_INTERNAL, *PHANDLE_INTERNAL;

typedef struct tdHANDLE_INTERNAL_THREAD {
    DWORD magic;
    DWORD type;
    pthread_t thread;
} HANDLE_INTERNAL_THREAD, *PHANDLE_INTERNAL_THREAD;

VOID CloseEvent(_In_ HANDLE hEvent);

BOOL CloseHandle(_In_ HANDLE hObject)
{
    PHANDLE_INTERNAL hi = (PHANDLE_INTERNAL)hObject;
    if(hi->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) { return FALSE; }
    switch(hi->type) {
        case OSCOMPATIBILITY_HANDLE_TYPE_THREAD:
            pthread_join(((PHANDLE_INTERNAL_THREAD)hi)->thread, NULL);
            break;
        case OSCOMPATIBILITY_HANDLE_TYPE_EVENT:
            CloseEvent(hObject);
            break;
        default:
            break;
    }
    LocalFree(hi);
    return TRUE;
}

#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE CLOCK_MONOTONIC
#endif /* CLOCK_MONOTONIC_COARSE */

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
    PHANDLE_INTERNAL_THREAD ph;
    pthread_t thread;
    int status;
    status = pthread_create(&thread, NULL, lpStartAddress, lpParameter);
    if(status) { return NULL; }
    ph = malloc(sizeof(HANDLE_INTERNAL_THREAD));
    if(!ph) { return NULL; }
    ph->magic = OSCOMPATIBILITY_HANDLE_INTERNAL;
    ph->type = OSCOMPATIBILITY_HANDLE_TYPE_THREAD;
    ph->thread = thread;
    return (HANDLE)ph;
}

BOOL GetExitCodeThread(_In_ HANDLE hThread, _Out_ LPDWORD lpExitCode)
{
    PHANDLE_INTERNAL_THREAD ph = (PHANDLE_INTERNAL_THREAD)hThread;
    *lpExitCode = 0;
    if((ph->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) || (ph->type != OSCOMPATIBILITY_HANDLE_TYPE_THREAD)) { return FALSE; }
    return 0 == pthread_join(ph->thread, NULL);
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
// BusySleep functionality below:
// ----------------------------------------------------------------------------

VOID BusySleep(_In_ DWORD us)
{
    long elapsed;
    struct timespec start, end;
    if(us) {
        if(us >= 20) {
            usleep(us);
        } else {
            clock_gettime(CLOCK_MONOTONIC, &start);
            do {
                clock_gettime(CLOCK_MONOTONIC, &end);
                elapsed = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
            } while (elapsed < us);
        }
    }
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

#endif /* LINUX || MACOS */



// ----------------------------------------------------------------------------
// WINUSB functionality below: (only Linux):
// ----------------------------------------------------------------------------

#ifdef LINUX

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

#endif /* LINUX */



// ----------------------------------------------------------------------------
// SRWLock functionality below:
// ----------------------------------------------------------------------------

#ifdef LINUX

#include <sys/syscall.h>
#include <linux/futex.h>

static int futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

VOID InitializeSRWLock(PSRWLOCK pSRWLock)
{
    ZeroMemory(pSRWLock, sizeof(SRWLOCK));
}

BOOL AcquireSRWLockExclusive_Try(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwZero = 0;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
        return TRUE;
    }
    __sync_sub_and_fetch_4(&pSRWLock->c, 1);
    return FALSE;
}

VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwZero;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
            return;
        }
        futex(&pSRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0);
    }
}

_Success_(return)
BOOL AcquireSRWLockExclusive_Timeout(_Inout_ PSRWLOCK pSRWLock, _In_ DWORD dwMilliseconds)
{
    DWORD dwZero;
    struct timespec ts;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
            return TRUE;
        }
        if((dwMilliseconds != 0) && (dwMilliseconds != 0xffffffff)) {
            ts.tv_sec = dwMilliseconds / 1000;
            ts.tv_nsec = (dwMilliseconds % 1000) * 1000 * 1000;
            if((-1 == futex(&pSRWLock->xchg, FUTEX_WAIT, 1, &ts, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&pSRWLock->c, 1);
                return FALSE;
            }
        } else {
            if((-1 == futex(&pSRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&pSRWLock->c, 1);
                return FALSE;
            }
        }
    }
}

VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwOne = 1;
    if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwOne, 0)) {
        if(__sync_sub_and_fetch_4(&pSRWLock->c, 1)) {
            futex(&pSRWLock->xchg, FUTEX_WAKE, 1, NULL, NULL, 0);
        }
    }
}

#endif /* LINUX */

#ifdef MACOS

VOID InitializeSRWLock(PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) {
        pSRWLock->sem = dispatch_semaphore_create(1);
    }
}

BOOL AcquireSRWLockExclusive_Try(_Inout_ PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    return (0 == dispatch_semaphore_wait(pSRWLock->sem, DISPATCH_TIME_NOW));
}

VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    dispatch_semaphore_wait(pSRWLock->sem, DISPATCH_TIME_FOREVER);
}

_Success_(return)
BOOL AcquireSRWLockExclusive_Timeout(_Inout_ PSRWLOCK pSRWLock, _In_ DWORD dwMilliseconds)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, dwMilliseconds * NSEC_PER_MSEC);
    return (0 == dispatch_semaphore_wait(pSRWLock->sem, timeout));
}

VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    if(pSRWLock->valid) {
        dispatch_semaphore_signal(pSRWLock->sem);
    }
}

#endif /* MACOS */



// ----------------------------------------------------------------------------
// EVENT functionality below:
// ----------------------------------------------------------------------------

#if defined(LINUX) || defined(MACOS)

typedef struct tdHANDLE_INTERNAL_EVENT2 {
    DWORD magic;
    DWORD type;
    BOOL fEventManualReset;
    SRWLOCK SRWLock;
} HANDLE_INTERNAL_EVENT2, *PHANDLE_INTERNAL_EVENT2;

// function is limited and not thread-safe, but use case in leechcore is single-threaded
DWORD WaitForSingleObject(_In_ HANDLE hHandle, _In_ DWORD dwMilliseconds)
{
    PHANDLE_INTERNAL_EVENT2 ph = (PHANDLE_INTERNAL_EVENT2)hHandle;
    BOOL fResult;
    if((ph->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) || (ph->type != OSCOMPATIBILITY_HANDLE_TYPE_EVENT)) { return 0xffffffff; }
    if(!AcquireSRWLockExclusive_Timeout(&ph->SRWLock, dwMilliseconds)) {
        return 0xffffffff;  // timeout
    }
    if(ph->fEventManualReset) {
        ReleaseSRWLockExclusive(&ph->SRWLock);
    }
    return 0;
}

DWORD WaitForMultipleObjectsAll(_In_ DWORD nCount, HANDLE *lpHandles, _In_ DWORD dwMilliseconds)
{
    DWORD i;
    BOOL fAll = FALSE;
    PHANDLE_INTERNAL_EVENT2 ph;
    // 1: verify handle validity
    for(i = 0; i < nCount; i++) {
        ph = *(PHANDLE_INTERNAL_EVENT2 *)(lpHandles + i);
        if((ph->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) || (ph->type != OSCOMPATIBILITY_HANDLE_TYPE_EVENT)) {
            return 0xffffffff;
        }
    }
    // 2: wait for all objects
    while(!fAll) {
        fAll = TRUE;
        for(i = 0; i < nCount; i++) {
            ph = *(PHANDLE_INTERNAL_EVENT2 *)(lpHandles + i);
            if(!AcquireSRWLockExclusive_Try(&ph->SRWLock)) {
                if(!AcquireSRWLockExclusive_Timeout(&ph->SRWLock, dwMilliseconds)) {
                    return 0xffffffff;  // timeout
                }
                fAll = FALSE;
            }
            ReleaseSRWLockExclusive(&ph->SRWLock);
        }
    }
    return 0;
}

DWORD WaitForMultipleObjectsSingle(_In_ DWORD nCount, HANDLE *lpHandles, _In_ DWORD dwMilliseconds)
{
    DWORD i;
    PHANDLE_INTERNAL_EVENT2 ph;
    // 1: verify handle validity
    for(i = 0; i < nCount; i++) {
        ph = *(PHANDLE_INTERNAL_EVENT2 *)(lpHandles + i);
        if((ph->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) || (ph->type != OSCOMPATIBILITY_HANDLE_TYPE_EVENT)) {
            return 0xffffffff;
        }
    }
    // 2: try find single available object - or else sleep and try again
    while(TRUE) {
        for(i = 0; i < nCount; i++) {
            ph = *(PHANDLE_INTERNAL_EVENT2 *)(lpHandles + i);
            if(AcquireSRWLockExclusive_Try(&ph->SRWLock)) {
                if(ph->fEventManualReset) {
                    ReleaseSRWLockExclusive(&ph->SRWLock);
                }
                return i;
            }
        }
        Sleep(5);
    }
}

DWORD WaitForMultipleObjects(_In_ DWORD nCount, HANDLE *lpHandles, _In_ BOOL bWaitAll, _In_ DWORD dwMilliseconds)
{
    return bWaitAll ?
        WaitForMultipleObjectsAll(nCount, lpHandles, dwMilliseconds) :
        WaitForMultipleObjectsSingle(nCount, lpHandles, dwMilliseconds);
}

BOOL SetEvent(_In_ HANDLE hEvent)
{
    PHANDLE_INTERNAL_EVENT2 ph = (PHANDLE_INTERNAL_EVENT2)hEvent;
    if((ph->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) || (ph->type != OSCOMPATIBILITY_HANDLE_TYPE_EVENT)) { return FALSE; }
    ReleaseSRWLockExclusive(&ph->SRWLock);
    return TRUE;
}

BOOL ResetEvent(_In_ HANDLE hEvent)
{
    PHANDLE_INTERNAL_EVENT2 ph = (PHANDLE_INTERNAL_EVENT2)hEvent;
    if((ph->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) || (ph->type != OSCOMPATIBILITY_HANDLE_TYPE_EVENT)) { return FALSE; }
    return AcquireSRWLockExclusive_Try(&ph->SRWLock);
}

HANDLE CreateEvent(_In_opt_ PVOID lpEventAttributes, _In_ BOOL bManualReset, _In_ BOOL bInitialState, _In_opt_ PVOID lpName)
{
    PHANDLE_INTERNAL_EVENT2 ph;
    ph = malloc(sizeof(HANDLE_INTERNAL_EVENT2));
    ZeroMemory(ph, sizeof(HANDLE_INTERNAL_EVENT2));
    ph->magic = OSCOMPATIBILITY_HANDLE_INTERNAL;
    ph->type = OSCOMPATIBILITY_HANDLE_TYPE_EVENT;
    ph->fEventManualReset = bManualReset;
    if(bInitialState) {
        SetEvent((HANDLE)ph);
    } else {
        ResetEvent((HANDLE)ph);
    }
    return (HANDLE)ph;
}

VOID CloseEvent(_In_ HANDLE hEvent)
{
    PHANDLE_INTERNAL_EVENT2 ph = (PHANDLE_INTERNAL_EVENT2)hEvent;
    if((ph->magic != OSCOMPATIBILITY_HANDLE_INTERNAL) || (ph->type != OSCOMPATIBILITY_HANDLE_TYPE_EVENT)) { return; }
    ph->type = OSCOMPATIBILITY_HANDLE_TYPE_NA;
    ReleaseSRWLockExclusive(&ph->SRWLock);
}

#endif /* LINUX || MACOS */
