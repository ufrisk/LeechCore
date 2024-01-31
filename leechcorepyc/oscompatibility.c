// oscompatibility.c : LeechCore Windows/Linux compatibility layer.
//
// (c) Ulf Frisk, 2017-2024
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
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>

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

VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
    pthread_mutex_unlock(&lpCriticalSection->mutex);
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
