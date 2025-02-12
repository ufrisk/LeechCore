//	leechagent.c : Implementation the LeechAgent service related functionality.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechagent.h"
#include "leechagent_rpc.h"
#include "leechagent_proc.h"
#include "leechrpc.h"
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

//-----------------------------------------------------------------------------
// MAIN, PARSE AND HELP FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Parse the application command line arguments.
* -- argc
* -- argv
* -- pConfig
* -- return
*/
_Success_(return)
BOOL LeechSvc_ParseArgs(_In_ int argc, _In_ char **argv, _In_ PLEECHSVC_CONFIG pConfig)
{
    LPSTR szOpt, szCurrentDirectory;
    DWORD c = 0, i = 1;
    while(i < argc) {
        if(0 == _stricmp(argv[i], "-insecure")) {
            pConfig->fInsecure = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-interactive")) {
            pConfig->fInteractive = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-daemon")) {
            pConfig->fDaemon = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-z") && (i + 1 < argc)) {
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-no-lock")) {
            pConfig->fNoLock = TRUE;
            i++;
            continue;
        } else if(0 == _stricmp(argv[i], "-grpc")) {
            continue;
        } else if(0 == _stricmp(argv[i], "-grpc-tls-p12") && (i + 1 < argc)) {
            szOpt = argv[i + 1];
            szCurrentDirectory = "";
            if((strlen(szOpt) > 2) && (szOpt[0] != '/') && (szOpt[0] != '\\') && (szOpt[1] != ':')) {
                szCurrentDirectory = pConfig->grpc.szCurrentDirectory;
            }
            _snprintf_s(pConfig->grpc.szTlsServerP12, _countof(pConfig->grpc.szTlsServerP12), _TRUNCATE, "%s%s", szCurrentDirectory, szOpt);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-grpc-client-ca") && (i + 1 < argc)) {
            szOpt = argv[i + 1];
            szCurrentDirectory = "";
            if((strlen(szOpt) > 2) && (szOpt[0] != '/') && (szOpt[0] != '\\') && (szOpt[1] != ':')) {
                szCurrentDirectory = pConfig->grpc.szCurrentDirectory;
            }
            _snprintf_s(pConfig->grpc.szTlsClientCaCert, _countof(pConfig->grpc.szTlsClientCaCert), _TRUNCATE, "%s%s", szCurrentDirectory, szOpt);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-grpc-tls-p12-password") && (i + 1 < argc)) {
            _snprintf_s(pConfig->grpc.szTlsServerP12Pass, _countof(pConfig->grpc.szTlsServerP12Pass), _TRUNCATE, "%s", argv[i + 1]);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-grpc-port") && (i + 1 < argc)) {
            strncpy_s(pConfig->szTcpPortGRPC, _countof(pConfig->szTcpPortGRPC), argv[i + 1], _TRUNCATE);
            i += 2;
            continue;
        } else if(0 == _stricmp(argv[i], "-grpc-listen-address") && (i + 1 < argc)) {
            _snprintf_s(pConfig->grpc.szListenAddress, _countof(pConfig->grpc.szListenAddress), _TRUNCATE, "%s", argv[i + 1]);
            i += 2;
            continue;
        }
        printf("LeechAgent: invalid argument '%s'\n", argv[i]);
        return FALSE;
    }
    if(!pConfig->fInsecure && (!pConfig->grpc.szTlsClientCaCert[0] || !pConfig->grpc.szTlsServerP12[0] || !pConfig->grpc.szTlsServerP12Pass[0])) {
        printf("gRPC missing required parameters: -grpc-tls-p12, -grpc-tls-p12-password, -grpc-client-ca\n");
        printf("     alternatively: -insecure\n");
        return FALSE;
    }
    if(!pConfig->hModuleGRPC) {
        pConfig->hModuleGRPC = LoadLibraryA(LEECHGRPC_LIBRARY_NAME);
        if(!pConfig->hModuleGRPC) {
            printf("Failed to load gRPC library "LEECHGRPC_LIBRARY_NAME".\n");
            return FALSE;
        }
    }
    return TRUE;
}

#define MAX_CONFIGFILE_ARGS 100
#define MAX_CONFIGFILE_ARG_LENGTH 4096

VOID LeechSvc_ParseArgs_FromConfigFile(_In_ PLEECHSVC_CONFIG pConfig)
{
    FILE *hFile;
    DWORD i, argc = 0;
    LPSTR argv[MAX_CONFIGFILE_ARGS] = { 0 };
    CHAR szBuffer[MAX_CONFIGFILE_ARG_LENGTH];
    CHAR szConfigFileName[MAX_PATH] = { 0 }; 
    CHAR *szToken, *ctx = NULL;
    SIZE_T cch;
    ZeroMemory(pConfig, sizeof(LEECHSVC_CONFIG));
    strcpy_s(pConfig->grpc.szListenAddress, _countof(pConfig->grpc.szListenAddress), "0.0.0.0");
    strcpy_s(pConfig->szTcpPortGRPC, _countof(pConfig->szTcpPortGRPC), LEECHSVC_TCP_PORT_GRPC);
    Util_GetPathLib(pConfig->grpc.szCurrentDirectory);
    _snprintf_s(szConfigFileName, _countof(szConfigFileName), _TRUNCATE, "%s%s", pConfig->grpc.szCurrentDirectory, LEECHAGENT_CONFIG_FILE);
    if(fopen_s(&hFile, szConfigFileName, "r")) { return; }
    while(fgets(szBuffer, sizeof(szBuffer), hFile)) {
        while((szToken = strtok_s((ctx ? NULL : szBuffer), " \n", &ctx))) {
            argv[argc] = strdup(szToken);
            argc++;
            if(argc >= MAX_CONFIGFILE_ARGS) { return; }
        }
    }
    LeechSvc_ParseArgs(argc, argv, pConfig);
    for(i = 0; i < argc; i++) {
        free(argv[i]);
    }
    fclose(hFile);
}

/*
* Print the help text to the end user.
*/
VOID LeechSvc_PrintHelp()
{
    printf(
        "LeechAgent - Remote memory acquisition and analysis:                          \n" \
        "                                                                              \n" \
        "The LeechAgent provides a way to connect to remote instances of the LeechCore \n" \
        "library.                                                                      \n" \
        "                                                                              \n" \
        "The LeechAgent supports gRPC (tcp/28474) using mTLS or INSECURE auth.         \n" \
        "gRPC is disabled by default, enable with '-grpc' command line option.         \n" \
        "To use mTLS authentication specify:                                           \n" \
        "'-grpc-client-ca', '-grpc-tls-p12' and '-grpc-tls-p12-password'.              \n" \
        "                                                                              \n" \
        "grpc:// connection requires the following port to be opened: tcp/28474        \n" \
        "The remote service will be installed in the C:\\Program Files\\LeechAgent\\   \n" \
        "directory of the remote system.                                               \n" \
        "                                                                              \n" \
        "The LeechAgent requires external files and software. For instructions how to  \n" \
        "prepare the agent for local or remote installation please visit:              \n" \
        "https://github.com/ufrisk/LeechCore/wiki/LeechAgent                           \n" \
        "                                                                              \n" \
        "The LeechAgent may also be run in interactive mode as a normal application    \n" \
        "by any user. (NB! some actions - such as loading the WinPMEM driver into the  \n" \
        "kernel may still require administrative privilegies). The default security    \n" \
        "mode is mutually authenticated kerberor, but the service may also be run in   \n" \
        "insecure / no security mode by supplying the 'insecure' option.               \n" \
        "WARNING! - LeechAgent provides means of REMOTE CODE EXECUTION and it is very  \n" \
        "insecure in insecure mode! Please only use in lab environments at own risk!   \n" \
        "                                                                              \n" \
        "Syntax:                                                                       \n" \
        "leechagent.exe -interactive            (run as a normal application)          \n" \
        "leechagent.exe -interactive -insecure  (same as above, but with no security)  \n");
}

/*
* Daemonize the application.
*/
VOID LeechSvc_Daemonize()
{
    pid_t pid;
    // 1: fork: let the parent exit
    if((pid = fork()) < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if(pid > 0) {
        printf("Daemonizing ...\n");
        exit(EXIT_SUCCESS);     // parent exit
    }
    // 2: child continues: become session leader
    if(setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }
    // 3: second fork to prevent reacquisition of a controlling terminal
    if((pid = fork()) < 0) {
        perror("second fork");
        exit(EXIT_FAILURE);
    }
    if(pid > 0) {
        exit(EXIT_SUCCESS);     // second parent exit
    }
    // 4: set file permissions mask and change working directory
    umask(0);
    if(chdir("/") < 0) {
        perror("chdir");
        exit(EXIT_FAILURE);
    }
    // 5: close all open file descriptors
    for(int fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
        close(fd);
    }
    // 6: redirect stdin, stdout, stderr to /dev/null
    int fd0 = open("/dev/null", O_RDWR);
    if (fd0 != -1) {
        dup2(fd0, STDIN_FILENO);
        dup2(fd0, STDOUT_FILENO);
        dup2(fd0, STDERR_FILENO);
    }
}

/*
* Create/open the process lock file in /var/run/ and report the result of it.
*/
VOID LeechSvc_AquireLockFile(_In_ PLEECHSVC_CONFIG pConfig)
{
    char buf[16];
    // Open (or create) the lock file.
    pConfig->fdLockFile = open(LEECHSVC_LOCKFILE, O_RDWR | O_CREAT, 0640);
    if (pConfig->fdLockFile  < 0) {
        perror("Unable to open lock file: "LEECHSVC_LOCKFILE);
        perror("Disable lock file checking with -no-lock");
        exit(EXIT_FAILURE);
    }
    // Try to acquire an exclusive lock on the file.
    // lockf() returns -1 if it fails to obtain the lock.
    if (lockf(pConfig->fdLockFile , F_TLOCK, 0) < 0) {
        perror("Unable to lock the lock file, is another instance running?");
        perror("Disable lock file checking with -no-lock");
        close(pConfig->fdLockFile);
        exit(EXIT_FAILURE);
    }
    // Successfully acquired the lock.
    // Truncate the file and write the current process's PID into it.
    if (ftruncate(pConfig->fdLockFile, 0) < 0) {
        perror("Failed to truncate lock file");
        close(pConfig->fdLockFile);
        exit(EXIT_FAILURE);
    }
    snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    if (write(pConfig->fdLockFile, buf, strlen(buf)) < 0) {
        perror("Failed to write PID to lock file");
        close(pConfig->fdLockFile);
        exit(EXIT_FAILURE);
    }
}

/*
* Run the "service".
* -- pConfig
*/
VOID LeechSvc_RunSvc(_In_ PLEECHSVC_CONFIG pConfig)
{
    if(pConfig->fDaemon && pConfig->fInsecure) {
        printf("Unable to start GRPC service. Insecure mode not allowed when running as daemon.\n");
        return;
    }
    if(!pConfig->fDaemon && !pConfig->fInteractive) {
        printf("Unable to start GRPC service. Either '-interactive' or '-daemon' mode required.\n");
        return;
    }
    if(!pConfig->fNoLock) {
        LeechSvc_AquireLockFile(pConfig);
    }
    if(pConfig->fDaemon) {
        LeechSvc_Daemonize();
    }
    LeechRpcOnLoadInitialize();
    if(!RpcStartGRPC(pConfig)) {
        printf("Unable to start GRPC service.\n");
        RpcStop();
        LeechRpcOnUnloadClose();
        return;
    }
    // Check whether to stop the service.
    while(TRUE) {
        Sleep(1000);
    }
    RpcStop();
    LeechRpcOnUnloadClose();
}

/*
* Main entry point of the service executable.
* -- argc
* -- argv
* -- return
*/
int main(int argc, char **argv)
{
    LEECHSVC_CONFIG cfg = { 0 };
    DWORD cchLocalUserUPN = MAX_PATH;
    WCHAR wszLocalUserUPN[MAX_PATH] = { 0 };
    // PARSE ARGUMENTS AND VALIDITY CHECK
    LeechSvc_ParseArgs_FromConfigFile(&cfg);
    if(!LeechSvc_ParseArgs(argc, argv, &cfg)) { return 0; }
    // RUN SERVICE:
    LeechSvc_RunSvc(&cfg);
    return 1;
}
