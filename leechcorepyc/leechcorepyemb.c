//	leechcorepyemb.c : Implementation of the LeechCore embedded Python environment
//                     used to execute python code in the context of MemProcFS API
//                     from the LeechAgent. This is in a separate file to avoid
//                     issues with missing python environments at process creation.
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#define Py_LIMITED_API 0x03060000
#ifdef _DEBUG
#undef _DEBUG
#include <python.h>
#define _DEBUG
#else
#include <python.h>
#endif
#include <Windows.h>
#include <leechcore.h>
#include "leechcorepyc.h"

#define PYTHON_PATH_MAX             7*MAX_PATH
#define PYTHON_PATH_DELIMITER       L";"

int(*g_PyRun_SimpleString)(const char* command) = NULL;
PyThreadState* g_pyThreadState = NULL;

VOID Util_GetPathDll(_Out_writes_(MAX_PATH) PWCHAR wszPath, _In_opt_ HMODULE hModule)
{
    SIZE_T i;
    GetModuleFileNameW(hModule, wszPath, MAX_PATH - 4);
    for(i = wcslen(wszPath) - 1; i > 0; i--) {
        if(wszPath[i] == L'/' || wszPath[i] == L'\\') {
            wszPath[i + 1] = L'\0';
            return;
        }
    }
}

_Success_(return) __declspec(dllexport)
BOOL LeechCorePyC_EmbPythonInitialize(_In_ HMODULE hDllPython)
{
    PyObject *pName = NULL, *pModule = NULL;
    WCHAR wszPathExe[MAX_PATH], wszPathBasePython[MAX_PATH], wszPathPython[PYTHON_PATH_MAX];
    WCHAR wszPythonLib[] = { L'p', L'y', L't', L'h', L'o', L'n', L'X', L'X', L'.', L'z', L'i', L'p', 0 };
    ZeroMemory(wszPathBasePython, MAX_PATH * sizeof(WCHAR));
    ZeroMemory(wszPathPython, PYTHON_PATH_MAX * sizeof(WCHAR));
    g_PyRun_SimpleString = (int(*)(const char*))GetProcAddress(hDllPython, "PyRun_SimpleString");
    if(!g_PyRun_SimpleString) { return FALSE; }
    // 0: fixup python zip version
    wszPythonLib[6] = (WCHAR)Py_GetVersion()[0];
    wszPythonLib[7] = (WCHAR)Py_GetVersion()[2];
    // 1: Construct Python Path
    Util_GetPathDll(wszPathExe, NULL);
    Util_GetPathDll(wszPathBasePython, hDllPython);
    // 1.1: python base directory (where python dll is located)
    wcscpy_s(wszPathPython, PYTHON_PATH_MAX, wszPathBasePython);
    // 1.2: python zip
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathBasePython);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPythonLib);
    // 1.3: main executable directory
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathExe);
    // 1.4: plugins directory
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, PYTHON_PATH_DELIMITER);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, wszPathExe);
    wcscat_s(wszPathPython, PYTHON_PATH_MAX, L"plugins\\");
    // 2: Initialize (Embedded) Python.
    Py_SetProgramName(L"LeechCorePythonEmbedded");
    Py_SetPath(wszPathPython);
    //wprintf(L"LeechSvc: Python Path: %s\n", wszPathPython);
    Py_Initialize();
    //PyEval_InitThreads();
    /*
    g_PyRun_SimpleString(
        "try:                           \n" \
        "    import leechcorepyc        \n" \
        "except:                        \n" \
        "    pass                       \n" \
        "try:                           \n" \
        "    import memprocfs           \n" \
        "except:                        \n" \
        "    pass                       \n" );
    */
    //PyEval_ReleaseLock();
    g_pyThreadState = PyEval_SaveThread();
    return TRUE;
}

/*
* Execute a python script in-memory inside the execution environment.
* -- szPythonProgram
*/
__declspec(dllexport)
BOOL LeechCorePyC_EmbExecPyInMem(_In_ LPSTR szPythonProgram)
{
    PyGILState_STATE gstate;
    if(!g_PyRun_SimpleString) { return FALSE; }
    gstate = PyGILState_Ensure();
    g_PyRun_SimpleString(szPythonProgram);
    PyGILState_Release(gstate);
    return TRUE;
}

/*
* Finalize the Python interpreter. This will also flush any remaining buffers
* to stdout / stderr. No calls must be made to Python after this call!
* -- szPythonProgram
*/
__declspec(dllexport)
VOID LeechCorePyC_EmbClose()
{
    __try {
        if(g_pyThreadState) {
            PyEval_RestoreThread(g_pyThreadState);
        }
        Py_FinalizeEx();
    } __except(EXCEPTION_EXECUTE_HANDLER) { ; }
}
