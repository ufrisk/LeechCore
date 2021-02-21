//	leechcorepyc.c : Implementation of the LeechCore Python API
//
// (c) Ulf Frisk, 2020-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x03060000
#ifdef _DEBUG
#undef _DEBUG
#include <Python.h>
#include <structmember.h>
#define _DEBUG
#else
#include <Python.h>
#include <structmember.h>
#endif
#ifdef _WIN32
#include <Windows.h>
#endif /* _WIN32 */
#ifdef LINUX
#include "oscompatibility.h"
#endif /* LINUX */
#include <leechcore.h>

typedef struct tdPyObjectLeechCore {
    PyObject_HEAD
    BOOL fValid;
    HANDLE hLC;
    LC_CONFIG cfg;
    PHANDLE phLCkeepalive;
} PyObjectLeechCore;

static PyObject *g_pPyTypeObjectLeechCore = NULL;
static PLC_CONFIG_ERRORINFO g_LEECHCORE_LAST_ERRORINFO = NULL;  // will be memory leaked - but it should be very rare.

int PyDict_SetItemString_DECREF(PyObject *dp, const char *key, PyObject *item)
{
    int i = PyDict_SetItemString(dp, key, item);
    Py_XDECREF(item);
    return i;
}

int PyList_Append_DECREF(PyObject *dp, PyObject *item)
{
    int i = PyList_Append(dp, item);
    Py_XDECREF(item);
    return i;
}

// () -> STR
/*
* () -> STR
* Retrieve the last error (on create).
*/
static PyObject *
LeechCorePYC_GetLastError(PyObject *self, PyObject *args)
{
    return g_LEECHCORE_LAST_ERRORINFO ?
        PyUnicode_FromWideChar(g_LEECHCORE_LAST_ERRORINFO->wszUserText, -1) :
        PyUnicode_FromFormat("%s", "");
}

/*
* Helper function to LcPy_Read():
* Read memory in a contiguous way with zero padding.
* to be read LcReadScatter() may be more efficient.
* -- hLC
* -- pa
* -- cb
* -- pb
* -- return = TRUE if at least 1 bytes of memory is successfully read.
*/
_Success_(return) BOOL
LeechCorePYC_ReadZeroPad(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb)
{
    // Similar to LcRead implementation but with zero padding:
    QWORD i, o, paBase, cMEMs;
    PPMEM_SCATTER ppMEMs = NULL;
    BOOL fFirst, fLast, f, fResult = FALSE;
    BYTE pbFirst[0x1000] = { 0 }, pbLast[0x1000] = { 0 };
    ZeroMemory(pb, cb);
    if(cb == 0) { return TRUE; }
    cMEMs = ((pa & 0xfff) + cb + 0xfff) >> 12;
    if(cMEMs == 0) { return FALSE; }
    fFirst = (pa & 0xfff) || (cb < 0x1000);
    fLast = (cMEMs > 1) && ((pa + cb) & 0xfff);
    f = LcAllocScatter3(
        fFirst ? pbFirst : NULL,
        fLast ? pbLast : NULL,
        cb - (fFirst ? 0x1000 - (pa & 0xfff) : 0) - (fLast ? (pa + cb) & 0xfff : 0),
        pb + ((pa & 0xfff) ? 0x1000 - (pa & 0xfff) : 0),
        (DWORD)cMEMs,
        &ppMEMs
    );
    if(!f) { goto fail; }
    paBase = pa & ~0xfff;
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i]->qwA = paBase + (i << 12);
    }
    LcReadScatter(hLC, (DWORD)cMEMs, ppMEMs);
    for(i = 0; i < cMEMs; i++) {
        if(ppMEMs[i]->f) {
            fResult = TRUE;
            break;
        }
    }
    if(fFirst) {
        o = pa & 0xfff;
        memcpy(pb, ppMEMs[0]->pb + o, min(cb, 0x1000 - (SIZE_T)o));
    }
    if(fLast) {
        o = ppMEMs[cMEMs - 1]->qwA;
        memcpy(pb + (SIZE_T)(o - pa), ppMEMs[cMEMs - 1]->pb, (SIZE_T)(pa + cb - o));
    }
    fResult = TRUE;
fail:
    LocalFree(ppMEMs);
    return fResult;
}

// (ULONG64, DWORD, (BOOL)) -> PBYTE
static PyObject*
#ifdef LINUX
// for some unexplainable reason 'pa' will always be 0 on some optimization
// levels on linux; but disabling optimization for the function solves issue.
__attribute__((optimize("O0")))
#endif /* LINUX */
LcPy_Read(PyObjectLeechCore *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result, fZeroPadFail = FALSE;
    ULONG64 pa;
    DWORD cb;
    PBYTE pb;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "Kk|p", &pa, &cb, &fZeroPadFail)) { return PyErr_Format(PyExc_RuntimeError, "Illegal arguments."); }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = fZeroPadFail ?
        LeechCorePYC_ReadZeroPad(self->hLC, pa, cb, pb) :
        LcRead(self->hLC, pa, cb, pb);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "Read: Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize((char *)pb, cb);
    LocalFree(pb);
    return pyBytes;
}

// ([ULONG64]) -> [{...}]
static PyObject *
LcPy_ReadScatter(PyObjectLeechCore *self, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyListDst, *pyDict;
    DWORD i, cMEMs;
    PMEM_SCATTER pMEM, *ppMEMs;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "O!", &PyList_Type, &pyListSrc)) { return PyErr_Format(PyExc_RuntimeError, "Illegal argument."); }
    cMEMs = (DWORD)PyList_Size(pyListSrc);
    // verify, allocate & initialize
    if((cMEMs == 0) || !LcAllocScatter1(cMEMs, &ppMEMs)) {
        Py_DECREF(pyListSrc);
        return PyList_New(0);
    }
    for(i = 0; i < cMEMs; i++) {
        pyListItemSrc = PyList_GetItem(pyListSrc, i); // borrowed reference
        if(!pyListItemSrc || !PyLong_Check(pyListItemSrc)) {
            Py_DECREF(pyListSrc);
            LcMemFree(ppMEMs);
            return PyErr_Format(PyExc_RuntimeError, "ReadScatter: Argument list contains non numeric item.");
        }
        ppMEMs[i]->qwA = PyLong_AsUnsignedLongLong(pyListItemSrc) & ~0xfff;
    }
    // call c-dll for LeechCore
    Py_BEGIN_ALLOW_THREADS;
    LcReadScatter(self->hLC, cMEMs, ppMEMs);
    Py_END_ALLOW_THREADS;
    if(!(pyListDst = PyList_New(0))) {
        LcMemFree(ppMEMs);
        return PyErr_NoMemory();
    }
    // parse result
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f && (pyDict = PyDict_New())) {
            PyDict_SetItemString_DECREF(pyDict, "addr", PyLong_FromUnsignedLongLong(pMEM->qwA));
            PyDict_SetItemString_DECREF(pyDict, "data", PyBytes_FromStringAndSize((char*)pMEM->pb, pMEM->cb));
            PyList_Append_DECREF(pyListDst, pyDict);
        }
    }
    LcMemFree(ppMEMs);
    return pyListDst;
}

// (ULONG64, PBYTE, (DWORD)) -> None
static PyObject*
LcPy_Write(PyObjectLeechCore *self, PyObject *args)
{
    BOOL result;
    ULONG64 va;
    PBYTE pb, pbPy;
    SIZE_T cb;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "Ky#", &va, &pbPy, &cb)) { return PyErr_Format(PyExc_RuntimeError, "Illegal argument."); }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    pb = LocalAlloc(0, cb);
    if(!pb) {
        return PyErr_NoMemory();
    }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result = LcWrite(self->hLC, va, (DWORD)cb, pb);
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "Write: Failed."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (ULONG64) -> ULONG64
static PyObject*
LcPy_GetOption(PyObjectLeechCore *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "K", &fOption)) { return PyErr_Format(PyExc_RuntimeError, "Illegal argument."); }
    Py_BEGIN_ALLOW_THREADS;
    result = LcGetOption(self->hLC, fOption, &qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "GetOption: Unable to retrieve value for option."); }
    return PyLong_FromUnsignedLongLong(qwValue);
}

// (ULONG64, ULONG64) -> None
static PyObject*
LcPy_SetOption(PyObjectLeechCore *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "KK", &fOption, &qwValue)) { return PyErr_Format(PyExc_RuntimeError, "Illegal argument."); }
    Py_BEGIN_ALLOW_THREADS;
    result = LcSetOption(self->hLC, fOption, qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "SetOption: Unable to set value for option."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (ULONG64, PBYTE) -> PBYTE
static PyObject*
LcPy_CommandData(PyObjectLeechCore *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    ULONG64 fOption;
    PBYTE pb, pbPy, pbDataOut;
    SIZE_T cb;
    DWORD cbDataOut = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "Ky#", &fOption, &pbPy, &cb)) { return PyErr_Format(PyExc_RuntimeError, "Illegal argument."); }
    if(!(pb = LocalAlloc(0, cb))) { return PyErr_NoMemory(); }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(self->hLC, fOption, (DWORD)cb, pb, &pbDataOut, &cbDataOut);
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "CommandData: Failed."); }
    pyBytes = PyBytes_FromStringAndSize((char*)pbDataOut, cbDataOut);
    LcMemFree(pbDataOut);
    return pyBytes;
}

// -> {'pfn1': {...}, ...}
static PyObject*
LcPy_GetCallStatistics(PyObjectLeechCore *self, void *closure)
{
    BOOL result;
    PyObject *pyDictResult, *pyDict;
    PLC_STATISTICS pLcStatistics = NULL;
    QWORD i, qwFreq, qwCallCount, qwCallTimeAvg_uS, qwCallTimeTotal_uS;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(!(pyDictResult = PyDict_New())) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(self->hLC, LC_CMD_STATISTICS_GET, 0, NULL, (PBYTE*)&pLcStatistics, NULL);
    Py_END_ALLOW_THREADS;
    QueryPerformanceFrequency((PLARGE_INTEGER)&qwFreq);
    if(result && (pLcStatistics->dwVersion == LC_STATISTICS_VERSION) && pLcStatistics->qwFreq) {
        for(i = 0; i <= LC_STATISTICS_ID_MAX; i++) {
            if((pyDict = PyDict_New())) {
                qwCallCount = qwCallTimeAvg_uS = qwCallTimeTotal_uS = 0;
                if(pLcStatistics->Call[i].c) {
                    qwCallCount = pLcStatistics->Call[i].c;
                    qwCallTimeTotal_uS = (pLcStatistics->Call[i].tm * 1000000ULL) / qwFreq;
                    qwCallTimeAvg_uS = (qwCallTimeTotal_uS / qwCallCount);
                }
                PyDict_SetItemString_DECREF(pyDict, "name", PyUnicode_FromFormat("%s", LC_STATISTICS_NAME[i]));
                PyDict_SetItemString_DECREF(pyDict, "count", PyLong_FromUnsignedLongLong(qwCallCount));
                PyDict_SetItemString_DECREF(pyDict, "us_tot", PyLong_FromUnsignedLongLong(qwCallTimeTotal_uS));
                PyDict_SetItemString_DECREF(pyDict, "us_avg", PyLong_FromUnsignedLongLong(qwCallTimeAvg_uS));
                PyDict_SetItemString_DECREF(pyDictResult, LC_STATISTICS_NAME[i], pyDict);
            }
        }
    }
    LocalFree(pLcStatistics);
    return pyDictResult;
}

// -> LONG
static PyObject *
LcPy_GetMaxAddr(PyObjectLeechCore *self, void *closure)
{
    BOOL result;
    QWORD pa;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    Py_BEGIN_ALLOW_THREADS;
    result = LcGetOption(self->hLC, LC_OPT_CORE_ADDR_MAX, &pa);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "Unable to retrieve max address.");
    }
    return PyLong_FromUnsignedLongLong(pa);
}

// -> [{'base': int, 'size': int, 'offset': int}, ...]
static PyObject*
LcPy_GetMemMap(PyObjectLeechCore *self, void *closure)
{
    PyObject *pyList, *pyDictEntry;
    PLC_MEMMAP_ENTRY pMemMap;
    DWORD i, cb, cMemMap;
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(!(pyList = PyList_New(0))) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(self->hLC, LC_CMD_MEMMAP_GET_STRUCT, 0, NULL, (PBYTE*)&pMemMap, &cb);
    Py_END_ALLOW_THREADS;
    if(result) {
        cMemMap = cb / sizeof(LC_MEMMAP_ENTRY);
        for(i = 0; i < cMemMap; i++) {
            if((pyDictEntry = PyDict_New())) {
                PyDict_SetItemString_DECREF(pyDictEntry, "base", PyLong_FromUnsignedLongLong(pMemMap[i].pa));
                PyDict_SetItemString_DECREF(pyDictEntry, "size", PyLong_FromUnsignedLongLong(pMemMap[i].cb));
                PyDict_SetItemString_DECREF(pyDictEntry, "offset", PyLong_FromUnsignedLongLong(pMemMap[i].paRemap));
                PyList_Append_DECREF(pyList, pyDictEntry);
            }
        }
    }
    return pyList;
}

// [{'base': int, 'size': int, 'offset': int}, ...]
static int
LcPy_SetMemMap(PyObjectLeechCore *self, PyObject *pyRuns, void *closure)
{
    PyObject *pyMemEntry, *pyMemValue;
    LPSTR sz = NULL;
    BOOL fResult = FALSE;
    QWORD paCurrent = 0;
    QWORD qwAddr, qwSize, qwRemap;
    DWORD i, cMemMap, cch = 0;
    // validate & setup:
    if(!self->fValid) { goto fail; }
    if(!PyObject_TypeCheck(pyRuns, &PyList_Type)) { goto fail; }
    if(!(cMemMap = (DWORD)PyList_Size(pyRuns))) { goto fail; }
    if(!(sz = LocalAlloc(LMEM_ZEROINIT, cMemMap * 64ULL + 1))) { goto fail; }
    // create text memmap:
    for(i = 0; i < cMemMap; i++) {
        pyMemEntry = PyList_GetItem(pyRuns, i); // borrowed reference
        if(!pyMemEntry || !PyObject_TypeCheck(pyMemEntry, &PyDict_Type)) { goto fail; }
        {
            pyMemValue = PyDict_GetItemString(pyMemEntry, "base");      // borrowed reference
            if(!pyMemValue || !PyLong_Check(pyMemValue)) { goto fail; }
            qwAddr = PyLong_AsUnsignedLongLong(pyMemValue);
        }
        {
            pyMemValue = PyDict_GetItemString(pyMemEntry, "size");      // borrowed reference
            if(!pyMemValue || !PyLong_Check(pyMemValue)) { goto fail; }
            qwSize = PyLong_AsUnsignedLongLong(pyMemValue);
        }
        {
            pyMemValue = PyDict_GetItemString(pyMemEntry, "offset");    // borrowed reference
            if(!pyMemValue || !PyLong_Check(pyMemValue)) { goto fail; }
            qwRemap = PyLong_AsUnsignedLongLong(pyMemValue);
        }
        if((qwAddr < paCurrent) || (qwAddr & 0xfff) || !qwSize || (qwSize & 0xfff)) { goto fail; }
        if(!qwRemap) { qwRemap = qwAddr; }
        paCurrent = qwAddr + qwSize;
        cch += _snprintf_s(sz + cch, 64, 64, "%04x %016llx %016llx %016llx\n", i, qwAddr, qwAddr + qwSize - 1, qwRemap);
    }
    // commit text memmap to leechcore:
    Py_BEGIN_ALLOW_THREADS;
    fResult = LcCommand(self->hLC, LC_CMD_MEMMAP_SET, cch + 1, (PBYTE)sz, NULL, NULL);
    Py_END_ALLOW_THREADS;
fail:
    LocalFree(sz);
    if(!fResult) {
        PyErr_SetString(PyExc_TypeError, "Cannot set memory map attribute");
        return -1;
    }
    return 0;
}

/*
* Helper function to LcPy_SetKeepalive():
* Keep alive thread for the FPGA. A user may set the is_keepalive attribute to
* TRUE and then a keepalive thread will be running reading data every 2s.
* NB! if the python type object is destroyed hLC will be invalid - this
* should however be gracefully handled by the underlying leechcore library.
*/
DWORD LeechCorePYC_KeepaliveThread(_In_ PHANDLE ctx)
{
    HANDLE hLC;
    QWORD pa, c = 0;
    BYTE pb[0x1000] = { 0 };
    while((hLC = *ctx)) {
        if(0 == (++c % 20)) {   // 100ms * 20 == 2s
            if(LcGetOption(hLC, LC_OPT_CORE_ADDR_MAX, &pa)) {
                LcRead(hLC, (pa - 1) & ~0xfff, 0x1000, pb);
            }
        }
        Sleep(100);
    }
    LocalFree(ctx);
    return 1;
}

// [{'base': int, 'size': int, 'offset': int}, ...]
static int
LcPy_SetKeepalive(PyObjectLeechCore *self, PyObject *pyKeepalive, void *closure)
{
    HANDLE hThread;
    BOOL fResult = FALSE;
    if(!self->fValid || !PyBool_Check(pyKeepalive)) { goto fail; }
    if(PyObject_IsTrue(pyKeepalive)) {
        if(self->phLCkeepalive) { return 0; }    // keepalive thread already running -> success!
        if(!(self->phLCkeepalive = LocalAlloc(LMEM_ZEROINIT, sizeof(HANDLE)))) { goto fail; }
        *self->phLCkeepalive = self->hLC;
        Py_BEGIN_ALLOW_THREADS;
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LeechCorePYC_KeepaliveThread, self->phLCkeepalive, 0, NULL);
        Py_END_ALLOW_THREADS;
        if(!hThread) {
            LocalFree(self->phLCkeepalive);
            self->phLCkeepalive = NULL;
            goto fail;
        }
        CloseHandle(hThread);
    } else {
        if(self->phLCkeepalive) {
            *self->phLCkeepalive = 0;       // keepalive memory allocation is free'd by keepalive thread
            self->phLCkeepalive = NULL;
        }
    }
    fResult = TRUE;
fail:
    if(!fResult) {
        PyErr_SetString(PyExc_TypeError, "Cannot set is_keepalive attribute");
        return -1;
    }
    return 0;
}

// -> True|False
static PyObject*
LcPy_GetKeepalive(PyObjectLeechCore *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    return PyBool_FromLong(self->phLCkeepalive ? 1 : 0);
}

static PyObject*
LcPy_repr(PyObjectLeechCore *self)
{
    PyObject *pyResult, *pyDictInfo;
    if(!self->fValid || !(pyDictInfo = PyDict_New())) {
        return PyUnicode_FromFormat("LeechCore: Invalid Handle.");
    }
    PyDict_SetItemString_DECREF(pyDictInfo, "device", PyUnicode_FromFormat("%s", self->cfg.szDevice));
    PyDict_SetItemString_DECREF(pyDictInfo, "type", PyUnicode_FromFormat("%s", self->cfg.szDeviceName));
    PyDict_SetItemString_DECREF(pyDictInfo, "remote", PyUnicode_FromFormat("%s", self->cfg.szRemote));
    PyDict_SetItemString_DECREF(pyDictInfo, "maxaddr", PyLong_FromUnsignedLongLong(self->cfg.paMax));
    pyResult = PyObject_Repr(pyDictInfo);
    Py_DECREF(pyDictInfo);
    return pyResult;
}

/*
* Initialize the object type - i.e. open up a handle to the leechcore library.
*/
static int
LcPy_init(PyObjectLeechCore *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = { "device", "remote", "flags", "maxaddr", NULL };
    QWORD paMax = 0;
    DWORD dwFlags = 0;
    LPSTR szDevice = NULL, szRemote = NULL;
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    ZeroMemory(&self->cfg, sizeof(LC_CONFIG));
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|skK", kwlist, &szDevice, &szRemote, &dwFlags, &paMax)) {
        PyErr_SetString(PyExc_TypeError, "Illegal argument.");
        return -1;
    }
    if(!szDevice || !szDevice[0]) {
        PyErr_SetString(PyExc_TypeError, "Required argument device is missing.");
        return -1;
    }
    Py_BEGIN_ALLOW_THREADS;
    self->cfg.dwVersion = LC_CONFIG_VERSION;
    self->cfg.dwPrintfVerbosity = (WORD)dwFlags;
    self->cfg.paMax = paMax;
    strncpy_s(self->cfg.szDevice, sizeof(self->cfg.szDevice) - 1, szDevice, _TRUNCATE);
    if(szRemote) { strncpy_s(self->cfg.szRemote, sizeof(self->cfg.szRemote) - 1, szRemote, _TRUNCATE); }
    self->hLC = LcCreateEx(&self->cfg, &pLcErrorInfo);
    Py_END_ALLOW_THREADS;
    if(!self->hLC) {
        if(pLcErrorInfo && (pLcErrorInfo->dwVersion == LC_CONFIG_ERRORINFO_VERSION) && pLcErrorInfo->cwszUserText) {
            g_LEECHCORE_LAST_ERRORINFO = pLcErrorInfo;
        } else {
            LcMemFree(pLcErrorInfo);
        }
        PyErr_SetString(PyExc_TypeError, "Unable to initialize.");
        return -1;
    }
    self->fValid = TRUE;
    return 0;
}

static void
LcPy_dealloc(PyObjectLeechCore *self)
{
    self->fValid = FALSE;
    Py_BEGIN_ALLOW_THREADS;
    if(self->phLCkeepalive) { *self->phLCkeepalive = 0; }     // keepalive memory allocation is free'd by keepalive thread
    LcClose(self->hLC);
    self->hLC = 0;
    Py_END_ALLOW_THREADS;
}

// () -> None
static PyObject*
LcPy_Close(PyObjectLeechCore *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    LcPy_dealloc(self);
    return Py_BuildValue("s", NULL);    // None returned on success.
}

/*
* Initialize the LeechCore Python Type Object.
* -- pModule
* -- return
*/
_Success_(return)
BOOL LcPy_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"close", (PyCFunction)LcPy_Close, METH_VARARGS, "Close the leechcore connection/handle"},
        {"read_scatter", (PyCFunction)LcPy_ReadScatter, METH_VARARGS, "Read scatter 4kB memory pages"},
        {"read", (PyCFunction)LcPy_Read, METH_VARARGS, "Read contigious memory"},
        {"write", (PyCFunction)LcPy_Write, METH_VARARGS, "Write memory"},
        {"get_option", (PyCFunction)LcPy_GetOption, METH_VARARGS, "Get option value"},
        {"set_option", (PyCFunction)LcPy_SetOption, METH_VARARGS, "Set option value"},
        {"command_data", (PyCFunction)LcPy_CommandData, METH_VARARGS, "Send/Receive command/data"},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"device", T_STRING_INPLACE, offsetof(PyObjectLeechCore, cfg.szDevice), READONLY, "device string"},
        {"remote", T_STRING_INPLACE, offsetof(PyObjectLeechCore, cfg.szRemote), READONLY, "remote string"},
        {"type", T_STRING_INPLACE, offsetof(PyObjectLeechCore, cfg.szDeviceName), READONLY, "device type string"},
        {"is_volatile", T_BOOL, offsetof(PyObjectLeechCore, cfg.fVolatile), READONLY, "memory is volatile"},
        {"is_writable", T_BOOL, offsetof(PyObjectLeechCore, cfg.fWritable), READONLY, "memory is writable"},
        {"is_remote", T_BOOL, offsetof(PyObjectLeechCore, cfg.fRemote), READONLY, "memory is remote"},
        {"is_remote_nocompress", T_BOOL, offsetof(PyObjectLeechCore, cfg.fRemoteDisableCompress), READONLY, "remote connection compression disabled"},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"maxaddr", (getter)LcPy_GetMaxAddr, (setter)NULL, "max physical address", NULL},
        {"memmap", (getter)LcPy_GetMemMap, (setter)LcPy_SetMemMap, "memory map", NULL},
        {"call_statistics", (getter)LcPy_GetCallStatistics, (setter)NULL, "memory map", NULL},
        {"is_keepalive", (getter)LcPy_GetKeepalive, (setter)LcPy_SetKeepalive, "keepalive enable/disable", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, LcPy_init},
        {Py_tp_dealloc, LcPy_dealloc},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {Py_tp_repr, LcPy_repr},            // str()
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "leechcorepyc.LeechCore",
        .basicsize = sizeof(PyObjectLeechCore),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyTypeObjectLeechCore = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "LeechCore", g_pPyTypeObjectLeechCore) < 0) {
            Py_DECREF(g_pPyTypeObjectLeechCore);
            g_pPyTypeObjectLeechCore = NULL;
        }
    }
    return g_pPyTypeObjectLeechCore ? TRUE : FALSE;
}

/*
* Entry point for the native module 'leechcorepyc'.
*/
EXPORTED_FUNCTION PyObject* PyInit_leechcorepyc(void)
{
    PyObject *pPyModule;
    static PyMethodDef ModuleMethods[] = {
        {"GetLastError", LeechCorePYC_GetLastError, METH_VARARGS, "Retrieve the last error (after failed LeechCore create)."},
        {NULL, NULL, 0, NULL}
    };
    static PyModuleDef ModuleDefinition = {
        PyModuleDef_HEAD_INIT, "leechcorepyc", NULL, -1, ModuleMethods,
        NULL, NULL, NULL, NULL
    };
    pPyModule = PyModule_Create(&ModuleDefinition);
    if(!pPyModule) { return NULL; }
    if(!LcPy_InitializeType(pPyModule)) {
        Py_DECREF(pPyModule);
        return NULL;
    }
    return pPyModule;
}
