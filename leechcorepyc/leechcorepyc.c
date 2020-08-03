//	leechcorepyc.c : Implementation of the LeechCore Python API
//
// (c) Ulf Frisk, 2020
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

HANDLE g_hLC = NULL;

inline int PyDict_SetItemString_DECREF(PyObject *dp, const char *key, PyObject *item)
{
    int i = PyDict_SetItemString(dp, key, item);
    Py_XDECREF(item);
    return i;
}

inline int PyList_Append_DECREF(PyObject *dp, PyObject *item)
{
    int i = PyList_Append(dp, item);
    Py_XDECREF(item);
    return i;
}

//-----------------------------------------------------------------------------
// LEECHCORE PYTHON API BELOW:
//-----------------------------------------------------------------------------

// (STR, STR, (DWORD), (ULONG64), (ULONG64)) -> {}
static PyObject*
LEECHCOREPYC_Open(PyObject *self, PyObject *args)
{
    PyObject *pyDict;
    BOOL result;
    DWORD dwFlags = 0;
    QWORD paMax = 0;
    LPSTR szDevice = NULL, szRemote = NULL;
    LC_CONFIG cfg = { 0 };
    if(!PyArg_ParseTuple(args, "ss|kKK", &szDevice, &szRemote, &dwFlags, &paMax)) { return NULL; }
    if(!szDevice || !szDevice[0]) {
        return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_Open: Required argument 'device' is missing.");
    }
    Py_BEGIN_ALLOW_THREADS;
    cfg.dwVersion = LC_CONFIG_VERSION;
    cfg.dwPrintfVerbosity = (WORD)dwFlags;
    cfg.paMax = paMax;
    strncpy_s(cfg.szDevice, sizeof(cfg.szDevice), szDevice, _TRUNCATE);
    if(szRemote) { strncpy_s(cfg.szRemote, sizeof(cfg.szRemote), szRemote, _TRUNCATE); }
    result =
        !g_hLC &&
        (g_hLC = LcCreate(&cfg));
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_Open: Failed.");
    }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    PyDict_SetItemString_DECREF(pyDict, "devicename", PyUnicode_FromFormat("%s", cfg.szDeviceName));
    PyDict_SetItemString_DECREF(pyDict, "device", PyUnicode_FromFormat("%s", cfg.szDevice));
    PyDict_SetItemString_DECREF(pyDict, "remote", PyUnicode_FromFormat("%s", cfg.szRemote));
    return pyDict;
}

// () -> None
static PyObject*
LEECHCOREPYC_Close(PyObject *self, PyObject *args)
{
    Py_BEGIN_ALLOW_THREADS;
    LcClose(g_hLC);
    g_hLC = NULL;
    Py_END_ALLOW_THREADS;
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// ([ULONG64]) -> [{...}]
static PyObject*
LEECHCOREPYC_ReadScatter(PyObject *self, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyListDst, *pyDict;
    QWORD pa;
    DWORD i, cMEMs;
    PMEM_SCATTER pMEM, *ppMEMs;
    if(!PyArg_ParseTuple(args, "O!", &PyList_Type, &pyListSrc)) { return NULL; }
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
            return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_ReadScatter: Argument list contains non numeric item.");
        }
        pa = PyLong_AsUnsignedLongLong(pyListItemSrc);
        ppMEMs[i]->qwA = PyLong_AsUnsignedLongLong(pyListItemSrc) & ~0xfff;
    }
    // call c-dll for LeechCore
    Py_BEGIN_ALLOW_THREADS;
    LcReadScatter(g_hLC, cMEMs, ppMEMs);
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
            PyDict_SetItemString_DECREF(pyDict, "data", PyBytes_FromStringAndSize(pMEM->pb, pMEM->cb));
            PyList_Append_DECREF(pyListDst, pyDict);
        }
    }
    LcMemFree(ppMEMs);
    return pyListDst;
}

// (ULONG64, DWORD) -> PBYTE
static PyObject*
LEECHCOREPYC_Read(PyObject *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    DWORD cb, cbRead = 0;
    ULONG64 pa;
    PBYTE pb;
    if(!PyArg_ParseTuple(args, "Kk", &pa, &cb)) { return NULL; }
    if(cb > 0x01000000) { return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_Read: Read larger than maxium supported 16MB requested."); }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = LcRead(g_hLC, pa, cb, pb);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_Read: Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize(pb, cbRead);
    LocalFree(pb);
    return pyBytes;
}

// (ULONG64, PBYTE, (DWORD)) -> None
static PyObject*
LEECHCOREPYC_Write(PyObject *self, PyObject *args)
{
    BOOL result;
    ULONG64 va;
    PBYTE pb, pbPy;
    SIZE_T cb;
    if(!PyArg_ParseTuple(args, "Ky#", &va, &pbPy, &cb)) { return NULL; }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    pb = LocalAlloc(0, cb);
    if(!pb) {
        return PyErr_NoMemory();
    }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result = LcWrite(g_hLC, va, (DWORD)cb, pb);
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_Write: Failed."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (ULONG64) -> ULONG64
static PyObject*
LEECHCOREPYC_GetOption(PyObject *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!PyArg_ParseTuple(args, "K", &fOption)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = LcGetOption(g_hLC, fOption, &qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_GetOption: Unable to retrieve value for option."); }
    return PyLong_FromUnsignedLongLong(qwValue);
}

// (ULONG64, ULONG64) -> None
static PyObject*
LEECHCOREPYC_SetOption(PyObject *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!PyArg_ParseTuple(args, "KK", &fOption, &qwValue)) { return NULL; }
    Py_BEGIN_ALLOW_THREADS;
    result = LcSetOption(g_hLC, fOption, qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_SetOption: Unable to set value for option."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (ULONG64, PBYTE) -> PBYTE
static PyObject*
LEECHCOREPYC_CommandData(PyObject *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    ULONG64 fOption;
    PBYTE pb, pbPy, pbDataOut;
    SIZE_T cb;
    DWORD cbDataOut = 0;
    if(!PyArg_ParseTuple(args, "Ky#", &fOption, &pbPy, &cb)) { return NULL; }
    pb = LocalAlloc(0, cb);
    if(!pb) {
        return PyErr_NoMemory();
    }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(g_hLC, fOption, (DWORD)cb, pb, &pbDataOut, &cbDataOut);
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_CommandData: Failed."); }
    pyBytes = PyBytes_FromStringAndSize(pbDataOut, cbDataOut);
    LcMemFree(pbDataOut);
    return pyBytes;
}

static PyMethodDef LEECHCOREPYC_Methods[] = {
    {"LEECHCOREPYC_Open", LEECHCOREPYC_Open, METH_VARARGS, "Initialize the LeechCore"},
    {"LEECHCOREPYC_Close", LEECHCOREPYC_Close, METH_VARARGS, "Try close the LeechCore"},
    {"LEECHCOREPYC_ReadScatter", LEECHCOREPYC_ReadScatter, METH_VARARGS, "Read scatter 4kB memory pages"},
    {"LEECHCOREPYC_Read", LEECHCOREPYC_Read, METH_VARARGS, "Read up to 16MB memory"},
    {"LEECHCOREPYC_Write", LEECHCOREPYC_Write, METH_VARARGS, "Write memory"},
    {"LEECHCOREPYC_GetOption", LEECHCOREPYC_GetOption, METH_VARARGS, "Get option value"},
    {"LEECHCOREPYC_SetOption", LEECHCOREPYC_SetOption, METH_VARARGS, "Set option value"},
    {"LEECHCOREPYC_CommandData", LEECHCOREPYC_CommandData, METH_VARARGS, "Send/Receive command/data from python plugin"},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef LEECHCOREPYC_Module = {
    PyModuleDef_HEAD_INIT, "leechcorepyc", NULL, -1, LEECHCOREPYC_Methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_leechcorepyc(void)
{
    return PyModule_Create(&LEECHCOREPYC_Module);
}
