//	leechcorepyc.c : Implementation of the LeechCore Python API
//
// (c) Ulf Frisk, 2019
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
#include "leechcore.h"

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
    QWORD paMax = 0, cbMaxSizeMemIo = 0;
    LPSTR szDevice = NULL, szRemote = NULL;
    LEECHCORE_CONFIG cfg = { 0 };
    if(!PyArg_ParseTuple(args, "ss|kKK", &szDevice, &szRemote, &dwFlags, &paMax, &cbMaxSizeMemIo)) { return NULL; }
    if(!szDevice || !szDevice[0]) {
        return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_Open: Required argument 'device' is missing.");
    }
    Py_BEGIN_ALLOW_THREADS;
    cfg.magic = LEECHCORE_CONFIG_MAGIC;
    cfg.version = LEECHCORE_CONFIG_VERSION;
    cfg.flags = (WORD)dwFlags;
    cfg.paMax = paMax;
    cfg.cbMaxSizeMemIo = cbMaxSizeMemIo;
    strncpy_s(cfg.szDevice, sizeof(cfg.szDevice), szDevice, _TRUNCATE);
    if(szRemote) { strncpy_s(cfg.szRemote, sizeof(cfg.szRemote), szRemote, _TRUNCATE); }
    result = LeechCore_Open(&cfg);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_Open: Failed.");
    }
    if(!(pyDict = PyDict_New())) { return PyErr_NoMemory(); }
    PyDict_SetItemString(pyDict, "flags", PyLong_FromLong((long)cfg.flags));
    PyDict_SetItemString(pyDict, "paMax", PyLong_FromUnsignedLongLong(cfg.paMax));
    PyDict_SetItemString(pyDict, "cbMaxSizeMemIo", PyLong_FromUnsignedLongLong(cfg.cbMaxSizeMemIo));
    PyDict_SetItemString(pyDict, "paMaxNative", PyLong_FromUnsignedLongLong(cfg.paMaxNative));
    PyDict_SetItemString(pyDict, "tpDevice", PyLong_FromLong((long)cfg.tpDevice));
    PyDict_SetItemString(pyDict, "fWritable", PyBool_FromLong(cfg.fWritable ? 1 : 0));
    PyDict_SetItemString(pyDict, "fVolatile", PyBool_FromLong(cfg.fVolatile ? 1 : 0));
    PyDict_SetItemString(pyDict, "fVolatileMaxAddress", PyBool_FromLong(cfg.fVolatileMaxAddress ? 1 : 0));
    PyDict_SetItemString(pyDict, "fRemote", PyBool_FromLong(cfg.fRemote ? 1 : 0));
    PyDict_SetItemString(pyDict, "VersionMajor", PyLong_FromLong((long)cfg.VersionMajor));
    PyDict_SetItemString(pyDict, "VersionMinor", PyLong_FromLong((long)cfg.VersionMinor));
    PyDict_SetItemString(pyDict, "VersionRevision", PyLong_FromLong((long)cfg.VersionRevision));
    PyDict_SetItemString(pyDict, "device", PyUnicode_FromFormat("%s", cfg.szDevice));
    PyDict_SetItemString(pyDict, "remote", PyUnicode_FromFormat("%s", cfg.szRemote));
    return pyDict;
}

// () -> None
static PyObject*
LEECHCOREPYC_Close(PyObject *self, PyObject *args)
{
    Py_BEGIN_ALLOW_THREADS;
    LeechCore_Close();
    Py_END_ALLOW_THREADS;
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// ([ULONG64]) -> [{...}]
static PyObject*
LEECHCOREPYC_ReadScatter(PyObject *self, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyListDst, *pyDict;
    BOOL result;
    QWORD pa;
    DWORD i, cMEMs;
    PMEM_IO_SCATTER_HEADER pMEM, *ppMEMs;
    if(!PyArg_ParseTuple(args, "O!", &PyList_Type, &pyListSrc)) { return NULL; }
    cMEMs = (DWORD)PyList_Size(pyListSrc);
    if(cMEMs == 0) {
        Py_DECREF(pyListSrc);
        return PyList_New(0);
    }
    // allocate & initialize
    result = LeechCore_AllocScatterEmpty(cMEMs, &ppMEMs);
    for(i = 0; i < cMEMs; i++) {
        pyListItemSrc = PyList_GetItem(pyListSrc, i); // borrowed reference
        if(!pyListItemSrc || !PyLong_Check(pyListItemSrc)) {
            Py_DECREF(pyListSrc);
            LocalFree(ppMEMs);
            return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_ReadScatter: Argument list contains non numeric item.");
        }
        pa = PyLong_AsUnsignedLongLong(pyListItemSrc);
        ppMEMs[i]->qwA = PyLong_AsUnsignedLongLong(pyListItemSrc) & ~0xfff;
    }
    // call c-dll for LeechCore
    Py_BEGIN_ALLOW_THREADS;
    LeechCore_ReadScatter(ppMEMs, cMEMs);
    Py_END_ALLOW_THREADS;
    if(!(pyListDst = PyList_New(0))) {
        LocalFree(ppMEMs);
        return PyErr_NoMemory();
    }
    // parse result
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if((pyDict = PyDict_New())) {
            PyDict_SetItemString(pyDict, "addr", PyLong_FromUnsignedLongLong(pMEM->qwA));
            PyDict_SetItemString(pyDict, "data", PyBytes_FromStringAndSize(pMEM->pb, pMEM->cb));
            PyList_Append(pyListDst, pyDict);
        }
    }
    LocalFree(ppMEMs);
    return pyListDst;
}

// (ULONG64, DWORD, (DWORD)) -> PBYTE
static PyObject*
LEECHCOREPYC_Read(PyObject *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    DWORD cb, cbRead = 0, flags = 0;
    ULONG64 pa;
    PBYTE pb;
    if(!PyArg_ParseTuple(args, "Kk|K", &pa, &cb, &flags)) { return NULL; }
    if(cb > 0x01000000) { return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_Read: Read larger than maxium supported 16MB requested."); }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = LeechCore_ReadEx(pa, pb, cb, flags, NULL);
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
    DWORD flags = 0;
    if(!PyArg_ParseTuple(args, "Ky#|k", &va, &pbPy, &cb, &flags)) { return NULL; }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    pb = LocalAlloc(0, cb);
    if(!pb) {
        return PyErr_NoMemory();
    }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result = LeechCore_WriteEx(va, pb, (DWORD)cb, flags);
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
    result = LeechCore_GetOption(fOption, &qwValue);
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
    result = LeechCore_SetOption(fOption, qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_SetOption: Unable to set value for option."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (ULONG64, PBYTE, (DWORD)) -> PBYTE
static PyObject*
LEECHCOREPYC_CommandData(PyObject *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    ULONG64 fOption;
    PBYTE pb, pbPy, pbDataOut;
    SIZE_T cb;
    DWORD cbDataOut = 0;
    if(!PyArg_ParseTuple(args, "Ky#|k", &fOption, &pbPy, &cb, &cbDataOut)) { return NULL; }
    if(!cbDataOut || (cbDataOut > 0x01000000)) { cbDataOut = 0x01000000; }
    pb = LocalAlloc(0, cb);
    if(!pb) {
        return PyErr_NoMemory();
    }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    pbDataOut = LocalAlloc(0, cbDataOut);
    result = pbDataOut && LeechCore_CommandData(fOption, pb, (DWORD)cb, pbDataOut, cbDataOut, &cbDataOut);
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "LEECHCOREPYC_CommandData: Failed."); }
    pyBytes = PyBytes_FromStringAndSize(pbDataOut, cbDataOut);
    LocalFree(pbDataOut);
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

__declspec(dllexport) PyObject* PyInit_leechcorepyc(void)
{
    return PyModule_Create(&LEECHCOREPYC_Module);
}
