//	leechcorepyc.c : Implementation of the LeechCore Python API
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __LEECHCOREPYC_H__
#define __LEECHCOREPYC_H__

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
#include <leechcore.h>
#include "oscompatibility.h"

extern PyObject *g_pPyType_LeechCore;
extern PyObject *g_pPyType_BarRequest;

typedef struct tdPyObj_LeechCore {
    PyObject_HEAD
    BOOL fValid;
    HANDLE hLC;
    LC_CONFIG cfg;
    PHANDLE phLCkeepalive;
    PyObject *fnBarCB;
    PyObject *fnTlpReadCB;
    PyObject *pyBarDictSingle[6];   // dict of pcie bar info.
    PyObject *pyBarListAll;         // list of pyBarSingle[0..5].
} PyObj_LeechCore;

typedef struct tdPyObj_BarRequest {
    PyObject_HEAD
    BOOL fValid;
    PyObj_LeechCore *pyLC;
    PLC_BAR_REQUEST pReq;
} PyObj_BarRequest;

_Success_(return) BOOL LcPy_BarRequest_InitializeType(PyObject *pModule);

PyObj_BarRequest* LcPy_BarRequest_InitializeInternal(_In_ PyObj_LeechCore *pyLC, _In_ PLC_BAR_REQUEST pReq);

#endif /* __LEECHCOREPYC_H__ */
