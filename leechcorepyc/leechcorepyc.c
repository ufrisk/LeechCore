//	leechcorepyc.c : Implementation of the LeechCore Python API
//
// (c) Ulf Frisk, 2020-2023
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "leechcorepyc.h"

PyObject *g_pPyType_LeechCore = NULL;
PLC_CONFIG_ERRORINFO g_LEECHCORE_LAST_ERRORINFO = NULL;  // will be memory leaked - but it should be very rare.

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


//-----------------------------------------------------------------------------
// LeechCorePYC HELPER FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

/*
* () -> STR
* Retrieve the last error (on create).
*/
static PyObject*
LeechCorePYC_GetLastError(PyObject *self, PyObject *args)
{
#ifdef _WIN32
    return g_LEECHCORE_LAST_ERRORINFO ?
        PyUnicode_FromWideChar(g_LEECHCORE_LAST_ERRORINFO->wszUserText, -1) :
        PyUnicode_FromFormat("%s", "");
#endif /* _WIN32 */
#ifdef LINUX
    return PyUnicode_FromFormat("%s", "");
#endif /* LINUX */ 
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
_Success_(return)
BOOL LeechCorePYC_ReadZeroPad(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb)
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



//-----------------------------------------------------------------------------
// FPGA-ONLY PCIe TLP FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

/*
* LeechCore callback function for read TLP. Callback calls into a Python
* function set by the user when the LeechCore callback was set up.
* NOTE! CALLBACK FUNCTION MUST NEVER CALL LEECHCORE DUE TO RISK OF DEADLOCK!
*/
VOID LcPy_TlpReadCB(PVOID ctx, _In_ DWORD cbTlp, _In_ PBYTE pbTlp, _In_opt_ DWORD cbInfo, _In_opt_ LPSTR szInfo)
{
    PyObj_LeechCore *self = (PyObj_LeechCore*)ctx;
    PyGILState_STATE gstate;
    PyObject *pyReturn, *pyArgs = NULL;
    gstate = PyGILState_Ensure();
    if(!cbTlp || !self || !self->fnTlpReadCB) { goto cleanup; }
    pyArgs = Py_BuildValue("y#s", pbTlp, cbTlp, szInfo);
    pyReturn = PyObject_CallObject(self->fnTlpReadCB, pyArgs);
    Py_XDECREF(pyArgs);
    Py_XDECREF(pyReturn);
cleanup:
    PyGILState_Release(gstate);
}

// (FUNCTION_CALLBACK, (BOOL, BOOL)) -> None
static PyObject*
LcPy_TlpRead(PyObj_LeechCore *self, PyObject *args)
{
    PyObject *pyCallback = NULL, *pyCallbackOld = NULL;
    BOOL fCallback = FALSE, fFilterCpl = FALSE, fThread = FALSE;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "tlp_read: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "|Opp", &pyCallback, &fFilterCpl, &fThread)) { return PyErr_Format(PyExc_RuntimeError, "tlp_read: Illegal argument."); }    // borrowed reference
    fCallback = PyCallable_Check(pyCallback);
    if(fCallback) {
        pyCallbackOld = self->fnTlpReadCB;
        self->fnTlpReadCB = pyCallback;
        Py_XINCREF(pyCallback);
        Py_XDECREF(pyCallbackOld);
    }
    // call c-dll for LeechCore
    Py_BEGIN_ALLOW_THREADS;
    if(fCallback) {
        LcSetOption(self->hLC, LC_OPT_FPGA_TLP_READ_CB_WITHINFO, 1);
        LcSetOption(self->hLC, LC_OPT_FPGA_TLP_READ_CB_FILTERCPL, fFilterCpl ? 1 : 0);
        LcCommand(self->hLC, LC_CMD_FPGA_TLP_CONTEXT, 0, (PBYTE)self, NULL, 0);
        LcCommand(self->hLC, LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, (PBYTE)LcPy_TlpReadCB, NULL, 0);
    } else {
        LcCommand(self->hLC, LC_CMD_FPGA_TLP_CONTEXT, 0, NULL, NULL, 0);
        LcCommand(self->hLC, LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, NULL, NULL, 0);
    }
    Py_END_ALLOW_THREADS;
    if(!fCallback) {
        pyCallbackOld = self->fnTlpReadCB;
        self->fnTlpReadCB = NULL;
        Py_XDECREF(pyCallbackOld);
    }
    Py_RETURN_NONE;
}

// ([PBYTE]) -> None
static PyObject*
LcPy_TlpWrite(PyObj_LeechCore *self, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc;
    DWORD i, cTLPs;
    PLC_TLP pTLPs;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "tlp_write: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "O!", &PyList_Type, &pyListSrc)) { return PyErr_Format(PyExc_RuntimeError, "tlp_write: Illegal argument."); }    // borrowed reference
    cTLPs = (DWORD)PyList_Size(pyListSrc);
    // verify, allocate & initialize
    if((cTLPs == 0) || !(pTLPs = LocalAlloc(LMEM_ZEROINIT, cTLPs * sizeof(LC_TLP)))) {
        Py_RETURN_NONE;
    }
    for(i = 0; i < cTLPs; i++) {
        pyListItemSrc = PyList_GetItem(pyListSrc, i); // borrowed reference
        if(!pyListItemSrc || !PyBytes_Check(pyListItemSrc)) {
            LocalFree(pTLPs);
            return PyErr_Format(PyExc_RuntimeError, "tlp_write: Argument list contains non bytes item.");
        }
        pTLPs[i].cb = (DWORD)PyBytes_Size(pyListItemSrc);
        pTLPs[i].pb = (PBYTE)PyBytes_AsString(pyListItemSrc);
    }
    // call c-dll for LeechCore
    Py_BEGIN_ALLOW_THREADS;
    LcCommand(self->hLC, LC_CMD_FPGA_TLP_WRITE_MULTIPLE, cTLPs * sizeof(LC_TLP), (PBYTE)pTLPs, NULL, NULL);
    LocalFree(pTLPs);
    Py_END_ALLOW_THREADS;
    Py_RETURN_NONE;
}

// (PBYTE) -> STRING
static PyObject*
LcPy_TlpToString(PyObj_LeechCore *self, PyObject *args)
{
    PyObject *pyString;
    PBYTE pb, sz = NULL;
    Py_ssize_t cb;
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "tlp_tostring: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "y#", &pb, &cb)) { return PyErr_Format(PyExc_RuntimeError, "tlp_tostring: Illegal arguments."); }
    if(cb == 0) {
        return PyUnicode_FromFormat("%s", "");
    }
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(self->hLC, LC_CMD_FPGA_TLP_TOSTRING, (DWORD)cb, pb, &sz, NULL);
    Py_END_ALLOW_THREADS;
    if(!result) {
        return PyErr_Format(PyExc_RuntimeError, "tlp_tostring: Failed.");
    }
    pyString = PyUnicode_FromFormat("%s", (LPSTR)sz);
    LcMemFree(sz);
    return pyString;
}



//-----------------------------------------------------------------------------
// FPGA-ONLY PCIe BAR FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

/*
* Helper function to initialize PCIe BAR info.
*/
_Success_(return)
BOOL LcPy_BarInfoFetch(PyObj_LeechCore* self)
{
    PyObject *pyList, *pyDictEntry;
    BOOL result;
    DWORD i;
    PLC_BAR pBarInfo = NULL;
    if(!self->fValid) { return FALSE; }
    if(self->pyBarListAll) { return TRUE; }
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(self->hLC, LC_CMD_FPGA_BAR_INFO, 0, NULL, (PBYTE*)&pBarInfo, NULL) && pBarInfo;
    Py_END_ALLOW_THREADS;
    if(!result) { return FALSE; }
    if(!(pyList = PyList_New(0))) { return FALSE; }
    for(i = 0; i < 6; i++) {
        if(pBarInfo[i].fValid) {
            pyDictEntry = PyDict_New();
            if(!pyDictEntry) {
                Py_DECREF(pyList);
                return FALSE;
            }
            PyDict_SetItemString_DECREF(pyDictEntry, "i_bar", PyLong_FromUnsignedLongLong(pBarInfo[i].iBar));
            PyDict_SetItemString_DECREF(pyDictEntry, "base", PyLong_FromUnsignedLongLong(pBarInfo[i].pa));
            PyDict_SetItemString_DECREF(pyDictEntry, "size", PyLong_FromUnsignedLongLong(pBarInfo[i].cb));
            PyDict_SetItemString_DECREF(pyDictEntry, "is_io", PyBool_FromLong((long)pBarInfo[i].fIO));
            PyDict_SetItemString_DECREF(pyDictEntry, "is_64_bit", PyBool_FromLong((long)pBarInfo[i].f64Bit));
            PyDict_SetItemString_DECREF(pyDictEntry, "is_prefetchable", PyBool_FromLong((long)pBarInfo[i].fPrefetchable));
            PyList_Append(pyList, pyDictEntry);
            self->pyBarDictSingle[i] = pyDictEntry;
        } else {
            PyList_Append(pyList, Py_None);
        }
    }
    self->pyBarListAll = pyList;
    return TRUE;
}

// -> [{...}, ..., {...}]
static PyObject*
LcPy_BarInfo(PyObj_LeechCore *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(self->pyBarListAll || LcPy_BarInfoFetch(self)) {
        Py_IncRef(self->pyBarListAll);
        return self->pyBarListAll;
    }
    return PyErr_Format(PyExc_RuntimeError, "bar_info: failed.");
}

// -> None
static PyObject*
LcPy_BarDisable(PyObj_LeechCore *self, PyObject *args)
{
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(self->fnBarCB) {
        Py_DECREF(self->fnBarCB);
        self->fnBarCB = NULL;
    }
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(self->hLC, LC_CMD_FPGA_BAR_FUNCTION_CALLBACK, 0, (PBYTE)LC_BAR_FUNCTION_CALLBACK_DISABLE, NULL, NULL);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "bar_disable(): failed."); }
    Py_RETURN_NONE;
}

// -> None
static PyObject*
LcPy_BarEnableZero(PyObj_LeechCore *self, PyObject *args)
{
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(self->fnBarCB) {
        Py_DECREF(self->fnBarCB);
        self->fnBarCB = NULL;
    }
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(self->hLC, LC_CMD_FPGA_BAR_FUNCTION_CALLBACK, 0, (PBYTE)LC_BAR_FUNCTION_CALLBACK_ZEROBAR, NULL, NULL);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "bar_enable_zero(): failed."); }
    Py_RETURN_NONE;
}

/*
* Callback function for BAR requests.
* Updating of pReq with read replies is handled inside LcPy_BarRequest object.
*/
VOID LcPy_BarCB(_Inout_ PLC_BAR_REQUEST pReq)
{
    PyObj_LeechCore *self = (PyObj_LeechCore*)pReq->ctx;
    PyObject *pyReturn = NULL, *pyArgs = NULL;
    PyObj_BarRequest *pyLcBarReq = NULL;
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    if(!self || !self->fnBarCB) { goto cleanup; }
    pyLcBarReq = LcPy_BarRequest_InitializeInternal(self, pReq);
    if(!pyLcBarReq) { goto cleanup; }
    pyArgs = Py_BuildValue("OO", self->pyBarDictSingle[pReq->pBar->iBar], pyLcBarReq);
    pyReturn = PyObject_CallObject(self->fnBarCB, pyArgs);
    pyLcBarReq->fValid = FALSE;
cleanup:
    Py_XDECREF(pyArgs);
    Py_XDECREF(pyReturn);
    Py_XDECREF(pyLcBarReq);
    PyGILState_Release(gstate);
}

// -> None
static PyObject*
LcPy_BarEnable(PyObj_LeechCore *self, PyObject *args)
{
    PyObject *pyCallback = NULL;
    BOOL result;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    if(self->fnBarCB) {
        Py_DECREF(self->fnBarCB);
        self->fnBarCB = NULL;
    }
    if(!self->pyBarListAll && !LcPy_BarInfoFetch(self)) { return PyErr_Format(PyExc_RuntimeError, "bar_enable(): failed."); }
    if(!PyArg_ParseTuple(args, "O", &pyCallback)) { return PyErr_Format(PyExc_RuntimeError, "bar_enable: Illegal argument."); }    // borrowed reference
    if(!PyCallable_Check(pyCallback)) { return PyErr_Format(PyExc_RuntimeError, "bar_enable: Callback not callable."); }
    Py_XINCREF(pyCallback);
    self->fnBarCB = pyCallback;
    Py_BEGIN_ALLOW_THREADS;
    result = 
        LcCommand(self->hLC, LC_CMD_FPGA_BAR_CONTEXT, 0, (PBYTE)self, NULL, NULL) &&
        LcCommand(self->hLC, LC_CMD_FPGA_BAR_FUNCTION_CALLBACK, 0, (PBYTE)LcPy_BarCB, NULL, NULL);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "bar_enable(): failed."); }
    Py_RETURN_NONE;
}



//-----------------------------------------------------------------------------
// GENERAL LEECHCORE FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

// (ULONG64, DWORD, (BOOL)) -> PBYTE
static PyObject* LINUX_NO_OPTIMIZE
LcPy_Read(PyObj_LeechCore *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result, fZeroPadFail = FALSE;
    ULONG64 pa;
    DWORD cb;
    PBYTE pb;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "read: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "Kk|p", &pa, &cb, &fZeroPadFail)) { return PyErr_Format(PyExc_RuntimeError, "read: Illegal arguments."); }
    pb = LocalAlloc(0, cb);
    if(!pb) { return PyErr_NoMemory(); }
    Py_BEGIN_ALLOW_THREADS;
    result = fZeroPadFail ?
        LeechCorePYC_ReadZeroPad(self->hLC, pa, cb, pb) :
        LcRead(self->hLC, pa, cb, pb);
    Py_END_ALLOW_THREADS;
    if(!result) {
        LocalFree(pb);
        return PyErr_Format(PyExc_RuntimeError, "read: Failed.");
    }
    pyBytes = PyBytes_FromStringAndSize((char *)pb, cb);
    LocalFree(pb);
    return pyBytes;
}

// ([ULONG64]) -> [{...}]
static PyObject *
LcPy_ReadScatter(PyObj_LeechCore *self, PyObject *args)
{
    PyObject *pyListSrc, *pyListItemSrc, *pyListDst, *pyDict;
    DWORD i, cMEMs;
    PMEM_SCATTER pMEM, *ppMEMs;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "read_scatter: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "O!", &PyList_Type, &pyListSrc)) { return PyErr_Format(PyExc_RuntimeError, "read_scatter: Illegal argument."); } // borrowed reference
    cMEMs = (DWORD)PyList_Size(pyListSrc);
    // verify, allocate & initialize
    if((cMEMs == 0) || !LcAllocScatter1(cMEMs, &ppMEMs)) {
        return PyList_New(0);
    }
    for(i = 0; i < cMEMs; i++) {
        pyListItemSrc = PyList_GetItem(pyListSrc, i); // borrowed reference
        if(!pyListItemSrc || !PyLong_Check(pyListItemSrc)) {
            LcMemFree(ppMEMs);
            return PyErr_Format(PyExc_RuntimeError, "read_scatter: Argument list contains non numeric item.");
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
LcPy_Write(PyObj_LeechCore *self, PyObject *args)
{
    BOOL result;
    ULONG64 va;
    PBYTE pb;
    Py_ssize_t cb;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "write: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "Ky#", &va, &pb, &cb)) { return PyErr_Format(PyExc_RuntimeError, "write: Illegal argument."); }
    if(cb == 0) {
        return Py_BuildValue("s", NULL);    // zero-byte write is always successful.
    }
    Py_BEGIN_ALLOW_THREADS;
    result = LcWrite(self->hLC, va, (DWORD)cb, pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "write: Failed."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (ULONG64) -> ULONG64
static PyObject*
LcPy_GetOption(PyObj_LeechCore *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "get_option: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "K", &fOption)) { return PyErr_Format(PyExc_RuntimeError, "get_option: Illegal argument."); }
    Py_BEGIN_ALLOW_THREADS;
    result = LcGetOption(self->hLC, fOption, &qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "get_option: Unable to retrieve value for option."); }
    return PyLong_FromUnsignedLongLong(qwValue);
}

// (ULONG64, ULONG64) -> None
static PyObject*
LcPy_SetOption(PyObj_LeechCore *self, PyObject *args)
{
    BOOL result;
    ULONG64 fOption, qwValue = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "set_option: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "KK", &fOption, &qwValue)) { return PyErr_Format(PyExc_RuntimeError, "set_option: Illegal argument."); }
    Py_BEGIN_ALLOW_THREADS;
    result = LcSetOption(self->hLC, fOption, qwValue);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "set_option: Unable to set value for option."); }
    return Py_BuildValue("s", NULL);    // None returned on success.
}

// (ULONG64, PBYTE) -> PBYTE
static PyObject*
LcPy_CommandData(PyObj_LeechCore *self, PyObject *args)
{
    PyObject *pyBytes;
    BOOL result;
    ULONG64 fOption;
    PBYTE pb, pbPy, pbDataOut;
    SIZE_T cb;
    DWORD cbDataOut = 0;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "command_data: LeechCore object not initialized."); }
    if(!PyArg_ParseTuple(args, "Ky#", &fOption, &pbPy, &cb)) { return PyErr_Format(PyExc_RuntimeError, "command_data: Illegal argument."); }
    if(!(pb = LocalAlloc(0, cb))) { return PyErr_NoMemory(); }
    memcpy(pb, pbPy, cb);
    Py_BEGIN_ALLOW_THREADS;
    result = LcCommand(self->hLC, fOption, (DWORD)cb, pb, &pbDataOut, &cbDataOut);
    LocalFree(pb);
    Py_END_ALLOW_THREADS;
    if(!result) { return PyErr_Format(PyExc_RuntimeError, "command_data: Failed."); }
    pyBytes = PyBytes_FromStringAndSize((char*)pbDataOut, cbDataOut);
    LcMemFree(pbDataOut);
    return pyBytes;
}

// -> {'pfn1': {...}, ...}
static PyObject*
LcPy_GetCallStatistics(PyObj_LeechCore *self, void *closure)
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
LcPy_GetMaxAddr(PyObj_LeechCore *self, void *closure)
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
LcPy_GetMemMap(PyObj_LeechCore *self, void *closure)
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
LcPy_SetMemMap(PyObj_LeechCore *self, PyObject *pyRuns, void *closure)
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
        PyErr_SetString(PyExc_TypeError, "Cannot set memory map attribute.");
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
LcPy_SetKeepalive(PyObj_LeechCore *self, PyObject *pyKeepalive, void *closure)
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



//-----------------------------------------------------------------------------
// LcPy INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

// -> True|False
static PyObject*
LcPy_GetKeepalive(PyObj_LeechCore *self, void *closure)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LeechCore object not initialized."); }
    return PyBool_FromLong(self->phLCkeepalive ? 1 : 0);
}

static PyObject*
LcPy_repr(PyObj_LeechCore *self)
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
LcPy_init(PyObj_LeechCore *self, PyObject *args, PyObject *kwds)
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
LcPy_dealloc(PyObj_LeechCore *self)
{
    DWORD i;
    self->fValid = FALSE;
    if(self->fnTlpReadCB) {
        Py_BEGIN_ALLOW_THREADS;
        LcCommand(self->hLC, LC_CMD_FPGA_TLP_CONTEXT, 0, NULL, NULL, 0);
        LcCommand(self->hLC, LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, NULL, NULL, 0);
        Sleep(5);
        Py_END_ALLOW_THREADS;
    }
    Py_BEGIN_ALLOW_THREADS;
    if(self->phLCkeepalive) { *self->phLCkeepalive = 0; }     // keepalive memory allocation is free'd by keepalive thread
    LcClose(self->hLC);
    self->hLC = 0;
    Py_END_ALLOW_THREADS;
    Py_XDECREF(self->fnBarCB);
    Py_XDECREF(self->fnTlpReadCB);
    Py_XDECREF(self->pyBarListAll);
    for(i = 0; i < 6; i++) {
        Py_XDECREF(self->pyBarDictSingle[i]);
    }
}

// () -> None
static PyObject*
LcPy_Close(PyObj_LeechCore *self, PyObject *args)
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
        // fpga-only functions below:
        {"bar_disable", (PyCFunction)LcPy_BarDisable, METH_VARARGS, "Disable PCIe BARs."},
        {"bar_enable", (PyCFunction)LcPy_BarEnable, METH_VARARGS, "Enable callback function for PCIe BARs"},
        {"bar_enable_zero", (PyCFunction)LcPy_BarEnableZero, METH_VARARGS, "Enable ZERO/NULL PCIe BARs"},
        {"tlp_tostring", (PyCFunction)LcPy_TlpToString, METH_VARARGS, "Convert binary PCIe TLP to string"},
        {"tlp_read", (PyCFunction)LcPy_TlpRead, METH_VARARGS, "Read PCIe TLPs using callback function"},
        {"tlp_write", (PyCFunction)LcPy_TlpWrite, METH_VARARGS, "Write a number of raw PCIe TLPs"},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {"device", T_STRING_INPLACE, offsetof(PyObj_LeechCore, cfg.szDevice), READONLY, "device string"},
        {"remote", T_STRING_INPLACE, offsetof(PyObj_LeechCore, cfg.szRemote), READONLY, "remote string"},
        {"type", T_STRING_INPLACE, offsetof(PyObj_LeechCore, cfg.szDeviceName), READONLY, "device type string"},
        {"is_volatile", T_BOOL, offsetof(PyObj_LeechCore, cfg.fVolatile), READONLY, "memory is volatile"},
        {"is_writable", T_BOOL, offsetof(PyObj_LeechCore, cfg.fWritable), READONLY, "memory is writable"},
        {"is_remote", T_BOOL, offsetof(PyObj_LeechCore, cfg.fRemote), READONLY, "memory is remote"},
        {"is_remote_nocompress", T_BOOL, offsetof(PyObj_LeechCore, cfg.fRemoteDisableCompress), READONLY, "remote connection compression disabled"},
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"bar_info", (getter)LcPy_BarInfo, (setter)NULL, "pcie bar information", NULL},
        {"call_statistics", (getter)LcPy_GetCallStatistics, (setter)NULL, "memory map", NULL},
        {"is_keepalive", (getter)LcPy_GetKeepalive, (setter)LcPy_SetKeepalive, "keepalive enable/disable", NULL},
        {"maxaddr", (getter)LcPy_GetMaxAddr, (setter)NULL, "max physical address", NULL},
        {"memmap", (getter)LcPy_GetMemMap, (setter)LcPy_SetMemMap, "memory map", NULL},
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
        .basicsize = sizeof(PyObj_LeechCore),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_LeechCore = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "LeechCore", g_pPyType_LeechCore) < 0) {
            Py_DECREF(g_pPyType_LeechCore);
            g_pPyType_LeechCore = NULL;
        }
    }
    return g_pPyType_LeechCore ? TRUE : FALSE;
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
    if(!LcPy_BarRequest_InitializeType(pPyModule)) {
        Py_DECREF(pPyModule);
        return NULL;
    }
    return pPyModule;
}
