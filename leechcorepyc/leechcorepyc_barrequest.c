// leechcorepyc_barrequest.c : implementation of LeechCore PCIe BAR request.
//
// (c) Ulf Frisk, 2023
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "leechcorepyc.h"

PyObject *g_pPyType_BarRequest = NULL;

// (PBYTE) -> None
static PyObject*
LcPy_BarRequest_Reply(PyObj_BarRequest *self, PyObject *args)
{
    PBYTE pb;
    Py_ssize_t cb;
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.reply(): Not initialized."); }
    if(!self->pReq->fRead) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.reply(): Only possible to reply to read requests."); }
    if(!PyArg_ParseTuple(args, "y#", &pb, &cb)) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.reply(): Illegal argument."); }
    if(cb != self->pReq->cbData) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.reply(): Provided length (%i) does not match required (%i) length.", cb, self->pReq->cbData); }
    memcpy(self->pReq->pbData, pb, cb);
    self->pReq->fReadReply = TRUE;
    Py_RETURN_NONE;
}

// () -> None
static PyObject*
LcPy_BarRequest_ReplyFail(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.reply_fail(): Not initialized."); }
    if(!self->pReq->fRead) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.reply_fail(): Only possible to reply to read requests."); }
    self->pReq->fReadReply = TRUE;
    self->pReq->cbData = 0;
    Py_RETURN_NONE;
}

// -> int
static PyObject*
LcPy_BarRequest_IBar(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.i_bar: Not initialized."); }
    return PyLong_FromLong((long)self->pReq->pBar->iBar);
}

// -> {}
static PyObject*
LcPy_BarRequest_Bar(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.bar: Not initialized."); }
    if(!self->pyLC->pyBarDictSingle[self->pReq->pBar->iBar]) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.bar: Fail."); }
    Py_IncRef(self->pyLC->pyBarDictSingle[self->pReq->pBar->iBar]);
    return self->pyLC->pyBarDictSingle[self->pReq->pBar->iBar];
}

// -> int
static PyObject*
LcPy_BarRequest_BeFirst(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.be_first: Not initialized."); }
    return PyLong_FromLong((long)self->pReq->bFirstBE);
}

// -> int
static PyObject*
LcPy_BarRequest_BeLast(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.be_last: Not initialized."); }
    return PyLong_FromLong((long)self->pReq->bLastBE);
}

// -> int
static PyObject*
LcPy_BarRequest_Tag(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.tag: Not initialized."); }
    return PyLong_FromLong((long)self->pReq->bTag);
}

// -> bool
static PyObject*
LcPy_BarRequest_IsRead(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.is_read: Not initialized."); }
    return PyBool_FromLong((long)self->pReq->fRead);
}

// -> bool
static PyObject*
LcPy_BarRequest_IsWrite(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.is_write: Not initialized."); }
    return PyBool_FromLong((long)self->pReq->fWrite);
}

// -> int
static PyObject*
LcPy_BarRequest_DataOffset(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.data_offset: Not initialized."); }
    return PyLong_FromLongLong(self->pReq->oData);
}

// -> int
static PyObject*
LcPy_BarRequest_DataLength(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.data_length: Not initialized."); }
    return PyLong_FromLong(self->pReq->cbData);
}

// -> bytes
static PyObject*
LcPy_BarRequest_DataWrite(PyObj_BarRequest *self, PyObject *args)
{
    if(!self->fValid) { return PyErr_Format(PyExc_RuntimeError, "LcBarRequest.data_write: Not initialized."); }
    if(!self->pReq->fWrite) {
        Py_RETURN_NONE;
    }
    return PyBytes_FromStringAndSize((const char*)self->pReq->pbData, (Py_ssize_t)self->pReq->cbData);
}



//-----------------------------------------------------------------------------
// LcPy_BarRequest INITIALIZATION AND CORE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

PyObj_BarRequest*
LcPy_BarRequest_InitializeInternal(_In_ PyObj_LeechCore *pyLC, _In_ PLC_BAR_REQUEST pReq)
{
    PyObj_BarRequest *pyObjBarRequest;
    if(!(pyObjBarRequest = PyObject_New(PyObj_BarRequest, (PyTypeObject*)g_pPyType_BarRequest))) { return NULL; }
    Py_INCREF(pyLC); pyObjBarRequest->pyLC = pyLC;
    pyObjBarRequest->pReq = pReq;
    pyObjBarRequest->fValid = TRUE;
    return pyObjBarRequest;
}

static PyObject*
LcPy_BarRequest_repr(PyObj_BarRequest *self)
{
    if(!self->fValid) {
        return PyUnicode_FromFormat("LcBarRequest:NotValid");
    }
    return PyUnicode_FromFormat("LcBarRequest:%i:%s:%x:%x",
        self->pReq->pBar->iBar,
        (self->pReq->fRead ? "Read" : "Write"),
        self->pReq->oData,
        self->pReq->cbData
    );
}

static int
LcPy_BarRequest_init(PyObj_BarRequest *self, PyObject *args, PyObject *kwds)
{
    PyErr_SetString(PyExc_TypeError, "LcBarRequest.init(): Not allowed.");
    return -1;
}

static void
LcPy_BarRequest_dealloc(PyObj_BarRequest *self)
{
    self->fValid = FALSE;
    Py_XDECREF(self->pyLC);
    PyObject_Del(self);
}

_Success_(return)
BOOL LcPy_BarRequest_InitializeType(PyObject *pModule)
{
    static PyMethodDef PyMethods[] = {
        {"reply", (PyCFunction)LcPy_BarRequest_Reply, METH_VARARGS, "Reply to a read request."},
        {"reply_fail", (PyCFunction)LcPy_BarRequest_ReplyFail, METH_VARARGS, "Reply fail/unsupported to a read request."},
        {NULL, NULL, 0, NULL}
    };
    static PyMemberDef PyMembers[] = {
        {NULL}
    };
    static PyGetSetDef PyGetSet[] = {
        {"i_bar", (getter)LcPy_BarRequest_IBar, (setter)NULL, "BAR index.", NULL},
        {"bar", (getter)LcPy_BarRequest_Bar, (setter)NULL, "PCIe BAR information.", NULL},
        {"be_first", (getter)LcPy_BarRequest_BeFirst, (setter)NULL, "First byte enable.", NULL},
        {"be_last", (getter)LcPy_BarRequest_BeLast, (setter)NULL, "Last byte enable.", NULL},
        {"data_offset", (getter)LcPy_BarRequest_DataOffset, (setter)NULL, "Offset of data within BAR.", NULL},
        {"data_length", (getter)LcPy_BarRequest_DataLength, (setter)NULL, "Length of data to read/write.", NULL},
        {"data_write", (getter)LcPy_BarRequest_DataWrite, (setter)NULL, "Data to write (also check byte enables).", NULL},
        {"is_read", (getter)LcPy_BarRequest_IsRead, (setter)NULL, "Is a read request (that should be replied to).", NULL},
        {"is_write", (getter)LcPy_BarRequest_IsWrite, (setter)NULL, "Is a write request.", NULL},
        {"tag", (getter)LcPy_BarRequest_Tag, (setter)NULL, "PCIe TLP tag.", NULL},
        {NULL}
    };
    static PyType_Slot PyTypeSlot[] = {
        {Py_tp_init, LcPy_BarRequest_init},
        {Py_tp_dealloc, LcPy_BarRequest_dealloc},
        {Py_tp_repr, LcPy_BarRequest_repr},
        {Py_tp_methods, PyMethods},
        {Py_tp_members, PyMembers},
        {Py_tp_getset, PyGetSet},
        {0, 0}
    };
    static PyType_Spec PyTypeSpec = {
        .name = "leechcorepyc.LcBarRequest",
        .basicsize = sizeof(PyObj_BarRequest),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = PyTypeSlot,
    };
    if((g_pPyType_BarRequest = PyType_FromSpec(&PyTypeSpec))) {
        if(PyModule_AddObject(pModule, "LcBarRequest", g_pPyType_BarRequest) < 0) {
            Py_DECREF(g_pPyType_BarRequest);
            g_pPyType_BarRequest = NULL;
        }
    }
    return g_pPyType_BarRequest ? TRUE : FALSE;
}
