/*
 * _avakill_hooks - C-level audit hooks for AvaKill.
 *
 * Installs an irremovable audit hook via PySys_AddAuditHook() that blocks
 * ctypes and gc introspection -- the two vectors that can defeat Python-level
 * audit hooks.
 *
 * This hook is stored in CPython's internal C linked list, NOT a Python list,
 * making it immune to ctypes pointer arithmetic or gc.get_objects() clearing.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>
#include <string.h>

/* Blocked audit events */
static const char *BLOCKED_EVENTS[] = {
    "ctypes.dlopen",
    "gc.get_objects",
    "gc.get_referrers",
    "gc.get_referents",
    NULL
};

/*
 * Armed flag: when 0, the hook allows all events (so pytest, pydantic,
 * and other libraries can use gc/ctypes during startup). Call arm() from
 * Python to activate blocking.
 */
static int armed = 0;

/*
 * The audit hook callback.
 *
 * Called by CPython for every audit event. Compares the event name
 * against the blocked list using pure C string operations -- no Python
 * objects are allocated or accessed.
 *
 * Returns 0 to allow, -1 to deny (with RuntimeError set).
 */
static int
avakill_audit_hook(const char *event, PyObject *args, void *userData)
{
    (void)args;
    (void)userData;

    if (!armed || event == NULL) {
        return 0;
    }

    for (const char **blocked = BLOCKED_EVENTS; *blocked != NULL; blocked++) {
        if (strcmp(event, *blocked) == 0) {
            PyErr_Format(
                PyExc_RuntimeError,
                "AvaKill: blocked audit event '%s' -- "
                "ctypes and gc introspection are disabled for security",
                event
            );
            return -1;
        }
    }

    return 0;
}

/* Python method: arm() -> None -- activate the hook blocking */
static PyObject *
avakill_arm(PyObject *self, PyObject *args)
{
    (void)self;
    (void)args;
    armed = 1;
    Py_RETURN_NONE;
}

/* Python method: is_active() -> bool -- True if hook is installed */
static PyObject *
avakill_is_active(PyObject *self, PyObject *args)
{
    (void)self;
    (void)args;
    Py_RETURN_TRUE;
}

/* Python method: is_armed() -> bool -- True if blocking is active */
static PyObject *
avakill_is_armed(PyObject *self, PyObject *args)
{
    (void)self;
    (void)args;
    if (armed) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyMethodDef module_methods[] = {
    {
        "arm",
        avakill_arm,
        METH_NOARGS,
        "Activate audit hook blocking. Call after startup initialization."
    },
    {
        "is_active",
        avakill_is_active,
        METH_NOARGS,
        "Return True if C-level audit hooks are installed."
    },
    {
        "is_armed",
        avakill_is_armed,
        METH_NOARGS,
        "Return True if audit hook blocking is armed (active)."
    },
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "_avakill_hooks",
    "C-level audit hooks for AvaKill security hardening.\n\n"
    "Blocks ctypes.dlopen and gc introspection to prevent bypass of\n"
    "Python-level audit hooks. Installed irremovably at import time.\n"
    "Call arm() after initialization to activate blocking.",
    -1,
    module_methods
};

PyMODINIT_FUNC
PyInit__avakill_hooks(void)
{
    /* Disable Python 3.14+ remote code injection (PEP 768) */
#ifdef _WIN32
    _putenv_s("PYTHON_DISABLE_REMOTE_DEBUG", "1");
#else
    setenv("PYTHON_DISABLE_REMOTE_DEBUG", "1", 1);
#endif

    /* Also set in Python's os.environ so it's visible from Python code
     * and inherited by child processes spawned via subprocess */
    {
        PyObject *os_mod = PyImport_ImportModule("os");
        if (os_mod) {
            PyObject *os_environ = PyObject_GetAttrString(os_mod, "environ");
            if (os_environ) {
                PyObject *key = PyUnicode_FromString("PYTHON_DISABLE_REMOTE_DEBUG");
                PyObject *val = PyUnicode_FromString("1");
                if (key && val) {
                    PyObject_SetItem(os_environ, key, val);
                }
                Py_XDECREF(key);
                Py_XDECREF(val);
                Py_DECREF(os_environ);
            }
            Py_DECREF(os_mod);
        }
        PyErr_Clear();  /* Don't fail module init if os.environ update fails */
    }

    /* Install the C-level audit hook -- this is irremovable */
    if (PySys_AddAuditHook(avakill_audit_hook, NULL) < 0) {
        return NULL;
    }

    return PyModule_Create(&module_def);
}
