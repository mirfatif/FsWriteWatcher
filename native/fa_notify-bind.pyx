from libc.stdlib cimport EXIT_FAILURE

cdef extern from 'fa_notify.c':
    struct fs_event:
        int uid
        int gid
        char *cmd
        char *p_cmd
        char *evt
        char *path

    cdef int start_fs_events(char *mount_path, void (*cb)(fs_event)) noexcept nogil
    cpdef void stop_fs_events() noexcept

    cdef char *EVENT_NAMES[6]

FS_EVENTS = [evt.decode() for evt in EVENT_NAMES]

cdef void fs_evt_cy_cb(fs_event event) noexcept nogil:
    with gil:
        global fs_evt_py_cb
        try:
            fs_evt_py_cb(event)
        except Exception as e:
            global fs_evt_py_cb_exc
            fs_evt_py_cb_exc = e
            stop_fs_events()

def start_fs_events_nat(mount_path, cb_func):
    global fs_evt_py_cb, fs_evt_py_cb_exc
    fs_evt_py_cb = cb_func
    fs_evt_py_cb_exc = None

    cdef char *mp = mount_path
    with nogil:
        if start_fs_events(mp, &fs_evt_cy_cb) == EXIT_FAILURE:
            raise OSError('Filesystem event listener failed')

    if fs_evt_py_cb_exc:
        raise fs_evt_py_cb_exc
