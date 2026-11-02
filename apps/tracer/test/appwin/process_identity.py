"""Role: read a macOS PID's kernel birth timestamp for safe app cleanup (#146)."""
import ctypes
import sys


class ProcBsdInfo(ctypes.Structure):
    """Public proc_bsdinfo fields needed to distinguish reused PIDs."""

    # Keep the full public layout, including fixed MAXCOMLEN arrays and padding.
    _fields_ = [
        ('flags', ctypes.c_uint32), ('status', ctypes.c_uint32), ('xstatus', ctypes.c_uint32),
        ('pid', ctypes.c_uint32), ('ppid', ctypes.c_uint32), ('uid', ctypes.c_uint32), ('gid', ctypes.c_uint32),
        ('ruid', ctypes.c_uint32), ('rgid', ctypes.c_uint32), ('svuid', ctypes.c_uint32), ('svgid', ctypes.c_uint32),
        ('reserved', ctypes.c_uint32), ('command', ctypes.c_char * 16), ('name', ctypes.c_char * 32),
        ('open_files', ctypes.c_uint32), ('process_group', ctypes.c_uint32), ('job_count', ctypes.c_uint32),
        ('tty_device', ctypes.c_uint32), ('tty_process_group', ctypes.c_uint32), ('nice', ctypes.c_int32),
        ('start_seconds', ctypes.c_uint64), ('start_microseconds', ctypes.c_uint64),
    ]


def process_identity(pid):
    """Return the requested PID and kernel microsecond birth time, or no identity."""
    if sys.platform != 'darwin' or pid <= 0:
        return None
    try:
        query = ctypes.CDLL('/usr/lib/libproc.dylib').proc_pidinfo
        query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        query.restype = ctypes.c_int
        info = ProcBsdInfo()
        size = ctypes.sizeof(info)
        read = query(pid, 3, 0, ctypes.byref(info), size)
    except (AttributeError, OSError):
        return None
    if read != size or info.pid != pid or info.start_microseconds >= 1_000_000:
        return None
    return int(info.pid), int(info.start_seconds), int(info.start_microseconds)
