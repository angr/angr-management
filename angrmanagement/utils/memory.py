from __future__ import annotations

import ctypes
import platform
import sys


def release_freed_heap() -> bool:
    """
    Return memory that glibc's allocator keeps after frees (malloc_trim) to the OS. Only glibc on Linux has it.

    :return: True if the heap was trimmed.
    """
    if sys.platform != "linux" or platform.libc_ver()[0] != "glibc":
        return False
    ctypes.CDLL("libc.so.6").malloc_trim(0)
    return True
