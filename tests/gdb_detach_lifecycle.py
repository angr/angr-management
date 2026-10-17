"""Observe detached fixture and keeper lifetimes across real application exit."""

from __future__ import annotations

import ctypes
import os
import select
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

APPLICATION = """
import sys
from angrmanagement.logic.debugger.gdb import GDBRuntime
runtime = GDBRuntime(timeout=20)
pid = runtime.launch(sys.argv[1])["pid"]
if sys.argv[2] == "stop":
    runtime.stop()
    runtime.close()
else:
    runtime.detach()
    if sys.argv[2] == "reconnect":
        runtime.launch(sys.argv[1])
        runtime.stop()
    if sys.argv[2] != "exit":
        runtime.close()
print(pid, flush=True)
"""


def children() -> list[int]:
    return [int(pid) for pid in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()]


def main() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0):  # PR_SET_CHILD_SUBREAPER, isolated to this observer.
        raise OSError(ctypes.get_errno(), "Cannot observe orphaned target/keeper exit status")
    descriptors = []
    try:
        result = subprocess.run(
            [sys.executable, "-P", "-c", APPLICATION, *sys.argv[1:]],
            capture_output=True,
            text=True,
            timeout=25,
            check=True,
        )
        pid = int(result.stdout.strip())
        if sys.argv[2] == "stop":
            assert not Path(f"/proc/{pid}").exists(), "Stop left its target alive"
            assert not children(), "Stop/close left a helper or debugger child"
            return
        pidfd = os.pidfd_open(pid)
        descriptors.append(pidfd)
        assert not select.select([pidfd], [], [], 0.2)[0], "Detached target died on close/reconnect/application exit"
        keepers = [
            child for child in children() if b"_terminal_keeper.py" in Path(f"/proc/{child}/cmdline").read_bytes()
        ]
        assert len(keepers) == 1, f"Expected one independent terminal keeper, got {keepers}"
        keeper = keepers[0]
        keeperfd = os.pidfd_open(keeper)
        descriptors.append(keeperfd)
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        assert select.select([keeperfd], [], [], 5)[0], "Terminal keeper outlived the target"
        _, status = os.waitpid(keeper, 0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
        deadline = time.monotonic() + 5
        while children() and time.monotonic() < deadline:
            for child in children():
                os.waitpid(child, os.WNOHANG)
            time.sleep(0.01)
        assert not children(), "Debugger descendants were not reaped"
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        for child in children():
            with suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)


if __name__ == "__main__":
    main()
