from __future__ import annotations

import codecs
import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .mi import RuntimeErrorBase

if TYPE_CHECKING:
    from collections.abc import Callable


class InferiorTerminal:
    """Keep inferior I/O separate from GDB's MI command stream."""

    def __init__(self, callback: Callable[[str], None]) -> None:
        if not hasattr(os, "openpty"):
            raise RuntimeErrorBase("Launching an interactive target requires POSIX PTY support; use attach or remote")
        try:
            self.master, self.slave = os.openpty()
        except OSError as exc:
            raise RuntimeErrorBase(f"Cannot create a target terminal: {exc}") from exc
        os.set_blocking(self.master, False)
        self.path = os.ttyname(self.slave)
        self._closed = threading.Event()
        self._callback = callback
        self._reader = threading.Thread(target=self._read, name="gdb-inferior-terminal", daemon=True)
        self._reader.start()

    def _read(self) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while not self._closed.is_set():
            try:
                ready, _, _ = select.select([self.master], [], [], 0.1)
                if ready:
                    data = os.read(self.master, 16384)
                    if not data:
                        return
                    self._callback(decoder.decode(data))
            except (OSError, ValueError):
                return

    def write(self, text: str) -> None:
        if self._closed.is_set():
            raise RuntimeErrorBase("The target terminal is closed")
        if len(text) > 65536:
            raise RuntimeErrorBase("Target input is limited to 65536 characters per request")
        try:
            data = text.encode("utf-8")
            deadline = time.monotonic() + 2
            while data:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeErrorBase("Target input buffer is full; some input may have been delivered")
                _, ready, _ = select.select([], [self.master], [], remaining)
                if not ready:
                    continue
                try:
                    written = os.write(self.master, data)
                except BlockingIOError:
                    continue
                data = data[written:]
        except OSError as exc:
            raise RuntimeErrorBase(f"Cannot write target input: {exc}") from exc

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._reader.join(timeout=1)
        os.close(self.master)
        os.close(self.slave)

    def prepare_detach(self, pid: int) -> subprocess.Popen:
        """Arrange an independent PTY owner before GDB releases a local target."""
        if not hasattr(os, "pidfd_open"):
            raise RuntimeErrorBase("Detaching a launched target requires Linux pidfd support to preserve its terminal")
        try:
            pidfd = os.pidfd_open(pid)
        except OSError as exc:
            raise RuntimeErrorBase(f"Cannot preserve the detached target's terminal: {exc}") from exc
        process = None
        try:
            process = subprocess.Popen(  # pylint:disable=consider-using-with
                [
                    sys.executable,
                    "-P",
                    str(Path(__file__).with_name("_terminal_keeper.py")),
                    str(self.master),
                    str(pidfd),
                ],
                pass_fds=(self.master, pidfd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            assert process.stdout is not None
            ready, _, _ = select.select([process.stdout], [], [], 10)
            if not ready or os.read(process.stdout.fileno(), 1) != b"R":
                raise RuntimeErrorBase("The detached target's terminal keeper did not start; target remains attached")
            process.stdout.close()
            return process
        except (OSError, RuntimeErrorBase) as exc:
            if process is not None:
                self.cancel_detach(process)
            raise RuntimeErrorBase(f"Cannot preserve the detached target's terminal: {exc}") from exc
        finally:
            os.close(pidfd)

    @staticmethod
    def cancel_detach(process: subprocess.Popen) -> None:
        """Reap a keeper after a failed detach while this object still owns the PTY."""
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()

    def finish_detach(self, process: subprocess.Popen) -> None:
        """Release local descriptors; the keeper lives only until the target exits."""
        self.close()
        # Reap while the app lives. On app exit the independent keeper is adopted
        # by the system reaper and continues holding the target's terminal open.
        threading.Thread(target=process.wait, name="gdb-detached-terminal-reaper", daemon=True).start()
