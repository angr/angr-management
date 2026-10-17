from __future__ import annotations

import codecs
import os
import select
import threading
import time
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
        self._closed.set()
        self._reader.join(timeout=1)
        os.close(self.master)
        os.close(self.slave)
