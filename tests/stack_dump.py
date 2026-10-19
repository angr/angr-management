"""
Every thread's stack from a test that is about to be killed for running too long.

pytest-timeout prints every thread's stack before it kills a test process, but an xdist worker's output never reaches
the log: all the controller reports is that the worker crashed. So conftest.py has a timer thread write the stacks to a
file shortly before pytest-timeout fires, in a directory the controller made, and the controller prints whatever is
left there at the end of the run. The timer needs the GIL, as pytest-timeout's own timer does, so it writes a tenth of
the timeout before pytest-timeout kills unless something holds the GIL past both. faulthandler would not need the GIL,
but it writes at most 100 threads, newest first, and a test process here can have more, which leaves out the main
thread.
"""

from __future__ import annotations

import os
import sys
import threading
import traceback
import uuid
from pathlib import Path

#: the directory, made by the controller (or the only process) and inherited by every xdist worker
DIRECTORY_VARIABLE = "ANGR_MANAGEMENT_TEST_STACK_DIR"


def thread_stacks() -> str:
    """Every thread's name and Python stack, innermost call last, the main thread first."""
    names = {thread.ident: thread.name for thread in threading.enumerate()}
    main = threading.main_thread().ident
    frames = sorted(sys._current_frames().items(), key=lambda item: item[0] != main)  # pylint:disable=protected-access
    return "\n".join(
        f"Thread {names.get(ident, '?')!r} ({ident}):\n" + "".join(traceback.format_stack(frame))
        for ident, frame in frames
    )


class LateStackDump:
    """One process's pending dump."""

    def __init__(self) -> None:
        self._timer: threading.Timer | None = None
        self._path: Path | None = None

    def arm(self, directory: str | os.PathLike[str], test: str, after: float) -> None:
        """Write every thread's stack to a new file in ``directory`` unless :meth:`disarm` is called within ``after``
        seconds."""
        self.disarm()
        # named for this arm alone: a replacement xdist worker can get a killed worker's pid, and its disarm must not
        # remove the killed worker's dump
        self._path = Path(directory) / f"{os.getpid()}-{uuid.uuid4().hex}.txt"
        self._timer = threading.Timer(after, self._write, (self._path, test, after))
        self._timer.name = "late stack dump"
        self._timer.daemon = True
        self._timer.start()

    def disarm(self) -> None:
        """Cancel the pending dump and remove its file: the test ended, so whatever it wrote is no hang."""
        if self._timer is None:
            return
        self._timer.cancel()
        self._timer.join()
        if self._path is not None:
            self._path.unlink(missing_ok=True)
        self._timer = self._path = None

    @staticmethod
    def _write(path: Path, test: str, after: float) -> None:
        # written aside and renamed, so a process killed while writing leaves no file rather than part of one
        partial = path.with_suffix(".partial")
        stacks = thread_stacks()
        partial.write_text(f"{test} was still running after {after:g} s. Every thread's stack:\n\n{stacks}", "utf-8")
        partial.replace(path)


def left_behind(directory: str | os.PathLike[str]) -> list[str]:
    """The dumps of processes that did not live to disarm them, oldest first."""
    paths = sorted(Path(directory).glob("*.txt"), key=lambda path: path.stat().st_mtime)
    return [path.read_text(encoding="utf-8", errors="replace") for path in paths]
