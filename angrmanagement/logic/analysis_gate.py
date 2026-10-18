"""
Lets the UI thread read what a CFG recovery on the job thread is still changing.

While CFG recovery runs, the views show the partial result as it grows: the linear view disassembles the blocks it
shows, and the graph view lays out a function. The recovery is meanwhile adding blocks to the same functions' graphs
and disassembling with the same capstone handle (``project.arch.capstone``), and neither may be used from two threads
at once. Two threads in one capstone handle crash the process or corrupt each other's instructions (``CsError:
Details are unavailable``, ``ValueError: NULL pointer access``), and reading a function's graph while the recovery
adds to it can make the recovery fail with ``RuntimeError: Already borrowed``.

So the recovery runs inside :meth:`AnalysisGate.running` and calls :meth:`AnalysisGate.pause_point` between its steps,
where it touches neither; the UI thread reads inside :meth:`AnalysisGate.access`, which waits until the recovery
stops at such a point and keeps it stopped until the read is done. A recovery step can be long (making the functions
at the end), so a reader gives up after a short wait, draws what it can without the functions, and draws again later;
:meth:`AnalysisGate.retry_when_done` asks for a call when the recovery is over.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING

from angrmanagement.logic.threads import gui_thread_schedule_async

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_l = logging.getLogger(__name__)

#: How long a reader waits for the running analysis to stop, in seconds. CFG recovery reaches a pause point every
#: few milliseconds while it scans, and at least every 50 ms (its progress notifications).
READ_TIMEOUT = 0.2


class AnalysisGate:
    """
    One analysis thread that changes the knowledge base, and the readers that wait for it to stop between steps.

    Readers on any other thread are granted access one at a time; a reader that holds access may enter again. The
    analysis thread itself always has access. A stop serves the readers that were waiting for it and ends when the
    last of them is done, so a reader that reads again at once waits for the next stop and the analysis goes on in
    between.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        #: the thread of the running analysis
        self._runner: int | None = None
        #: an analysis waits for the current read to end before it starts
        self._starting = False
        #: the analysis is stopped at a pause point for the readers
        self._paused = False
        self._waiting = 0
        #: the thread that has access, and how many times it entered
        self._reader: int | None = None
        self._depth = 0
        #: a reader gave up and the analysis has not stopped since: the next readers give up at once
        self._missed = False
        self._retries: list[Callable[[], object]] = []

    @property
    def busy(self) -> bool:
        """Whether an analysis is running."""
        return self._runner is not None

    @contextmanager
    def running(self) -> Iterator[None]:
        """Run an analysis that changes what the readers read; it must call :meth:`pause_point` between steps."""
        me = threading.get_ident()
        with self._cond:
            # a read that started before the analysis finishes first
            self._starting = True
            self._cond.wait_for(lambda: self._reader is None or self._reader == me)
            self._starting = False
            self._runner = me
            self._paused = False
            self._missed = False
            self._cond.notify_all()
        try:
            yield
        finally:
            with self._cond:
                self._runner = None
                self._paused = False
                self._missed = False
                retries, self._retries = self._retries, []
                self._cond.notify_all()
            for retry in retries:
                gui_thread_schedule_async(_run_retry, args=(retry,))

    def pause_point(self) -> None:
        """
        Called by the analysis between steps: if a reader is waiting, stop until it is done. Cheap when nobody
        waits.
        """
        if not self._waiting and not self._missed:
            return
        with self._cond:
            if self._runner != threading.get_ident():
                return
            self._missed = False
            if not self._waiting:
                return
            self._paused = True
            self._cond.notify_all()
            self._cond.wait_for(lambda: not self._paused)

    def _free(self) -> bool:
        return self._reader is None and not self._starting and (self._runner is None or self._paused)

    def _end_pause_if_served(self) -> None:
        if self._paused and self._waiting == 0 and self._reader is None:
            self._paused = False
        self._cond.notify_all()

    @contextmanager
    def access(self, timeout: float = READ_TIMEOUT) -> Iterator[bool]:
        """
        Read what the analysis changes: yields True with the analysis stopped (or none running), or False when it did
        not stop within ``timeout`` seconds, in which case the caller must not read the functions or disassemble.
        """
        me = threading.get_ident()
        holds = False
        with self._cond:
            if self._reader == me:
                self._depth += 1
                holds = True
            elif self._runner != me:
                if self._free():
                    holds = True
                elif self._runner is not None and self._missed:
                    holds = False
                else:
                    self._waiting += 1
                    self._cond.notify_all()
                    holds = self._cond.wait_for(self._free, timeout)
                    self._waiting -= 1
                    if not holds:
                        self._missed = self._runner is not None
                        # the analysis may have stopped for us just too late; let it go on
                        self._end_pause_if_served()
                if holds and self._reader is None:
                    self._reader = me
                    self._depth = 1
            granted = holds or self._runner == me
        try:
            yield granted
        finally:
            if holds:
                with self._cond:
                    self._depth -= 1
                    if self._depth == 0:
                        self._reader = None
                        self._end_pause_if_served()

    def retry_when_done(self, callback: Callable[[], object]) -> None:
        """Call ``callback`` on the UI thread when the running analysis is over (at once if none is running)."""
        with self._cond:
            if self._runner is not None:
                if callback not in self._retries:
                    self._retries.append(callback)
                return
        gui_thread_schedule_async(_run_retry, args=(callback,))


def _run_retry(callback: Callable[[], object]) -> None:
    try:
        callback()
    except Exception:  # pylint:disable=broad-except
        # the view that asked may be gone by now
        _l.warning("A read deferred until CFG recovery was done failed", exc_info=True)


#: The gate of something with no analysis of its own (a test's stand-in instance): always open.
_OPEN_GATE = AnalysisGate()


def gate_of(instance: object) -> AnalysisGate:
    """``instance``'s gate, or one that is always open when it has none."""
    gate = getattr(instance, "analysis_gate", None)
    return gate if gate is not None else _OPEN_GATE
