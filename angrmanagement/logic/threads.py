"""
Running code on the UI thread.

Every frontend has one thread that owns its widgets, the UI thread. Code on other threads (jobs, the MCP server, the
daemon) hands callables to it through ``GlobalInfo.executor``, an object implementing :class:`UIExecutor`. The Qt
frontend installs a ``QtExecutor`` (angrmanagement.ui.qt_executor) that posts Qt events. Headless code gets a
:class:`DirectExecutor`.

In a headless process the thread that owns the DirectExecutor must pump it, by calling ``process_pending()`` (or
``pump()``) while it waits; ``JobManager.join_all_jobs`` does. A thread that blocks in ``schedule`` waits until the
owning thread pumps, so the owning thread must never block on such a thread without pumping.

The module functions below are the original API and delegate to ``GlobalInfo.executor``.
"""

from __future__ import annotations

import functools
import logging
import queue
import threading
import time
from typing import TYPE_CHECKING, Any, Protocol

from . import GlobalInfo

if TYPE_CHECKING:
    from collections.abc import Callable

_l = logging.getLogger(__name__)


class UIExecutor(Protocol):
    """Runs callables on the UI thread of a frontend."""

    def is_ui_thread(self) -> bool:
        """Whether the calling thread is the UI thread."""
        raise NotImplementedError

    def schedule[T](
        self,
        func: Callable[..., T],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> T | None:
        """
        Run ``func`` on the UI thread and return its result, inline when called on the UI thread.

        :raises: Whatever ``func`` raises.
        :returns: The result of ``func``, or None if it did not run within ``timeout`` seconds.
        """
        raise NotImplementedError

    def schedule_async(
        self, func: Callable[..., Any], args: tuple[Any, ...] | None = None, kwargs: dict[str, Any] | None = None
    ) -> None:
        """Run ``func`` on the UI thread without waiting for it; inline when called on the UI thread."""
        raise NotImplementedError

    def process_pending(self) -> int | None:
        """
        On the UI thread, run the callables that are waiting. A no-op for an executor without a queue.

        :returns: How many callables ran, when the executor knows.
        """
        raise NotImplementedError


class _PendingCall:
    """A callable waiting in a DirectExecutor queue, and its outcome."""

    __slots__ = ("func", "args", "kwargs", "async_", "done", "result", "exception")

    def __init__(self, func: Callable[..., Any], args, kwargs, async_: bool) -> None:
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.async_ = async_
        self.done = threading.Event()
        self.result: Any = None
        self.exception: BaseException | None = None

    def run(self) -> None:
        try:
            self.result = self.func(*(self.args or ()), **(self.kwargs or {}))
        except Exception as ex:  # pylint:disable=broad-exception-caught
            self.exception = ex
            if self.async_:
                _l.exception("Exception occurred in an async job:")
        self.done.set()


class DirectExecutor:
    """
    The executor of a headless process.

    The thread that creates it is its UI thread. Callables scheduled from other threads wait in a queue until the UI
    thread calls ``process_pending()`` or ``pump()``; a callable scheduled on the UI thread runs inline.
    """

    def __init__(self) -> None:
        self._owner = threading.get_ident()
        self._queue: queue.SimpleQueue[_PendingCall] = queue.SimpleQueue()

    def is_ui_thread(self) -> bool:
        return threading.get_ident() == self._owner

    def schedule[T](
        self,
        func: Callable[..., T],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> T | None:
        if self.is_ui_thread():
            return func(*(args or ()), **(kwargs or {}))

        call = _PendingCall(func, args, kwargs, False)
        self._queue.put(call)
        # like the Qt executor, a call that times out stays queued and still runs when the UI thread pumps
        if not call.done.wait(timeout=timeout):
            return None
        if call.exception is not None:
            raise call.exception
        return call.result

    def schedule_async(
        self, func: Callable[..., Any], args: tuple[Any, ...] | None = None, kwargs: dict[str, Any] | None = None
    ) -> None:
        if self.is_ui_thread():
            func(*(args or ()), **(kwargs or {}))
            return
        self._queue.put(_PendingCall(func, args, kwargs, True))

    def process_pending(self) -> int:
        """
        Run the callables queued so far, on the UI thread. Callables they queue in turn wait for the next call.

        :returns: How many callables ran; 0 when called on any thread but the UI thread.
        """
        if not self.is_ui_thread():
            return 0
        count = 0
        for _ in range(self._queue.qsize()):
            try:
                call = self._queue.get_nowait()
            except queue.Empty:
                break
            call.run()
            count += 1
        return count

    def pump(self, timeout: float) -> int:
        """
        Wait up to ``timeout`` seconds for a callable to arrive, then run everything queued. UI thread only.

        :returns: How many callables ran.
        """
        if not self.is_ui_thread():
            return 0
        try:
            call = self._queue.get(timeout=timeout)
        except queue.Empty:
            return 0
        call.run()
        return 1 + self.process_pending()

    def pump_until(self, predicate: Callable[[], bool], timeout: float | None = None, interval: float = 0.01) -> bool:
        """
        Pump until ``predicate()`` holds or ``timeout`` seconds pass. UI thread only.

        :returns: Whether the predicate held.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while not predicate():
            if deadline is not None and time.monotonic() >= deadline:
                return False
            self.pump(interval)
        return True


def is_gui_thread() -> bool:
    """
    :returns: Whether the current thread is the GUI thread.
    """
    return GlobalInfo.executor.is_ui_thread()


def needs_gui_thread(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        return gui_thread_schedule(f, args=args, kwargs=kwargs)

    return inner


def gui_thread_schedule[T](
    func: Callable[..., T],
    args: tuple[Any, ...] | None = None,
    timeout: float | None = None,
    kwargs: dict[str, Any] | None = None,
) -> T | None:
    """
    Schedules the given callable to be executed on the GUI thread. If the current thread is the GUI thread, the callable
    is executed immediately.

    :raises: Any exception raised by the callable.
    :returns: The result of the callable, or None if the callable timed out.
    """
    return GlobalInfo.executor.schedule(func, args=args, kwargs=kwargs, timeout=timeout)


def gui_thread_schedule_async[T](
    func: Callable[..., T], args: tuple[Any, ...] | None = None, kwargs: dict[str, Any] | None = None
) -> None:
    """
    Schedules the given callable to be executed on the GUI thread. If the current thread is the GUI thread, the callable
    is executed immediately. Otherwise, the callable is executed as an event on the GUI thread.

    :returns: None
    """
    GlobalInfo.executor.schedule_async(func, args=args, kwargs=kwargs)


def __getattr__(name: str):
    # ExecuteCodeEvent is a Qt event and lives with the Qt executor; resolve its old import path on demand so that
    # importing this module never imports PySide6.
    if name == "ExecuteCodeEvent":
        from angrmanagement.ui.qt_executor import ExecuteCodeEvent  # pylint:disable=import-outside-toplevel

        return ExecuteCodeEvent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
