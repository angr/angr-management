"""
Running code on the Textual UI thread.

:class:`TextualExecutor` is the ``GlobalInfo.executor`` of the terminal frontend. The UI thread is the thread that runs
the Textual app's event loop; callables scheduled from other threads are posted to that loop with
``call_soon_threadsafe``. A callable that returns a :class:`Deferred` (a UI service waiting for the user, say) completes
when the deferred future does, so a worker thread can wait for an answer without the loop blocking.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

_l = logging.getLogger(__name__)


class Deferred:
    """A result that is not there yet: ``future`` resolves to it on the UI loop."""

    __slots__ = ("default", "future")

    def __init__(self, future: asyncio.Future, default: Any = None) -> None:
        self.future = future
        self.default = default


class _Call:
    """A callable waiting to run on the UI loop, and its outcome."""

    __slots__ = ("args", "blocking", "done", "exception", "func", "kwargs", "result")

    def __init__(self, func: Callable[..., Any], args, kwargs, blocking: bool) -> None:
        self.func = func
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.blocking = blocking
        self.done = threading.Event()
        self.result: Any = None
        self.exception: BaseException | None = None

    def succeed(self, result: Any) -> None:
        self.result = result
        self.done.set()

    def fail(self, exception: BaseException) -> None:
        self.exception = exception
        if not self.blocking:
            _l.error("Exception occurred in an async job:", exc_info=exception)
        self.done.set()


class TextualExecutor:
    """
    The executor of the terminal frontend.

    The thread that creates it is the UI thread until :meth:`attach` is called on the thread that runs the event
    loop. Calls made before the loop is attached wait and run when it is.
    """

    def __init__(self) -> None:
        self._owner = threading.get_ident()
        self._loop: asyncio.AbstractEventLoop | None = None
        # the context of the UI loop (Textual keeps the active app in a context variable)
        self._context: contextvars.Context | None = None
        self._pending: list[_Call] = []
        self._lock = threading.Lock()
        #: whether the callable running now was scheduled by a thread that waits for its result
        self.serving_blocking_call = False

    def attach(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Run scheduled callables on ``loop`` (the running loop by default); the calling thread is the UI thread."""
        self._owner = threading.get_ident()
        loop = loop if loop is not None else asyncio.get_running_loop()
        with self._lock:
            self._loop = loop
            self._context = contextvars.copy_context()
            pending, self._pending = self._pending, []
        for call in pending:
            loop.call_soon(self._run, call, context=self._context.copy())

    def detach(self) -> None:
        """The loop is gone; later calls wait for the next :meth:`attach`."""
        with self._lock:
            self._loop = None

    @property
    def attached(self) -> bool:
        return self._loop is not None

    def is_ui_thread(self) -> bool:
        return threading.get_ident() == self._owner

    def schedule(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        if self.is_ui_thread():
            result = func(*(args or ()), **(kwargs or {}))
            return result.default if isinstance(result, Deferred) else result
        call = _Call(func, args, kwargs, True)
        self._submit(call)
        # like the Qt executor, a call that times out stays queued and still runs later
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
        self._submit(_Call(func, args, kwargs, False))

    def process_pending(self) -> int:  # pylint:disable=no-self-use
        """The event loop runs scheduled callables itself; nothing to do here."""
        return 0

    def _submit(self, call: _Call) -> None:
        with self._lock:
            loop = self._loop
            context = self._context
            if loop is None or context is None:
                self._pending.append(call)
                return
        try:
            # a callback runs in the context of the thread that schedules it unless told otherwise
            loop.call_soon_threadsafe(self._run, call, context=context.copy())
        except RuntimeError:
            # the loop closed under us
            with self._lock:
                self._pending.append(call)

    def _run(self, call: _Call) -> None:
        self.serving_blocking_call = call.blocking
        try:
            result = call.func(*call.args, **call.kwargs)
        except Exception as ex:  # pylint:disable=broad-exception-caught
            call.fail(ex)
            return
        finally:
            self.serving_blocking_call = False
        if isinstance(result, Deferred):

            def on_done(future: asyncio.Future) -> None:
                if future.cancelled():
                    call.succeed(result.default)
                elif future.exception() is not None:
                    call.fail(future.exception())  # type: ignore[arg-type]
                else:
                    call.succeed(future.result())

            result.future.add_done_callback(on_done)
        else:
            call.succeed(result)
