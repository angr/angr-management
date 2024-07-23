from __future__ import annotations

import contextlib
import threading
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from PySide6.QtCore import QCoreApplication, QEvent

from . import GlobalInfo

if TYPE_CHECKING:
    from collections.abc import Callable

T = TypeVar("T")


class ExecuteCodeEvent(QEvent, Generic[T]):
    """ExecuteCodeEvent represents a custom event that executes a callable on the GUI thread."""

    func: Callable[..., T]
    args: tuple[Any, ...] | None
    kwargs: dict[str, Any] | None
    event: threading.Event
    result: T | None
    exception: Exception | None
    async_: bool

    def __init__(
        self,
        func: Callable[..., T],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
        async_: bool = False,
    ) -> None:
        super().__init__(QEvent.Type.User)
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.event = threading.Event()
        self.result = None
        self.exception = None
        self.async_ = async_

    def execute(self) -> T:
        return self.func(*(self.args or ()), **(self.kwargs or {}))


def is_gui_thread() -> bool:
    """
    :returns: Whether the current thread is the GUI thread.
    """
    return threading.get_ident() == GlobalInfo.gui_thread or GlobalInfo.gui_thread is None


def gui_thread_schedule(
    func: Callable[..., T],
    args: tuple[Any, ...] | None = None,
    timeout: int | None = None,
    kwargs: dict[str, Any] | None = None,
) -> T:
    """
    Schedules the given callable to be executed on the GUI thread. If the current thread is the GUI thread, the callable
    is executed immediately.

    :raises: Any exception raised by the callable.
    :returns: The result of the callable, or None if the callable timed out.
    """
    if is_gui_thread():
        return func(*(args or ()), **(kwargs or {}))

    event = ExecuteCodeEvent(func, args=args, kwargs=kwargs)

    if GlobalInfo.is_test:
        GlobalInfo.add_event_during_test(event)
    else:
        try:
            QCoreApplication.postEvent(GlobalInfo.main_window, event)
        except RuntimeError:
            # the application is exiting and the main window has been destroyed. just let it go
            return None

    event.event.wait(timeout=timeout)  # TODO: unsafe. to be fixed later.
    if not event.event.is_set():
        # it timed out without getting scheduled to execute...
        return None

    if event.exception is not None:
        raise event.exception

    return event.result


def gui_thread_schedule_async(
    func: Callable[..., T], args: tuple[Any, ...] | None = None, kwargs: dict[str, Any] | None = None
) -> None:
    """
    Schedules the given callable to be executed on the GUI thread. If the current thread is the GUI thread, the callable
    is executed immediately. Otherwise, the callable is executed as an event on the GUI thread.

    :returns: None
    """
    if is_gui_thread():
        func(*(args or ()), **(kwargs or {}))
        return

    event = ExecuteCodeEvent(func, args=args, kwargs=kwargs, async_=True)

    if GlobalInfo.is_test:
        GlobalInfo.add_event_during_test(event)
    else:
        with contextlib.suppress(RuntimeError):  # the application is exiting and the main window has been destroyed.
            QCoreApplication.postEvent(GlobalInfo.main_window, event)
