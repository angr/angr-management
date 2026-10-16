"""The UI executor of the Qt frontend: callables run on the GUI thread as posted Qt events."""

from __future__ import annotations

import contextlib
import logging
import threading
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QCoreApplication, QEvent, QObject, QThread

from angrmanagement.logic import GlobalInfo

if TYPE_CHECKING:
    from collections.abc import Callable

_l = logging.getLogger(__name__)


class ExecuteCodeEvent[T](QEvent):
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


class QExecuteCodeEventReceiver(QObject):
    """
    A class that receives ExecuteCodeEvent and executes the code on the GUI thread.
    """

    def event(self, event, /):
        if not isinstance(event, ExecuteCodeEvent):
            return False
        try:
            event.result = event.execute()
        except Exception as ex:  # pylint:disable=broad-except
            event.exception = ex
            if event.async_:
                _l.exception("Exception occurred in an async job:")
        event.event.set()
        return True


class QtExecutor:
    """
    Runs callables on the Qt GUI thread by posting an ExecuteCodeEvent to ``GlobalInfo.event_receiver``.

    The GUI thread is ``GlobalInfo.gui_thread``, which the frontend sets at start-up.
    """

    def is_ui_thread(self) -> bool:
        return QThread.currentThread() == GlobalInfo.gui_thread

    def schedule[T](
        self,
        func: Callable[..., T],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> T | None:
        if self.is_ui_thread():
            return func(*(args or ()), **(kwargs or {}))

        event = ExecuteCodeEvent(func, args=args, kwargs=kwargs)

        try:
            QCoreApplication.postEvent(GlobalInfo.event_receiver, event)
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

    def schedule_async(
        self, func: Callable[..., Any], args: tuple[Any, ...] | None = None, kwargs: dict[str, Any] | None = None
    ) -> None:
        if self.is_ui_thread():
            func(*(args or ()), **(kwargs or {}))
            return

        event = ExecuteCodeEvent(func, args=args, kwargs=kwargs, async_=True)

        with contextlib.suppress(RuntimeError):  # the application is exiting and the main window has been destroyed.
            QCoreApplication.postEvent(GlobalInfo.event_receiver, event)

    def process_pending(self) -> None:
        QCoreApplication.processEvents()
