"""
A signal that does not depend on Qt.

``Signal`` mirrors the part of Qt's signal API that angr management uses: ``connect``, ``disconnect`` and ``emit``.
Listeners always run on the UI thread, which is what Qt's automatic connection does for a receiver that lives on the
GUI thread: an emit on the UI thread calls the listeners inline, and an emit on any other thread hands the delivery to
``GlobalInfo.executor.schedule_async``.
"""

from __future__ import annotations

import inspect
import logging
import threading
from typing import TYPE_CHECKING, Any

from . import GlobalInfo

if TYPE_CHECKING:
    from collections.abc import Callable

_l = logging.getLogger(__name__)


def max_positional_args(func: Callable[..., Any]) -> int | None:
    """
    Return how many positional arguments ``func`` accepts, or None if it takes any number (or cannot be inspected).

    Qt drops trailing signal arguments that a slot does not take, so a ``(job, exception)`` signal may be connected
    to a slot that takes only ``job``. Signal does the same.
    """
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return None
    count = 0
    for param in sig.parameters.values():
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            return None
        if param.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            count += 1
    return count


class Signal:
    """
    A list of listeners that are called, on the UI thread, with the arguments of each ``emit``.

    The argument types are documentation only; they are kept so a declaration reads like the Qt signal it replaces.
    A listener that raises is logged and does not stop the other listeners.
    """

    def __init__(self, *arg_types: Any, name: str | None = None) -> None:
        self.arg_types = arg_types
        self.name = name
        self._listeners: list[tuple[Callable[..., Any], int | None]] = []
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"<Signal {self.name or ''}{self.arg_types!r} with {len(self._listeners)} listeners>"

    def connect(self, func: Callable[..., Any]) -> None:
        """Add a listener. Connecting the same callable twice calls it twice per emit, as Qt does."""
        entry = (func, max_positional_args(func))
        with self._lock:
            self._listeners.append(entry)

    def disconnect(self, func: Callable[..., Any] | None = None) -> bool:
        """
        Remove one connection of ``func``, or every listener when ``func`` is None.

        :returns: Whether anything was removed.
        """
        with self._lock:
            if func is None:
                removed = bool(self._listeners)
                self._listeners.clear()
                return removed
            for idx, (listener, _) in enumerate(self._listeners):
                if listener == func:
                    del self._listeners[idx]
                    return True
        return False

    def emit(self, *args: Any) -> None:
        """Call every listener with ``args``, on the UI thread."""
        executor = GlobalInfo.executor
        if executor.is_ui_thread():
            self._deliver(args)
        else:
            executor.schedule_async(self._deliver, (args,))

    def _deliver(self, args: tuple[Any, ...]) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for func, max_args in listeners:
            try:
                func(*(args if max_args is None else args[:max_args]))
            except Exception:  # pylint:disable=broad-exception-caught
                _l.exception("Exception in a listener of %r", self)
