from __future__ import annotations

from collections.abc import Callable
from threading import Thread
from typing import Any


def start_daemon_thread(target: Callable[..., Any], name: str, args: tuple[Any] = None) -> Thread:
    """
    Start a daemon thread.
    """
    t = Thread(target=target, name=name, args=args if args else ())
    t.daemon = True
    t.start()
    return t
