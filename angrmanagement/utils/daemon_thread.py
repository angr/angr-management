from threading import Thread
from typing import Any, Callable, Tuple


def start_daemon_thread(target: Callable[..., Any], name: str, args: Tuple[Any] = None) -> Thread:
    """
    Start a daemon thread.
    """
    t = Thread(target=target, name=name, args=args if args else ())
    t.daemon = True
    t.start()
    return t
