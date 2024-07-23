from __future__ import annotations


class SynchronizedHighlightRegion:
    """
    A region of memory to be highlighted in synchronized views.
    """

    def __init__(self, addr: int, size: int) -> None:
        self.addr: int = addr
        self.size: int = size
