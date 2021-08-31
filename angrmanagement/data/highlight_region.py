class SynchronizedHighlightRegion:
    """
    A region of memory to be highlighted in synchronized views.
    """

    def __init__(self, addr: int, size: int):
        self.addr: int = addr
        self.size: int = size
