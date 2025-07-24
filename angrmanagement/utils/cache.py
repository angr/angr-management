from __future__ import annotations

from typing import TYPE_CHECKING

from cachetools import LRUCache

if TYPE_CHECKING:
    from collections.abc import Callable


class SmartLRUCache(LRUCache):
    """
    A smart LRU cache that calls an eviction function when an item is evicted from the cache.

    This is based the SmartLRUCache in claripy. Because we may make claripy optional in the future, I decide to make a
    copy of this class in angr management instead.
    """

    def __init__(self, maxsize, getsizeof=None, evict: Callable | None = None):
        LRUCache.__init__(self, maxsize, getsizeof=getsizeof)
        self._evict: Callable | None = evict

    def popitem(self):
        key, val = LRUCache.popitem(self)
        if self._evict is not None:
            self._evict(key, val)
        return key, val
