from __future__ import annotations

from typing import TYPE_CHECKING

from sortedcontainers import SortedDict

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


class TaggedIntervalMap:
    """
    Catalogs features of intervals.
    """

    def __init__(self, nbits: int = 0) -> None:
        """
        :param nbits: Number of binning bits. Higher values reduce detail. 0 for no binning.
        """
        self._nbits: int = nbits
        self._map: SortedDict = SortedDict()  # SortedDict[int, int]

    @property
    def nbits(self) -> int:
        return self._nbits

    def add(self, addr: int, size: int, tags: int) -> None:
        """
        Add interval starting at `addr` of `size` bytes.

        When binning, intervals endpoints are aligned to 2^nbits. Gaps between added intervals are populated with
        implicit intervals having tag value of 0. Overlapping intervals will have tag bits OR'd together.

        Adjacent intervals in the interval map have unique tags. When intervals are added to the map, any adjacent stops
        with identical tags will be eliminated so the map retains this property.

        For example: if an interval(addr=0, size=100, tags=1) is added, followed by (100, 100, 1), the resulting
        interval in the map will be (0, 200, 1).
        """
        assert addr >= 0
        assert size >= 0
        assert tags != 0

        if size == 0:
            return

        max_bin_offset = (1 << self._nbits) - 1
        mask = ~max_bin_offset

        start_addr = addr & mask  # Round down to bin alignment
        end_addr = (addr + size + max_bin_offset) & mask  # Round up to bin alignment

        if self._is_already_covered(start_addr, end_addr, tags):
            return

        self._insert_stop(start_addr)
        self._insert_stop(end_addr)
        for affected_addr in self._map.irange(start_addr, end_addr, inclusive=(True, False)):
            self._map[affected_addr] |= tags
        self._eliminate_extraneous_stops(start_addr, end_addr)

    def add_many(self, intervals: Iterable[tuple[int, int, int]]) -> None:
        """
        Add (addr, size, tags) intervals. The resulting map equals the one built by calling add() on each of them.

        The batch is binned, sorted and merged into disjoint pieces first, then each piece updates the map once.
        """
        for addr, size, tags in self.coalesce(intervals, self._nbits):
            self._or_range(addr, addr + size, tags)

    @staticmethod
    def coalesce(intervals: Iterable[tuple[int, int, int]], nbits: int = 0) -> list[tuple[int, int, int]]:
        """
        Bin (addr, size, tags) intervals to 2^nbits and merge them into sorted, disjoint (addr, size, tags) pieces with
        tags OR'd where they overlap. Adjacent pieces have different tags or a gap between them. Coalescing at a finer
        binning first does not change what a coarser map gets from add_many().
        """
        max_bin_offset = (1 << nbits) - 1
        mask = ~max_bin_offset
        binned = []
        for addr, size, tags in intervals:
            assert addr >= 0 and size >= 0 and tags != 0
            if size:
                binned.append(((addr & mask), (addr + size + max_bin_offset) & mask, tags))
        if not binned:
            return []
        binned.sort()

        # merge overlapping or adjacent intervals of each tag value
        runs: dict[int, list[list[int]]] = {}
        for start, end, tags in binned:
            tag_runs = runs.get(tags)
            if tag_runs is None:
                runs[tags] = [[start, end]]
            else:
                last = tag_runs[-1]
                if start <= last[1]:
                    if end > last[1]:
                        last[1] = end
                else:
                    tag_runs.append([start, end])
        if len(runs) == 1:
            ((tags, tag_runs),) = runs.items()
            return [(start, end - start, tags) for start, end in tag_runs]

        # sweep over the runs; runs of one tag value are disjoint, so each tag value is active at most once
        events = []
        for tags, tag_runs in runs.items():
            for start, end in tag_runs:
                events.append((start, 1, tags))
                events.append((end, 0, tags))
        events.sort()
        pieces: list[tuple[int, int, int]] = []
        active: set[int] = set()
        cur_tags = 0
        cur_start = 0
        i = 0
        n = len(events)
        while i < n:
            pos = events[i][0]
            while i < n and events[i][0] == pos:
                _, is_start, tags = events[i]
                if is_start:
                    active.add(tags)
                else:
                    active.discard(tags)
                i += 1
            new_tags = 0
            for tags in active:
                new_tags |= tags
            if new_tags != cur_tags:
                if cur_tags:
                    pieces.append((cur_start, pos - cur_start, cur_tags))
                cur_tags = new_tags
                cur_start = pos
        return pieces

    def _or_range(self, start: int, end: int, tags: int) -> None:
        """
        OR `tags` into [start, end) (already binned) and keep the map canonical: no adjacent stops with equal tags.
        """
        m = self._map
        floor_key = next(m.irange(maximum=start, reverse=True), None)
        at_start = 0 if floor_key is None else m[floor_key]
        inner = list(m.irange(start, end, inclusive=(False, False)))
        if not inner and at_start | tags == at_start:
            return  # already covered

        if floor_key == start:
            before = next(m.irange(maximum=start, inclusive=(True, False), reverse=True), None)
            prev_tags = 0 if before is None else m[before]
        else:
            prev_tags = at_start
        at_end = m[end] if end in m else (m[inner[-1]] if inner else at_start)

        # start stop
        new_tags = at_start | tags
        if new_tags == prev_tags:
            if floor_key == start:
                del m[start]
        else:
            if floor_key != start or at_start != new_tags:
                m[start] = new_tags
            prev_tags = new_tags
        # stops inside the range
        for addr in inner:
            old_tags = m[addr]
            new_tags = old_tags | tags
            if new_tags == prev_tags:
                del m[addr]
            else:
                if new_tags != old_tags:
                    m[addr] = new_tags
                prev_tags = new_tags
        # end stop keeps the tags that were in effect at `end`
        if end in m:
            if m[end] == prev_tags:
                del m[end]
        elif at_end != prev_tags:
            m[end] = at_end

    def _insert_stop(self, addr: int) -> None:
        """
        Insert a new interval stop point at `addr`, if one is not already present in the map. Tags are copied from
        nearest stop before `addr`.
        """
        if addr not in self._map:
            idx = self._map.bisect(addr) - 1
            self._map[addr] = self._map.peekitem(idx)[1] if idx >= 0 else 0

    def _is_already_covered(self, min_addr: int, end_addr: int, tags: int) -> bool:
        """
        Determine if interval [min_addr, end_addr) is covered by an existing range with identical tags.
        """
        idx = self._map.bisect(min_addr) - 1
        if idx >= 0 and len(self._map) > idx + 1:
            e_addr, e_tags = self._map.peekitem(idx)
            e_addr_next, _ = self._map.peekitem(idx + 1)
            return (e_addr <= min_addr) and (end_addr <= e_addr_next) and (e_tags == tags)
        return False

    def _eliminate_extraneous_stops(self, min_addr: int, max_addr: int) -> None:
        """
        Canonicalize the map by eliminating adjacent stops with identical tags both inside and directly outside of
        [min_addr, max_addr].
        """
        keys_to_drop = []
        prev_tags = None
        for addr, _, tags in self.irange(min_addr, max_addr):
            if tags == prev_tags:
                keys_to_drop.append(addr)
            else:
                prev_tags = tags

        for addr in keys_to_drop:
            del self._map[addr]

    def irange(self, min_addr: int | None = None, max_addr: int | None = None) -> Iterator[tuple[int, int, int]]:
        """
        Iterate over intervals intersecting [min_addr, max_addr], yielding interval (addr, size, tags) tuples. Implicit
        gap intervals (with tags=0) are also returned.

        :param min_addr: Minimum address (inclusive) to begin iterating from. If None, iterate from start of map.
        :param max_addr: Maximum address (inclusive) to iterate to. If None, iterate to end of map.
        """
        if not self._map:
            return

        start_idx = 0 if min_addr is None else max(0, self._map.bisect_left(min_addr) - 1)
        stop_idx = None if max_addr is None else (self._map.bisect(max_addr) + 1)

        start_addr, tags = self._map.peekitem(start_idx)
        for addr in self._map.islice(start_idx + 1, stop_idx):
            yield (start_addr, addr - start_addr, tags)
            tags = self._map[addr]
            start_addr = addr
