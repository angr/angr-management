"""
The feature map without a toolkit: a strip across the window showing what each part of the memory space holds.

The CFB's regions are laid side by side along the strip, each as wide as its share of the bytes (an extern, TLS or
kernel object counts as 80 bytes, so it shows without taking the strip). Each item of the CFB is tagged as code, data
or a string, and the tags are binned at several levels of detail so a narrow region is drawn from a coarse map.
:class:`FeatureMapModel` keeps the maps and the layout, and :class:`FeatureMapPresenter` adds the cursors of the view
the user works in and the jump a click asks for, as the Qt feature map toolbar does.
"""

from __future__ import annotations

import contextlib
import logging
import time
from threading import Lock
from typing import TYPE_CHECKING, Any

import cle
from angr.block import Block
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort
from sortedcontainers import SortedDict

from angrmanagement.config.color import Color
from angrmanagement.data.tagged_interval_map import TaggedIntervalMap
from angrmanagement.logic.threads import gui_thread_schedule_async

from .base import container

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from angr.analyses.cfg.cfb import MemoryRegion

    from angrmanagement.data.instance import Instance

log = logging.getLogger(__name__)

#: The colour entry of each tag bit: code, data, strings.
FEATURE_TAG_COLORS = (
    "feature_map_regular_function_color",
    "feature_map_data_color",
    "feature_map_string_color",
)
UNKNOWN_COLOR = "feature_map_unknown_color"
DELIMITER_COLOR = "feature_map_delimiter_color"
#: The binning bits of each level of detail, coarsest first.
NBITS_PER_LOD = (13, 12, 8, 6, 4, 0)
#: How many bytes a region not drawn to scale counts as.
UNSCALED_REGION_BYTES = 80


def feature_tags(item: Any) -> int | None:
    """The tag bit mask of a CFB item: code, data or a string; None for anything else."""
    if isinstance(item, Block):
        b = 0
    elif isinstance(item, MemoryData):
        sort: Any = item.sort
        b = {
            MemoryDataSort.String: 2,
            MemoryDataSort.UnicodeString: 2,
        }.get(sort, 1)
    else:
        return None
    return 1 << b


def tag_color(colors: Sequence[Color], tags: int) -> Color:
    """The colour of ``tags``: the average of the colours of its bits (``colors`` in bit order)."""
    picked = [colors[i] for i in range(len(colors)) if tags & (1 << i)]
    n = len(picked)
    return Color(
        round(sum(c.r for c in picked) / n),
        round(sum(c.g for c in picked) / n),
        round(sum(c.b for c in picked) / n),
    )


def shown_to_scale(mr: MemoryRegion) -> bool:
    """Whether a region is as wide as its bytes; an extern, TLS or kernel object is not."""
    return not isinstance(mr.object, cle.ExternObject | cle.TLSObject | cle.KernelObject)


class FeatureMapModel:
    """
    The feature maps of a CFB at each level of detail, and the regions laid along a strip ``width`` units wide.
    The maps are built and grown under :attr:`lock`, because the CFG job adds objects from its thread.
    """

    def __init__(self, instance: Instance) -> None:
        self.instance = instance
        self.lock = Lock()
        self.width: float = 1
        self.maps: list[TaggedIntervalMap] = []
        self.addr_to_region: SortedDict = SortedDict()  # SortedDict[int, MemoryRegion]
        self.region_to_position: dict[MemoryRegion, float] = {}
        self.region_to_width: dict[MemoryRegion, float] = {}
        self.position_to_region: SortedDict = SortedDict()  # SortedDict[float, MemoryRegion]
        self.clear()

    def clear(self) -> None:
        self.maps = [TaggedIntervalMap(nbits) for nbits in NBITS_PER_LOD]

    #
    # The maps
    #

    def build(self) -> None:
        """Tag every item of the CFB again, then fill the coarser maps from the finest (call under the lock)."""
        cfb = container(self.instance.cfb)
        if cfb.am_none:
            return
        self.clear()
        num_items = 0
        time_start = time.time()
        try:
            cfb_obj: Any = cfb.am_obj
            for addr, item in cfb_obj._blanket.items():  # pylint: disable=protected-access
                if not getattr(item, "size", None):
                    continue
                tags = feature_tags(item)
                if tags is None:
                    continue
                self.maps[-1].add(addr, item.size, tags)
                num_items += 1
        except (RuntimeError, KeyError, IndexError):
            # the CFB may be mutated by the CFG recovery job thread while we iterate over it; keep what we have
            # collected so far - a following objects_added event will repaint
            pass
        log.debug("Reduced %d items in CFB in %.4f s", num_items, time.time() - time_start)
        for i in range(len(self.maps) - 2, -1, -1):
            fm_in, fm_out = self.maps[i + 1], self.maps[i]
            for addr, size, tags in fm_in.irange():
                if tags != 0:
                    fm_out.add(addr, size, tags)

    def add_objects(self, objs: Iterable[tuple[int, Any]]) -> bool:
        """Tag the objects the CFG job added; returns whether any was tagged."""
        added = False
        with self.lock:
            for addr, item in objs:
                tags = feature_tags(item)
                if tags is None or item.size is None:
                    continue
                for fm in self.maps:
                    fm.add(addr, item.size, tags)
                added = True
        return added

    def items(self, lod: int, min_addr: int, max_addr: int) -> list[tuple[int, int, int]]:
        """The intervals of the map at ``lod`` between two addresses: (address, size, tags)."""
        with self.lock:
            return list(self.maps[lod].irange(min_addr, max_addr))

    #
    # The layout
    #

    def _first_overlapping_region(self, mr: MemoryRegion) -> MemoryRegion | None:
        start_idx = max(0, self.addr_to_region.bisect_left(mr.addr) - 1)
        for e_addr in self.addr_to_region.islice(start_idx):
            e_mr = self.addr_to_region[e_addr]
            if (e_mr.addr + e_mr.size) <= mr.addr:
                continue
            if e_mr.addr < (mr.addr + mr.size):
                return e_mr
        return None

    def layout(self, width: float) -> None:
        """Lay the regions along a strip ``width`` units wide."""
        self.width = width
        self.addr_to_region.clear()
        self.position_to_region.clear()
        self.region_to_position.clear()
        self.region_to_width.clear()
        cfb = container(self.instance.cfb)
        if cfb.am_none:
            return
        # Add regions from largest to smallest
        cfb_obj: Any = cfb.am_obj
        for new_mr in sorted(cfb_obj.regions, key=lambda mr: mr.size, reverse=True):
            mr = self._first_overlapping_region(new_mr)
            if mr is not None:
                log.debug("Skipping CFB region %s, which overlaps %s", new_mr, mr)
                continue
            self.addr_to_region[new_mr.addr] = new_mr
        # Determine total displayed byte count
        rem_bytes = 0
        region_to_size = {}
        for mr in self.addr_to_region.values():
            size = mr.size if shown_to_scale(mr) else UNSCALED_REGION_BYTES
            region_to_size[mr] = size
            rem_bytes += size
        # Determine region widths in scene units
        rem_width = width
        for mr in self.addr_to_region.values():
            region_width = max(round(region_to_size[mr] * rem_width / rem_bytes), 1)
            self.region_to_width[mr] = region_width
            rem_bytes -= region_to_size[mr]
            rem_width -= region_width
        # Determine region position in scene units
        position = 0
        for mr in self.addr_to_region.values():
            self.region_to_position[mr] = position
            self.position_to_region[position] = mr
            position += self.region_to_width[mr]

    def region_at_addr(self, addr: int) -> MemoryRegion | None:
        start_idx = max(0, self.addr_to_region.bisect_left(addr) - 1)
        for mr_addr in self.addr_to_region.islice(start_idx):
            mr = self.addr_to_region[mr_addr]
            if mr.addr + mr.size < addr:
                continue
            if mr.addr > addr:
                break
            return mr
        return None

    def position_at_addr(self, addr: int) -> float | None:
        mr = self.region_at_addr(addr)
        if mr is None or mr.size == 0:
            return None
        offset = addr - mr.addr
        assert offset >= 0
        return self.region_to_position[mr] + self.region_to_width[mr] * offset / mr.size

    def region_at_position(self, pos: float) -> MemoryRegion | None:
        """The region at ``pos``, or the last one before it."""
        try:
            key = next(self.position_to_region.irange(maximum=pos, reverse=True))
        except StopIteration:
            return None
        return self.position_to_region[key]

    def addr_at_position(self, pos: float) -> int | None:
        mr = self.region_at_position(pos)
        if mr is None:
            return None
        pos -= self.region_to_position[mr]
        width = self.region_to_width[mr]
        if width < 1:
            return mr.addr
        return mr.addr + int(pos / width * mr.size)

    def region_span(self, mr: MemoryRegion) -> tuple[float, float]:
        """Where a region starts on the strip, and how wide it is."""
        return self.region_to_position[mr], self.region_to_width[mr]

    def lod_for(self, mr: MemoryRegion) -> int:
        """The level of detail to draw a region at: the coarsest whose bins are no more than three units."""
        bytes_per_unit = int(mr.size / self.region_to_width[mr])
        for idx, bits_per_bin in enumerate(NBITS_PER_LOD):
            if bytes_per_unit * 3 >= 1 << bits_per_bin:
                return idx
        return -1

    def regions_between(self, pos_l: float, pos_r: float) -> list[MemoryRegion]:
        """The regions shown between two positions, in order."""
        out = []
        start_idx = max(0, self.position_to_region.bisect_left(pos_l) - 1)
        for pos in self.position_to_region.islice(start_idx):
            if pos > pos_r:
                break
            mr = self.position_to_region[pos]
            if pos + self.region_to_width[mr] <= pos_l:
                continue
            out.append(mr)
        return out

    def tooltip_at(self, pos: float) -> str:
        """What is at ``pos``: the CFB item there and its region; empty when nothing is."""
        mr = self.region_at_position(pos)
        addr = self.addr_at_position(pos)
        if mr is None or addr is None:
            return ""
        with contextlib.suppress(KeyError):
            cfb_obj: Any = container(self.instance.cfb).am_obj
            item = cfb_obj.floor_item(addr)
            if item is not None:
                return f"{item[1]!s} in {mr!s}"
        return ""

    def tags_between(self, mr: MemoryRegion, min_addr: int, max_addr: int) -> int:
        """The tags of every item of ``mr`` between two addresses, OR'd, at the region's level of detail."""
        tags = 0
        lo = max(min_addr, mr.addr)
        hi = min(max_addr, mr.addr + mr.size - 1)
        if hi < lo:
            return 0
        for _addr, size, item_tags in self.items(self.lod_for(mr), lo, hi):
            if size:
                tags |= item_tags
        return tags


def jump_to_feature_addr(workspace: Any, addr: int | None) -> None:
    """Show ``addr`` in the view the user worked in last, if it can jump."""
    target_view = workspace.view_manager.most_recently_focused_view
    if addr is not None and hasattr(target_view, "jump_to"):
        target_view.jump_to(addr)


def view_state_cursors(instance: Instance) -> list[int] | None:
    """The cursors of the focused view, or None when no view says where it is."""
    vs = container(instance.active_view_state)
    if vs.am_none:
        return None
    state: Any = vs.am_obj
    return list(state.cursors)


class FeatureMapPresenter:
    """
    The feature map of the main instance: the model, the cursors of the focused view, and the jump a click asks for.
    The frontend sets :attr:`on_changed` (the maps or the layout changed) and :attr:`on_cursors_changed`, and may set
    :attr:`on_reloading`, called before the maps are rebuilt. ``workspace`` may be None when the frontend does the
    jump itself, as the Qt feature map's toolbar does.
    """

    #: the CFG job adds objects in bursts; redraw at most this often
    MIN_REFRESH_INTERVAL = 1 / 30

    def __init__(self, workspace: Any, instance: Instance | None = None) -> None:
        self.workspace = workspace
        self.instance: Instance = instance if instance is not None else workspace.main_instance
        self.model = FeatureMapModel(self.instance)
        self.cursors: list[int] = []
        self.on_changed: Callable[[], Any] | None = None
        self.on_cursors_changed: Callable[[], Any] | None = None
        self.on_reloading: Callable[[], Any] | None = None
        self._last_refresh = 0.0
        self._refresh_pending = False
        container(self.instance.cfb).am_subscribe(self._on_cfb_event)
        container(self.instance.active_view_state).am_subscribe(self._on_view_state_updated)
        self.reload()

    def close(self) -> None:
        container(self.instance.cfb).am_unsubscribe(self._on_cfb_event)
        container(self.instance.active_view_state).am_unsubscribe(self._on_view_state_updated)

    def reload(self) -> None:
        if self.on_reloading is not None:
            self.on_reloading()
        with self.model.lock:
            self.model.build()
        self.refresh()

    def refresh(self) -> None:
        self._last_refresh = time.time()
        self._refresh_pending = False
        if self.on_changed is not None:
            self.on_changed()

    def _on_cfb_event(self, **kwargs) -> None:
        if "objects_added" in kwargs:  # called by the CFG job's thread
            if (
                self.model.add_objects(kwargs["objects_added"])
                and not self._refresh_pending
                and time.time() - self._last_refresh > self.MIN_REFRESH_INTERVAL
            ):
                self._refresh_pending = True
                gui_thread_schedule_async(self.refresh)
        elif not kwargs:
            # a new CFB may be set from the job's thread too
            gui_thread_schedule_async(self.reload)

    def _on_view_state_updated(self, **_kwargs) -> None:
        cursors = view_state_cursors(self.instance)
        if cursors is None:
            return
        self.cursors = cursors
        if self.on_cursors_changed is not None:
            gui_thread_schedule_async(self.on_cursors_changed)

    def select_at_position(self, pos: float) -> int | None:
        """A click at ``pos``: show its address in the view the user worked in last; returns the address."""
        addr = self.model.addr_at_position(pos)
        jump_to_feature_addr(self.workspace, addr)
        return addr


__all__ = [
    "DELIMITER_COLOR",
    "FEATURE_TAG_COLORS",
    "NBITS_PER_LOD",
    "UNKNOWN_COLOR",
    "FeatureMapModel",
    "FeatureMapPresenter",
    "feature_tags",
    "jump_to_feature_addr",
    "shown_to_scale",
    "tag_color",
    "view_state_cursors",
]
