"""
The trace map without a toolkit.

The map is a strip over the events of the trace a trace debugger replays: where the debugger is, the trace's
checkpoints, and the event under the mouse. :func:`trace_position` reads those numbers from the debugger,
:func:`pos_from_addr` and :func:`addr_from_pos` convert between an event and a position along a map ``width`` long,
and :meth:`TraceMapModel.segments` lists what to draw as ``(start, end, kind)`` positions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angrmanagement.logic.debugger import DebuggerWatcher
from angrmanagement.logic.debugger.bintrace import BintraceDebugger

from .base import InstancePresenter

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.instance import Instance

#: How wide the shading on each side of the current position is, as a share of the map's length.
FRONTIER_SHARE = 0.15
#: The kinds of segment, in the order they are drawn (later ones on top).
SEGMENT_KINDS = ("frontier_before", "frontier_after", "checkpoint", "current", "hover")


def trace_position(debugger: Any) -> tuple[int, int, list[int]]:
    """
    Where a trace debugger is: the number of events replayed, the number of events in the trace, and the event
    numbers of the checkpoints. All zero (and no checkpoints) for any other debugger.
    """
    if isinstance(debugger, BintraceDebugger):
        # FIXME: Expose trace info as TraceDebugger abstraction between Debugger<>BintraceDebugger
        t = debugger._trace.trace  # pylint: disable=protected-access
        s = debugger._trace_dbg.state  # pylint: disable=protected-access
        if s and s.event_count >= 0:
            return s.event_count, t.get_num_events(), [c.event_count for c in t.checkpoints]
    return 0, 0, []


def pos_from_addr(addr: int, total: int, width: int) -> int | None:
    """The position of event ``addr`` along a map ``width`` long, or None if it is not in the trace."""
    if total == 0 or addr > total:
        return None
    return int(addr / total * width)


def addr_from_pos(pos: int, total: int, width: int) -> int:
    """The event at position ``pos`` along a map ``width`` long."""
    return int(pos * total // width)


class TraceMapModel:
    """The numbers the map shows and the event under the mouse."""

    def __init__(self) -> None:
        self.addr = 0
        self.total = 0
        self.checkpoints: list[int] = []
        self.hover_addr: int | None = None

    def update(self, debugger: Any) -> None:
        self.addr, self.total, self.checkpoints = trace_position(debugger)

    def segments(self, width: int) -> list[tuple[int, int, str]]:
        """
        What to draw along a map ``width`` long, as ``(start, end, kind)`` with ``end`` exclusive, in the order to
        draw it: the shading before and after the current position, the checkpoints, the current position and the
        hovered event.
        """
        out: list[tuple[int, int, str]] = []
        current = pos_from_addr(self.addr, self.total, width)
        if current is not None:
            frontier = max(int(FRONTIER_SHARE * width), 1)
            out.append((max(current - frontier, 0), current, "frontier_before"))
            out.append((current + 1, min(current + 1 + frontier, width), "frontier_after"))
        for checkpoint in self.checkpoints:
            pos = pos_from_addr(checkpoint, self.total, width)
            if pos is not None:
                out.append((pos, pos + 1, "checkpoint"))
        if current is not None:
            out.append((min(current, width - 1), min(current, width - 1) + 1, "current"))
        if self.hover_addr is not None:
            pos = pos_from_addr(self.hover_addr, self.total, width)
            if pos is not None:
                out.append((min(pos, width - 1), min(pos, width - 1) + 1, "hover"))
        return out


class TraceMapPresenter(InstancePresenter):
    """The trace map: it follows the debugger, and a click replays the trace to the event at the click."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "top") -> None:
        super().__init__(workspace, "tracemap", instance, default_docking_position)
        self.base_caption = "Trace Map"
        self.model = TraceMapModel()
        #: called after the numbers changed
        self.on_changed: Callable[[], None] | None = None
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, instance.debugger_mgr.debugger)
        self._on_debugger_state_updated()

    def close(self) -> None:
        self._dbg_watcher.shutdown()

    def _on_debugger_state_updated(self) -> None:
        self.model.update(self._dbg_watcher.debugger.am_obj)
        if self.on_changed is not None:
            self.on_changed()

    def hover(self, pos: int | None, width: int) -> None:
        """The mouse is over position ``pos`` (None: it left the map)."""
        self.model.hover_addr = None if pos is None else addr_from_pos(pos, self.model.total, width)

    def select_offset(self, pos: int, width: int) -> None:
        """Replay the trace to the event at position ``pos``."""
        dbg = self._dbg_watcher.debugger.am_obj
        if not isinstance(dbg, BintraceDebugger):
            return
        dbg.replay_to_nth_event(addr_from_pos(pos, self.model.total, width))


__all__ = [
    "SEGMENT_KINDS",
    "TraceMapModel",
    "TraceMapPresenter",
    "addr_from_pos",
    "pos_from_addr",
    "trace_position",
]
