from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from .object_container import ObjectContainer

if TYPE_CHECKING:
    from collections.abc import Sequence


class BreakpointType(Enum):
    """
    Type of breakpoint.
    """

    Execute = 0
    Read = 1
    Write = 2


class Breakpoint:
    """
    A breakpoint / watchpoint.
    """

    __slots__ = ("type", "addr", "_size", "comment")

    def __init__(self, type_: BreakpointType, addr: int, size: int = 1, comment: str = "") -> None:
        self.type: BreakpointType = type_
        self.addr: int = addr
        self._size = size
        self.comment: str = comment

    @property
    def size(self):
        if self.type == BreakpointType.Execute:
            return 1
        return self._size

    @size.setter
    def size(self, v: int) -> None:
        self._size = v


class BreakpointManager:
    """
    Manager of breakpoints.
    """

    def __init__(self) -> None:
        self.breakpoints: ObjectContainer = ObjectContainer([], "List of breakpoints")

    def clear(self) -> None:
        self.breakpoints.clear()
        self.breakpoints.am_event()

    def add_breakpoint(self, bp: Breakpoint) -> None:
        self.breakpoints.append(bp)
        self.breakpoints.am_event(added=bp)

    def remove_breakpoint(self, bp: Breakpoint) -> None:
        self.breakpoints.remove(bp)
        self.breakpoints.am_event(removed=bp)

    def add_exec_breakpoint(self, addr: int) -> None:
        self.add_breakpoint(Breakpoint(BreakpointType.Execute, addr))

    def toggle_exec_breakpoint(self, addr: int) -> None:
        # is there a breakpoint at this address?
        found_bp = None
        for bp in self.breakpoints:
            if bp.type == BreakpointType.Execute and bp.addr == addr:
                # yes!
                found_bp = bp
                break

        if found_bp is None:
            self.add_exec_breakpoint(addr)
        else:
            self.remove_breakpoint(found_bp)

    def get_breakpoints_at(self, addr: int) -> Sequence[Breakpoint]:
        return [bp for bp in self.breakpoints if bp.addr <= addr < (bp.addr + bp.size)]
