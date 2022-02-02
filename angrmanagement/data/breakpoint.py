from enum import Enum
from typing import Sequence

from .object_container import ObjectContainer


class BreakpointType(Enum):
    """
    Type of breakpoint.
    """

    Execute = 1
    Read = 2
    Write = 4


class Breakpoint:
    """
    A breakpoint / watchpoint.
    """

    __slots__ = (
        'type', 'addr', 'length', 'comment'
    )

    def __init__(self, type_: BreakpointType, addr: int, length: int = 1, comment: str = ''):
        self.type: BreakpointType = type_
        self.addr: int = addr
        self.length: int = length
        self.comment: str = comment


class BreakpointManager:
    """
    Manager of breakpoins.
    """

    def __init__(self):
        self.breakpoints: ObjectContainer = ObjectContainer([], 'List of breakpoints')

    def clear(self):
        self.breakpoints.clear()
        self.breakpoints.am_event()

    def add_breakpoint(self, bp: Breakpoint):
        self.breakpoints.append(bp)
        self.breakpoints.am_event(added=bp)

    def remove_breakpoint(self, bp: Breakpoint):
        self.breakpoints.remove(bp)
        self.breakpoints.am_event(removed=bp)

    def add_exec_breakpoint(self, addr):
        self.add_breakpoint(Breakpoint(BreakpointType.Execute, addr))

    def get_breakpoints_at(self, addr: int) -> Sequence[Breakpoint]:
        return [bp for bp in self.breakpoints
                     if bp.addr <= addr < (bp.addr + bp.length)]
