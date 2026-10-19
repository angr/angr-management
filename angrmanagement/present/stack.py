"""The stack view without a toolkit: the words above the stack pointer, and breakpoints on them."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.logic.debugger import DebuggerWatcher

from .base import InstancePresenter
from .menus import Menu, MenuEntry
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    import angr

    from angrmanagement.data.instance import Instance

#: How many stack words the view shows.
STACK_ROWS = 15


class StackTableModel(ListTableModel[int]):
    """The first :data:`STACK_ROWS` words of the stack of ``state``; the rows are word indices."""

    COL_OFFSET = 0
    COL_VALUE = 1

    COLUMNS: ClassVar[list[Column]] = [Column("Offset", 8), Column("Value", stretch=True)]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, presenter: StackPresenter | None = None) -> None:
        super().__init__()
        self.state: angr.SimState | None = None
        self.presenter = presenter

    def set_state(self, state: angr.SimState | None) -> None:
        self.state = state
        self.set_rows([] if state is None else list(range(STACK_ROWS)))

    @property
    def word_size(self) -> int:
        return self.state.arch.bits // 8 if self.state is not None else 0

    def column_text(self, obj: int, col: int) -> str:
        width = self.word_size
        offset = obj * width
        if col == self.COL_OFFSET:
            return str(offset)
        if col == self.COL_VALUE and self.state is not None:
            return repr(self.state.stack_read(offset, width))
        return ""

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None or not rows:
            return None
        return self.presenter.breakpoint_menu(list(rows)[0])


class StackPresenter(InstancePresenter):
    """The stack view: it follows the debugger and sets breakpoints on stack words."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "right") -> None:
        super().__init__(workspace, "stack", instance, default_docking_position)
        self.base_caption = "Stack"
        self.model = StackTableModel(self)
        self._dbg_manager = instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    def close(self) -> None:
        self._dbg_watcher.shutdown()

    def _on_debugger_state_updated(self) -> None:
        dbg = self._dbg_manager.debugger
        self.model.set_state(None if dbg.am_none else dbg.simstate)

    def set_breakpoint(self, row: int, bp_type: BreakpointType = BreakpointType.Execute) -> None:
        """Break on the stack word of ``row``."""
        state = self.model.state
        if state is None or not state.regs.sp.concrete:
            return
        width = state.arch.bits // 8
        offset = row * width + state.solver.eval(state.regs.sp)
        self.instance.breakpoint_mgr.add_breakpoint(Breakpoint(bp_type, offset, width))

    def breakpoint_menu(self, row: int) -> Menu:
        menu = Menu("Set &breakpoint")
        for caption, bp_type in (
            ("Break on &Execute", BreakpointType.Execute),
            ("Break on &Read", BreakpointType.Read),
            ("Break on &Write", BreakpointType.Write),
        ):
            menu.add(MenuEntry(caption, lambda t=bp_type: self.set_breakpoint(row, t)))
        return menu
