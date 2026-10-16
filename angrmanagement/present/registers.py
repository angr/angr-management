"""The registers view without a toolkit: the general-purpose registers of the debugger's current state."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from angrmanagement.logic.debugger import DebuggerWatcher

from .base import InstancePresenter
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    import angr
    from archinfo import Register

    from angrmanagement.data.instance import Instance


class RegistersTableModel(ListTableModel["Register"]):
    """The general-purpose registers of ``state``; a register whose value changed since the last state is marked."""

    COL_REGISTER = 0
    COL_VALUE = 1

    COLUMNS: ClassVar[list[Column]] = [Column("Name", 8), Column("Value", stretch=True)]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self) -> None:
        super().__init__()
        self.state: angr.SimState | None = None
        self._last_state: angr.SimState | None = None

    def update_state(self, state: angr.SimState | None) -> None:
        self._last_state = self.state.copy() if self.state is not None else None
        self.state = state
        regs = [] if state is None else [reg for reg in state.arch.register_list if reg.general_purpose]
        self.set_rows(regs)

    def column_text(self, obj: Register, col: int) -> str:
        if col == self.COL_REGISTER:
            return obj.name
        if col == self.COL_VALUE and self.state is not None:
            return repr(self.state.regs.get(obj.name))
        return ""

    def did_data_change(self, reg: Register) -> bool:
        if self._last_state is None or self.state is None:
            return False
        return bool(self.state.solver.eval(self.state.regs.get(reg.name) != self._last_state.regs.get(reg.name)))

    def style_key(self, obj: Register, col: int) -> str | None:
        return "table.changed" if self.did_data_change(obj) else None


class RegistersPresenter(InstancePresenter):
    """The registers view: it follows the debugger."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "right") -> None:
        super().__init__(workspace, "registers", instance, default_docking_position)
        self.base_caption = "Registers"
        self.model = RegistersTableModel()
        self._dbg_manager = instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    def close(self) -> None:
        self._dbg_watcher.shutdown()

    def _on_debugger_state_updated(self) -> None:
        dbg = self._dbg_manager.debugger
        self.model.update_state(None if dbg.am_none else dbg.simstate)
