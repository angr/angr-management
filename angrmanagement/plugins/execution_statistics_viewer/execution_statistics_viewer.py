from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule
from angrmanagement.plugins.base_plugin import BasePlugin, qt_frontend
from angrmanagement.present.marks import Mark
from angrmanagement.present.menus import Menu, MenuEntry

if TYPE_CHECKING:
    from angrmanagement.ui.views import DisassemblyView, SymexecView
    from angrmanagement.ui.workspace import Workspace


class ExecutionStatisticsViewer(BasePlugin):
    """
    Add a step_callback hook to count how many state on and passthrough of a particular address.
    return the result in build_qblock_annotations callback and show in the disassmbly view by
    fetch_qblock_annotations function.

    In the Qt frontend the counts are annotations and the active states a label in the disassembly view's status bar;
    in the terminal they are marks (``block_marks``) and the status bar's text (``status_bar_text``).
    """

    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)
        self.passthrough_counts = defaultdict(int)
        self.addr_to_active_states = defaultdict(list)
        self.returning_to_here_states = defaultdict(list)
        self.bb_addrs = None
        self.instance = self.workspace.main_instance

        self.active_states_label = None
        if self.symexec_view:
            self.current_simgr = self.symexec_view.current_simgr
            self.current_simgr.am_subscribe(self._on_simgr_selected)
        if qt_frontend():
            self._init_widgets()

    @property
    def disasm_view(self) -> DisassemblyView:
        return self.workspace.view_manager.first_view_in_category("disassembly")

    @property
    def symexec_view(self) -> SymexecView:
        return self.workspace.view_manager.first_view_in_category("symexec")

    def count_passthrough(self, simgr) -> None:
        """Prior to stepping the active states, increment the passthrough count on the basic block(s) that will be
        executed next."""
        if self.bb_addrs is None:
            self.bb_addrs = {b.addr for b in self.instance.cfg.nodes()}
        for s in simgr.active:
            for i_addr in s.block().instruction_addrs:
                if i_addr in self.bb_addrs:
                    self.passthrough_counts[i_addr] += 1

    def step_callback(self, simgr) -> None:
        """Called after stepping the simgr"""
        self.count_passthrough(simgr)
        self.count_active_states(simgr)
        gui_thread_schedule(self._refresh_gui)

    def count_active_states(self, simgr) -> None:
        """Count the number of states at each instruction in the program. Do some special work to figure out how many
        states are under each call and syscall instruction."""
        self.addr_to_active_states = defaultdict(list)
        self.returning_to_here_states = defaultdict(list)
        for s in simgr.active:
            # Count states at instruction
            self.addr_to_active_states[s.addr].append(s)
            # Count states under calls
            stack_frame = s.callstack
            while stack_frame:
                self.returning_to_here_states[stack_frame.ret_addr].append(s)
                stack_frame = stack_frame.next
            # Count states in syscalls
            if s.history.jumpkind.startswith("Ijk_Sys"):
                self.addr_to_active_states[s.history.jump_source].append(s)

    def _on_simgr_selected(self, *args, src=None, **kwargs) -> None:  # pylint: disable=unused-argument
        """Listener for when a new simgr is selected in the symexec view"""
        if src in ["clicked", "from above"]:
            # The "from above" event is emitted when you create a new simgr via right click menu in disasm view
            self.passthrough_counts = defaultdict(int)
            self.addr_to_active_states = defaultdict(list)
            self.returning_to_here_states = defaultdict(list)
            if not self.current_simgr.am_none:
                self.count_active_states(self.current_simgr)
            self._refresh_gui()

    def _simgr(self):
        """The selected simulation manager's container, or None while there is no symbolic execution view."""
        simgr = getattr(self, "current_simgr", None)
        if simgr is None and self.symexec_view:
            self.current_simgr = simgr = self.symexec_view.current_simgr
            simgr.am_subscribe(self._on_simgr_selected)
        return simgr

    def update_active_states_label(self) -> None:
        simgr = self._simgr()
        if self.active_states_label is not None and simgr is not None and not simgr.am_none:
            self.active_states_label.setText(f"Active states: {len(simgr.active)}")

    def status_bar_text(self) -> str | None:
        """The active states, in the terminal's status bar (the Qt view has its label)."""
        if qt_frontend():
            return None
        simgr = self._simgr()
        return f"Active states: {len(simgr.active)}" if simgr is not None and not simgr.am_none else "Active states: 0"

    def block_marks(self, block_addr: int, view) -> list[Mark]:
        """
        The counts as marks, for the terminal: the states at each instruction of the block (with the Qt
        annotation's Select and Move To in a menu) and how many passed through it.
        """
        simgr = self._simgr()
        if qt_frontend() or simgr is None or simgr.am_none:
            return []
        project: Any = self.instance.project.am_obj
        try:
            block = project.factory.block(block_addr)
        except Exception:  # pylint:disable=broad-exception-caught
            return []
        marks = []
        for insn in block.capstone.insns:
            addr = insn.address
            active_states = list(self.addr_to_active_states[addr])
            if insn.mnemonic == "call":
                active_states += self.returning_to_here_states[addr + insn.size]
            if active_states:
                marks.append(
                    Mark(
                        str(len(active_states)),
                        "disasm.mark.active",
                        "before",
                        1,
                        lambda states=active_states: self._states_menu(states),
                        addr=addr,
                    )
                )
            passthrough_count = self.passthrough_counts[addr]
            if passthrough_count > 0:
                marks.append(Mark(str(passthrough_count), "disasm.mark.passthrough", "before", 0, addr=addr))
        return marks

    def _states_menu(self, states) -> None:
        """The active count's menu: select those states in the symbolic execution view, or move them to a stash."""

        def select() -> None:
            symexec_view = self.symexec_view
            if symexec_view:
                symexec_view.select_states(states)
                symexec_view.workspace.raise_view(symexec_view)

        def move() -> None:
            def then(to_stash: str | None) -> None:
                symexec_view = self.symexec_view
                if to_stash is None or symexec_view is None:
                    return
                symexec_view.current_simgr.move("active", to_stash, lambda s: s in states)
                symexec_view.current_simgr.am_event(src="move")
                self._refresh_gui()

            GlobalInfo.ui_services.prompt_text_async("Move to?", "Target Stash Name:", "", then)

        GlobalInfo.ui_services.popup_menu(Menu("States", [MenuEntry("Select", select), MenuEntry("Move To", move)]))

    def build_qblock_annotations(self, qblock):
        from angrmanagement.ui.widgets.qinst_annotation import (  # pylint:disable=import-outside-toplevel
            QActiveCount,
            QPassthroughCount,
        )

        simgr = self._simgr()
        if simgr is None or simgr.am_none:
            # If there's no simgr selected at this moment, then there arent' any labels to show? Maybe
            return []

        qinsns = qblock.addr_to_insns.values()

        items = []
        for qinsn in qinsns:
            addr = qinsn.addr
            active_states = []
            passthrough_count = 0
            active_states += self.addr_to_active_states[addr]
            passthrough_count += self.passthrough_counts[addr]
            if qinsn.insn.mnemonic.opcode_string == "call":
                ret_addr = qinsn.insn.addr + qinsn.insn.size
                active_states += self.returning_to_here_states[ret_addr]
            if len(active_states) > 0:
                items.append(QActiveCount(qinsn.addr, active_states))
            if passthrough_count > 0:
                items.append(QPassthroughCount(qinsn.addr, passthrough_count))
        return items

    def _refresh_gui(self) -> None:
        self.update_active_states_label()
        if self.disasm_view is not None:
            self.disasm_view.refresh()

    def _init_widgets(self) -> None:
        from PySide6.QtWidgets import QLabel  # pylint:disable=import-outside-toplevel

        statusbar_layout = self.disasm_view._statusbar.layout()
        label = QLabel("Active states: 0")
        label.setStyleSheet("QLabel {color: green}")
        statusbar_layout.insertWidget(1, label)
        self.active_states_label = label
