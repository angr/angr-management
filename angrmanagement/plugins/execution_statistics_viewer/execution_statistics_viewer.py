from collections import defaultdict
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QLabel

from angrmanagement.logic.threads import gui_thread_schedule
from angrmanagement.plugins.base_plugin import BasePlugin
from angrmanagement.ui.widgets.qinst_annotation import QActiveCount, QPassthroughCount

if TYPE_CHECKING:
    from angrmanagement.ui.views import DisassemblyView, SymexecView


class ExecutionStatisticsViewer(BasePlugin):
    """
    Add a step_callback hook to count how many state on and passthrough of a particular address.
    return the result in build_qblock_annotations callback and show in the disassmbly view by
    fetch_qblock_annotations function.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passthrough_counts = defaultdict(int)
        self.addr_to_active_states = defaultdict(list)
        self.returning_to_here_states = defaultdict(list)
        self.bb_addrs = None
        self.instance = self.workspace.main_instance

        if self.symexec_view:
            self.current_simgr = self.symexec_view.current_simgr
            self.current_simgr.am_subscribe(self._on_simgr_selected)
        self._init_widgets()

    @property
    def disasm_view(self) -> "DisassemblyView":
        return self.workspace.view_manager.first_view_in_category("disassembly")

    @property
    def symexec_view(self) -> "SymexecView":
        return self.workspace.view_manager.first_view_in_category("symexec")

    def count_passthrough(self, simgr):
        """Prior to stepping the active states, increment the passthrough count on the basic block(s) that will be
        executed next."""
        if self.bb_addrs is None:
            self.bb_addrs = {b.addr for b in self.instance.cfg.nodes()}
        for s in simgr.active:
            for i_addr in s.block().instruction_addrs:
                if i_addr in self.bb_addrs:
                    self.passthrough_counts[i_addr] += 1

    def step_callback(self, simgr):
        """Called after stepping the simgr"""
        self.count_passthrough(simgr)
        self.count_active_states(simgr)
        gui_thread_schedule(self._refresh_gui)

    def count_active_states(self, simgr):
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

    def _on_simgr_selected(self, *args, src=None, **kwargs):  # pylint: disable=unused-argument
        """Listener for when a new simgr is selected in the symexec view"""
        if src in ["clicked", "from above"]:
            # The "from above" event is emitted when you create a new simgr via right click menu in disasm view
            self.passthrough_counts = defaultdict(int)
            self.addr_to_active_states = defaultdict(list)
            self.returning_to_here_states = defaultdict(list)
            if not self.current_simgr.am_none:
                self.count_active_states(self.current_simgr)
            self._refresh_gui()

    def update_active_states_label(self):
        if not self.current_simgr.am_none:
            self.active_states_label.setText(f"Active states: {len(self.current_simgr.active)}")

    def build_qblock_annotations(self, qblock):
        if self.current_simgr.am_none:
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

    def _refresh_gui(self):
        self.update_active_states_label()
        self.disasm_view.refresh()

    def _init_widgets(self):
        statusbar_layout = self.disasm_view._statusbar.layout()
        label = QLabel("Active states: 0")
        label.setStyleSheet("QLabel {color: green}")
        statusbar_layout.insertWidget(1, label)
        self.active_states_label = label
