from typing import List, Iterator, Optional

from PySide2.QtGui import QColor
from angr.analyses.disassembly import Instruction
from angr.sim_manager import SimulationManager

from angrmanagement.data.jobs.loading import LoadBinaryJob
from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation, QPassthroughCount
from angrmanagement.ui.widgets.qblock import QBlock
from angrmanagement.plugins import BasePlugin

from angrmanagement.ui.workspace import Workspace
from angrmanagement.data.instance import Instance
from angrmanagement.ui.views import DisassemblyView

import angr

from PySide2.QtWidgets import QFileDialog


class RecompilationPlugin(BasePlugin):
    CHANGE_COMP_CMD_EVT = 0
    CHANGE_COMP_DIR_EVT = 1

    def __init__(self, workspace):
        super().__init__(workspace)
        self.recolor_map = set()
        self.recompilation_view: Optional[DisassemblyView] = None

        #workspace.instance.register_container('bookmarks', lambda: [], List[int], 'Bookmarked addresses')

    MENU_BUTTONS = ('Change Compilation Command...', 'Change Compilation Directory...')

    def build_context_menu_functions(self, funcs): # pylint: disable=unused-argument
        yield ("Load recompiled object", self.load_recompiled_obj)

    def handle_click_menu(self, idx):
        if idx == self.CHANGE_COMP_CMD_EVT:
            print("Change compiler command")
        elif idx == self.CHANGE_COMP_DIR_EVT:
            print("Change compiler dir")

    def color_graph_diff(self, og_disasm: DisassemblyView, new_disasm: DisassemblyView):
        og_insn_map = og_disasm.disasm.raw_result_map['instructions']
        new_insn_map = new_disasm.disasm.raw_result_map['instructions']

        og_sorted_addrs = sorted(list(og_insn_map.keys()))
        new_sorted_addrs = sorted(list(new_insn_map.keys()))

        for idx, addr in enumerate(og_sorted_addrs):
            if idx > len(new_sorted_addrs):
                break

            og_insn: Instruction = og_insn_map[og_sorted_addrs[idx]]
            new_insn = new_insn_map[new_sorted_addrs[idx]]
            
            og_str = str(og_insn.insn).strip().replace("\t", "").replace(" ", "").split(":")[1]
            new_str = str(new_insn.insn).strip().replace("\t", "").replace(" ", "").split(":")[1]
            
            if og_str != new_str:
                self.recolor_map.add(new_sorted_addrs[idx])

        new_disasm.redraw_current_graph()
        #self.recolor_map = set()

    def color_insn(self, addr, selected):
        if addr in self.recolor_map:
            return QColor("red")

    def _reset_recompiled_view(self):
        self.recolor_map = set()
        if not self.recompilation_view:
            return

        self.workspace.remove_view(self.recompilation_view)
        del self.recompilation_view.instance
        del self.recompilation_view

    def _construct_new_recomp_view(self, obj_path):
        recomp_instance = Instance()
        recomp_instance.workspace = self.workspace
        recomp_instance.project.am_obj = angr.Project(obj_path, auto_load_libs=False)
        recomp_instance.cfg = recomp_instance.project.analyses.CFG()
        func = recomp_instance.cfg.functions['sub_11c9d'] #recomp_instance.project.entry]

        new_disass = DisassemblyView(recomp_instance, "center")
        new_disass.category = "recompilation"
        new_disass.base_caption = "Recompilation"
        self.recompilation_view = new_disass

        return func

    def load_recompiled_obj(self, *arg, **kwargs):
        filepath, _ = QFileDialog.getOpenFileName(caption="Load Recompiled Object")
        if not filepath:
            return

        self._reset_recompiled_view()
        func = self._construct_new_recomp_view(filepath)

        self.workspace.add_view(self.recompilation_view)
        self.recompilation_view.display_function(func)
        self.workspace.view_manager.raise_view(self.recompilation_view)
        self.recompilation_view.jump_to(func.addr)

        self.color_graph_diff(self.workspace._get_or_create_disassembly_view(), self.recompilation_view)

