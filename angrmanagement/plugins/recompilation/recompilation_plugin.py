from typing import List, Iterator, Optional
from pathlib import Path
import logging

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFileDialog
from angr.analyses.disassembly import Instruction

from angrmanagement.data.jobs.loading import LoadBinaryJob
from angrmanagement.ui.widgets.qinst_annotation import QInstructionAnnotation, QPassthroughCount
from angrmanagement.ui.widgets.qblock import QBlock
from angrmanagement.plugins import BasePlugin

from angrmanagement.ui.workspace import Workspace
from angrmanagement.data.instance import Instance
from angrmanagement.ui.views import DisassemblyView

import angr

from .recompilation_view import RevisedDisassemblyView
from .function_diff import FunctionDiff, LinearFunctionDiff, BFSFunctionDiff

l = logging.getLogger(__name__)


class RecompilationPlugin(BasePlugin):
    LOAD_BINARY_CMD_EVT = 0
    DIFF_COLOR_MAP = {
        FunctionDiff.OBJ_ADDED: QColor("green"),
        FunctionDiff.OBJ_CHANGED: QColor("yellow"),
        FunctionDiff.OBJ_DELETED: QColor("red"),
        FunctionDiff.OBJ_UNMODIFIED: None
    }

    #CHANGE_COMP_CMD_EVT = 0
    #CHANGE_COMP_DIR_EVT = 1

    def __init__(self, workspace):
        super().__init__(workspace)
        self.recolor_map = set()
        self.recompilation_instance: Optional[Instance] = None
        self.current_revised_view: Optional[DisassemblyView] = None
        self.diff_algo: Optional[FunctionDiff] = None
        # workspace.instance.register_container('bookmarks', lambda: [], List[int], 'Bookmarked addresses')

    MENU_BUTTONS = ("Load revised binary for diffing...",)
    #MENU_BUTTONS = ("Change Compilation Command...", "Change Compilation Directory..."

    #
    # UI Callback Handlers
    #

    def build_context_menu_functions(self, funcs):  # pylint: disable=unused-argument
        yield ("Syncronize", self.syncronize_with_original_disassembly_view)

    def handle_click_menu(self, idx):
        if idx == self.LOAD_BINARY_CMD_EVT:
            l.info("Selecting a revised binary for diffing...")
            filepath, _ = QFileDialog.getOpenFileName(caption="Load Recompiled Object")
            if not filepath:
                l.info("Binary selection cancelled.")
                return

            self.load_revised_binary_from_file(Path(filepath))

    def color_insn(self, addr, selected):
        if self.diff_algo is None:
            return

        diff_value = self.diff_algo.addr_diff_value(addr)
        return self.DIFF_COLOR_MAP[diff_value]

    #
    # View Construction
    #

    def color_graph_diff(self, og_disasm: DisassemblyView, new_disasm: DisassemblyView):
        try:
            base_func = og_disasm.function.am_obj
            rev_func = new_disasm.function.am_obj
        except Exception:
            return

        if base_func is None or rev_func is None:
            return

        self.diff_algo = BFSFunctionDiff(base_func, rev_func)
        new_disasm.redraw_current_graph()

    def _destroy_recompiled_view(self):
        self.recolor_map = set()
        if self.current_revised_view:
            self.workspace.remove_view(self.current_revised_view)
            del self.current_revised_view

        if self.recompilation_instance:
            del self.recompilation_instance

    def _create_instance_from_binary(self, file_path: Path):
        recompilation_instance = Instance()
        recompilation_instance.recompilation_plugin = self
        recompilation_instance.workspace = self.workspace
        recompilation_instance.project.am_obj = angr.Project(file_path, auto_load_libs=False)
        recompilation_instance.cfg = recompilation_instance.project.analyses.CFG()
        #func = recompilation_instance.cfg.functions["get_prefix"]  # recomp_instance.project.entry]
        l.warning(f"Finished loading recompilation instance for {file_path}")

        return recompilation_instance

    def _create_revised_disassembly_view(self):
        new_disass = RevisedDisassemblyView(self.recompilation_instance, "center")
        new_disass.category = "recompilation"
        new_disass.base_caption = "Recompilation"
        self.current_revised_view = new_disass
        self.workspace.add_view(self.current_revised_view)
        return self.current_revised_view
    
    def jump_to_in_revised_view(self, func):
        self.current_revised_view.display_function(func)
        self.current_revised_view.jump_to(func.addr)

    def syncronize_with_original_disassembly_view(self, *args, **kwargs):
        og_view = self.workspace._get_or_create_disassembly_view()
        if not og_view:
            print("No og view")
            return None

        try:
            func_obj = og_view.current_function
        except NotImplementedError:
            print("No current_function")
            return None

        if func_obj is None or func_obj.am_obj is None:
            print("No am obj")
            return None

        og_func = func_obj.am_obj
        og_func_name = og_func.name

        try:
            revised_func = self.recompilation_instance.cfg.functions[og_func_name]
        except KeyError:
            print(f"The function {og_func_name} does not exist in the revised binary")
            return

        self.recolor_map = set()
        self.jump_to_in_revised_view(revised_func)
        # TODO: move me
        self.color_graph_diff(og_view, self.current_revised_view)

    def load_revised_binary_from_file(self, file_path: Path):
        self._destroy_recompiled_view()
        self.recompilation_instance = self._create_instance_from_binary(file_path)
        self._create_revised_disassembly_view()
        self.syncronize_with_original_disassembly_view()
        self.workspace.view_manager.raise_view(self.current_revised_view)
