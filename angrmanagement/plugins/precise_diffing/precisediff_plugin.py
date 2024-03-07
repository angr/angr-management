import logging
from pathlib import Path
from typing import Optional

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFileDialog

from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs.cfg_generation import CFGGenerationJob
from angrmanagement.data.jobs.loading import LoadBinaryJob
from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views import DisassemblyView

from .diff_view import DiffDisassemblyView
from .function_diff import BFSFunctionDiff, FunctionDiff
from .settings_dialog import SettingsDialog

logger = logging.getLogger(__name__)


class PreciseDiffPlugin(BasePlugin):
    """
    A plugin for performing precisions diffs on two binaries loaded in angr-management.
    """

    DIFF_SETTINGS_CMD_EVT = 0
    LOAD_BINARY_CMD_EVT = 1
    RELOAD_BINARY_CMD_EVT = 2
    MENU_BUTTONS = ("Precise Diffing settings...", "Load binary for Precise Diffing...", "Refresh loaded diff binary")

    def __init__(self, workspace):
        super().__init__(workspace)
        self.diff_instance: Optional[Instance] = None
        self.current_revised_view: Optional[DisassemblyView] = None

        self.loaded_binary: Optional[Path] = None
        self.diff_algo: Optional[FunctionDiff] = None

        self.prefer_symbols = True
        self.resolve_strings = True
        self.use_addrs = False
        self.diff_algo_class = BFSFunctionDiff
        self.add_color = QColor(0xDDFFDD)
        self.del_color = QColor(0xFF7F7F)
        self.chg_color = QColor(0xF4ECC2)

        self.seen_insns = set()

    #
    # UI Callback Handlers
    #

    def handle_click_menu(self, idx):
        if idx == self.DIFF_SETTINGS_CMD_EVT:
            dialog = SettingsDialog(self)
            dialog.exec()
            if dialog.updates and self.loaded_binary:
                self.syncronize_with_original_disassembly_view()

        elif idx == self.LOAD_BINARY_CMD_EVT:
            filepath, _ = QFileDialog.getOpenFileName(caption="Load Recompiled Object")
            if not filepath:
                logger.warning("Binary selection cancelled.")
                return

            self.load_revised_binary_from_file(Path(filepath))

        elif idx == self.RELOAD_BINARY_CMD_EVT and self.loaded_binary is not None:
            self.load_revised_binary_from_file(self.loaded_binary)

    def color_insn(self, addr, selected, disasm_view):
        if disasm_view != self.current_revised_view:
            return None

        if self.diff_algo is None:
            return None

        diff_value = self.diff_algo.addr_diff_value(addr)
        return self._color_map(diff_value)

    #
    # View Construction
    #

    def _color_map(self, diff_value):
        diff_map = {
            FunctionDiff.OBJ_ADDED: self.add_color,
            FunctionDiff.OBJ_DELETED: self.del_color,
            FunctionDiff.OBJ_CHANGED: self.chg_color,
            FunctionDiff.OBJ_UNMODIFIED: None,
        }

        return diff_map[diff_value]

    def color_graph_diff(self, og_disasm: DisassemblyView, new_disasm: DisassemblyView):
        try:
            base_func = og_disasm.function.am_obj
            rev_func = new_disasm.function.am_obj
        except (AttributeError, ValueError):
            return

        if base_func is None or rev_func is None:
            return

        self.diff_algo = self.diff_algo_class(
            base_func,
            rev_func,
            disas_base=og_disasm.disasm,
            disas_rev=new_disasm.disasm,
            view_base=og_disasm,
            view_rev=new_disasm,
            resolve_strings=self.resolve_strings,
            prefer_symbols=self.prefer_symbols,
        )
        new_disasm.redraw_current_graph()

    def _destroy_recompiled_view(self):
        if self.current_revised_view:
            self.workspace.remove_view(self.current_revised_view)
            del self.current_revised_view

        if self.diff_instance:
            del self.diff_instance

    def _create_instance_from_binary(self, file_path: Path):
        self.diff_instance.recompilation_plugin = self
        self.diff_instance.workspace = self.workspace

        job = LoadBinaryJob(file_path, on_finish=self._create_instance_from_binary_done)
        self.loaded_binary = file_path
        self.diff_instance.add_job(job)

    def _create_instance_from_binary_done(self):
        job = CFGGenerationJob(on_finish=self._generate_binary_cfg_done)
        self.diff_instance.add_job(job)

    def _generate_binary_cfg_done(self):
        self.revised_binary_loaded()

    def _create_revised_disassembly_view(self):
        new_disass = DiffDisassemblyView(self.workspace, self.diff_instance, "center")
        new_disass.category = "diff"
        new_disass.base_caption = "Precise Diff"
        self.current_revised_view = new_disass
        self.workspace.add_view(self.current_revised_view)
        return self.current_revised_view

    def jump_to_in_revised_view(self, func):
        self.current_revised_view.display_function(func)
        self.current_revised_view.jump_to(func.addr)

    # pylint:disable=unused-argument
    def syncronize_with_original_disassembly_view(self, *args, **kwargs):
        og_view = self.workspace._get_or_create_view("disassembly", DisassemblyView)
        if not og_view:
            return

        try:
            func_obj = og_view.current_function
        except NotImplementedError:
            return

        if func_obj is None or func_obj.am_obj is None:
            return

        og_func = func_obj.am_obj
        og_func_name = og_func.name

        lookup_sym = og_func.addr if self.use_addrs else og_func_name
        try:
            revised_func = self.diff_instance.kb.functions[lookup_sym]
        except KeyError:
            logger.warning(
                "The function %s does not exist in the diffed binary",
                hex(lookup_sym) if self.use_addrs else og_func_name,
            )
            return

        self.jump_to_in_revised_view(revised_func)
        self.color_graph_diff(og_view, self.current_revised_view)

    def load_revised_binary_from_file(self, file_path: Path):
        self._destroy_recompiled_view()
        self.diff_instance = Instance()
        self._create_instance_from_binary(file_path)

    def revised_binary_loaded(self):
        self._create_revised_disassembly_view()
        self.syncronize_with_original_disassembly_view()
        self.workspace.view_manager.raise_view(self.current_revised_view)

        original_disass_view = self.diff_instance.workspace._get_or_create_view("disassembly", DisassemblyView)
        self.current_revised_view.sync_with_state_object(original_disass_view.sync_state)
