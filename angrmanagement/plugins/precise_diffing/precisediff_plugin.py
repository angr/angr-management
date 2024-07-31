from __future__ import annotations

import difflib
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QFileDialog

from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs.cfg_generation import CFGGenerationJob
from angrmanagement.data.jobs.loading import LoadBinaryJob
from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views import CodeView, DisassemblyView

from .diff_view import DiffCodeView, DiffDisassemblyView
from .function_diff import BFSFunctionDiff, FunctionDiff
from .settings_dialog import SettingsDialog

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

logger = logging.getLogger(__name__)


class PreciseDiffPlugin(BasePlugin):
    """
    A plugin for performing precisions diffs on two binaries loaded in angr-management.
    """

    DIFF_SETTINGS_CMD_EVT = 0
    LOAD_BINARY_CMD_EVT = 1
    RELOAD_BINARY_CMD_EVT = 2
    MENU_BUTTONS = ("Precise Diffing settings...", "Load binary for Precise Diffing...", "Refresh loaded diff binary")

    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)
        self.diff_instance: Instance | None = None
        self.current_revised_view: DisassemblyView | None = None
        self.current_revised_code: CodeView | None = None

        self.loaded_binary: Path | None = None
        self.diff_algo: FunctionDiff | None = None

        self.prefer_symbols = True
        self.resolve_strings = True
        self.resolve_insns = True
        self.use_addrs = False
        self.ignore_globals = True
        self.diff_algo_class = BFSFunctionDiff
        self.add_color = QColor(0xDDFFDD)
        self.decomp_add_color = QColor(141, 237, 141, int(0.5 * 255))
        self.del_color = QColor(0xFF7F7F)
        self.decomp_del_color = QColor(237, 141, 141, int(0.5 * 255))
        self.chg_color = QColor(0xF4ECC2)
        self.decomp_chg_color = QColor(247, 247, 138, int(0.5 * 255))

        self._differing_funcs = set()

        self._old_disass_keypress = None
        self._old_code_keypress = None

    #
    # UI Callback Handlers
    #

    def handle_click_menu(self, idx: int) -> None:
        if idx == self.DIFF_SETTINGS_CMD_EVT:
            dialog = SettingsDialog(self)
            dialog.exec()
            if dialog.updates and self.loaded_binary:
                self.syncronize_with_original_disassembly_view()
            self.ignore_globals = dialog._ignore_globals.isChecked()

        elif idx == self.LOAD_BINARY_CMD_EVT:
            params = {}
            # if a project is loaded, we use the base directory of the project
            if (
                not self.workspace.main_instance.project.am_none
                and self.workspace.main_instance.project.loader.main_object is not None
                and isinstance(self.workspace.main_instance.project.loader.main_object.binary, str)
            ):
                params["dir"] = os.path.dirname(self.workspace.main_instance.project.loader.main_object.binary)
            filepath, _ = QFileDialog.getOpenFileName(caption="Load Recompiled Object", **params)
            if not filepath:
                return

            self.load_revised_binary_from_file(Path(filepath))

        elif idx == self.RELOAD_BINARY_CMD_EVT and self.loaded_binary is not None:
            self.load_revised_binary_from_file(self.loaded_binary)

    def color_insn(self, addr: int, selected, disasm_view):
        if disasm_view != self.current_revised_view:
            return None

        if self.diff_algo is None:
            return None

        diff_value = self.diff_algo.addr_diff_value(addr)
        return self._color_map(diff_value)

    def color_func(self, func) -> QColor | None:
        return self.chg_color if func in self._differing_funcs else None

    #
    # View Construction
    #

    def _compute_differing_funcs(self):
        self._differing_funcs = set()
        base_funcs = self.workspace.main_instance.kb.functions
        base_proj = self.workspace.main_instance.project

        rev_funcs = self.diff_instance.kb.functions
        rev_proj = self.diff_instance.project

        hash_diff_pairs = []
        for func in base_funcs.values():
            if func.is_plt or func.is_syscall:
                continue

            func_key = func.addr if self.use_addrs else func.name
            if func_key not in rev_funcs:
                # TODO: do add/del highlighting
                continue

            rev_func = rev_funcs[func_key]
            base_f_hash = hashlib.md5(base_proj.loader.memory.load(func.addr, func.size)).hexdigest()
            rev_f_hash = hashlib.md5(rev_proj.loader.memory.load(rev_func.addr, rev_func.size)).hexdigest()

            if base_f_hash != rev_f_hash:
                hash_diff_pairs.append((func, rev_func))

        for base_func, rev_func in hash_diff_pairs:
            if (base_func.size != rev_func.size) or self._funcs_differ(base_func, rev_func):
                self._differing_funcs.add(base_func)

    def _funcs_differ(self, base_func, rev_func) -> bool:
        """
        We need to grab the disassembly view for each function (which may require focusing) and then compare them
        in the diffing algorithm that is more intensive than just comparing hashes.
        """
        base_disass = self.workspace.view_manager.first_view_in_category("disassembly")
        rev_disass = self.current_revised_view
        base_disass.function = base_func
        rev_disass.function = rev_func

        self.diff_algo = self.diff_algo_class(
            base_func,
            rev_func,
            disas_base=base_disass.disasm,
            disas_rev=rev_disass.disasm,
            view_base=base_disass,
            view_rev=rev_disass,
            resolve_strings=self.resolve_strings,
            prefer_symbols=self.prefer_symbols,
            resolve_insn_addrs=self.resolve_insns,
        )

        return self.diff_algo.differs

    def _color_map(self, diff_value):
        diff_map = {
            FunctionDiff.OBJ_ADDED: self.add_color,
            FunctionDiff.OBJ_DELETED: self.del_color,
            FunctionDiff.OBJ_CHANGED: self.chg_color,
            FunctionDiff.OBJ_UNMODIFIED: None,
        }

        return diff_map[diff_value]

    def color_functions_table(self):
        self._compute_differing_funcs()
        base_func_view = self.workspace.view_manager.first_view_in_category("functions")
        if base_func_view is not None:
            base_func_view.reset_cache_and_refresh()

    def color_graph_diff(self, og_disasm: DisassemblyView, new_disasm: DisassemblyView) -> None:
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
            resolve_insn_addrs=self.resolve_insns,
        )
        new_disasm.redraw_current_graph()

    def color_pseudocode_diff(self, *args) -> None:  # pylint:disable=unused-argument
        og_code = self.workspace._get_or_create_view("pseudocode", CodeView)
        new_code = self.workspace._get_or_create_view("pseudocode_diff", DiffCodeView)
        try:
            base_func = og_code.codegen.text
            rev_func = new_code.codegen.text
            if self.ignore_globals:
                base_func = re.sub(r"g_[a-fA-F0-9]+", lambda m: "_" * len(m.group(0)), base_func)
                rev_func = re.sub(r"g_[a-fA-F0-9]+", lambda m: "_" * len(m.group(0)), rev_func)
        except (AttributeError, ValueError):
            return

        if base_func is None or rev_func is None:
            return

        base_lines = base_func.splitlines()
        rev_lines = rev_func.splitlines()
        diff_lines = list(difflib.ndiff(base_lines, rev_lines))
        # diff_lines = list(difflib.unified_diff(base_lines, rev_lines, lineterm=""))

        new_idx = 0
        old_idx = 0
        for line in diff_lines:
            real_line = line[2:]
            idx = None
            view = None
            color = None
            if line.startswith("+"):
                idx = rev_func.find(real_line, new_idx)
                new_idx = idx + len(real_line)
                color = self.decomp_add_color
                view = new_code
            elif line.startswith("-"):
                idx = base_func.find(real_line, old_idx)
                old_idx = idx + len(real_line)
                color = self.decomp_del_color
                view = og_code

            if view is not None and idx > -1:
                self.color_lines(view, idx, len(real_line), color)

    @staticmethod
    def color_lines(view: CodeView, start: int, length: int, color: QColor):
        # Create a QTextCursor from the QTextEdit
        cursor = QTextCursor(view.document)

        # Move the cursor to the start position and select the text range
        cursor.setPosition(start)
        cursor.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, length)

        # Create a QTextCharFormat and set the background color
        char_format = QTextCharFormat()
        char_format.setBackground(color)

        # Apply the char format to the selected text
        cursor.setCharFormat(char_format)

    def _destroy_revised_view(self) -> None:
        if self.current_revised_view:
            self.workspace.remove_view(self.current_revised_view)
            del self.current_revised_view

        self._differing_funcs = set()
        if self.diff_instance:
            del self.diff_instance

    def _create_instance_from_binary(self, file_path: Path) -> None:
        self.diff_instance.recompilation_plugin = self
        self.diff_instance.workspace = self.workspace

        job = LoadBinaryJob(self.workspace.main_instance, file_path, on_finish=self._create_instance_from_binary_done)
        self.loaded_binary = file_path
        self.workspace.job_manager.add_job(job)

    def _create_instance_from_binary_done(self, _: Any) -> None:
        job = CFGGenerationJob(self.workspace.main_instance, on_finish=self._generate_binary_cfg_done)
        self.workspace.job_manager.add_job(job)

    def _generate_binary_cfg_done(self, cfg_info: Any) -> None:
        cfg_model, _ = cfg_info
        self.diff_instance.cfg = cfg_model
        self.revised_binary_loaded()

    def _create_revised_disassembly_view(self):
        new_disass = DiffDisassemblyView(self.workspace, "right", self.diff_instance)
        new_disass.category = "diff"
        new_disass.base_caption = "Precise Diff"
        self.current_revised_view = new_disass
        self.workspace.add_view(self.current_revised_view)
        return self.current_revised_view

    def _create_revised_code_view(self):
        new_psuedocode = DiffCodeView(self.workspace, "right", self.diff_instance, self.color_pseudocode_diff)
        new_psuedocode.category = "pseudocode_diff"
        new_psuedocode.base_caption = "Precise Diff Pseudocode"
        self.current_revised_code = new_psuedocode
        self.workspace.add_view(self.current_revised_code)
        return self.current_revised_code

    def jump_to_in_revised_view(self, func) -> None:
        self.current_revised_view.display_function(func)
        self.current_revised_view.jump_to(func.addr)

    def syncronize_with_original_disassembly_view(self) -> None:
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
        if not self._old_disass_keypress:
            self._old_disass_keypress = og_view.keyPressEvent
            og_view.keyPressEvent = self.stub_disass_keypress

            og_psuedo = self.workspace._get_or_create_view("pseudocode", CodeView)
            self._old_code_keypress = og_psuedo.keyPressEvent
            og_psuedo.keyPressEvent = self.stub_code_keypress

    def stub_disass_keypress(self, event):
        self._old_disass_keypress(event)
        if event.key() in {Qt.Key_Tab, Qt.Key_F5}:
            self.current_revised_view.keyPressEvent(event)
            self.color_pseudocode_diff(
                self.workspace._get_or_create_view("pseudocode", CodeView), self.current_revised_code
            )

    def stub_code_keypress(self, event):
        if event.key() == Qt.Key_Tab:
            self.current_revised_code.keyPressEvent(event)
        self._old_code_keypress(event)

    def load_revised_binary_from_file(self, file_path: Path) -> None:
        self._destroy_revised_view()
        self.diff_instance = Instance()
        self._create_instance_from_binary(file_path)

    def revised_binary_loaded(self) -> None:
        self._create_revised_disassembly_view()
        self._create_revised_code_view()
        self.syncronize_with_original_disassembly_view()
        self.workspace.view_manager.raise_view(self.current_revised_view)

        original_disass_view = self.diff_instance.workspace._get_or_create_view("disassembly", DisassemblyView)
        self.current_revised_view.sync_with_state_object(original_disass_view.sync_state)
        self.color_functions_table()
