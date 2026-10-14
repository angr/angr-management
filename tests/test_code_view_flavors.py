"""
Rust- and Go-flavor pseudocode in CodeView: globals and calls must be highlighted and double-clickable, exactly
like their C-flavor counterparts.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import angr
import cle
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from common import AngrManagementTestCase, test_location
from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QColor, QKeyEvent

from angrmanagement.config import Conf
from angrmanagement.ui.views.code_view import CodeView
from angrmanagement.ui.widgets import qccode_highlighter


def _is_global(var) -> bool:
    return isinstance(var, SimMemoryVariable) and not isinstance(var, SimStackVariable)


def _scoped_cfg(proj: angr.Project, root: int, window: int = 0x2000):
    """A CFG over ``root`` and its direct callees only; a whole-binary CFG takes a minute on these binaries."""
    main_object = proj.loader.main_object
    tmp_kb = angr.KnowledgeBase(proj)
    proj.analyses[angr.analyses.CFGFast].prep(kb=tmp_kb)(
        normalize=True, regions=[(root, root + window)], start_at_entry=False, function_starts=[root], symbols=False
    )
    callgraph = tmp_kb.functions.callgraph
    starts = {root} | {c for c in callgraph.successors(root) if main_object.contains_addr(c)}
    cfg = proj.analyses.CFGFast(
        normalize=True,
        regions=[(a, a + window) for a in sorted(starts)],
        start_at_entry=False,
        function_starts=sorted(starts),
        symbols=True,
        force_smart_scan=False,
        show_progressbar=False,
    )
    proj.analyses.CompleteCallingConventions(prioritize_func_addrs=[root], skip_other_funcs=True)
    return cfg


class FlavorCodeViewTest(AngrManagementTestCase):
    """Opens one function of a Rust or Go binary in CodeView under the given flavor."""

    __test__ = False  # only the per-flavor subclasses run
    FLAVOR = ""

    def setUp(self) -> None:
        super().setUp()
        # tell the three colors apart; the defaults paint globals and functions the same blue
        self._saved = {
            k: getattr(Conf, k)
            for k in ("pseudocode_variable_color", "pseudocode_global_variable_color", "pseudocode_function_color")
        }
        Conf.pseudocode_variable_color = QColor(0x10, 0x20, 0x30)
        Conf.pseudocode_global_variable_color = QColor(0x40, 0x50, 0x60)
        Conf.pseudocode_function_color = QColor(0x70, 0x80, 0x90)
        qccode_highlighter.reset_formats()

        proj, cfg_model, func_addr = self._load()
        inst = self.main.workspace.main_instance
        inst.project.am_obj = proj
        inst.project.am_event()
        inst.cfg.am_obj = cfg_model
        inst.cfg.am_event()
        self.main.workspace.job_manager.join_all_jobs()

        self.func = proj.kb.functions[func_addr]
        self.code_view: CodeView = self.main.workspace._get_or_create_view("pseudocode", CodeView)
        self.code_view.function.am_obj = self.func
        self.code_view.decompile(flavor=self.FLAVOR)
        self.main.workspace.job_manager.join_all_jobs()
        assert self.code_view.codegen.flavor == self.FLAVOR
        self.code_view.textedit.code_highlighter.rehighlight()

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            setattr(Conf, k, v)
        qccode_highlighter.reset_formats()
        del self.code_view
        super().tearDown()

    def _load(self):
        raise NotImplementedError

    # helpers

    def _elements(self):
        posmap = self.code_view.codegen.map_pos_to_node
        assert posmap is not None
        return [elem for _, elem in sorted(posmap.items())]

    def _global_element(self):
        for elem in self._elements():
            if _is_global(getattr(elem.obj, "variable", None)):
                return elem
        raise AssertionError("no global variable in the pseudocode")

    def _call_element(self):
        for elem in self._elements():
            if getattr(elem.obj, "callee_func", None) is not None and "ins_addr" in elem.obj.tags:
                return elem
        raise AssertionError("no call to a known function in the pseudocode")

    def _format_at(self, pos: int):
        doc = self.code_view.textedit.document()
        block = doc.findBlock(pos)
        off = pos - block.position()
        for fr in block.layout().formats():
            if fr.start <= off < fr.start + fr.length:
                # the FormatRange dies with the list; keep a copy of what we need
                return QColor(fr.format.foreground().color())
        return None

    def _assert_color(self, elem, conf_attr: str) -> None:
        color = self._format_at(elem.start)
        text = self.code_view.codegen.text[elem.start : elem.start + elem.length]
        assert color is not None, f"{text!r} is not highlighted at all"
        assert color == getattr(Conf, conf_attr), f"{text!r} is not painted as {conf_attr}"

    def _double_click_at(self, pos: int) -> None:
        cursor = self.code_view.textedit.textCursor()
        cursor.setPosition(pos)
        self.code_view.textedit.setTextCursor(cursor)
        self.code_view._on_mouse_doubleclicked()

    # tests

    def test_global_variable_is_highlighted(self):
        self._assert_color(self._global_element(), "pseudocode_global_variable_color")

    def test_function_call_is_highlighted(self):
        self._assert_color(self._call_element(), "pseudocode_function_color")

    def test_double_click_global_variable_jumps_to_it(self):
        elem = self._global_element()
        with patch.object(self.main.workspace, "jump_to") as jump_to:
            self._double_click_at(elem.start)
        jump_to.assert_called_once_with(elem.obj.variable.addr)

    def test_double_click_function_call_decompiles_callee(self):
        elem = self._call_element()
        with patch.object(self.main.workspace, "decompile_function") as decompile_function:
            self._double_click_at(elem.start)
        decompile_function.assert_called_once()
        assert decompile_function.call_args.args[0] is elem.obj.callee_func


class TestGoCodeView(FlavorCodeViewTest):
    """main.main of a Go 1.22 binary reads os.Args and main.counter and calls main.parse and friends."""

    __test__ = True
    FLAVOR = "go"

    def _load(self):
        path = os.path.join(test_location, "x86_64", "go", "go1.22.5", "basics")
        addr = cle.Loader(path, auto_load_libs=False).find_symbol("main.main").rebased_addr
        proj = angr.Project(path, auto_load_libs=False)
        return proj, _scoped_cfg(proj, addr).model, addr

    def _first_statement_pos(self) -> int:
        return min(elem.posmap_pos for _, elem in self.code_view.codegen.map_addr_to_pos.items())

    def test_focus_on_function_head_places_cursor(self):
        # the Go stack-check preamble has no statement, so the head precedes every rendered address
        cursor = self.code_view.textedit.textCursor()
        cursor.setPosition(len(self.code_view.codegen.text) - 1)
        self.code_view.textedit.setTextCursor(cursor)
        self.main.workspace.decompile_function(self.func, curr_ins=self.func.addr)
        self.main.workspace.job_manager.join_all_jobs()
        assert self.code_view.textedit.textCursor().position() == self._first_statement_pos()

    def test_tab_falls_back_to_function_head(self):
        self.code_view.addr.am_obj = 0
        with patch.object(self.main.workspace, "jump_to") as jump_to:
            self.code_view.keyPressEvent(QKeyEvent(QEvent.KeyPress, Qt.Key_Tab, Qt.NoModifier))
        jump_to.assert_called_once_with(self.func.addr)

    def test_jump_to_another_function_switches_function(self):
        inst = self.main.workspace.main_instance
        inst.cfb.am_obj = inst.project.analyses.CFB(kb=inst.project.kb)
        callee = inst.project.kb.functions["main.parse"]
        with patch.object(self.code_view, "decompile") as decompile:
            self.code_view.jump_to(callee.addr)
        assert self.code_view.function.am_obj is callee
        decompile.assert_called_once()


class TestRustCodeView(FlavorCodeViewTest):
    """A small function of Rust coreutils fmt that takes the address of g_51bbb0 and calls sub_437190."""

    __test__ = True
    FLAVOR = "rust"
    FUNC_ADDR = 0x4383B0

    def _load(self):
        path = os.path.join(test_location, "x86_64", "rust", "coreutils", "nightly-2023-05-22-O3", "fmt")
        proj = angr.Project(path, auto_load_libs=False)
        return proj, _scoped_cfg(proj, self.FUNC_ADDR, window=0x400).model, self.FUNC_ADDR


if __name__ == "__main__":
    unittest.main()
