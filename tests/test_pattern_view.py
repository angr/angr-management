# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest

import angr
from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.known_patterns import PAny, PAnyStmt, PCallStmt, PConst, PLoad, PReturn, PStmtSeq
from angr.analyses.decompiler.known_patterns.dsl import PatternExpr
from common import AngrManagementTestCase, test_location
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor, QTextFormat
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QLabel, QMessageBox

from angrmanagement.config import Conf
from angrmanagement.ui.views import CodeView, DisassemblyView
from angrmanagement.ui.views.pattern_view import PatternView
from angrmanagement.ui.widgets.qpattern_graph import QPatternNode


def _all_nodes(editor, path=()):
    out = []
    for child_path, child in editor.children(path):
        out.append((child_path, child))
        out.extend(_all_nodes(editor, child_path))
    return out


class TestPatternView(AngrManagementTestCase):
    def _decompile_main(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()
        func = main.workspace.main_instance.project.kb.functions["main"]

        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()
        main.workspace.job_manager.join_all_jobs()
        code_view = main.workspace._get_or_create_view("pseudocode", CodeView)
        assert code_view.codegen.am_obj is not None
        return func, code_view

    def _decompile(self, binary: str, func_name: str):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", binary)
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()
        func = main.workspace.main_instance.project.kb.functions[func_name]

        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()
        main.workspace.job_manager.join_all_jobs()
        code_view = main.workspace._get_or_create_view("pseudocode", CodeView)
        assert code_view.codegen.am_obj is not None
        return func, code_view

    @staticmethod
    def _select_text(code_view, regex: str) -> str:
        """Select the first span of the pseudocode that ``regex`` matches, as a user dragging
        over those lines would."""
        text = code_view.codegen.am_obj.text
        m = re.search(regex, text)
        assert m is not None, f"{regex!r} is not in the pseudocode"
        cursor = code_view.textedit.textCursor()
        cursor.setPosition(m.start())
        cursor.setPosition(m.end(), QTextCursor.MoveMode.KeepAnchor)
        code_view.textedit.setTextCursor(cursor)
        return m.group(0)

    def _select_two_statements(self, func, code_view) -> tuple[int, int]:
        """Select the text of two assignment/store statements of one block, by the instruction
        addresses their chunks carry."""
        codegen = code_view.codegen.am_obj
        chunks: dict[int, list[tuple[int, int]]] = {}
        for pos, elem in codegen.map_pos_to_node.items():
            ins = (getattr(elem.obj, "tags", None) or {}).get("ins_addr")
            if ins is not None:
                chunks.setdefault(ins, []).append((pos, pos + elem.length))
        cache = self.main.workspace.main_instance.kb.decompilations[(func.addr, "pseudocode")]
        for block in cache.clinic.cc_graph:
            addrs = []
            for stmt in block.statements:
                ins = stmt.tags.get("ins_addr")
                if isinstance(stmt, (Assignment, Store)) and ins in chunks and ins not in addrs:
                    addrs.append(ins)
            if len(addrs) >= 2:
                spans = chunks[addrs[0]] + chunks[addrs[1]]
                start, end = min(s for s, _ in spans), max(e for _, e in spans)
                cursor = code_view.textedit.textCursor()
                cursor.setPosition(start)
                cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
                code_view.textedit.setTextCursor(cursor)
                return start, end
        raise AssertionError("no block renders two statements")

    def test_selection_becomes_an_editable_pattern(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)

        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert isinstance(view, PatternView)
        assert view.editor is not None
        assert view.editor.pattern.call_name == "my_idiom"
        assert view.origin_func == func.addr

        leaves = view.editor.leaves()
        assert len(leaves) >= 2
        graph = view._graph_widget.graph
        assert graph is not None
        assert graph.number_of_nodes() > len(leaves), "a fresh pattern shows its expressions too"
        assert view.collapsed == set()
        assert all(isinstance(n, QPatternNode) for n in graph.nodes())

    def test_double_click_expands_and_collapses_without_editing(self):
        _, code_view = self._decompile("1after909", "doit")
        self._select_text(code_view, r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n')
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None
        path, _ = next((p, node) for p, node in view.editor.leaves() if not isinstance(node, PAnyStmt))
        full = view._graph_widget.graph.number_of_nodes()

        view.activate_node(path)  # collapse the statement
        assert path in view.collapsed
        assert view._graph_widget.graph.number_of_nodes() < full
        view.activate_node(path)
        assert view._graph_widget.graph.number_of_nodes() == full

        # an expression with children collapses too, and nothing about the pattern changes
        before = view.editor.pattern
        child_path = next(
            c for c, n in _all_nodes(view.editor) if isinstance(n, PatternExpr) and view.editor.children(c)
        )
        view.activate_node(child_path)
        assert child_path in view.collapsed and view.editor.pattern == before
        assert not isinstance(view.editor.node_at(child_path), PAny)
        view.activate_node(child_path)
        assert view._graph_widget.graph.number_of_nodes() == full

        # wildcarding is the property panel's job
        view._apply_property("wildcard", child_path, True)
        assert isinstance(view.editor.node_at(child_path), PAny)
        view.undo()
        assert not isinstance(view.editor.node_at(child_path), PAny)

        view.set_leaf_mode(path, "optional")
        assert view.editor.node_at(path).optional is True
        view.set_leaf_mode(path, "wildcard")
        assert isinstance(view.editor.node_at(path), PAnyStmt)

    @staticmethod
    def _property_index(view, key):
        """The value cell of the property panel item ``key`` names, as the panel's model has it."""
        model = view._model
        for gi, group in enumerate(model.rootItem.children):
            for ci, child in enumerate(group.children):
                if view._item_keys.get(id(child)) == key:
                    return model.index(ci, 1, model.index(gi, 0)), child
        raise AssertionError(f"no property {key}")

    def test_wildcards_can_be_turned_back_from_the_property_panel(self):
        _, code_view = self._decompile("1after909", "doit")
        self._select_text(code_view, r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n')
        view = code_view.textedit.create_pattern(call_name="p")
        assert view is not None and view.editor is not None

        # an expression: check, then uncheck, through the panel's model
        path = ("stmts", 1, "call", "args", 0)
        before = view.editor.node_at(path)
        view.select_node(path)
        index, _ = self._property_index(view, ("wildcard", path))
        view._model.setData(index, Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
        assert isinstance(view.editor.node_at(path), PAny)
        index, item = self._property_index(view, ("wildcard", path))
        assert item.value is True
        view._model.setData(index, Qt.CheckState.Unchecked, Qt.ItemDataRole.CheckStateRole)
        assert view.editor.node_at(path) == before, "unchecking puts the expression back"
        _, item = self._property_index(view, ("wildcard", path))
        assert item.value is False

        # a statement: wildcard mode and back
        stmt = ("stmts", 1)
        shape = view.editor.node_at(stmt)
        view.select_node(stmt)
        index, _ = self._property_index(view, ("leaf_mode", stmt))
        view._model.setData(index, "wildcard", Qt.ItemDataRole.EditRole)
        assert isinstance(view.editor.node_at(stmt), PAnyStmt)
        index, _ = self._property_index(view, ("leaf_mode", stmt))
        view._model.setData(index, "required", Qt.ItemDataRole.EditRole)
        assert view.editor.node_at(stmt) == shape

        # the string the generator left open was never anything else: the box is locked
        string_arg = ("stmts", 0, "call", "args", 0)
        assert isinstance(view.editor.node_at(string_arg), PAny)
        view.select_node(string_arg)
        index, item = self._property_index(view, ("wildcard", string_arg))
        assert item.readonly and "Lift the pattern again" in item.description
        assert not view._model.flags(index) & Qt.ItemFlag.ItemIsUserCheckable
        assert view._model.setData(index, Qt.CheckState.Unchecked, Qt.ItemDataRole.CheckStateRole) is False
        assert isinstance(view.editor.node_at(string_arg), PAny)

    def test_clicks_on_the_canvas_select_and_toggle(self):
        """Through Qt's own event delivery: a release only reaches an item that took the press."""
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None
        self.main.workspace.raise_view(view)
        path, _ = next((p, node) for p, node in view.editor.leaves() if not isinstance(node, PAnyStmt))
        canvas = view._graph_widget

        def point_of(node_path):
            item = view._nodes_by_path[node_path]
            canvas.centerOn(item)
            return canvas.mapFromScene(item.sceneBoundingRect().center())

        QTest.mouseClick(canvas.viewport(), Qt.MouseButton.LeftButton, pos=point_of(path))
        assert view.selected_path == path, "a single click selects"
        assert path not in view.collapsed, "and does not toggle"

        QTest.mouseDClick(canvas.viewport(), Qt.MouseButton.LeftButton, pos=point_of(path))
        assert path in view.collapsed, "a double click toggles"

    def test_save_puts_the_pattern_in_the_knowledge_base(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None
        view.min_similarity = 0.7

        stored = view.save()
        kb = self.main.workspace.main_instance.kb
        assert stored is not None
        assert kb.patterns.get("my_idiom") is stored
        assert stored.min_similarity == 0.7
        assert stored.origin_func == func.addr

        # saving again replaces rather than refuses
        view.editor.set_display_name("renamed")
        again = view.save()
        assert again is not None and again.pattern.display_name == "renamed"
        assert len(kb.patterns) == 1

    def test_search_finds_the_selection_in_its_own_function(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None

        view.search_current_function()
        self.main.workspace.job_manager.join_all_jobs()

        assert view.matches, "the statements the pattern came from must be found"
        best = view.matches[0]
        assert best.func_addr == func.addr
        assert best.similarity == 1.0
        assert best.verified
        assert view._matches_table.rowCount() == len(view.matches)
        assert view._matches_table.item(0, 0).text() == func.name

        view.jump_to_match(0)  # must not raise; the disassembly view lands on the function
        disasm_view = self.main.workspace._get_or_create_view("disassembly", DisassemblyView)
        assert disasm_view.function.am_obj is not None
        assert disasm_view.function.am_obj.addr == func.addr

    def test_apply_outlines_the_selection_in_the_pseudocode(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None
        assert "my_idiom(" not in code_view.codegen.am_obj.text

        view.apply()
        self.main.workspace.job_manager.join_all_jobs()

        assert "my_idiom(" in code_view.codegen.am_obj.text, "the pattern's own statements must decompile as its call"

    def test_error_exit_story_on_doit(self):
        """The user story: select `puts("String is empty."); fflush(stdout); return 0xffffffff;`
        in doit, make it the pattern PatternErrorsOut, apply it, and every error exit of doit
        decompiles as a call carrying its own message."""
        func, code_view = self._decompile("1after909", "doit")
        self._select_text(code_view, r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n')

        view = code_view.textedit.create_pattern(call_name="PatternErrorsOut")
        assert view is not None and view.editor is not None
        pattern = view.editor.pattern
        assert pattern.call_name == "PatternErrorsOut"

        # two calls and a return: puts loses its string argument, fflush keeps the global
        # stream pointer, the return keeps its constant, and nothing becomes a parameter
        assert isinstance(pattern.pattern, PStmtSeq)
        puts, fflush, ret = pattern.pattern.stmts
        assert isinstance(puts, PCallStmt) and puts.call.names == {"puts"}
        assert len(puts.call.args) == 1 and isinstance(puts.call.args[0], PAny)
        assert isinstance(fflush, PCallStmt) and fflush.call.names == {"fflush"}
        assert len(fflush.call.args) == 1 and isinstance(fflush.call.args[0], PLoad)
        # the global is named, not pinned to this build's address, so the pattern travels
        assert fflush.call.args[0].addr == PConst(symbol="stdout")
        assert isinstance(ret, PReturn) and ret.values == (PConst(value=0xFFFFFFFF),)
        assert pattern.params == ()
        assert len(view.editor.leaves()) == 3

        # the symbol is editable from the property panel and survives export and import
        stdout_path = ("stmts", 1, "call", "args", 0, "addr")
        view.select_node(stdout_path)
        view._apply_property("const_symbol", stdout_path, "stderr")
        assert view.editor.node_at(stdout_path) == PConst(symbol="stderr")
        view._apply_property("const_symbol", stdout_path, "stdout")
        assert view.editor.node_at(stdout_path) == PConst(symbol="stdout")
        stored = view.save()
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "p.json")
            view.export_stored(stored, path)
            with open(path, encoding="utf-8") as f:
                assert '"symbol": "stdout"' in f.read()
            view.delete_stored(stored)
            back = view.import_stored(path)
            assert back.pattern.pattern.stmts[1].call.args[0].addr == PConst(symbol="stdout")
        view.edit_stored(back)

        view.apply()
        self.main.workspace.job_manager.join_all_jobs()

        text = code_view.codegen.am_obj.text
        calls = re.findall(r'PatternErrorsOut\("([^"]*)"\)', text)
        assert "Empty title" in calls and "Cannot open document." in calls, calls
        assert len(calls) == 8, calls

    def test_discovery_reuses_the_pseudocode_views_decompilation(self):
        """The view decompiles with its own settings; discovery must not decompile again
        with the defaults, nor replace the view's cache."""
        from angr.analyses.decompiler.decompiler import Decompiler  # pylint:disable=import-outside-toplevel

        func, _ = self._decompile("1after909", "doit")
        kb = self.main.workspace.main_instance.kb
        cache = kb.decompilations[(func.addr, "pseudocode")]
        runs = []
        orig = Decompiler._decompile
        Decompiler._decompile = lambda dec: runs.append(dec.func.addr) or orig(dec)
        try:
            view = self.main.workspace._get_or_create_view("pattern", PatternView)
            view._min_size.setValue(3)
            view.discover(func)
            self.main.workspace.job_manager.join_all_jobs()
        finally:
            Decompiler._decompile = orig
        assert view.families, "discovery ran on the cached decompilation"
        assert not runs, "and never decompiled"
        assert kb.decompilations[(func.addr, "pseudocode")] is cache

    def _discover_entry(self):
        """The Analyze menu's discovery item, triggered the way a click would."""
        entries = [e for e in self.main._analyze_menu.entries if getattr(e, "caption", None) == "Discover &Patterns..."]
        assert len(entries) == 1, "the Analyze menu offers pattern discovery"
        return entries[0]._qaction

    def _run_discovery(self):
        """Analyze > Discover Patterns opens the Discover tab; its button starts the run."""
        self._discover_entry().trigger()
        view = self.main.workspace.view_manager.first_view_in_category("pattern")
        assert isinstance(view, PatternView) and view._tabs.currentWidget() is view._discover_tab
        # doit's error exit is three statements, below the default minimum
        view._min_size.setValue(3)
        view._discover_btn.click()
        return view

    def test_discover_menu_opens_the_discover_tab_without_running(self):
        from angrmanagement.data.jobs import PatternDiscoveryJob  # pylint:disable=import-outside-toplevel

        main = self.main
        binpath = os.path.join(test_location, "x86_64", "1after909")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()
        started = []
        main.workspace.job_manager.job_starting.connect(started.append)

        self._discover_entry().trigger()
        main.workspace.job_manager.join_all_jobs()
        view = main.workspace.view_manager.first_view_in_category("pattern")
        assert isinstance(view, PatternView) and view._tabs.currentWidget() is view._discover_tab
        assert main.workspace.view_manager.current_tab is view
        assert view._min_size.value() == 6
        labels = [w.text() for w in view._discover_tab.findChildren(QLabel)]
        assert "Min statements" in labels and "Min size" not in labels
        assert not any(isinstance(j, PatternDiscoveryJob) for j in started), "nothing runs yet"

        # without a decompiled function, the button warns and bails
        warnings = []
        orig = QMessageBox.warning
        QMessageBox.warning = lambda *args, **kwargs: warnings.append(args) or QMessageBox.StandardButton.Ok
        try:
            view._discover_btn.click()
        finally:
            QMessageBox.warning = orig
        main.workspace.job_manager.join_all_jobs()
        assert len(warnings) == 1 and "No function is currently decompiled" in warnings[0][2]
        assert not any(isinstance(j, PatternDiscoveryJob) for j in started)

    def test_discovery_from_the_menu_finds_the_error_exit_idiom(self):
        """Analyze > Discover Patterns on doit: the error-exit family's lifted pattern finds
        every error exit, and applying it outlines them."""
        func, code_view = self._decompile("1after909", "doit")
        view = self._run_discovery()
        self.main.workspace.job_manager.join_all_jobs()
        assert view.discovered_func == func.addr and view.families
        assert view._families_table.rowCount() == len(view.families)

        def is_error_exit(family) -> bool:
            if family.pattern is None or not isinstance(family.pattern.pattern, PStmtSeq):
                return False
            stmts = family.pattern.pattern.stmts
            return (
                len(stmts) == 3
                and isinstance(stmts[0], PCallStmt)
                and stmts[0].call.names == {"puts"}
                and isinstance(stmts[1], PCallStmt)
                and stmts[1].call.names == {"fflush"}
                and isinstance(stmts[2], PReturn)
            )

        index = next(i for i, f in enumerate(view.families) if is_error_exit(f))
        family = view.families[index]
        # discovery drops copies that sit close together; the lifted pattern does not
        assert family.found >= 8 and family.covered == family.copies

        # sorting moves rows; each still knows its family, and numbers sort as numbers
        table = view._families_table
        table.sortItems(4, Qt.SortOrder.DescendingOrder)
        found_order = [view.families[view.family_at(r)].found for r in range(table.rowCount())]
        assert found_order == sorted(found_order, reverse=True)
        row = next(r for r in range(table.rowCount()) if view.family_at(r) == index)
        assert table.item(row, 0).text() == str(family.copies)

        # a double click opens the family's first copy in the pseudocode view, not the disassembly
        other = next(f for f in self.main.workspace.main_instance.kb.functions.values() if f.name == "main")
        self.main.workspace.decompile_function(other)
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.function.am_obj is other
        table.cellDoubleClicked.emit(row, 1)
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.function.am_obj is func
        assert self.main.workspace.view_manager.current_tab is code_view

        # ...with every line of every copy of the family highlighted, and nothing else
        lines = code_view.pattern_highlighted_lines
        assert lines, "the family's lines are highlighted"
        doc = code_view._doc
        texts = [doc.findBlockByNumber(n).text().strip() for n in lines]
        # a copy may return another value: the family is alike, not identical
        assert all(t.startswith(("puts(", "fflush(stdout)", "return ")) for t in texts), texts
        assert sum(1 for t in texts if t.startswith("puts(")) == family.copies
        assert sum(1 for t in texts if t.startswith("return ")) == family.copies
        sel = code_view._pattern_selections[0]
        assert sel.format.background().color() == Conf.pseudocode_pattern_highlight_color
        assert sel.format.property(QTextFormat.Property.FullWidthSelection) is True
        cursor_line = code_view.textedit.textCursor().blockNumber()
        assert doc.findBlockByNumber(cursor_line).text().strip().startswith(("puts(", "fflush(")), "on the first copy"

        # it follows the text when the pseudocode is regenerated
        code_view.codegen.am_event()
        assert len(code_view.pattern_highlighted_lines) == len(lines)

        # the first Escape dismisses the highlight and stays; the pseudocode is still doit's
        QTest.keyClick(code_view.textedit, Qt.Key.Key_Escape)
        assert code_view.pattern_highlighted_lines == []
        assert code_view.function.am_obj is func

        # showing another function drops it
        table.cellDoubleClicked.emit(row, 1)
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.pattern_highlighted_lines
        self.main.workspace.decompile_function(other)
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.pattern_highlighted_lines == []
        self.main.workspace.decompile_function(func)
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.pattern_highlighted_lines == [], "and it does not come back with the function"

        assert view.load_family(index)
        assert view.editor is not None and view.origin_func == func.addr
        assert view._tabs.currentWidget() is view._pattern_tab
        view.apply()
        self.main.workspace.job_manager.join_all_jobs()

        call = view.editor.pattern.call_name
        calls = re.findall(rf'{call}\("([^"]*)"', code_view.codegen.am_obj.text)
        assert "Empty title" in calls and "Cannot open document." in calls, calls

    def test_pseudocode_dock_lists_patterns_with_their_matches(self):
        """The pseudocode view's Patterns dock shares the Pattern tab's library, and adds what
        the outliner pass did with each pattern in the function on screen."""
        func, code_view = self._decompile("1after909", "doit")
        table = code_view.patterns_table
        assert table is not None and table.rowCount() == 0
        headers = [table.horizontalHeaderItem(j).text() for j in range(table.columnCount())]
        # the numbers come right after the name, so a narrow dock shows them without scrolling
        assert headers[:5] == ["Pattern", "Enabled", "Highlight", "Matches", "Outlined"]

        self._select_text(code_view, r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n')
        view = code_view.textedit.create_pattern(call_name="PatternErrorsOut")
        assert view is not None
        view.save()
        # saved, off as every new pattern is, and not applied here yet
        assert table.rowCount() == 1
        assert [table.item(0, j).text() for j in (0, 1, 3, 4)] == ["patternerrorsout", "off", "0", "0"]

        view.apply()
        self.main.workspace.job_manager.join_all_jobs()
        # Save & Redecompile turns it on: redecompiling with it off would change nothing
        assert view.enabled and table.item(0, 1).text() == "on"
        matches, outlined = int(table.item(0, 3).text()), int(table.item(0, 4).text())
        assert outlined == 8 and matches >= outlined

        # a change in either place shows in both
        code_view._pattern_library.toggle(self.main.workspace.main_instance.kb.patterns.get("patternerrorsout"))
        assert table.item(0, 1).text() == "off" and view._library_table.item(0, 2).text() == "off"

        # Edit opens the pattern in the pattern view
        table.selectRow(0)
        code_view._pattern_library._on_edit_clicked()
        assert view.editor is not None and view.editor.pattern.name == "patternerrorsout"
        assert self.main.workspace.view_manager.current_tab is view

    def _apply_error_exit_pattern(self):
        """doit decompiled with the error-exit pattern applied; returns (func, code view, pattern view)."""
        func, code_view = self._decompile("1after909", "doit")
        self._select_text(code_view, r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n')
        view = code_view.textedit.create_pattern(call_name="PatternErrorsOut")
        assert view is not None
        assert view._apply_btn.text() == "Save && Redecompile"
        view._apply_btn.click()
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.codegen.am_obj.text.count("PatternErrorsOut(") == 8
        return func, code_view, view

    def test_dock_checkbox_marks_and_the_button_applies(self):
        """A click on Enabled only marks the pattern; the dock's button applies every mark and
        decompiles again, and does nothing when the marks change nothing."""
        _, code_view, _ = self._apply_error_exit_pattern()
        library = code_view._pattern_library
        table = code_view.patterns_table
        button = library._apply_btn
        kb = self.main.workspace.main_instance.kb
        codegen = code_view.codegen.am_obj
        assert button.text() == "Apply Patterns && Redecompile" and not button.isEnabled()
        assert table.item(0, 1).checkState() == Qt.CheckState.Checked and not table.item(0, 0).font().bold()

        table.item(0, 1).setCheckState(Qt.CheckState.Unchecked)  # a click on the box
        self.main.workspace.job_manager.join_all_jobs()
        assert kb.patterns.get("patternerrorsout").enabled, "only marked"
        assert code_view.codegen.am_obj is codegen, "and not decompiled"
        assert table.item(0, 1).text() == "off (unapplied)"
        assert all(table.item(0, j).font().bold() for j in range(table.columnCount()))
        assert button.isEnabled()

        # clicking it back clears the mark: nothing to apply
        table.item(0, 1).setCheckState(Qt.CheckState.Checked)
        assert table.item(0, 1).text() == "on" and not table.item(0, 0).font().bold()
        assert not button.isEnabled() and not library.pending
        assert library.apply_pending() is False
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.codegen.am_obj is codegen, "an unchanged set is not decompiled again"

        table.item(0, 1).setCheckState(Qt.CheckState.Unchecked)
        button.click()
        self.main.workspace.job_manager.join_all_jobs()
        assert kb.patterns.get("patternerrorsout").enabled is False
        assert "PatternErrorsOut(" not in code_view.codegen.am_obj.text, "decompiled again without it"
        assert table.item(0, 1).text() == "off" and not table.item(0, 0).font().bold()
        assert not button.isEnabled()

        table.item(0, 1).setCheckState(Qt.CheckState.Checked)
        assert table.item(0, 1).text() == "on (unapplied)"
        button.click()
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.codegen.am_obj.text.count("PatternErrorsOut(") == 8

    def test_dock_table_sorts_and_rows_keep_their_patterns(self):
        from angr.knowledge_plugins.patterns import StoredPattern  # pylint:disable=import-outside-toplevel

        _, code_view, _ = self._apply_error_exit_pattern()
        kb = self.main.workspace.main_instance.kb
        data = kb.patterns.get("patternerrorsout").to_dict()
        data["pattern"]["name"] = "aaa_unused"
        data["enabled"] = False
        kb.patterns.store(StoredPattern.from_dict(data))
        self.main.workspace.on_patterns_changed()
        library = code_view._pattern_library
        table = code_view.patterns_table

        def names() -> list[str]:
            return [library.stored_at(r).name for r in range(table.rowCount())]

        assert names() == ["aaa_unused", "patternerrorsout"], "by name at first"

        # by the Matches column, as numbers, and the rows follow their patterns
        table.sortItems(3, Qt.SortOrder.DescendingOrder)
        assert names() == ["patternerrorsout", "aaa_unused"]
        assert int(table.item(0, 3).text()) >= 8 and table.item(1, 3).text() == "0"

        # a click on a moved row acts on its own pattern, and a reload keeps the order
        table.item(1, 1).setCheckState(Qt.CheckState.Checked)
        assert library.pending == {"aaa_unused": True}
        assert names() == ["patternerrorsout", "aaa_unused"]
        table.selectRow(1)
        assert library.selection().name == "aaa_unused"

    def test_graph_context_menu_expands_and_collapses_everything(self):
        _, _, view = self._apply_error_exit_pattern()
        graph = view._graph_widget
        statements = len(view.editor.leaves())
        everything = len({p for p, _ in view.editor.leaves()} | {p for p, _ in _all_nodes(view.editor)})
        assert statements < everything and len(graph.blocks) == everything, "small patterns start fully expanded"

        menu = graph.context_menu()  # kept alive: its actions die with it
        actions = {a.text(): a for a in menu.actions()}
        assert list(actions) == ["Expand all", "Collapse all"]
        actions["Collapse all"].trigger()
        assert len(graph.blocks) == statements
        actions["Expand all"].trigger()
        assert len(graph.blocks) == everything

    def _show_graph(self, view):
        """The harness never shows the window; geometry needs a visible, sized viewport."""
        from PySide6.QtWidgets import QApplication  # pylint:disable=import-outside-toplevel

        self.main.resize(1400, 900)
        self.main.show()
        self.main.workspace.raise_view(view)
        view._tabs.setCurrentWidget(view._pattern_tab)
        QApplication.processEvents()
        return view._graph_widget

    @staticmethod
    def _tree_offset(graph):
        """How far the tree's center sits from the viewport's center, in pixels."""
        center = graph.mapFromScene(graph.scene().itemsBoundingRect().center())
        diff = center - graph.viewport().rect().center()
        return abs(diff.x()), abs(diff.y())

    def test_expand_all_then_collapse_all_keeps_the_tree_centered(self):
        _, _, view = self._apply_error_exit_pattern()
        graph = self._show_graph(view)
        view.collapse_all()
        view.expand_all()
        view.collapse_all()
        dx, dy = self._tree_offset(graph)
        assert dx <= 2 and dy <= 2, (dx, dy)
        # the scene is only as large as what is on it, with room to drag
        rect, items = graph.scene().sceneRect(), graph.scene().itemsBoundingRect()
        assert rect.width() <= items.width() + 2 * graph.LEFT_PADDING + 1
        # zoomed out, too
        graph.zoom(out=True)
        view.expand_all()
        dx, dy = self._tree_offset(graph)
        assert dx <= 2 and dy <= 2, (dx, dy)

    def test_double_click_keeps_the_node_in_place(self):
        _, _, view = self._apply_error_exit_pattern()
        graph = self._show_graph(view)
        path = next(p for p, _ in view.editor.leaves()[1:] if view.editor.children(p))

        def where():
            node = next(b for b in graph.blocks if b.path == path)
            return graph.mapFromScene(node.scenePos())

        before = where()
        view.activate_node(path)  # what a double click does: collapse
        assert path in view.collapsed
        after = where()
        assert abs(after.x() - before.x()) <= 1 and abs(after.y() - before.y()) <= 1, (before, after)
        view.activate_node(path)  # and expand again
        again = where()
        assert abs(again.x() - before.x()) <= 1 and abs(again.y() - before.y()) <= 1, (before, again)

    def test_nodes_are_labelled_with_ail_class_names(self):
        _, _, view = self._apply_error_exit_pattern()
        labels = {b.path: b._title.text() for b in view._graph_widget.blocks}
        statements = [labels[p] for p, _ in view.editor.leaves()]
        assert statements == ["Call puts", "Call fflush", "Return"], statements
        assert "Const &stdout" in labels.values(), labels
        assert not any(t.startswith(("assign", "store", "call statement", "load", "var")) for t in labels.values())

    @staticmethod
    def _menu_actions(menu):
        return {a.text(): a for a in menu.actions()}

    def _disasm(self):
        return self.main.workspace.view_manager.first_view_in_category("disassembly")

    def test_discover_table_context_menu(self):
        from PySide6.QtWidgets import QPushButton  # pylint:disable=import-outside-toplevel

        func, code_view = self._decompile("1after909", "doit")
        view = self._run_discovery()
        self.main.workspace.job_manager.join_all_jobs()
        table = view._families_table
        buttons = [b.text() for b in view._discover_tab.findChildren(QPushButton)]
        assert "Edit pattern" not in buttons, "the menu replaced the button"

        rows = [r for r in range(table.rowCount()) if view.families[view.family_at(r)].pattern is not None][:2]
        table.selectRow(rows[0])
        index = view.family_at(rows[0])
        menu = view.families_context_menu()
        actions = self._menu_actions(menu)
        assert list(actions) == [
            "Highlight patterns in pseudocode",
            "Highlight patterns in disassembly",
            "Edit pattern...",
        ]
        assert all(a.isEnabled() for a in actions.values())

        actions["Highlight patterns in disassembly"].trigger()
        disasm = self._disasm()
        assert disasm.pattern_highlight_addrs == set().union(*view.families[index].copy_addrs)
        assert self.main.workspace.view_manager.current_tab is disasm
        assert code_view.has_pattern_highlight, "Clear highlights reaches the disassembly"
        from angrmanagement.ui.widgets.qinstruction import QInstruction  # pylint:disable=import-outside-toplevel

        insns = [i for i in disasm.current_graph.scene().items() if isinstance(i, QInstruction)]
        painted = [i for i in insns if i._calc_backcolor() == Conf.disasm_view_pattern_highlight_color]
        assert painted and {i.addr for i in painted} <= disasm.pattern_highlight_addrs

        actions["Highlight patterns in pseudocode"].trigger()
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.function.am_obj is func and code_view.pattern_highlighted_lines
        assert code_view.clear_pattern_highlight()
        assert not disasm.pattern_highlight_addrs and not code_view.pattern_highlighted_lines

        actions["Edit pattern..."].trigger()
        assert view.editor is not None and view._tabs.currentWidget() is view._pattern_tab

        # two families: both highlight, but only one can be edited
        view._tabs.setCurrentWidget(view._discover_tab)
        table.selectRow(rows[0])
        table.selectionModel().select(
            table.model().index(rows[1], 0),
            table.selectionModel().SelectionFlag.Select | table.selectionModel().SelectionFlag.Rows,
        )
        menu = view.families_context_menu()
        actions = self._menu_actions(menu)
        assert not actions["Edit pattern..."].isEnabled()
        actions["Highlight patterns in disassembly"].trigger()
        both = [view.families[view.family_at(r)] for r in rows]
        assert disasm.pattern_highlight_addrs == set().union(*(a for f in both for a in f.copy_addrs))

    def test_pattern_tables_context_menu(self):
        func, code_view, view = self._apply_error_exit_pattern()
        kb = self.main.workspace.main_instance.kb
        stats = kb.patterns.stats(func.addr, "patternerrorsout")
        table = code_view.patterns_table
        table.selectRow(0)
        menu = code_view._pattern_library.context_menu()
        actions = self._menu_actions(menu)
        assert list(actions) == [
            "Highlight patterns in pseudocode",
            "Highlight patterns in disassembly",
            "Edit pattern...",
        ]

        actions["Highlight patterns in pseudocode"].trigger()
        texts = [code_view._doc.findBlockByNumber(n).text().strip() for n in code_view.pattern_highlighted_lines]
        assert len(texts) == 8 and all("PatternErrorsOut(" in t for t in texts), texts
        assert table.item(0, 2).checkState() == Qt.CheckState.Checked, "the Highlight box follows"

        actions["Highlight patterns in disassembly"].trigger()
        assert self._disasm().pattern_highlight_addrs == set().union(*stats.match_addrs)

        # the Pattern view's table acts on the pseudocode view's function, too
        view._library_table.selectRow(0)
        menu = view._library.context_menu()
        actions = self._menu_actions(menu)
        code_view.clear_pattern_highlight()
        actions["Highlight patterns in disassembly"].trigger()
        assert self._disasm().pattern_highlight_addrs == set().union(*stats.match_addrs)
        view.editor = None
        actions["Edit pattern..."].trigger()
        assert view.editor is not None and view.editor.pattern.name == "patternerrorsout"

        # a pattern that did not apply at the last decompilation has nothing to highlight
        code_view.clear_pattern_highlight()
        kb.patterns.set_enabled("patternerrorsout", False)
        code_view.decompile(reset_cache=True)
        self.main.workspace.job_manager.join_all_jobs()
        table.selectRow(0)
        menu = code_view._pattern_library.context_menu()
        actions = self._menu_actions(menu)
        actions["Highlight patterns in disassembly"].trigger()
        actions["Highlight patterns in pseudocode"].trigger()
        assert not self._disasm().pattern_highlight_addrs and not code_view.pattern_highlighted_lines

    def test_dock_highlights_the_calls_a_pattern_became(self):
        _, code_view, _ = self._apply_error_exit_pattern()
        table = code_view.patterns_table
        assert code_view.pattern_highlighted_lines == []

        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        lines = code_view.pattern_highlighted_lines
        texts = [code_view._doc.findBlockByNumber(n).text().strip() for n in lines]
        assert len(lines) == 8 and all("PatternErrorsOut(" in t for t in texts), texts
        assert "8 call(s)" in table.item(0, 2).toolTip()

        # it follows the pseudocode through a fresh decompilation
        code_view.decompile(reset_cache=True)
        self.main.workspace.job_manager.join_all_jobs()
        assert len(code_view.pattern_highlighted_lines) == 8
        assert table.item(0, 2).checkState() == Qt.CheckState.Checked

        table.item(0, 2).setCheckState(Qt.CheckState.Unchecked)
        assert code_view.pattern_highlighted_lines == []

        # Escape clears it, box included
        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        QTest.keyClick(code_view.textedit, Qt.Key.Key_Escape)
        assert code_view.pattern_highlighted_lines == []
        assert table.item(0, 2).checkState() == Qt.CheckState.Unchecked

    def test_dock_matches_come_from_the_last_decompilation(self):
        """Matches are what the pass found the last time the function was decompiled, and 0
        for a pattern that was off then; nothing is counted in the background."""
        func, code_view, _ = self._apply_error_exit_pattern()
        table = code_view.patterns_table
        kb = self.main.workspace.main_instance.kb
        assert int(table.item(0, 3).text()) >= 8

        kb.patterns.set_enabled("patternerrorsout", False)
        code_view.decompile(reset_cache=True)
        self.main.workspace.job_manager.join_all_jobs()
        assert kb.patterns.stats(func.addr, "patternerrorsout") is None, "the pass did not search for it"
        assert [table.item(0, j).text() for j in (3, 4)] == ["0", "0"]
        assert not self.main.workspace.job_manager.jobs, "and nothing counts it"

    def test_dock_highlight_works_without_the_pass_numbers(self):
        """The pass's numbers are not saved with the project; the calls on screen are enough
        to highlight an applied pattern, and nothing is decompiled again."""
        _, code_view, _ = self._apply_error_exit_pattern()
        kb = self.main.workspace.main_instance.kb
        kb.patterns._stats.clear()  # what a project loaded from a database has
        code_view.reload_patterns()
        table = code_view.patterns_table
        codegen = code_view.codegen.am_obj
        assert "8 call(s)" in table.item(0, 2).toolTip()

        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        texts = [code_view._doc.findBlockByNumber(n).text().strip() for n in code_view.pattern_highlighted_lines]
        assert len(texts) == 8 and all("PatternErrorsOut(" in t for t in texts), texts
        table.item(0, 2).setCheckState(Qt.CheckState.Unchecked)
        assert code_view.pattern_highlighted_lines == []

        table.selectRow(0)
        menu = code_view._pattern_library.context_menu()
        {a.text(): a for a in menu.actions()}["Highlight patterns in pseudocode"].trigger()
        assert len(code_view.pattern_highlighted_lines) == 8
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.codegen.am_obj is codegen, "never decompiled again"

    def test_pattern_highlights_can_be_cleared_from_the_menu_or_the_dock(self):
        func, code_view, _ = self._apply_error_exit_pattern()
        table = code_view.patterns_table
        button = code_view._clear_highlights_btn
        edit = code_view.textedit

        def menu_texts():
            menu = edit.get_context_menu()  # kept alive: its actions die with it
            return [a.text() for a in menu.actions()]

        assert not button.isEnabled() and "Clear pattern highlights" not in menu_texts()

        # the right-click menu clears a pattern's highlight, box included
        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        assert code_view.pattern_highlighted_lines and button.isEnabled()
        assert "Clear pattern highlights" in menu_texts()
        edit.action_clear_pattern_highlights.trigger()
        assert code_view.pattern_highlighted_lines == []
        assert table.item(0, 2).checkState() == Qt.CheckState.Unchecked
        assert not button.isEnabled() and "Clear pattern highlights" not in menu_texts()

        # the dock's button clears a Discover family's highlight and a pattern's together
        stats = code_view.instance.kb.patterns.stats(func.addr, "patternerrorsout")
        code_view.highlight_pattern(func.addr, [frozenset(stats.call_addrs[:1])])
        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        assert button.isEnabled()
        button.click()
        assert code_view.pattern_highlighted_lines == [] and not code_view.has_pattern_highlight
        assert not button.isEnabled()

    def test_discovery_runs_blocking_with_the_progress_dialog(self):
        from angrmanagement.data.jobs import PatternDiscoveryJob  # pylint:disable=import-outside-toplevel

        func, _ = self._decompile("1after909", "doit")
        started, labels = [], []
        self.main.workspace.job_manager.job_starting.connect(started.append)
        dialog = self.main._progress_dialog
        orig = dialog.setLabelText
        dialog.setLabelText = lambda text: labels.append(text) or orig(text)
        try:
            self._run_discovery()
            self.main.workspace.job_manager.join_all_jobs()
        finally:
            dialog.setLabelText = orig

        jobs = [j for j in started if isinstance(j, PatternDiscoveryJob)]
        assert len(jobs) == 1 and jobs[0].blocking, "a modal progress dialog shows the discovery"
        assert any(t.startswith("Discovering patterns in doit") for t in labels), labels
        view = self.main.workspace.view_manager.first_view_in_category("pattern")
        assert view.discovered_func == func.addr and view.families

    def test_found_is_filled_in_the_background_after_the_table(self):
        from angrmanagement.data.jobs import (  # pylint:disable=import-outside-toplevel
            PatternDiscoveryJob,
            PatternFoundJob,
        )

        self._decompile("1after909", "doit")
        started, shown = [], []
        self.main.workspace.job_manager.job_starting.connect(started.append)
        orig = PatternView._show_families

        def spy(view, result):
            # what the table shows the moment discovery ends
            shown.append([f.found for f in result.families if f.pattern is not None])
            orig(view, result)
            shown.append([view._families_table.item(r, 4).text() for r in range(view._families_table.rowCount())])

        PatternView._show_families = spy
        try:
            self._run_discovery()
            self.main.workspace.job_manager.join_all_jobs()
        finally:
            PatternView._show_families = orig
        view = self.main.workspace.view_manager.first_view_in_category("pattern")

        # this run's discovery ended before its counts existed
        kinds = [type(j) for j in started]
        assert PatternDiscoveryJob in kinds and PatternFoundJob in kinds
        assert kinds.index(PatternFoundJob) > kinds.index(PatternDiscoveryJob)
        assert shown and all(n is None for n in shown[0]), "no search inside the blocking job"
        assert "…" in shown[1]
        # and every count arrived afterwards
        texts = [view._families_table.item(r, 4).text() for r in range(view._families_table.rowCount())]
        assert "…" not in texts
        assert all(f.found is not None for f in view.families if f.pattern is not None)

    def test_consecutive_only_keeps_every_copy_one_straight_run(self):
        from angrmanagement.data.jobs import PatternDiscoveryJob  # pylint:disable=import-outside-toplevel

        self._decompile("1after909", "doit")
        started, results = [], []
        self.main.workspace.job_manager.job_starting.connect(started.append)
        self.main.workspace.show_pattern_discovery()
        self.main.workspace.job_manager.join_all_jobs()
        view = self.main.workspace.view_manager.first_view_in_category("pattern")
        combo = view._statements
        assert [combo.itemText(i) for i in range(combo.count())] == [
            "Any order",
            "Follow control flow",
            "Consecutive only",
        ]
        assert combo.currentText() == "Consecutive only", "the default"
        combo.setCurrentIndex(0)
        combo.setCurrentIndex(2)
        view._min_size.setValue(3)
        orig = PatternView._show_families
        PatternView._show_families = lambda v, result: results.append(result) or orig(v, result)
        try:
            self._run_discovery()
            self.main.workspace.job_manager.join_all_jobs()
        finally:
            PatternView._show_families = orig

        job = [j for j in started if isinstance(j, PatternDiscoveryJob)][-1]
        assert job.statements == "consecutive"
        (result,) = results
        assert result.families
        graph = result.graph
        nodes = {(b.addr, b.idx): b for b in graph}
        for family in result.families:
            for stmts in family.copy_stmts:
                blocks = {nodes[loc] for loc, _ in stmts}
                # one straight run: every block but the first has one predecessor, inside the copy,
                # and that predecessor has it as its only successor
                heads = [b for b in blocks if not any(p in blocks for p in graph.predecessors(b))]
                assert len(heads) == 1, family
                for b in blocks - set(heads):
                    (pred,) = graph.predecessors(b)
                    assert pred in blocks and graph.out_degree[pred] == 1

    def test_cancel_stops_discovery_inside_the_alignment(self):
        from angr.analyses.decompiler.pattern_match import Checkpoint  # pylint:disable=import-outside-toplevel

        from angrmanagement.data.jobs import pattern_discovery  # pylint:disable=import-outside-toplevel

        _, _ = self._decompile("1after909", "doit")
        manager = self.main.workspace.job_manager
        fired = []

        def eager_checkpoint(low_priority=True, callback=None, **_):
            def cancel_then_check():
                # the manager learns of a started job through a queued signal; the dialog's
                # Cancel cannot reach the job before then
                if not isinstance(manager._current_job, pattern_discovery.PatternDiscoveryJob):
                    callback()
                    return
                # what the dialog's Cancel does, pressed while the alignment runs
                fired.append(1)
                manager.interrupt_current_job()
                callback()

            return Checkpoint(low_priority, cancel_then_check, freq=1, interval=0.0)

        orig = pattern_discovery.Checkpoint
        pattern_discovery.Checkpoint = eager_checkpoint
        try:
            self._run_discovery()
            manager.join_all_jobs()
        finally:
            pattern_discovery.Checkpoint = orig

        view = self.main.workspace.view_manager.first_view_in_category("pattern")
        assert len(fired) == 1, "stopped at the first checkpoint, inside the alignment"
        assert view.discovered_func is None and view._families_table.rowCount() == 0

    def test_library_lists_toggles_exports_and_imports(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None
        kb = self.main.workspace.main_instance.kb

        stored = view.save()
        # a new pattern is saved off
        assert [view._library_table.item(0, j).text() for j in range(3)] == ["my_idiom", "my_idiom", "off"]

        view.toggle_stored(stored)
        assert kb.patterns.get("my_idiom").enabled is True
        assert view._library_table.item(0, 2).text() == "on"
        view.toggle_stored(stored)
        assert kb.patterns.get("my_idiom").enabled is False

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "p.json")
            view.export_stored(stored, path)
            view.delete_stored(stored)
            assert len(kb.patterns) == 0
            assert view._library_table.rowCount() == 0

            back = view.import_stored(path)
            assert back.pattern == stored.pattern
            assert back.enabled is False
            assert kb.patterns.get("my_idiom") is back
            assert view._library_table.rowCount() == 1

        view.edit_stored(back)
        assert view.editor is not None and view.editor.pattern == back.pattern
        assert view.enabled is False

    def test_loosen_constants_from_the_view(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None
        pinned = [p for p, n in _all_nodes(view.editor) if isinstance(n, PConst) and n.value is not None]
        assert view.loosen_constants() == len(pinned)
        assert all(view.editor.node_at(p).value is None for p in pinned)
        view.undo()
        assert all(view.editor.node_at(p).value is not None for p in pinned)

    def test_more_loosening_actions_and_the_strictness_setting(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None
        view.cut_depth()
        view.loosen_interior_captures()

        view.require_verified = False
        stored = view.save()
        assert stored is not None and stored.require_verified is False
        view.load_stored(stored)
        assert view.require_verified is False

        # a failed leaf from a selected match row is marked on the canvas
        view.search_current_function()
        self.main.workspace.job_manager.join_all_jobs()
        assert view.matches
        view.matches[0].failed_leaves = [0]
        view.show_match(0)
        node = view._nodes_by_path[view.editor.leaves()[0][0]]
        assert node.failed

    def test_search_all_functions_runs(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None

        view.search_all_functions()
        self.main.workspace.job_manager.join_all_jobs()

        assert any(r.func_addr == func.addr and r.similarity == 1.0 for r in view.matches)

    def test_a_suggested_subrun_relifts_the_pattern(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None
        view.search_current_function()
        self.main.workspace.job_manager.join_all_jobs()
        origin = next(r for r in view.matches if r.similarity == 1.0)

        # pretend the occurrence had to be cut down to its own first half
        origin.suggested_start = origin.start_addr
        origin.suggested_end = origin.end_addr
        origin.suggested_coverage = 0.5
        view.matches = [origin]
        view._show_matches(view.matches)
        assert "try" in view._matches_table.item(0, 5).text()

        assert view.use_suggestion(0)
        assert view.editor.pattern.call_name == "my_idiom"
        assert view.editor.leaves()
        assert view.origin_func == func.addr

    def test_no_selection_makes_no_pattern(self):
        _func, code_view = self._decompile_main()
        cursor = code_view.textedit.textCursor()
        cursor.clearSelection()
        code_view.textedit.setTextCursor(cursor)
        assert code_view.textedit.create_pattern(call_name="x") is None


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
