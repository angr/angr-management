# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest

from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.known_patterns import PAny, PAnyStmt, PCallStmt, PConst, PLoad, PReturn, PStmtSeq
from angr.analyses.decompiler.known_patterns.dsl import PatternExpr
from common import AngrManagementTestCase, open_analyzed_project, test_location
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
    #: read_bin's first error exit, as the pseudocode shows it
    ERROR_EXIT = r'puts\("Failed to read length."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n'

    def _decompile_main(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        open_analyzed_project(main, binpath)
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
        open_analyzed_project(main, binpath)
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

    @staticmethod
    def _property_index(view, key):
        """The value cell of the property panel item ``key`` names, as the panel's model has it."""
        model = view._model
        for gi, group in enumerate(model.rootItem.children):
            for ci, child in enumerate(group.children):
                if view._item_keys.get(id(child)) == key:
                    return model.index(ci, 1, model.index(gi, 0)), child
        raise AssertionError(f"no property {key}")

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

    def _discover_entry(self):
        """The Analyze menu's discovery item, triggered the way a click would."""
        entries = [e for e in self.main._analyze_menu.entries if getattr(e, "caption", None) == "Discover &Patterns..."]
        assert len(entries) == 1, "the Analyze menu offers pattern discovery"
        return entries[0]._qaction

    def _run_discovery(self, min_statements: int = 3):
        """Analyze > Discover Patterns opens the Discover tab; its button starts the run."""
        self._discover_entry().trigger()
        view = self.main.workspace.view_manager.first_view_in_category("pattern")
        assert isinstance(view, PatternView) and view._tabs.currentWidget() is view._discover_tab
        # the error exit is three statements, below the default minimum
        view._min_size.setValue(min_statements)
        view._discover_btn.click()
        return view

    def test_discover_menu_opens_the_discover_tab_without_running(self):
        from angrmanagement.data.jobs import PatternDiscoveryJob  # pylint:disable=import-outside-toplevel

        main = self.main
        binpath = os.path.join(test_location, "x86_64", "1after909")
        open_analyzed_project(main, binpath)
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

    def _apply_error_exit_pattern(self):
        """read_bin decompiled with the error-exit pattern applied; returns (func, code view, pattern view)."""
        func, code_view = self._decompile("1after909", "read_bin")
        self._select_text(code_view, self.ERROR_EXIT)
        view = code_view.textedit.create_pattern(call_name="PatternErrorsOut")
        assert view is not None
        assert view._apply_btn.text() == "Save && Redecompile"
        view._apply_btn.click()
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.codegen.am_obj.text.count("PatternErrorsOut(") == 3
        return func, code_view, view

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

    @staticmethod
    def _menu_actions(menu):
        return {a.text(): a for a in menu.actions()}

    def _disasm(self):
        return self.main.workspace.view_manager.first_view_in_category("disassembly")

    def test_pattern_editor(self):
        """The pattern view's canvas and property panel, on a fresh error-exit pattern from read_bin."""
        _, code_view = self._decompile("1after909", "read_bin")
        self._select_text(code_view, self.ERROR_EXIT)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None
        graph = self._show_graph(view)

        # nodes are labelled with AIL class names
        labels = {b.path: b._title.text() for b in graph.blocks}
        statements = [labels[p] for p, _ in view.editor.leaves()]
        assert statements == ["Call puts", "Call fflush", "Return"], statements
        assert "Const &stdout" in labels.values(), labels
        assert not any(t.startswith(("assign", "store", "call statement", "load", "var")) for t in labels.values())

        # the graph's context menu expands and collapses everything
        n_statements = len(view.editor.leaves())
        everything = len({p for p, _ in view.editor.leaves()} | {p for p, _ in _all_nodes(view.editor)})
        assert n_statements < everything and len(graph.blocks) == everything, "small patterns start fully expanded"
        menu = graph.context_menu()  # kept alive: its actions die with it
        actions = {a.text(): a for a in menu.actions()}
        assert list(actions) == ["Expand all", "Collapse all"]
        actions["Collapse all"].trigger()
        assert len(graph.blocks) == n_statements
        actions["Expand all"].trigger()
        assert len(graph.blocks) == everything

        # expand all then collapse all keeps the tree centered, zoomed or not
        view.collapse_all()
        view.expand_all()
        view.collapse_all()
        dx, dy = self._tree_offset(graph)
        assert dx <= 2 and dy <= 2, (dx, dy)
        # the scene is only as large as what is on it, with room to drag
        rect, items = graph.scene().sceneRect(), graph.scene().itemsBoundingRect()
        assert rect.width() <= items.width() + 2 * graph.LEFT_PADDING + 1
        graph.zoom(out=True)
        view.expand_all()
        dx, dy = self._tree_offset(graph)
        assert dx <= 2 and dy <= 2, (dx, dy)

        # a double click keeps the node where it is on screen
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

        # through Qt's own event delivery: a release only reaches an item that took the press
        path, _ = next((p, node) for p, node in view.editor.leaves() if not isinstance(node, PAnyStmt))

        def point_of(node_path):
            item = view._nodes_by_path[node_path]
            graph.centerOn(item)
            return graph.mapFromScene(item.sceneBoundingRect().center())

        QTest.mouseClick(graph.viewport(), Qt.MouseButton.LeftButton, pos=point_of(path))
        assert view.selected_path == path, "a single click selects"
        assert path not in view.collapsed, "and does not toggle"
        QTest.mouseDClick(graph.viewport(), Qt.MouseButton.LeftButton, pos=point_of(path))
        assert path in view.collapsed, "a double click toggles"
        view.expand_all()

        # wildcards can be turned back from the property panel: an expression, check then uncheck
        expr = ("stmts", 1, "call", "args", 0)
        before = view.editor.node_at(expr)
        view.select_node(expr)
        index, _ = self._property_index(view, ("wildcard", expr))
        view._model.setData(index, Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)
        assert isinstance(view.editor.node_at(expr), PAny)
        index, item = self._property_index(view, ("wildcard", expr))
        assert item.value is True
        view._model.setData(index, Qt.CheckState.Unchecked, Qt.ItemDataRole.CheckStateRole)
        assert view.editor.node_at(expr) == before, "unchecking puts the expression back"
        _, item = self._property_index(view, ("wildcard", expr))
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

        # a double click expands and collapses without editing; wildcarding is the panel's job
        full = graph.graph.number_of_nodes()
        view.activate_node(path)
        assert path in view.collapsed
        assert graph.graph.number_of_nodes() < full
        view.activate_node(path)
        assert graph.graph.number_of_nodes() == full
        before = view.editor.pattern
        child_path = next(
            c for c, n in _all_nodes(view.editor) if isinstance(n, PatternExpr) and view.editor.children(c)
        )
        view.activate_node(child_path)
        assert child_path in view.collapsed and view.editor.pattern == before
        assert not isinstance(view.editor.node_at(child_path), PAny)
        view.activate_node(child_path)
        assert graph.graph.number_of_nodes() == full
        view._apply_property("wildcard", child_path, True)
        assert isinstance(view.editor.node_at(child_path), PAny)
        view.undo()
        assert not isinstance(view.editor.node_at(child_path), PAny)
        view.set_leaf_mode(path, "optional")
        assert view.editor.node_at(path).optional is True
        view.set_leaf_mode(path, "wildcard")
        assert isinstance(view.editor.node_at(path), PAnyStmt)

    def test_save_library_and_loosening(self):
        """Save a selection's pattern, loosen it, and move it through the library."""
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert isinstance(view, PatternView) and view.editor is not None
        assert view.editor.pattern.call_name == "my_idiom" and view.origin_func == func.addr
        leaves = view.editor.leaves()
        assert len(leaves) >= 2
        graph = view._graph_widget.graph
        assert graph.number_of_nodes() > len(leaves), "a fresh pattern shows its expressions too"
        assert view.collapsed == set() and all(isinstance(n, QPatternNode) for n in graph.nodes())
        kb = self.main.workspace.main_instance.kb

        # loosening constants, undone
        pinned = [p for p, n in _all_nodes(view.editor) if isinstance(n, PConst) and n.value is not None]
        assert view.loosen_constants() == len(pinned)
        assert all(view.editor.node_at(p).value is None for p in pinned)
        view.undo()
        assert all(view.editor.node_at(p).value is not None for p in pinned)

        # save puts it in the knowledge base, off as every new pattern is
        view.min_similarity = 0.7
        stored = view.save()
        assert stored is not None and kb.patterns.get("my_idiom") is stored
        assert stored.min_similarity == 0.7 and stored.origin_func == func.addr
        assert [view._library_table.item(0, j).text() for j in range(3)] == ["my_idiom", "my_idiom", "off"]
        # saving again replaces rather than refuses
        view.editor.set_display_name("renamed")
        stored = view.save()
        assert stored is not None and stored.pattern.display_name == "renamed"
        assert len(kb.patterns) == 1

        # the library toggles, exports, deletes, imports and edits
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

        # more loosening, and the strictness setting survives a save and load
        view.cut_depth()
        view.loosen_interior_captures()
        view.require_verified = False
        stored = view.save()
        assert stored is not None and stored.require_verified is False
        view.load_stored(stored)
        assert view.require_verified is False

    def test_search(self):
        """Search a selection's pattern in its own function and in all of them, and re-lift it."""
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None

        # the statements the pattern came from are found
        view.search_current_function()
        self.main.workspace.job_manager.join_all_jobs()
        assert view.matches
        best = view.matches[0]
        assert best.func_addr == func.addr and best.similarity == 1.0 and best.verified
        assert view._matches_table.rowCount() == len(view.matches)
        assert view._matches_table.item(0, 0).text() == func.name
        view.jump_to_match(0)  # the disassembly view lands on the function
        disasm_view = self.main.workspace._get_or_create_view("disassembly", DisassemblyView)
        assert disasm_view.function.am_obj is not None and disasm_view.function.am_obj.addr == func.addr

        # a failed leaf of a selected match row is marked on the canvas
        view.matches[0].failed_leaves = [0]
        view.show_match(0)
        assert view._nodes_by_path[view.editor.leaves()[0][0]].failed
        view.matches[0].failed_leaves = []

        # every function
        view.search_all_functions()
        self.main.workspace.job_manager.join_all_jobs()
        assert any(r.func_addr == func.addr and r.similarity == 1.0 for r in view.matches)

        # a suggested sub-run re-lifts the pattern; pretend the occurrence had to be cut down
        origin = next(r for r in view.matches if r.func_addr == func.addr and r.similarity == 1.0)
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

    def test_dock_enabling_and_numbers(self):
        """The Patterns dock: its rows and numbers, deferred enabling, and sorting."""
        from angr.knowledge_plugins.patterns import StoredPattern  # pylint:disable=import-outside-toplevel

        _, code_view = self._decompile("1after909", "read_bin")
        kb = self.main.workspace.main_instance.kb
        library = code_view._pattern_library
        table = code_view.patterns_table
        assert table is not None and table.rowCount() == 0
        headers = [table.horizontalHeaderItem(j).text() for j in range(table.columnCount())]
        # the numbers come right after the name, so a narrow dock shows them without scrolling
        assert headers[:5] == ["Pattern", "Enabled", "Highlight", "Matches", "Outlined"]

        # saved, off as every new pattern is, and not applied here yet
        self._select_text(code_view, self.ERROR_EXIT)
        view = code_view.textedit.create_pattern(call_name="PatternErrorsOut")
        assert view is not None
        view.save()
        assert table.rowCount() == 1
        assert [table.item(0, j).text() for j in (0, 1, 3, 4)] == ["patternerrorsout", "off", "0", "0"]
        # Save & Redecompile turns it on: redecompiling with it off would change nothing
        assert view._apply_btn.text() == "Save && Redecompile"
        view._apply_btn.click()
        self.main.workspace.job_manager.join_all_jobs()
        assert view.enabled and table.item(0, 1).text() == "on"
        assert code_view.codegen.am_obj.text.count("PatternErrorsOut(") == 3
        matches, outlined = int(table.item(0, 3).text()), int(table.item(0, 4).text())
        assert outlined == 3 and matches >= outlined

        # a click on Enabled only marks the pattern; the dock's button applies every mark
        button = library._apply_btn
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
        # Matches say what the last decompilation found: 0 for a pattern off then, counted by nobody
        assert kb.patterns.stats(code_view.function.am_obj.addr, "patternerrorsout") is None
        assert [table.item(0, j).text() for j in (3, 4)] == ["0", "0"]
        assert not self.main.workspace.job_manager.jobs
        assert table.item(0, 1).text() == "off" and not table.item(0, 0).font().bold()
        assert not button.isEnabled()
        table.item(0, 1).setCheckState(Qt.CheckState.Checked)
        assert table.item(0, 1).text() == "on (unapplied)"
        button.click()
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.codegen.am_obj.text.count("PatternErrorsOut(") == 3

        # sorting moves rows; each keeps its pattern
        data = kb.patterns.get("patternerrorsout").to_dict()
        data["pattern"]["name"] = "aaa_unused"
        data["enabled"] = False
        kb.patterns.store(StoredPattern.from_dict(data))
        self.main.workspace.on_patterns_changed()

        def names() -> list[str]:
            return [library.stored_at(r).name for r in range(table.rowCount())]

        assert names() == ["aaa_unused", "patternerrorsout"], "by name at first"
        # by the Matches column, as numbers, and the rows follow their patterns
        table.sortItems(3, Qt.SortOrder.DescendingOrder)
        assert names() == ["patternerrorsout", "aaa_unused"]
        assert int(table.item(0, 3).text()) >= 3 and table.item(1, 3).text() == "0"
        # a click on a moved row acts on its own pattern, and a reload keeps the order
        table.item(1, 1).setCheckState(Qt.CheckState.Checked)
        assert library.pending == {"aaa_unused": True}
        assert names() == ["patternerrorsout", "aaa_unused"]
        table.selectRow(1)
        assert library.selection().name == "aaa_unused"

        # a change in either place shows in both, and Edit opens the pattern in the pattern view
        library.toggle(kb.patterns.get("patternerrorsout"))
        assert table.item(0, 1).text() == "off"
        row = next(
            r for r in range(view._library_table.rowCount()) if view._library.stored_at(r).name == "patternerrorsout"
        )
        assert view._library_table.item(row, 2).text() == "off"
        table.selectRow(0)
        library._on_edit_clicked()
        assert view.editor is not None and view.editor.pattern.name == "patternerrorsout"
        assert self.main.workspace.view_manager.current_tab is view

    def test_dock_highlighting(self):
        """Highlighting an applied pattern: the dock's box, the tables' menus, and clearing."""
        func, code_view, view = self._apply_error_exit_pattern()
        kb = self.main.workspace.main_instance.kb
        stats = kb.patterns.stats(func.addr, "patternerrorsout")
        table = code_view.patterns_table
        button = code_view._clear_highlights_btn
        edit = code_view.textedit

        def menu_texts():
            menu = edit.get_context_menu()  # kept alive: its actions die with it
            return [a.text() for a in menu.actions()]

        def highlighted_texts():
            return [code_view._doc.findBlockByNumber(n).text().strip() for n in code_view.pattern_highlighted_lines]

        # the Highlight box bands the calls the pattern became
        assert code_view.pattern_highlighted_lines == []
        assert not button.isEnabled() and "Clear pattern highlights" not in menu_texts()
        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        texts = highlighted_texts()
        assert len(texts) == 3 and all("PatternErrorsOut(" in t for t in texts), texts
        assert "3 call(s)" in table.item(0, 2).toolTip()
        assert button.isEnabled() and "Clear pattern highlights" in menu_texts()
        # it follows the pseudocode through a fresh decompilation
        code_view.decompile(reset_cache=True)
        self.main.workspace.job_manager.join_all_jobs()
        assert len(code_view.pattern_highlighted_lines) == 3
        assert table.item(0, 2).checkState() == Qt.CheckState.Checked
        table.item(0, 2).setCheckState(Qt.CheckState.Unchecked)
        assert code_view.pattern_highlighted_lines == []

        # cleared by Escape, by the right-click menu and by the dock's button, box included
        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        QTest.keyClick(edit, Qt.Key.Key_Escape)
        assert code_view.pattern_highlighted_lines == []
        assert table.item(0, 2).checkState() == Qt.CheckState.Unchecked
        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        edit.action_clear_pattern_highlights.trigger()
        assert code_view.pattern_highlighted_lines == []
        assert table.item(0, 2).checkState() == Qt.CheckState.Unchecked
        assert not button.isEnabled() and "Clear pattern highlights" not in menu_texts()
        # the button clears a Discover family's highlight and a pattern's together
        stats = kb.patterns.stats(func.addr, "patternerrorsout")
        code_view.highlight_pattern(func.addr, [frozenset(stats.call_addrs[:1])])
        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        assert button.isEnabled()
        button.click()
        assert code_view.pattern_highlighted_lines == [] and not code_view.has_pattern_highlight
        assert not button.isEnabled()

        # both pattern tables' context menus
        table.selectRow(0)
        menu = code_view._pattern_library.context_menu()
        actions = self._menu_actions(menu)
        assert list(actions) == [
            "Highlight patterns in pseudocode",
            "Highlight patterns in disassembly",
            "Edit pattern...",
        ]
        actions["Highlight patterns in pseudocode"].trigger()
        texts = highlighted_texts()
        assert len(texts) == 3 and all("PatternErrorsOut(" in t for t in texts), texts
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
        code_view.clear_pattern_highlight()

        # the pass's numbers are not saved with a project; the calls on screen are enough
        kb.patterns._stats.clear()  # what a project loaded from a database has
        code_view.reload_patterns()
        codegen = code_view.codegen.am_obj
        assert "3 call(s)" in table.item(0, 2).toolTip()
        table.item(0, 2).setCheckState(Qt.CheckState.Checked)
        texts = highlighted_texts()
        assert len(texts) == 3 and all("PatternErrorsOut(" in t for t in texts), texts
        table.item(0, 2).setCheckState(Qt.CheckState.Unchecked)
        assert code_view.pattern_highlighted_lines == []
        table.selectRow(0)
        menu = code_view._pattern_library.context_menu()
        self._menu_actions(menu)["Highlight patterns in pseudocode"].trigger()
        assert len(code_view.pattern_highlighted_lines) == 3
        self.main.workspace.job_manager.join_all_jobs()
        assert code_view.codegen.am_obj is codegen, "never decompiled again"
        code_view.clear_pattern_highlight()

        # a pattern that did not apply at the last decompilation has nothing to highlight
        kb.patterns.set_enabled("patternerrorsout", False)
        code_view.decompile(reset_cache=True)
        self.main.workspace.job_manager.join_all_jobs()
        table.selectRow(0)
        menu = code_view._pattern_library.context_menu()
        actions = self._menu_actions(menu)
        actions["Highlight patterns in disassembly"].trigger()
        actions["Highlight patterns in pseudocode"].trigger()
        assert not self._disasm().pattern_highlight_addrs and not code_view.pattern_highlighted_lines

    def test_discovery_run(self):
        """One discovery on read_bin: it reuses the view's decompilation, blocks behind the
        progress dialog, fills Found in afterwards, and keeps every copy one straight run."""
        from angr.analyses.decompiler.decompiler import Decompiler  # pylint:disable=import-outside-toplevel

        from angrmanagement.data.jobs import (  # pylint:disable=import-outside-toplevel
            PatternDiscoveryJob,
            PatternFoundJob,
        )

        func, _ = self._decompile("1after909", "read_bin")
        kb = self.main.workspace.main_instance.kb
        cache = kb.decompilations[(func.addr, "pseudocode")]
        started, labels, shown, results, runs = [], [], [], [], []
        self.main.workspace.job_manager.job_starting.connect(started.append)

        # the statement modes, "Consecutive only" by default
        self.main.workspace.show_pattern_discovery()
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

        dialog = self.main._progress_dialog
        orig_label = dialog.setLabelText
        dialog.setLabelText = lambda text: labels.append(text) or orig_label(text)
        orig_show = PatternView._show_families

        def spy(v, result):
            # what the table shows the moment discovery ends
            results.append(result)
            shown.append([f.found for f in result.families if f.pattern is not None])
            orig_show(v, result)
            shown.append([v._families_table.item(r, 4).text() for r in range(v._families_table.rowCount())])

        PatternView._show_families = spy
        orig_decompile = Decompiler._decompile
        Decompiler._decompile = lambda dec: runs.append(dec.func.addr) or orig_decompile(dec)
        try:
            self._run_discovery()
            self.main.workspace.job_manager.join_all_jobs()
        finally:
            dialog.setLabelText = orig_label
            PatternView._show_families = orig_show
            Decompiler._decompile = orig_decompile

        # it ran on the view's cached decompilation, and never decompiled
        assert view.discovered_func == func.addr and view.families
        assert not runs
        assert kb.decompilations[(func.addr, "pseudocode")] is cache

        # a modal progress dialog shows it
        jobs = [j for j in started if isinstance(j, PatternDiscoveryJob)]
        assert len(jobs) == 1 and jobs[0].blocking
        assert jobs[0].statements == "consecutive"
        assert any(t.startswith("Discovering patterns in read_bin") for t in labels), labels

        # Found is filled in by a later background job
        kinds = [type(j) for j in started]
        assert PatternFoundJob in kinds and kinds.index(PatternFoundJob) > kinds.index(PatternDiscoveryJob)
        assert shown and all(n is None for n in shown[0]), "no search inside the blocking job"
        assert "…" in shown[1]
        texts = [view._families_table.item(r, 4).text() for r in range(view._families_table.rowCount())]
        assert "…" not in texts
        assert all(f.found is not None for f in view.families if f.pattern is not None)

        # consecutive only: every copy is one straight run
        (result,) = results
        graph = result.graph
        nodes = {(b.addr, b.idx): b for b in graph}
        for family in result.families:
            for stmts in family.copy_stmts:
                blocks = {nodes[loc] for loc, _ in stmts}
                # every block but the first has one predecessor, inside the copy, and that
                # predecessor has it as its only successor
                heads = [b for b in blocks if not any(p in blocks for p in graph.predecessors(b))]
                assert len(heads) == 1, family
                for b in blocks - set(heads):
                    (pred,) = graph.predecessors(b)
                    assert pred in blocks and graph.out_degree[pred] == 1

    def test_discover_table(self):
        """Analyze > Discover Patterns on read_bin: the families table, its double click and
        context menu, and applying the error-exit family's pattern."""
        from PySide6.QtWidgets import QPushButton  # pylint:disable=import-outside-toplevel

        func, code_view = self._decompile("1after909", "read_bin")
        # read_bin's printf/fflush pairs are a second, two-statement family
        view = self._run_discovery(min_statements=2)
        self.main.workspace.job_manager.join_all_jobs()
        assert view.discovered_func == func.addr and view.families
        table = view._families_table
        assert table.rowCount() == len(view.families)

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
        assert family.found >= 3 and family.covered == family.copies

        # sorting moves rows; each still knows its family, and numbers sort as numbers
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
        # the first Escape dismisses the highlight and stays on the function
        QTest.keyClick(code_view.textedit, Qt.Key.Key_Escape)
        assert code_view.pattern_highlighted_lines == []
        assert code_view.function.am_obj is func

        # the context menu replaces the Edit pattern button
        buttons = [b.text() for b in view._discover_tab.findChildren(QPushButton)]
        assert "Edit pattern" not in buttons
        self.main.workspace.raise_view(view)
        view._tabs.setCurrentWidget(view._discover_tab)
        rows = [r for r in range(table.rowCount()) if view.families[view.family_at(r)].pattern is not None][:2]
        table.selectRow(row)
        menu_one = view.families_context_menu()  # kept alive: Edit pattern... fires from it at the end
        actions = self._menu_actions(menu_one)
        assert list(actions) == [
            "Highlight patterns in pseudocode",
            "Highlight patterns in disassembly",
            "Edit pattern...",
        ]
        assert all(a.isEnabled() for a in actions.values())
        actions["Highlight patterns in disassembly"].trigger()
        disasm = self._disasm()
        assert disasm.pattern_highlight_addrs == set().union(*family.copy_addrs)
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
        # two families: both highlight, but only one can be edited
        table.selectRow(rows[0])
        table.selectionModel().select(
            table.model().index(rows[1], 0),
            table.selectionModel().SelectionFlag.Select | table.selectionModel().SelectionFlag.Rows,
        )
        menu_two = view.families_context_menu()
        two = self._menu_actions(menu_two)
        assert not two["Edit pattern..."].isEnabled()
        two["Highlight patterns in disassembly"].trigger()
        both = [view.families[view.family_at(r)] for r in rows]
        assert disasm.pattern_highlight_addrs == set().union(*(a for f in both for a in f.copy_addrs))
        code_view.clear_pattern_highlight()

        # Edit pattern... loads the family's pattern; applying it outlines every error exit
        actions["Edit pattern..."].trigger()
        assert view.editor is not None and view.origin_func == func.addr
        assert view._tabs.currentWidget() is view._pattern_tab
        view.apply()
        self.main.workspace.job_manager.join_all_jobs()
        call = view.editor.pattern.call_name
        calls = re.findall(rf'{call}\("([^"]*)"', code_view.codegen.am_obj.text)
        assert "Length exceeds capacity." in calls and "Error while reading." in calls, calls

    def test_cancel_stops_discovery_inside_the_alignment(self):
        from angr.analyses.decompiler.pattern_match import Checkpoint  # pylint:disable=import-outside-toplevel

        from angrmanagement.data.jobs import pattern_discovery  # pylint:disable=import-outside-toplevel

        _, _ = self._decompile("1after909", "read_bin")
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

    def test_no_selection_makes_no_pattern(self):
        _func, code_view = self._decompile_main()
        cursor = code_view.textedit.textCursor()
        cursor.clearSelection()
        code_view.textedit.setTextCursor(cursor)
        assert code_view.textedit.create_pattern(call_name="x") is None


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
