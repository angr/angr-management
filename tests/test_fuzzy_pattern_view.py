# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import sys
import tempfile
import unittest

import angr
from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.known_patterns import PAny, PAnyStmt, PConst
from common import AngrManagementTestCase, test_location
from PySide6.QtGui import QTextCursor

from angrmanagement.ui.views import CodeView, DisassemblyView
from angrmanagement.ui.views.fuzzy_pattern_view import FuzzyPatternView
from angrmanagement.ui.widgets.qfuzzy_pattern_graph import QFuzzyPatternNode


def _all_nodes(editor, path=()):
    out = []
    for child_path, child in editor.children(path):
        out.append((child_path, child))
        out.extend(_all_nodes(editor, child_path))
    return out


class TestFuzzyPatternView(AngrManagementTestCase):
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

        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
        assert isinstance(view, FuzzyPatternView)
        assert view.editor is not None
        assert view.editor.pattern.call_name == "my_idiom"
        assert view.origin_func == func.addr

        leaves = view.editor.leaves()
        assert len(leaves) >= 2
        graph = view._graph_widget.graph
        assert graph is not None
        assert graph.number_of_nodes() == len(leaves), "one node per statement until something is expanded"
        assert all(isinstance(n, QFuzzyPatternNode) for n in graph.nodes())

    def test_nodes_can_be_toggled_expanded_and_wildcarded(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None
        path, leaf = next((p, node) for p, node in view.editor.leaves() if not isinstance(node, PAnyStmt))
        n_leaves = len(view.editor.leaves())

        view.set_leaf_mode(path, "optional")
        assert view.editor.node_at(path).optional is True

        view.activate_node(path)  # expand the statement into its expression tree
        assert path in view.expanded
        assert view._graph_widget.graph.number_of_nodes() > n_leaves

        child_path, _ = view.editor.children(path)[0]
        view.activate_node(child_path)  # an expression double-clicked becomes a wildcard
        assert isinstance(view.editor.node_at(child_path), PAny)

        view.undo()
        assert not isinstance(view.editor.node_at(child_path), PAny)

        view.set_leaf_mode(path, "wildcard")
        assert isinstance(view.editor.node_at(path), PAnyStmt)
        assert path not in view.expanded
        assert view._graph_widget.graph.number_of_nodes() == n_leaves

    def test_save_puts_the_pattern_in_the_knowledge_base(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
        assert view is not None
        view.min_similarity = 0.7

        stored = view.save()
        kb = self.main.workspace.main_instance.kb
        assert stored is not None
        assert kb.fuzzy_patterns.get("my_idiom") is stored
        assert stored.min_similarity == 0.7
        assert stored.origin_func == func.addr

        # saving again replaces rather than refuses
        view.editor.set_display_name("renamed")
        again = view.save()
        assert again is not None and again.pattern.display_name == "renamed"
        assert len(kb.fuzzy_patterns) == 1

    def test_search_finds_the_selection_in_its_own_function(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
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
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
        assert view is not None
        assert "my_idiom(" not in code_view.codegen.am_obj.text

        view.apply()
        self.main.workspace.job_manager.join_all_jobs()

        assert "my_idiom(" in code_view.codegen.am_obj.text, "the pattern's own statements must decompile as its call"

    def test_library_lists_toggles_exports_and_imports(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
        assert view is not None
        kb = self.main.workspace.main_instance.kb

        stored = view.save()
        assert [view._library_table.item(0, j).text() for j in range(3)] == ["my_idiom", "my_idiom", "on"]

        view.toggle_stored(stored)
        assert kb.fuzzy_patterns.get("my_idiom").enabled is False
        assert view._library_table.item(0, 2).text() == "off"

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "p.json")
            view.export_stored(stored, path)
            view.delete_stored(stored)
            assert len(kb.fuzzy_patterns) == 0
            assert view._library_table.rowCount() == 0

            back = view.import_stored(path)
            assert back.pattern == stored.pattern
            assert back.enabled is False
            assert kb.fuzzy_patterns.get("my_idiom") is back
            assert view._library_table.rowCount() == 1

        view.edit_stored(back)
        assert view.editor is not None and view.editor.pattern == back.pattern
        assert view.enabled is False

    def test_loosen_constants_from_the_view(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
        assert view is not None and view.editor is not None
        pinned = [p for p, n in _all_nodes(view.editor) if isinstance(n, PConst) and n.value is not None]
        assert view.loosen_constants() == len(pinned)
        assert all(view.editor.node_at(p).value is None for p in pinned)
        view.undo()
        assert all(view.editor.node_at(p).value is not None for p in pinned)

    def test_more_loosening_actions_and_the_strictness_setting(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
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
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
        assert view is not None

        view.search_all_functions()
        self.main.workspace.job_manager.join_all_jobs()

        assert any(r.func_addr == func.addr and r.similarity == 1.0 for r in view.matches)

    def test_a_suggested_subrun_relifts_the_pattern(self):
        func, code_view = self._decompile_main()
        self._select_two_statements(func, code_view)
        view = code_view.textedit.create_fuzzy_pattern(call_name="my_idiom")
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
        assert code_view.textedit.create_fuzzy_pattern(call_name="x") is None


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
