"""
Test cases for the comment annotation workflow: inline editing, comment kinds and the Comments view.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import angr
from common import AngrManagementTestCase, ProjectOpenTestCase, test_location
from PySide6.QtCore import Qt

from angrmanagement.config import Conf
from angrmanagement.data.annotations import CommentKind
from angrmanagement.ui.views.code_view import CodeView
from angrmanagement.ui.views.comments_view import CommentsView
from angrmanagement.ui.views.disassembly_view import DisassemblyView
from angrmanagement.ui.widgets.qfunction_comment import QFunctionCommentBanner


class TestInlineComments(ProjectOpenTestCase):
    """Inline comment editing in the disassembly view."""

    def setUp(self):
        super().setUp()
        self.disasm_view = DisassemblyView(self.workspace, "center", self.instance)
        self.func = next(iter(self.project.kb.functions.values()))
        self.addr = self.func.addr + 1

    def tearDown(self):
        self.disasm_view.close()
        super().tearDown()

    def test_inline_editor_sets_comment(self):
        editor = self.disasm_view.begin_inline_comment(self.addr)
        assert editor is not None
        editor.setText("first note")
        editor.commit()
        assert self.project.kb.comments[self.addr] == "first note"

    def test_inline_editor_prefills_and_edits(self):
        self.workspace.set_comment(self.addr, "original")
        editor = self.disasm_view.begin_inline_comment(self.addr)
        assert editor.text() == "original"
        editor.setText("edited")
        editor.commit()
        assert self.project.kb.comments[self.addr] == "edited"

    def test_inline_editor_clearing_deletes_comment(self):
        self.workspace.set_comment(self.addr, "to be removed")
        editor = self.disasm_view.begin_inline_comment(self.addr)
        editor.setText("")
        editor.commit()
        assert self.addr not in self.project.kb.comments

    def test_inline_editor_escape_cancels(self):
        self.workspace.set_comment(self.addr, "unchanged")
        editor = self.disasm_view.begin_inline_comment(self.addr)
        editor.setText("discard me")
        editor.cancel()
        assert self.project.kb.comments[self.addr] == "unchanged"

    def test_multiline_comment_falls_back_to_dialog(self):
        self.workspace.set_comment(self.addr, "line one\nline two")
        with patch.object(self.disasm_view, "popup_comment_dialog") as mock_dialog:
            assert self.disasm_view.begin_inline_comment(self.addr) is None
            mock_dialog.assert_called_once()

    def test_semicolon_key_uses_selected_instruction(self):
        self.disasm_view.infodock.selected_insns.add(self.addr)
        editor = self.disasm_view.begin_inline_comment()
        assert editor is not None
        assert editor.addr == self.addr
        editor.cancel()


class TestCommentKinds(ProjectOpenTestCase):
    """Function comments and repeatable comments."""

    def setUp(self):
        super().setUp()
        self.annotations = self.instance.annotations
        self.func = next(iter(self.project.kb.functions.values()))

    def test_function_entry_comment_defaults_to_function_kind(self):
        self.workspace.set_comment(self.func.addr, "what this does")
        assert self.annotations.kind_of(self.func.addr) == CommentKind.FUNCTION
        assert self.annotations.function_comment(self.func.addr) == "what this does"
        # not repeated inline next to the first instruction
        assert self.annotations.inline_comment(self.func.addr) is None

    def test_function_comment_banner_renders_lines(self):
        self.workspace.set_comment(self.func.addr, "line one\nline two", kind=CommentKind.FUNCTION)
        banner = QFunctionCommentBanner(self.instance, self.func.addr, Conf)
        assert len(banner._text_items) == 2
        assert banner._text_items[0].text() == "; line one"
        assert banner.height > 0

    def test_function_comment_banner_collapses_when_empty(self):
        banner = QFunctionCommentBanner(self.instance, self.func.addr, Conf)
        assert banner.height == 0
        self.workspace.set_comment(self.func.addr, "now there is one", kind=CommentKind.FUNCTION)
        banner.refresh()
        assert banner.height > 0

    def test_plain_kind_at_function_entry_renders_inline(self):
        self.workspace.set_comment(self.func.addr, "just here", kind=CommentKind.PLAIN)
        assert self.annotations.function_comment(self.func.addr) is None
        assert self.annotations.inline_comment(self.func.addr) == "just here"

    def test_repeatable_comment_shows_at_call_sites(self):
        callgraph = self.project.kb.functions.callgraph
        callee_addr = next(
            addr for addr in callgraph.nodes if list(callgraph.predecessors(addr)) and addr in self.project.kb.functions
        )
        self.workspace.set_comment(callee_addr, "the callee", kind=CommentKind.REPEATABLE)

        referencing = self.annotations._referencing_insns(self.project.kb, callee_addr)
        assert referencing, "expected at least one referencing instruction"
        for ins_addr in referencing:
            shown = [text for _, text in self.annotations.repeatable_comments_at(ins_addr)]
            assert shown == ["the callee"]

    def test_plain_comment_does_not_repeat(self):
        callgraph = self.project.kb.functions.callgraph
        callee_addr = next(addr for addr in callgraph.nodes if list(callgraph.predecessors(addr)))
        self.workspace.set_comment(callee_addr, "not repeated", kind=CommentKind.PLAIN)
        for ins_addr in self.annotations._referencing_insns(self.project.kb, callee_addr):
            assert self.annotations.repeatable_comments_at(ins_addr) == []


class TestCommentsView(ProjectOpenTestCase):
    """The dockable Comments view."""

    def setUp(self):
        super().setUp()
        self.view = CommentsView(self.workspace, "bottom", self.instance)
        self.table = self.view._comment_table._table_view
        self.model = self.table._model
        self.func = next(iter(self.project.kb.functions.values()))

    def tearDown(self):
        self.view.close()
        super().tearDown()

    def _texts(self, column):
        rows = range(len(self.model.comments))
        return [self.model.data(self.model.index(r, column), Qt.ItemDataRole.DisplayRole) for r in rows]

    def test_lists_comments_and_updates_live(self):
        assert self.model.rowCount() == 0
        self.workspace.set_comment(self.func.addr + 1, "alpha")
        assert self.model.rowCount() == 1
        self.workspace.set_comment(self.func.addr + 2, "beta")
        assert self.model.rowCount() == 2
        assert "alpha" in self._texts(self.model.COMMENT_COL)
        self.workspace.set_comment(self.func.addr + 1, "")
        assert self.model.rowCount() == 1

    def test_columns_report_address_function_and_kind(self):
        self.workspace.set_comment(self.func.addr, "the header", kind=CommentKind.FUNCTION)
        assert self._texts(self.model.ADDRESS_COL) == [f"{self.func.addr:#x}"]
        assert self._texts(self.model.FUNCTION_COL) == [self.func.name]
        assert self._texts(self.model.KIND_COL) == ["Function"]

    def test_filtering(self):
        self.workspace.set_comment(self.func.addr + 1, "keep me")
        self.workspace.set_comment(self.func.addr + 2, "drop me")
        self.view._comment_table._filter_box.setText("keep")
        assert self._texts(self.model.COMMENT_COL) == ["keep me"]
        self.view._comment_table._filter_box.setText("")
        assert self.model.rowCount() == 2

    def test_sorting_by_address(self):
        self.workspace.set_comment(self.func.addr + 2, "second")
        self.workspace.set_comment(self.func.addr + 1, "first")
        self.model.sort(self.model.ADDRESS_COL, Qt.SortOrder.DescendingOrder)
        assert self._texts(self.model.COMMENT_COL) == ["second", "first"]

    def test_multiline_comment_shows_first_line_with_full_text_in_tooltip(self):
        self.workspace.set_comment(self.func.addr + 1, "summary\ndetail")
        index = self.model.index(0, self.model.COMMENT_COL)
        assert self.model.data(index, Qt.ItemDataRole.DisplayRole) == "summary ..."
        assert self.model.data(index, Qt.ItemDataRole.ToolTipRole) == "summary\ndetail"

    def test_context_menu_delete_removes_comment(self):
        self.workspace.set_comment(self.func.addr + 1, "temporary")
        self.table._delete(self.model.comments)
        assert self.func.addr + 1 not in self.project.kb.comments


class TestPseudocodeComments(AngrManagementTestCase):
    """Comments made against the pseudocode view."""

    def setUp(self):
        super().setUp()
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        workspace = self.main.workspace
        instance = workspace.main_instance
        instance.project.am_obj = proj
        instance.cfg = proj.kb.cfgs["CFGFast"]
        instance.project.am_event(initialized=True)
        workspace.job_manager.join_all_jobs()

        self.workspace = workspace
        self.instance = instance
        self.func = proj.kb.functions.function(name="authenticate")

        self.code_view = workspace._get_or_create_view("pseudocode", CodeView)
        self.code_view.function = self.func
        workspace.job_manager.join_all_jobs()

    def _rendered_addr(self) -> int:
        return next(addr for addr, _ in self.code_view.codegen.map_addr_to_pos.items())

    def test_comment_set_edit_and_delete(self):
        addr = self._rendered_addr()
        editor = self.code_view.textedit.begin_inline_comment(addr, "")
        editor.setText("what this line does")
        editor.commit()
        assert self.instance.kb.comments[addr] == "what this line does"
        assert "what this line does" in self.code_view.codegen.text
        assert "Orphaned comments" not in self.code_view.codegen.text

        editor = self.code_view.textedit.begin_inline_comment(addr, self.instance.kb.comments[addr])
        assert editor.text() == "what this line does"
        editor.setText("")
        editor.commit()
        assert addr not in self.instance.kb.comments
        self.code_view.codegen.am_event()
        assert "what this line does" not in self.code_view.codegen.text

    def test_comment_survives_redecompilation(self):
        addr = self._rendered_addr()
        self.workspace.set_comment(addr, "survives")
        assert "survives" in self.code_view.codegen.text

        self.code_view.decompile(reset_cache=True)
        self.workspace.job_manager.join_all_jobs()
        assert "survives" in self.code_view.codegen.text
        assert "Orphaned comments" not in self.code_view.codegen.text

    def test_function_entry_comment_renders_once(self):
        self.workspace.set_comment(self.func.addr, "the whole function", kind=CommentKind.FUNCTION)
        self.code_view.codegen.am_event()
        text = self.code_view.codegen.text
        assert text.count("the whole function") == 1
        assert "Orphaned comments" not in text

    def test_disassembly_comment_shows_in_pseudocode(self):
        addr = self._rendered_addr()
        disasm_view = self.workspace._get_or_create_view("disassembly", DisassemblyView)
        editor = disasm_view.begin_inline_comment(addr)
        editor.setText("written in the disassembly")
        editor.commit()
        assert "written in the disassembly" in self.code_view.codegen.text


if __name__ == "__main__":
    unittest.main()
