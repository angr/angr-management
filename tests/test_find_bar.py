"""
Test cases for the Ctrl+F find bars in the pseudocode and disassembly views.
"""

from __future__ import annotations

import os
import unittest
from collections import Counter

import angr
from common import AngrManagementTestCase, test_location
from PySide6.QtWidgets import QApplication

from angrmanagement.ui.views.disassembly_view import DisassemblyView

# a small function, so that displaying and decompiling it stays cheap
SMALL_FUNC_ADDR = 0x4016A0

# ProjectOpenTestCase drains the job queue with the default two-second idle window, which dominates
# the runtime of these tests. The analyses we need are all done well before that.
JOB_DRAIN_PERIOD = 0.3


class FindBarTestCase(AngrManagementTestCase):
    """Opens the test binary with a short job-drain window."""

    def setUp(self):
        super().setUp()
        instance = self.main.workspace.main_instance
        instance.project.am_obj = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs(wait_period=JOB_DRAIN_PERIOD)

    @property
    def workspace(self):
        return self.main.workspace

    @property
    def instance(self):
        return self.workspace.main_instance


class TestDisassemblyFindBar(FindBarTestCase):
    """Tests for Ctrl+F in the disassembly view."""

    def setUp(self):
        super().setUp()
        self.disasm: DisassemblyView = self.workspace._get_or_create_view("disassembly", DisassemblyView)
        self.disasm.display_function(self.instance.kb.functions.get_by_addr(SMALL_FUNC_ADDR))

    def test_find_bar_hidden_until_activated(self):
        assert self.disasm._find_bar.isHidden()
        self.disasm.show_find_bar()
        assert not self.disasm._find_bar.isHidden()

    def test_find_matches_instruction_text(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("mov")
        assert self.disasm._find_matches
        assert all("mov" in text for _, text in self.disasm._find_matches)
        assert self.disasm._find_bar._status_label.text() == f"1 of {len(self.disasm._find_matches)}"
        assert self.disasm._find_matches[0][0] in self.disasm.infodock.selected_insns

    def test_find_next_and_previous_wrap(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("mov")
        total = len(self.disasm._find_matches)
        assert total > 1
        self.disasm.find_previous()
        assert self.disasm._find_index == total - 1
        self.disasm.find_next()
        assert self.disasm._find_index == 0

    def test_find_regex(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._regex_box.setChecked(True)
        self.disasm._find_bar._query_box.setText(r"^mov\s")
        assert self.disasm._find_matches
        assert all(text.startswith("mov ") for _, text in self.disasm._find_matches)

    def test_bad_regex_is_reported(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._regex_box.setChecked(True)
        self.disasm._find_bar._query_box.setText("(")
        assert self.disasm._find_matches == []
        assert self.disasm._find_bar._query_box.toolTip()

    def test_close_clears_matches(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("mov")
        self.disasm._find_bar.close_bar()
        assert self.disasm._find_matches == []
        assert self.disasm._find_bar.isHidden()

    def test_no_match_clears_highlights(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("mov")
        assert self.disasm.infodock.selected_insns
        self.disasm._find_bar._query_box.setText("movzzzzz")
        assert self.disasm._find_matches == []
        assert not self.disasm.infodock.selected_insns


class TestCodeViewFindBar(FindBarTestCase):
    """Tests for Ctrl+F in the pseudocode view."""

    def setUp(self):
        super().setUp()
        self.workspace.decompile_function(self.instance.kb.functions.get_by_addr(SMALL_FUNC_ADDR))
        self.workspace.job_manager.join_all_jobs(wait_period=JOB_DRAIN_PERIOD)
        QApplication.processEvents()
        self.code_view = self.workspace.view_manager.first_view_in_category("pseudocode")

    def _common_token(self) -> str:
        """The most frequent letter in the decompiled text, so the query is guaranteed to hit."""
        text = self.code_view.textedit.toPlainText()
        assert text
        return Counter(c for c in text.lower() if c.isalpha()).most_common(1)[0][0]

    def test_find_highlights_all_matches(self):
        token = self._common_token()
        text = self.code_view.textedit.toPlainText()
        self.code_view.show_find_bar()
        self.code_view._find_bar._query_box.setText(token)
        assert len(self.code_view._find_matches) == text.lower().count(token)
        assert len(self.code_view._find_selections) == len(self.code_view._find_matches)
        assert all(text[s:e].lower() == token for s, e in self.code_view._find_matches)
        assert self.code_view._find_bar._status_label.text().endswith(f"of {len(self.code_view._find_matches)}")

    def test_find_next_moves_cursor(self):
        token = self._common_token()
        self.code_view.show_find_bar()
        self.code_view._find_bar._query_box.setText(token)
        assert len(self.code_view._find_matches) > 1
        first = self.code_view.textedit.textCursor().position()
        self.code_view.find_next()
        assert self.code_view.textedit.textCursor().position() != first

    def test_find_is_case_insensitive_by_default(self):
        self.code_view.textedit.setPlainText("Alpha alpha ALPHA", "text/x-csrc", "utf-8")
        self.code_view.show_find_bar()
        self.code_view._find_bar._query_box.setText("alpha")
        assert len(self.code_view._find_matches) == 3
        self.code_view._find_bar._case_box.setChecked(True)
        assert len(self.code_view._find_matches) == 1

    def test_close_clears_highlights(self):
        self.code_view.show_find_bar()
        self.code_view._find_bar._query_box.setText(self._common_token())
        self.code_view._find_bar.close_bar()
        assert self.code_view._find_matches == []
        assert self.code_view._find_selections == []

    def test_option_toggle_keeps_current_match(self):
        self.code_view.textedit.setPlainText("foo foo foo", "text/x-csrc", "utf-8")
        self.code_view.show_find_bar()
        self.code_view._find_bar._query_box.setText("foo")
        assert len(self.code_view._find_matches) == 3
        assert self.code_view._find_index == 0
        start = self.code_view.textedit.textCursor().selectionStart()
        for box in (self.code_view._find_bar._case_box, self.code_view._find_bar._regex_box):
            for checked in (True, False):
                box.setChecked(checked)
                assert len(self.code_view._find_matches) == 3
                assert self.code_view._find_index == 0
                assert self.code_view.textedit.textCursor().selectionStart() == start


if __name__ == "__main__":
    unittest.main()
