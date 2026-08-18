"""
Test cases for the Ctrl+F find bars in the pseudocode and disassembly views.
"""

from __future__ import annotations

import os
import unittest
from collections import Counter
from unittest.mock import patch

import angr
from angr.knowledge_plugins.cfg import MemoryDataSort
from common import AngrManagementTestCase, test_location
from PySide6.QtWidgets import QApplication

from angrmanagement.config import Conf
from angrmanagement.ui.views.disassembly_view import DisassemblyView

# a small function, so that displaying and decompiling it stays cheap
SMALL_FUNC_ADDR = 0x4016A0

# ProjectOpenTestCase drains the job queue with the default two-second idle window, which dominates
# the runtime of these tests. The analyses we need are all done well before that.
JOB_DRAIN_PERIOD = 0.3


def in_other(other, a) -> bool:
    return other.addr <= a < other.addr + other.size


def in_displayed(a) -> bool:
    return SMALL_FUNC_ADDR <= a < SMALL_FUNC_ADDR + 0x1000


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

    def test_cleared_query_clears_highlights(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("mov")
        assert self.disasm.infodock.selected_insns
        self.disasm._find_bar._query_box.setText("")
        assert self.disasm._find_matches == []
        assert not self.disasm.infodock.selected_insns

    def test_close_keeps_only_current_match(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("mov")
        current = self.disasm._find_matches[self.disasm._find_index][0]
        assert len(self.disasm.infodock.selected_insns) > 1
        self.disasm._find_bar.close_bar()
        assert set(self.disasm.infodock.selected_insns) == {current}

    def _distant_function(self):
        """A function at least a page away from SMALL_FUNC_ADDR."""
        kb = self.instance.kb
        candidates = [kb.functions.get_by_addr(addr) for addr in kb.functions if abs(addr - SMALL_FUNC_ADDR) > 0x1000]
        candidates = [f for f in candidates if not f.is_simprocedure and not f.is_alignment and f.size > 0]
        assert candidates
        return max(candidates, key=lambda f: abs(f.addr - SMALL_FUNC_ADDR))

    def test_linear_find_covers_visible_functions(self):
        other = self._distant_function()
        self.disasm.display_linear_viewer()
        self.disasm.jump_to(other.addr)
        query = next(iter(other.blocks)).capstone.insns[0].mnemonic

        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText(query)
        assert any(in_other(other, addr) for addr, _ in self.disasm._find_matches)
        # the displayed function is off screen now, so it must not contribute matches
        assert not any(in_displayed(addr) for addr, _ in self.disasm._find_matches)

    def test_linear_scroll_reapplies_query(self):
        other = self._distant_function()
        self.disasm.display_linear_viewer()
        self.disasm.show_find_bar()
        query = next(iter(other.blocks)).capstone.insns[0].mnemonic
        self.disasm._find_bar._query_box.setText(query)
        # the distant function is off screen, so it contributes no matches yet
        assert not any(in_other(other, addr) for addr, _ in self.disasm._find_matches)

        # scrolling the viewport to the distant function re-applies the query
        self.disasm._linear_viewer.navigate_to_addr(other.addr)
        assert any(in_other(other, addr) for addr, _ in self.disasm._find_matches)
        assert any(in_other(other, addr) for addr in self.disasm.infodock.selected_insns)

    def test_linear_typing_does_not_navigate(self):
        self.disasm.display_linear_viewer()
        self.disasm.show_find_bar()
        with patch.object(self.disasm._linear_viewer, "show_instruction") as nav:
            self.disasm._find_bar._query_box.setText("mov")
            nav.assert_not_called()
        assert self.disasm._find_matches
        assert self.disasm.infodock.selected_insns
        assert self.disasm._find_bar._status_label.text().endswith(f"of {len(self.disasm._find_matches)}")
        # explicit stepping still navigates
        with patch.object(self.disasm._linear_viewer, "show_instruction") as nav:
            self.disasm.find_next()
            nav.assert_called()

    def test_find_is_whitespace_tolerant(self):
        # capstone renders "lea rdi, [rip + 0x2059d9]"; the query is typed without spaces, the
        # way the disassembly view renders operands
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("[rip+0x2059d9]")
        assert self.disasm._find_matches

    def test_graph_find_stays_in_current_function(self):
        self.disasm.display_disasm_graph()
        func = self.instance.kb.functions.get_by_addr(SMALL_FUNC_ADDR)
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("mov")
        assert self.disasm._find_matches
        assert all(func.addr <= addr < func.addr + func.size for addr, _ in self.disasm._find_matches)

    def test_find_mode_dropdown(self):
        combo = self.disasm._find_bar._mode_combo
        assert combo is not None
        modes = [combo.itemText(i) for i in range(combo.count())]
        assert modes == ["Text", "Text (instruction only)", "Byte pattern"]

    def test_text_mode_searches_comments(self):
        func = self.instance.kb.functions.get_by_addr(SMALL_FUNC_ADDR)
        addr = next(iter(func.blocks)).capstone.insns[0].address
        self.instance.kb.comments[addr] = "FINDME_COMMENT"
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText("FINDME_COMMENT")
        assert [a for a, _ in self.disasm._find_matches] == [addr]
        # the instruction-only mode ignores comments
        self.disasm._find_bar._mode_combo.setCurrentText("Text (instruction only)")
        assert self.disasm._find_matches == []
        # ... but still matches instruction text
        self.disasm._find_bar._query_box.setText("mov")
        assert self.disasm._find_matches

    def test_byte_pattern_matches_instruction_bytes(self):
        func = self.instance.kb.functions.get_by_addr(SMALL_FUNC_ADDR)
        insn = next(i for b in func.blocks for i in b.capstone.insns if i.size >= 2)
        raw = bytes(insn.insn.bytes)
        self.disasm.show_find_bar()
        self.disasm._find_bar._mode_combo.setCurrentText("Byte pattern")
        self.disasm._find_bar._query_box.setText(raw.hex(" "))
        assert insn.address in [a for a, _ in self.disasm._find_matches]
        # wildcard bytes are supported
        tokens = raw.hex(" ").split()
        tokens[1] = "??"
        self.disasm._find_bar._query_box.setText(" ".join(tokens))
        assert insn.address in [a for a, _ in self.disasm._find_matches]

    def test_byte_pattern_matches_across_instructions(self):
        func = self.instance.kb.functions.get_by_addr(SMALL_FUNC_ADDR)
        insns = next(iter(func.blocks)).capstone.insns
        first, second = insns[0], insns[1]
        assert first.address + first.size == second.address
        raw = bytes(first.insn.bytes) + bytes(second.insn.bytes)
        self.disasm.show_find_bar()
        self.disasm._find_bar._mode_combo.setCurrentText("Byte pattern")
        self.disasm._find_bar._query_box.setText(raw.hex(" "))
        assert first.address in [a for a, _ in self.disasm._find_matches]

    def test_byte_pattern_match_limit(self):
        func = self.instance.kb.functions.get_by_addr(SMALL_FUNC_ADDR)
        assert sum(1 for b in func.blocks for _ in b.capstone.insns) > 5
        old_limit = Conf.find_match_limit
        Conf.find_match_limit = 5
        try:
            self.disasm.show_find_bar()
            self.disasm._find_bar._mode_combo.setCurrentText("Byte pattern")
            self.disasm._find_bar._query_box.setText("??")
            assert len(self.disasm._find_matches) == 5
            assert "of 5+" in self.disasm._find_bar._status_label.text()
        finally:
            Conf.find_match_limit = old_limit

    def test_byte_pattern_invalid_reports_error(self):
        self.disasm.show_find_bar()
        self.disasm._find_bar._mode_combo.setCurrentText("Byte pattern")
        self.disasm._find_bar._query_box.setText("zz")
        assert self.disasm._find_matches == []
        assert self.disasm._find_bar._query_box.toolTip()

    def _string_memory_data(self):
        cfg = self.instance.cfg.am_obj
        for md in cfg.memory_data.values():
            if md.sort == MemoryDataSort.String and md.content and len(md.content) >= 6 and md.size:
                return md
        raise AssertionError("no string memory data found")

    def test_linear_text_search_covers_data(self):
        md = self._string_memory_data()
        self.disasm.display_linear_viewer()
        self.disasm._linear_viewer.navigate_to_addr(md.addr)
        self.disasm.show_find_bar()
        snippet = md.content[:6].decode("latin-1")
        self.disasm._find_bar._query_box.setText(snippet)
        assert md.addr in [a for a, _ in self.disasm._find_matches]
        assert md.addr in self.disasm._find_data_matches
        # graph mode shows no data blocks, so data must not be searched there
        self.disasm.display_disasm_graph()
        assert md.addr not in [a for a, _ in self.disasm._find_matches]

    def test_linear_byte_pattern_covers_data(self):
        md = self._string_memory_data()
        self.disasm.display_linear_viewer()
        self.disasm._linear_viewer.navigate_to_addr(md.addr)
        self.disasm.show_find_bar()
        self.disasm._find_bar._mode_combo.setCurrentText("Byte pattern")
        self.disasm._find_bar._query_box.setText(bytes(md.content[:6]).hex(" "))
        data_hits = [a for a, _ in self.disasm._find_matches if a in self.disasm._find_data_matches]
        assert any(md.addr <= a < md.addr + md.size for a in data_hits)

    def test_stepping_to_data_match_selects_label(self):
        md = self._string_memory_data()
        self.disasm.display_linear_viewer()
        self.disasm._linear_viewer.navigate_to_addr(md.addr)
        self.disasm.show_find_bar()
        self.disasm._find_bar._query_box.setText(md.content[:6].decode("latin-1"))
        addrs = [a for a, _ in self.disasm._find_matches]
        idx = next(i for i, a in enumerate(addrs) if a in self.disasm._find_data_matches)
        self.disasm._find_index = (idx - 1) % len(addrs)
        self.disasm.find_next()
        current = self.disasm._find_matches[self.disasm._find_index][0]
        assert current in self.disasm._find_data_matches
        assert self.disasm.infodock.is_label_selected(self.disasm._find_data_matches[current])


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
