# pylint:disable=no-self-use
from __future__ import annotations

import os
import unittest

import angr
from common import AngrManagementTestCase, test_location
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from angrmanagement.data.search import SearchKind, SearchResult
from angrmanagement.ui.views.search_view import SearchView
from angrmanagement.ui.views.strings_view import StringsView
from angrmanagement.ui.widgets.qfind_bar import QFindBar
from angrmanagement.ui.widgets.qsearch_table import QSearchTableModel

# ProjectOpenTestCase drains the job queue with the default two-second idle window, which dominates
# the runtime of these tests. The analyses we need are all done well before that.
JOB_DRAIN_PERIOD = 0.3


class SearchTestCase(AngrManagementTestCase):
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


class TestSearchResultModel(unittest.TestCase):
    """Tests for the result table model, which needs no project."""

    def setUp(self):
        self.model = QSearchTableModel()
        self.model.set_results(
            [
                SearchResult(0x2000, "insn", "mov", "mov rax, rbx", 0x2000, "beta"),
                SearchResult(0x1000, "ascii", "hello", "hello world", None, ""),
                SearchResult(0x3000, "bytes", "48 8b", "48 8b 04", 0x3000, "alpha"),
            ]
        )

    def test_row_and_column_counts(self):
        assert self.model.rowCount() == 3
        assert self.model.columnCount() == len(QSearchTableModel.HEADER)

    def test_addresses_are_rendered_as_hex(self):
        index = self.model.index(0, QSearchTableModel.ADDRESS_COL)
        assert self.model.data(index, Qt.ItemDataRole.DisplayRole) == "0x2000"

    def test_sort_by_address(self):
        self.model.sort(QSearchTableModel.ADDRESS_COL)
        assert [r.addr for r in self.model.results] == [0x1000, 0x2000, 0x3000]

    def test_sort_by_function_descending(self):
        self.model.sort(QSearchTableModel.FUNCTION_COL, Qt.SortOrder.DescendingOrder)
        assert [r.func_name for r in self.model.results] == ["beta", "alpha", ""]

    def test_filter_matches_any_column(self):
        self.model.filter("alpha")
        assert [r.addr for r in self.model.results] == [0x3000]
        self.model.filter("0x1000")
        assert [r.addr for r in self.model.results] == [0x1000]
        self.model.filter("")
        assert self.model.rowCount() == 3
        assert self.model.total_count == 3

    def test_result_at_out_of_range(self):
        assert self.model.result_at(99) is None


class TestSearchView(SearchTestCase):
    """Tests for the Search view against a real binary."""

    def setUp(self):
        super().setUp()
        self.workspace.show_search_view()
        self.view: SearchView = self.workspace.view_manager.first_view_in_category("search")

    def _run_search(self, kind: SearchKind, text: str) -> list[SearchResult]:
        self.view._kind_combo.setCurrentIndex(list(SearchKind).index(kind))
        self.view._query_box.setText(text)
        self.view.search()
        self.workspace.job_manager.join_all_jobs(wait_period=JOB_DRAIN_PERIOD)
        QApplication.processEvents()
        return self.view.results

    def test_view_is_registered(self):
        assert isinstance(self.view, SearchView)
        assert self.view.category == "search"
        names = [self.view._scope_combo.itemText(i) for i in range(self.view._scope_combo.count())]
        assert names[0] == "Entire address space"
        assert "Section: .text" in names

    def test_string_search_populates_results(self):
        results = self._run_search(SearchKind.STRING, "GLIBC")
        assert results
        assert self.view._status_label.text() == f"{len(results)} results"
        assert self.view._table.model_.rowCount() == len(results)

    def test_byte_search_with_wildcards(self):
        assert self._run_search(SearchKind.BYTES, "7f ?? 4c 46")

    def test_invalid_query_reports_status(self):
        assert self._run_search(SearchKind.BYTES, "zz") == []
        assert "hex" in self.view._status_label.text()
        assert self.view._search_button.isEnabled()

    def test_filter_narrows_results(self):
        results = self._run_search(SearchKind.DISASSEMBLY, "xor")
        assert results
        self.view._filter_box.setText("__nothing_matches_this__")
        assert self.view._table.model_.rowCount() == 0
        assert self.view._status_label.text() == f"0/{len(results)} results"

    def test_navigate_to_result_selects_instruction(self):
        results = self._run_search(SearchKind.DISASSEMBLY, "xor")
        assert results
        self.view.navigate_to_result(results[0])
        disasm = self.workspace.view_manager.first_view_in_category("disassembly")
        assert results[0].addr in disasm.infodock.selected_insns

    def test_navigate_to_none_is_a_no_op(self):
        self.view.navigate_to_result(None)

    def test_copy_helpers(self):
        results = [SearchResult(0x1234, "insn", "mov", "mov rax, rbx", 0x1000, "main")]
        SearchView.copy_addresses(results)
        assert QApplication.clipboard().text() == "0x1234"
        SearchView.copy_matches(results)
        assert QApplication.clipboard().text() == "mov"
        SearchView.copy_rows(results)
        assert QApplication.clipboard().text().startswith("0x1234\tinsn\tmain\t")

    def test_options_visibility_follows_kind(self):
        self.view._kind_combo.setCurrentIndex(list(SearchKind).index(SearchKind.IMMEDIATE))
        assert self.view._format_combo.isVisibleTo(self.view)
        assert not self.view._decompile_box.isVisibleTo(self.view)
        self.view._kind_combo.setCurrentIndex(list(SearchKind).index(SearchKind.DECOMPILATION))
        assert self.view._decompile_box.isVisibleTo(self.view)
        assert not self.view._format_combo.isVisibleTo(self.view)

    def test_named_constant_fills_query(self):
        self.view._kind_combo.setCurrentIndex(list(SearchKind).index(SearchKind.IMMEDIATE))
        self.view._constants_button.menu().actions()[0].trigger()
        assert self.view._query_box.text()
        assert self.view._format_combo.currentText() in ("float", "double", "int32", "int64")

    def test_decompiled_count_label(self):
        self.view._kind_combo.setCurrentIndex(list(SearchKind).index(SearchKind.DECOMPILATION))
        assert self.view._decomp_count_label.isVisibleTo(self.view)
        assert self.view._decomp_count_label.text() == "0 functions decompiled"
        # the label is hidden for other kinds
        self.view._kind_combo.setCurrentIndex(list(SearchKind).index(SearchKind.STRING))
        assert not self.view._decomp_count_label.isVisibleTo(self.view)

        func = self.instance.kb.functions.get_by_addr(0x4016A0)
        self.instance.project.am_obj.analyses.Decompiler(
            func, cfg=self.instance.cfg.am_obj, flavor="pseudocode", use_cache=True
        )
        self.view._kind_combo.setCurrentIndex(list(SearchKind).index(SearchKind.DECOMPILATION))
        assert self.view._decomp_count_label.text() == "1 function decompiled"

    def test_case_and_regex_checkboxes_are_unified(self):
        find_bar = QFindBar()
        strings_view = StringsView(self.workspace, "center", self.instance)

        case_boxes = [find_bar._case_box, self.view._case_box]
        regex_boxes = [find_bar._regex_box, self.view._regex_box, strings_view._regex_checkbox]
        assert all(box.text() == "Aa" for box in case_boxes)
        assert all(box.toolTip() == "Case sensitive" for box in case_boxes)
        assert all(box.text() == ".*" for box in regex_boxes)
        assert all(box.toolTip() == "Regular expression" for box in regex_boxes)


if __name__ == "__main__":
    unittest.main()
