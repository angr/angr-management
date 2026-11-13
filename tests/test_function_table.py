# pylint:disable=missing-class-docstring,wrong-import-order,protected-access
from __future__ import annotations

import os
import unittest
from typing import TYPE_CHECKING

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.ui.views import FunctionsView

if TYPE_CHECKING:
    from angrmanagement.ui.widgets.qfunction_table import QFunctionTable


class TestFunctionTableIncrementalRefresh(AngrManagementTestCase):
    """
    The functions table grows incrementally while functions are being added (as during CFG recovery).
    """

    def setUp(self):
        super().setUp()
        self.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        self.funcs = self.proj.kb.functions
        view = self.main.workspace.view_manager.first_view_in_category("functions")
        assert isinstance(view, FunctionsView)
        self.table: QFunctionTable = view._function_table
        self._next_addr = 0x500000

    def _add(self, n: int, alignment: bool = False, name: str | None = None) -> list[int]:
        addrs = []
        for _ in range(n):
            addr = self._next_addr
            self._next_addr += 0x10
            func = self.funcs.function(addr=addr, create=True, name=name)
            assert func is not None
            func.is_alignment = alignment
            addrs.append(addr)
        return addrs

    def _rows(self) -> list[int]:
        func_list = self.table._table_view._model.func_list
        assert func_list is not None
        return [f.addr for f in func_list]

    def _raw(self) -> list[int]:
        raw = self.table._table_view._model._raw_func_list
        assert raw is not None
        return [f.addr for f in raw]

    def test_alignment_toggle_during_recovery(self):
        normal = self._add(3)
        align = self._add(2, alignment=True)
        self.table.function_manager = self.funcs
        # two refreshes: the second one used to drop the hidden entries of the first from the raw list
        normal += self._add(4)
        align += self._add(3, alignment=True)
        self.table.refresh()
        normal += self._add(2)
        align += self._add(1, alignment=True)
        self.table.refresh()

        assert not self.table.show_alignment_functions
        assert sorted(self._rows()) == sorted(normal)
        assert sorted(self._raw()) == sorted(self.funcs.function_addrs_set.copy())
        assert self.table._table_view._model.totalCount() == len(self.funcs)

        self.table.toggle_show_alignment_functions()
        assert sorted(self._rows()) == sorted(normal + align)
        self.table.toggle_show_alignment_functions()
        assert sorted(self._rows()) == sorted(normal)

    def test_incremental_matches_full_filter(self):
        self._add(3, name="foo_a")
        self._add(2, name="bar_a")
        self._add(1, alignment=True, name="foo_align")
        self.table.function_manager = self.funcs
        self.table.filter_functions("foo")
        self._add(3, name="foo_b")
        self._add(2, name="bar_b")
        self._add(1, alignment=True, name="foo_align_b")
        self.table.refresh()
        incremental = self._rows()
        assert len(incremental) == 6

        # a full re-filter yields the same rows in the same order
        self.table.filter_functions("")
        self.table.filter_functions("foo")
        assert self._rows() == incremental

        removed = incremental[1]
        del self.funcs[removed]
        self.table.refresh()
        assert removed not in self._rows()
        assert removed not in self._raw()
        assert self._rows() == [a for a in incremental if a != removed]


if __name__ == "__main__":
    unittest.main()
