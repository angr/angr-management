# pylint:disable=missing-class-docstring,wrong-import-order,duplicate-code
from __future__ import annotations

import os
import unittest
from typing import TYPE_CHECKING
from unittest.mock import patch

import angr
from common import AngrManagementTestCase, test_location
from PySide6.QtWidgets import QApplication, QDialog

from angrmanagement.ui.views import DisassemblyView

if TYPE_CHECKING:
    from angrmanagement.ui.views import CodeView


class TestRetypeFunction(AngrManagementTestCase):
    def setUp(self) -> None:
        super().setUp()

        binpath = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(binpath, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_obj = proj
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()

        self.func = proj.kb.functions["authenticate"]
        disasm_view = self.main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(self.func)
        disasm_view.decompile_current_function()
        self.main.workspace.job_manager.join_all_jobs()

        self.code_view: CodeView = self.main.workspace.view_manager.first_view_in_category("pseudocode")  # type: ignore

    def tearDown(self) -> None:
        super().tearDown()
        del self.code_view

    @staticmethod
    def _mock_exec_with_type(new_type):
        def mock_exec(dialog_self, *_args, **_kwargs):
            dialog_self.new_type = new_type
            QApplication.processEvents()
            return QDialog.DialogCode.Accepted

        return mock_exec

    def test_retype_function_return_type(self):
        cfunc = self.code_view.codegen.cfunc
        assert cfunc is not None
        assert self.func.prototype is not None
        assert self.func.prototype.c_repr() == "unsigned long long ()(char *, char *)"

        new_proto = angr.types.parse_type("int (char *, char *)", arch=self.main.workspace.main_instance.project.arch)
        textedit = self.code_view._textedit
        assert textedit is not None

        with patch(
            "angrmanagement.ui.dialogs.retype_node.RetypeNode.exec_",
            self._mock_exec_with_type(new_proto),
        ):
            textedit.retype_node(node=cfunc)
        self.main.workspace.job_manager.join_all_jobs()

        assert self.func.prototype is not None
        assert self.func.prototype.returnty is not None
        assert self.func.prototype.returnty.c_repr() == "int"
        assert self.func.prototype.c_repr() == "int ()(char *, char *)"

    def test_retype_argument_via_function(self):
        cfunc = self.code_view.codegen.cfunc
        assert cfunc is not None
        assert self.func.prototype is not None
        assert self.func.prototype.c_repr() == "unsigned long long ()(char *, char *)"

        new_proto = angr.types.parse_type(
            "unsigned long long (int *, char *)", arch=self.main.workspace.main_instance.project.arch
        )
        textedit = self.code_view._textedit
        assert textedit is not None

        with patch(
            "angrmanagement.ui.dialogs.retype_node.RetypeNode.exec_",
            self._mock_exec_with_type(new_proto),
        ):
            textedit.retype_node(node=cfunc)
        self.main.workspace.job_manager.join_all_jobs()

        assert self.func.prototype is not None
        assert self.func.prototype.c_repr() == "unsigned long long ()(int *, char *)"

        cfunc = self.code_view.codegen.cfunc
        assert cfunc is not None
        assert len(cfunc.arg_list) == 2
        assert cfunc.arg_list[0].type is not None
        assert cfunc.arg_list[0].type.c_repr() == "int *"


if __name__ == "__main__":
    unittest.main()
