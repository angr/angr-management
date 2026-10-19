# pylint:disable=missing-class-docstring,wrong-import-order,duplicate-code
from __future__ import annotations

import os
import unittest
from typing import TYPE_CHECKING
from unittest.mock import patch

import angr
from angr.analyses.decompiler.structured_codegen.c import CVariable
from common import AngrManagementTestCase, test_location
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog

from angrmanagement.ui.dialogs.rename_node import RenameNode
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
        assert self.func.prototype.c_repr() == "unsigned int ()(char *, char *)"

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
        assert self.func.prototype.c_repr() == "unsigned int ()(char *, char *)"

        new_proto = angr.types.parse_type(
            "unsigned int (int *, char *)", arch=self.main.workspace.main_instance.project.arch
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
        assert self.func.prototype.c_repr() == "unsigned int ()(int *, char *)"

        cfunc = self.code_view.codegen.cfunc
        assert cfunc is not None
        assert len(cfunc.arg_list) == 2
        assert cfunc.arg_list[0].type is not None
        assert cfunc.arg_list[0].type.c_repr() == "int *"

    def test_retype_function_keeps_earlier_edits(self):
        # rename a local variable (arguments are named by the prototype, so they would survive anyway) and give it a
        # manual type, the way the pseudocode view does
        cfunc = self.code_view.codegen.cfunc
        assert cfunc is not None
        local_vars = cfunc.get_unified_local_vars()
        local_var_node = None
        assert self.code_view.codegen.map_pos_to_node is not None
        for _, item in self.code_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, CVariable) and item.obj.unified_variable in local_vars:
                local_var_node = item.obj
                break
        assert local_var_node is not None
        rename_node = RenameNode(code_view=self.code_view, node=local_var_node, func=self.func)
        rename_node._name_box.setText("")
        QTest.keyClicks(rename_node._name_box, "var_kept")
        QTest.mouseClick(rename_node._ok_button, Qt.MouseButton.LeftButton)
        assert local_var_node.unified_variable is not None
        ident = local_var_node.unified_variable.ident
        assert local_var_node.unified_variable.name == "var_kept"
        kb = self.main.workspace.main_instance.kb
        manual_type = angr.types.parse_type("unsigned long long", arch=self.main.workspace.main_instance.project.arch)
        kb.dec_variables[cfunc.addr].set_variable_type(
            local_var_node.variable, manual_type, all_unified=True, mark_manual=True
        )

        # retyping the function drops and re-derives its variables; the edits must come back
        new_proto = angr.types.parse_type("int (char *, char *)", arch=self.main.workspace.main_instance.project.arch)
        with patch(
            "angrmanagement.ui.dialogs.retype_node.RetypeNode.exec_",
            self._mock_exec_with_type(new_proto),
        ):
            self.code_view._textedit.retype_node(node=cfunc)
        self.main.workspace.job_manager.join_all_jobs()

        assert self.func.prototype is not None
        assert self.func.prototype.c_repr() == "int ()(char *, char *)"
        varman = kb.dec_variables[self.func.addr]
        var = next(v for v in varman.get_unified_variables(sort=None) if v.ident == ident)
        assert var.name == "var_kept"
        assert var in varman.variables_with_manual_types
        assert varman.get_variable_type(var).c_repr() == "unsigned long long"
        assert self.code_view.codegen.text is not None
        assert "unsigned long long var_kept" in self.code_view.codegen.text


if __name__ == "__main__":
    unittest.main()
