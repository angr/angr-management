# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import unittest
from typing import TYPE_CHECKING
from unittest.mock import patch

import angr
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimTemporaryVariable
from common import AngrManagementTestCase, test_location
from PySide6.QtWidgets import QApplication, QDialog

from angrmanagement.ui.views import DisassemblyView

if TYPE_CHECKING:
    from angrmanagement.ui.views import CodeView


class TestRetypeVariables(AngrManagementTestCase):
    def setUp(self) -> None:
        super().setUp()

        binpath = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(binpath, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_obj = proj
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()

        self.func = proj.kb.functions["authenticate"]
        # decompile the function
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

    def _find_local_variable_node(self) -> CVariable | None:
        cfunc = self.code_view.codegen.cfunc
        assert cfunc is not None
        arg_ids = {id(a) for a in cfunc.arg_list}
        assert self.code_view.codegen.map_pos_to_node is not None
        for _, item in self.code_view.codegen.map_pos_to_node.items():
            obj = item.obj
            if (
                isinstance(obj, CVariable)
                and obj.unified_variable is not None
                and not isinstance(obj.variable, SimTemporaryVariable)
                and id(obj) not in arg_ids
            ):
                return obj
        return None

    def test_retype_argument(self):
        assert self.func.prototype is not None
        assert self.func.prototype.c_repr() == "unsigned long long ()(char *, char *)"

        cfunc = self.code_view.codegen.cfunc
        assert cfunc is not None
        assert len(cfunc.arg_list) > 0

        arg_node = cfunc.arg_list[0]
        assert arg_node is not None
        assert arg_node.name == "a0"
        assert arg_node.type is not None
        assert arg_node.type.c_repr() == "char *"

        new_type = angr.types.parse_type("int *", arch=self.main.workspace.main_instance.project.arch)
        textedit = self.code_view._textedit
        assert textedit is not None

        with patch(
            "angrmanagement.ui.dialogs.retype_node.RetypeNode.exec_",
            self._mock_exec_with_type(new_type),
        ):
            textedit.retype_node(node=arg_node)

        self.main.workspace.job_manager.join_all_jobs()

        assert self.func.prototype.c_repr() == "unsigned long long ()(int *, char *)"

        cfunc = self.code_view.codegen.cfunc
        assert cfunc is not None
        assert len(cfunc.arg_list) == 2
        assert cfunc.arg_list[0].name == "a0"
        assert cfunc.arg_list[0].type is not None
        assert cfunc.arg_list[0].type.c_repr() == "int *"

    def test_retype_local_variable(self):
        local_var_node = self._find_local_variable_node()
        assert local_var_node is not None
        assert isinstance(local_var_node, CVariable)

        original_var = local_var_node.variable
        original_type = local_var_node.type
        assert original_type is not None

        new_type = angr.types.parse_type("long", arch=self.main.workspace.main_instance.project.arch)
        assert original_type is not new_type

        textedit = self.code_view._textedit
        assert textedit is not None

        with patch(
            "angrmanagement.ui.dialogs.retype_node.RetypeNode.exec_",
            self._mock_exec_with_type(new_type),
        ):
            textedit.retype_node(node=local_var_node)

        self.main.workspace.job_manager.join_all_jobs()

        variable_kb = self.code_view.codegen._variable_kb
        vm = variable_kb.variables[self.func.addr]
        updated_type = vm.get_variable_type(original_var)

        assert updated_type is not None
        assert updated_type is not original_type
        assert updated_type is new_type


if __name__ == "__main__":
    unittest.main()
