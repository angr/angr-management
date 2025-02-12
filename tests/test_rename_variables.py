# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import unittest
from typing import TYPE_CHECKING

import angr
from angr.analyses.decompiler.structured_codegen.c import CVariable
from common import AngrManagementTestCase, test_location
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest

from angrmanagement.ui.dialogs.rename_node import RenameNode
from angrmanagement.ui.views import DisassemblyView

if TYPE_CHECKING:
    from angrmanagement.ui.views import CodeView


class TestRenameVariables(AngrManagementTestCase):

    def setUp(self) -> None:
        super().setUp()

        binpath = os.path.join(test_location, "x86_64", "1after909")
        proj = angr.Project(binpath, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_obj = proj
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()

        self.func = proj.kb.functions["doit"]
        assert self.func is not None

        # decompile the function
        disasm_view = self.main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(self.func)
        disasm_view.decompile_current_function()
        self.main.workspace.job_manager.join_all_jobs()

        self.code_view: CodeView = self.main.workspace.view_manager.first_view_in_category("pseudocode")

    def tearDown(self) -> None:
        super().tearDown()
        del self.code_view

    def test_rename_a_local_variable_in_pseudocode_view(self):
        # find a node for local variable
        local_var_node = None
        assert self.code_view.codegen.map_pos_to_node is not None
        for _, item in self.code_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, CVariable) and item.obj.unified_variable is not None:
                local_var_node = item.obj
                break

        assert local_var_node is not None

        # rename it
        rename_node = RenameNode(code_view=self.code_view, node=local_var_node, func=self.func)
        rename_node._name_box.setText("")
        QTest.keyClicks(rename_node._name_box, "var_abcd")
        QTest.mouseClick(rename_node._ok_button, Qt.MouseButton.LeftButton)

        assert local_var_node.unified_variable is not None
        assert local_var_node.unified_variable.name == "var_abcd"

    def test_rename_a_global_variable_in_pseudocode_view(self):
        # find a node for global variable
        global_var_node = None
        assert self.code_view.codegen.map_pos_to_node is not None
        for _, item in self.code_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, CVariable) and item.obj.variable.name == "stdout":
                global_var_node = item.obj
                break

        assert global_var_node is not None

        # rename it
        rename_node = RenameNode(code_view=self.code_view, node=global_var_node, func=self.func)
        rename_node._name_box.setText("")
        QTest.keyClicks(rename_node._name_box, "std_notout")
        QTest.mouseClick(rename_node._ok_button, Qt.MouseButton.LeftButton)

        assert global_var_node.variable.name == "std_notout"


if __name__ == "__main__":
    unittest.main()
