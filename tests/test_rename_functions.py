# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import sys
import unittest

import angr
from angr.analyses.decompiler.structured_codegen.c import CFunction, CFunctionCall
from common import AngrManagementTestCase, test_location
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest

from angrmanagement.ui.dialogs.rename_label import RenameLabel
from angrmanagement.ui.dialogs.rename_node import RenameNode
from angrmanagement.ui.views import CodeView, DisassemblyView


class TestRenameFunctions(AngrManagementTestCase):

    def test_rename_a_function_in_disasm_and_pseudocode_views(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        # decompile the function
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()
        main.workspace.job_manager.join_all_jobs()

        pseudocode_view = main.workspace._get_or_create_view("pseudocode", CodeView)

        # find the node for function
        func_node = None
        assert pseudocode_view.codegen.map_pos_to_node is not None
        for _, item in pseudocode_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, CFunction):
                func_node = item.obj
                break

        assert func_node is not None, "The CFunction instance is not found."
        assert func_node.name == "main"

        # rename the function in the disassembly view
        rlabel = RenameLabel(disasm_view, func.addr, parent=None)
        rlabel._name_box.setText("")
        QTest.keyClicks(rlabel._name_box, "asdf")
        QTest.mouseClick(rlabel._ok_button, Qt.MouseButton.LeftButton)

        assert func.name == "asdf"
        assert func_node.name == "main"

        # rename the function in the pseudocode view
        rnode = RenameNode(code_view=pseudocode_view, node=func_node)
        rnode._name_box.setText("")
        QTest.keyClicks(rnode._name_box, "fdsa")
        QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

        assert func.name == "fdsa"

    def test_rename_a_callee_in_pseudocode_view(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()

        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        # decompile the function
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()

        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["authenticate"]
        _ = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        pseudocode_view = main.workspace._get_or_create_view("pseudocode", CodeView)

        # find the node for function
        func_node = None
        assert pseudocode_view.codegen.map_pos_to_node is not None
        for _, item in pseudocode_view.codegen.map_pos_to_node.items():
            if (
                isinstance(item.obj, CFunctionCall)
                and item.obj.callee_func
                and item.obj.callee_func.name == "authenticate"
            ):
                func_node = item.obj
                break

        assert func_node is not None, "The CFunction instance is not found."

        # rename the function in the pseudocode view
        rnode = RenameNode(code_view=pseudocode_view, node=func_node)
        rnode._name_box.setText("")
        QTest.keyClicks(rnode._name_box, "authenticate_1337")
        QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

        assert func.name == "authenticate_1337"


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
