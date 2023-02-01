# pylint:disable=missing-class-docstring,wrong-import-order
import os
import threading
import unittest
from typing import TYPE_CHECKING

import angr
from angr.analyses.decompiler.structured_codegen.c import CVariable
from common import start_main_window_and_event_loop, test_location
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest

from angrmanagement.logic.threads import gui_thread_schedule
from angrmanagement.ui.dialogs.rename_node import RenameNode

if TYPE_CHECKING:
    from angrmanagement.ui.views import CodeView


class TestRenameVariables(unittest.TestCase):
    def setUp(self) -> None:
        self.event = threading.Event()
        _, self.main = start_main_window_and_event_loop(self.event)

        binpath = os.path.join(test_location, "x86_64", "1after909")
        proj = angr.Project(binpath, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_obj = proj
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.main_instance.join_all_jobs()

        self.func = proj.kb.functions["doit"]
        self.assertIsNotNone(self.func)

        # decompile the function
        disasm_view = self.main.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        gui_thread_schedule(disasm_view.display_function, args=(self.func,))
        disasm_view.decompile_current_function()
        self.main.workspace.main_instance.join_all_jobs()
        self.code_view: "CodeView" = self.main.workspace.view_manager.first_view_in_category("pseudocode")

    def tearDown(self) -> None:
        self.main = None
        self.code_view = None
        self.event.set()

    def _test_rename_a_local_variable_in_pseudocode_view(self):
        # find a node for local variable
        local_var_node = None
        for _, item in self.code_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, CVariable) and item.obj.unified_variable is not None:
                local_var_node = item.obj
                break

        self.assertIsNotNone(local_var_node)

        # rename it
        rename_node = RenameNode(code_view=self.code_view, node=local_var_node, func=self.func)
        rename_node._name_box.setText("")
        QTest.keyClicks(rename_node._name_box, "var_abcd")
        QTest.mouseClick(rename_node._ok_button, Qt.MouseButton.LeftButton)

        self.assertEqual(local_var_node.unified_variable.name, "var_abcd")

    def test_rename_a_local_variable_in_pseudocode_view(self):
        gui_thread_schedule(self._test_rename_a_local_variable_in_pseudocode_view)

    def _test_rename_a_global_variable_in_pseudocode_view(self):
        # find a node for global variable
        global_var_node = None
        for _, item in self.code_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, CVariable) and item.obj.variable.name == "stdout":
                global_var_node = item.obj
                break

        self.assertIsNotNone(global_var_node)

        # rename it
        rename_node = RenameNode(code_view=self.code_view, node=global_var_node, func=self.func)
        rename_node._name_box.setText("")
        QTest.keyClicks(rename_node._name_box, "std_notout")
        QTest.mouseClick(rename_node._ok_button, Qt.MouseButton.LeftButton)

        self.assertEqual(global_var_node.variable.name, "std_notout")

    def test_rename_a_global_variable_in_pseudocode_view(self):
        gui_thread_schedule(self._test_rename_a_global_variable_in_pseudocode_view)


if __name__ == "__main__":
    unittest.main()
