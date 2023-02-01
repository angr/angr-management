# pylint:disable=missing-class-docstring,wrong-import-order
import os
import sys
import threading
import unittest

import angr
from angr.analyses.decompiler.structured_codegen.c import CFunction, CFunctionCall
from common import start_main_window_and_event_loop, test_location
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest

from angrmanagement.logic.threads import gui_thread_schedule
from angrmanagement.ui.dialogs.rename_label import RenameLabel
from angrmanagement.ui.dialogs.rename_node import RenameNode


class TestRenameFunctions(unittest.TestCase):
    def setUp(self):
        self.event = threading.Event()
        _, self.main = start_main_window_and_event_loop(self.event)

    def tearDown(self) -> None:
        self.event.set()
        del self.main

    def _test_rename_a_function_in_disasm_and_pseudocode_views(self):
        main = self.main

        func = main.workspace.main_instance.project.kb.functions["main"]
        disasm_view = main.workspace._get_or_create_disassembly_view()
        pseudocode_view = main.workspace._get_or_create_pseudocode_view()

        # find the node for function
        for _, item in pseudocode_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, CFunction):
                func_node = item.obj
                break
        else:
            self.fail("The CFunction instance is not found.")

        self.assertEqual(func_node.name, "main")

        # rename the function in the disassembly view
        rlabel = RenameLabel(disasm_view, func.addr, parent=None)
        rlabel._name_box.setText("")
        QTest.keyClicks(rlabel._name_box, "asdf")
        QTest.mouseClick(rlabel._ok_button, Qt.MouseButton.LeftButton)

        self.assertEqual(func.name, "asdf")
        self.assertEqual(func_node.name, "main")

        # rename the function in the pseudocode view
        rnode = RenameNode(code_view=pseudocode_view, node=func_node)
        rnode._name_box.setText("")
        QTest.keyClicks(rnode._name_box, "fdsa")
        QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

        self.assertEqual(func.name, "fdsa")

    def test_rename_a_function_in_disasm_and_pseudocode_views(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.main_instance.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        self.assertIsNotNone(func)

        # decompile the function
        disasm_view = main.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        gui_thread_schedule(disasm_view.display_function, args=(func,))
        disasm_view.decompile_current_function()
        main.workspace.main_instance.join_all_jobs()

        # run the jobless method in the GUI thread
        gui_thread_schedule(self._test_rename_a_function_in_disasm_and_pseudocode_views)

    def _test_rename_a_callee_in_pseudocode_view(self):
        main = self.main

        func = main.workspace.main_instance.project.kb.functions["authenticate"]
        _ = main.workspace._get_or_create_disassembly_view()
        pseudocode_view = main.workspace._get_or_create_pseudocode_view()

        # find the node for function
        for _, item in pseudocode_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, CFunctionCall) and item.obj.callee_func.name == "authenticate":
                func_node = item.obj
                break
        else:
            self.fail("The CFunction instance is not found.")

        # rename the function in the pseudocode view
        rnode = RenameNode(code_view=pseudocode_view, node=func_node)
        rnode._name_box.setText("")
        QTest.keyClicks(rnode._name_box, "authenticate_1337")
        QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

        self.assertEqual(func.name, "authenticate_1337")

    def test_rename_a_callee_in_pseudocode_view(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.main_instance.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        self.assertIsNotNone(func)

        # decompile the function
        disasm_view = main.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        gui_thread_schedule(disasm_view.display_function, args=(func,))
        disasm_view.decompile_current_function()
        main.workspace.main_instance.join_all_jobs()

        # run the jobless method in the GUI thread
        gui_thread_schedule(self._test_rename_a_callee_in_pseudocode_view)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
