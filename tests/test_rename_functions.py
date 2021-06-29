import os
import sys
import unittest

from PySide2.QtTest import QTest
from PySide2.QtCore import Qt

from angrmanagement.ui.main_window import MainWindow
from angrmanagement.ui.dialogs.rename_label import RenameLabel
from angrmanagement.ui.dialogs.rename_node import RenameNode
import angr

from common import setUp, test_location


class TestRenameFunctions(unittest.TestCase):
    def setUp(self):
        setUp()

    def test_rename_a_function_in_disasm_and_pseudocode_views(self):
        main = MainWindow(show=False)
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.instance.project.am_event()
        main.workspace.instance.join_all_jobs()

        func = main.workspace.instance.project.kb.functions['main']
        assert func is not None

        # decompile the function
        disasm_view = main.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()
        main.workspace.instance.join_all_jobs()
        pseudocode_view = main.workspace._get_or_create_pseudocode_view()

        # find the node for function
        for _, item in pseudocode_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CFunction):
                break
        else:
            assert False, "The CFunction instance is not found."
        assert item.obj.name == "main"

        # rename the function in the disassembly view
        rlabel = RenameLabel(disasm_view, func.addr, parent=None)
        rlabel._name_box.setText("")
        QTest.keyClicks(rlabel._name_box, "asdf")
        QTest.mouseClick(rlabel._ok_button, Qt.MouseButton.LeftButton)

        assert func.name == "asdf"
        assert item.obj.name == "main"

        # rename the function in the pseudocode view
        rnode = RenameNode(code_view=pseudocode_view, node=item.obj)
        rnode._name_box.setText("")
        QTest.keyClicks(rnode._name_box, "fdsa")
        QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

        assert func.name == "fdsa"


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
