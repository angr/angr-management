import hashlib
import os
import random
import sys
import string
import unittest

from PySide2.QtTest import QTest
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QGraphicsScene, QGraphicsView

import angr
from angrmanagement.ui.main_window import MainWindow
from angrmanagement.ui.dialogs.rename_label import RenameLabel
from angrmanagement.ui.dialogs.rename_node import RenameNode

from common import setUp, test_location

from slacrs import Slacrs
from slacrs.model import HumanActivityVariableRename, HumanActivityFunctionRename, HumanActivityClickBlock, HumanActivityClickInsn


class TestHumanActivities(unittest.TestCase):
    def setUp(self):
        setUp()
        # set up a random database through environment variable SLACRS_DATABASE
        self.db_name = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        os.environ['SLACRS_DATABASE'] = f"sqlite:////tmp/{self.db_name}.sqlite"
        self.session = Slacrs().session()

    def tearDown(self):
        self.session.close()
        os.remove(f"/tmp/{self.db_name}.sqlite")

    def _open_a_project(self):
        main = MainWindow(show=False)
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.instance.project.am_event()
        main.workspace.instance.join_all_jobs()
        self.project = binpath
        with open(binpath, 'rb') as f:
            self.project_md5 = hashlib.md5(f.read()).hexdigest()
        return main

    def test_open_a_project(self):
        self._open_a_project()

    def test_rename_a_function_in_disasm_and_pseudocode_views(self):
        main = self._open_a_project()

        func = main.workspace.instance.project.kb.functions['main']
        self.assertIsNotNone(func)

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

        function_rename = self.session.query(HumanActivityFunctionRename).filter(
            HumanActivityFunctionRename.project_md5 == self.project_md5,
            HumanActivityFunctionRename.old_name == "main",
            HumanActivityFunctionRename.new_name == "fdsa",
        ).one()
        self.assertIsNotNone(function_rename)

    def test_rename_a_variable_in_pseudocode_view(self):
        main = self._open_a_project()

        func = main.workspace.instance.project.kb.functions['main']
        self.assertIsNotNone(func)

        # decompile the function
        disasm_view = main.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()
        main.workspace.instance.join_all_jobs()
        pseudocode_view = main.workspace._get_or_create_pseudocode_view()

        # find an arbitrary node for a variable
        for _, item in pseudocode_view.codegen.map_pos_to_node.items():
            if isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CVariable) \
                    and item.obj.unified_variable is not None:
                variable_node = item.obj
                break
        else:
            self.fail("Cannot find a testing variable.")

        # rename the variable in the pseudocode view
        rnode = RenameNode(code_view=pseudocode_view, node=variable_node)
        rnode._name_box.setText("")
        QTest.keyClicks(rnode._name_box, "fdsa")
        QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

        self.assertEqual(variable_node.unified_variable.name, "fdsa")

        variable_rename = self.session.query(HumanActivityVariableRename).filter(
            HumanActivityVariableRename.project_md5 == self.project_md5,
            HumanActivityVariableRename.new_name == "fdsa",
        ).one()
        self.assertIsNotNone(variable_rename)

    def test_click_block(self):
        main_window = self._open_a_project()
        func = main_window.workspace.instance.project.kb.functions['main']
        self.assertIsNotNone(func)

        # display function main
        disasm_view = main_window.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        disasm_view.display_function(func)

        # get and click the first bbl of function main
        block = disasm_view.current_graph._insaddr_to_block.get(func.addr)
        scene = QGraphicsScene()
        scene.addItem(block)
        view = QGraphicsView(scene)
        QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton)

        # assert that slacrs logged the information
        result = self.session.query(HumanActivityClickBlock).filter(
            HumanActivityClickBlock.project_md5 == self.project_md5,
            HumanActivityClickBlock.addr == func.addr,
        ).one()
        self.assertIsNotNone(result)

    def test_click_insn(self):
        main_window = self._open_a_project()
        func = main_window.workspace.instance.project.kb.functions['main']
        self.assertIsNotNone(func)

        # display function main
        disasm_view = main_window.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        disasm_view.display_function(func)

        # get and click the first bbl of function main
        block = disasm_view.current_graph._insaddr_to_block.get(func.addr)
        insn = block.addr_to_insns[func.addr]
        scene = QGraphicsScene()
        scene.addItem(insn)
        view = QGraphicsView(scene)
        QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton)

        # assert that slacrs logged the information
        result = self.session.query(HumanActivityClickInsn).filter(
            HumanActivityClickInsn.project_md5 == self.project_md5,
            HumanActivityClickInsn.addr == insn.addr,
        ).one()
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
