import hashlib
import os
import random
import sys
import string
import unittest
from time import sleep

from PySide6.QtTest import QTest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGraphicsScene, QGraphicsView

import angr
from angrmanagement.ui.main_window import MainWindow
from angrmanagement.ui.dialogs.rename_label import RenameLabel
from angrmanagement.ui.dialogs.rename_node import RenameNode

from common import setUp, test_location

from slacrs import Slacrs
from slacrs.model import HumanActivity, HumanActivityEnum

from angrmanagement.config import Conf
from angrmanagement.config.config_entry import ConfigurationEntry


Conf._entries["checrs_backend_str"] = ConfigurationEntry("checrs_backend_str", str, "", default_value="")
Conf.checrs_backend_str = "sqlite:////tmp/testtest.sqlite"


class TestHumanActivities(unittest.TestCase):
    def setUp(self):
        setUp()

    def tearDown(self):
        pass
        os.remove("/tmp/testtest.sqlite")

    def _open_a_project(self):
        main = MainWindow(show=False)
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.main_instance.join_all_jobs()
        self.project = binpath
        # import ipdb; ipdb.set_trace()
        self.project_md5 = main.workspace.main_instance.project.loader.main_object.md5.hex()
        return main

    def test_open_a_project(self):
        self._open_a_project()

    def test_rename_a_function_in_disasm_and_pseudocode_views(self):
        main = self._open_a_project()

        func = main.workspace.main_instance.project.kb.functions["main"]
        self.assertIsNotNone(func)

        # decompile the function
        disasm_view = main.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()
        main.workspace.main_instance.join_all_jobs()
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

        sleep(5)
        self.session = Slacrs(database=Conf.checrs_backend_str).session()
        function_rename = (
            self.session.query(HumanActivity)
            .filter(
                HumanActivity.project_md5 == self.project_md5,
                HumanActivity.category == HumanActivityEnum.FunctionRename,
                HumanActivity.old_name == "main",
                HumanActivity.new_name == "fdsa",
            )
            .one()
        )
        self.session.close()
        self.assertIsNotNone(function_rename)

    def test_rename_a_variable_in_pseudocode_view(self):
        main = self._open_a_project()

        func = main.workspace.main_instance.project.kb.functions["main"]
        self.assertIsNotNone(func)

        # decompile the function
        disasm_view = main.workspace._get_or_create_disassembly_view()
        disasm_view._t_flow_graph_visible = True
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()
        main.workspace.main_instance.join_all_jobs()
        pseudocode_view = main.workspace._get_or_create_pseudocode_view()

        # find an arbitrary node for a variable
        for _, item in pseudocode_view.codegen.map_pos_to_node.items():
            if (
                isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CVariable)
                and item.obj.unified_variable is not None
            ):
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

        sleep(5)
        self.session = Slacrs(database=Conf.checrs_backend_str).session()
        variable_rename = (
            self.session.query(HumanActivity)
            .filter(
                HumanActivity.project_md5 == self.project_md5,
                HumanActivity.new_name == "fdsa",
            )
            .one()
        )
        self.session.close()
        self.assertIsNotNone(variable_rename)

    def test_click_block(self):
        main_window = self._open_a_project()
        func = main_window.workspace.main_instance.project.kb.functions["main"]
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
        sleep(5)
        self.session = Slacrs(database=Conf.checrs_backend_str).session()
        result = (
            self.session.query(HumanActivity)
            .filter(
                HumanActivity.project_md5 == self.project_md5,
                HumanActivity.addr == func.addr,
            )
            .one()
        )
        self.session.close()
        self.assertIsNotNone(result)

    def test_click_insn(self):
        main_window = self._open_a_project()
        func = main_window.workspace.main_instance.project.kb.functions["main"]
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
        sleep(5)
        self.session = Slacrs(database=Conf.checrs_backend_str).session()
        result = (
            self.session.query(HumanActivity)
            .filter(
                HumanActivity.project_md5 == self.project_md5,
                HumanActivity.addr == insn.addr,
            )
            .one()
        )
        self.session.close()
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
