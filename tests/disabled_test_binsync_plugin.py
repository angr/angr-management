import os
import sys
import tempfile
import time
import unittest

from PySide6.QtTest import QTest
from PySide6.QtCore import Qt

import angr
import common
from angrmanagement.ui.dialogs.rename_node import RenameNode
from angrmanagement.ui.main_window import MainWindow
from angrmanagement.plugins.binsync.binsync_plugin import BinsyncPlugin
from angrmanagement.plugins.binsync.ui.config_dialog import SyncConfig
from angrmanagement.plugins.binsync.ui.sync_menu import SyncMenu


class TestBinsyncPlugin(unittest.TestCase):
    """
    Unit Tests to test the BinSync Plugin for syncing across two users.
    """

    def setUp(self):
        common.setUp()

    def test_function_rename(self):
        binpath = os.path.join(common.test_location, "x86_64", "fauxware")
        new_function_name = "leet_main"
        user_1 = "user_1"
        user_2 = "user_2"

        with tempfile.TemporaryDirectory() as sync_dir_path:
            # ====== USER 1 ======
            # setup GUI
            main = MainWindow(show=False)
            main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
            main.workspace.main_instance.project.am_event()
            main.workspace.main_instance.join_all_jobs()
            func = main.workspace.main_instance.project.kb.functions["main"]
            self.assertIsNotNone(func)

            # find the binsync plugin
            # noinspection PyTypeChecker
            binsync_plugin = next(
                iter([p for p in main.workspace.plugins.active_plugins if "Binsync" in str(p)])
            )  # type: BinsyncPlugin

            # configure, and connect
            config = SyncConfig(main.workspace.main_instance, binsync_plugin.controller)
            config._user_edit.setText("")
            config._repo_edit.setText("")
            QTest.keyClicks(config._user_edit, user_1)
            QTest.keyClicks(config._repo_edit, sync_dir_path)
            # always init for first user
            QTest.mouseClick(config._initrepo_checkbox, Qt.MouseButton.LeftButton)
            QTest.mouseClick(config._ok_button, Qt.MouseButton.LeftButton)

            self.assertTrue(binsync_plugin.controller.sync.connected)
            self.assertEqual(binsync_plugin.controller.sync.client.master_user, user_1)

            # trigger a function rename in decompilation
            disasm_view = main.workspace._get_or_create_disassembly_view()
            disasm_view._t_flow_graph_visible = True
            disasm_view.display_function(func)
            disasm_view.decompile_current_function()
            main.workspace.main_instance.join_all_jobs()
            pseudocode_view = main.workspace._get_or_create_pseudocode_view()
            for _, item in pseudocode_view.codegen.map_pos_to_node.items():
                if isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CFunction):
                    func_node = item.obj
                    break
            else:
                self.fail("The CFunction instance is not found.")
            rnode = RenameNode(code_view=pseudocode_view, node=func_node)
            rnode._name_box.setText("")
            QTest.keyClicks(rnode._name_box, new_function_name)
            QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

            self.assertEqual(func.name, new_function_name)

            # assure a new commit makes it to the repo
            time.sleep(10)
            # reset the repo
            os.remove(sync_dir_path + "/.git/binsync.lock")

            # ====== USER 2 ======
            # setup GUI
            main = MainWindow(show=False)
            main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
            main.workspace.main_instance.project.am_event()
            main.workspace.main_instance.join_all_jobs()
            func = main.workspace.main_instance.project.kb.functions["main"]
            self.assertIsNotNone(func)

            # find the binsync plugin
            # noinspection PyTypeChecker
            binsync_plugin = next(
                iter([p for p in main.workspace.plugins.active_plugins if "Binsync" in str(p)])
            )  # type: BinsyncPlugin

            # configure, and connect
            config = SyncConfig(main.workspace.main_instance, binsync_plugin.controller)
            config._user_edit.setText("")
            config._repo_edit.setText("")
            QTest.keyClicks(config._user_edit, user_2)
            QTest.keyClicks(config._repo_edit, sync_dir_path)
            QTest.mouseClick(config._ok_button, Qt.MouseButton.LeftButton)

            self.assertTrue(binsync_plugin.controller.sync.connected)
            self.assertEqual(binsync_plugin.controller.sync.client.master_user, user_2)
            self.assertIn(user_1, [u.name for u in binsync_plugin.controller.sync.users()])

            # pull down the changes
            # TODO: this could be more GUI based
            sync_menu = SyncMenu(binsync_plugin.controller, [func])
            sync_menu._do_action("Sync", user_1, func)

            # get the current decompilation of the function
            func_code = binsync_plugin.controller.decompile_function(func)

            self.assertEqual(func_code.cfunc.name, new_function_name)
            self.assertEqual(func.name, new_function_name)

            common.app.exit(0)

    def test_stack_variable_rename(self):
        binpath = os.path.join(common.test_location, "x86_64", "fauxware")
        var_offset = -0x18
        new_var_name = "leet_buff"
        user_1 = "user_1"
        user_2 = "user_2"

        with tempfile.TemporaryDirectory() as sync_dir_path:
            # ====== USER 1 ======
            # setup GUI
            main = MainWindow(show=False)
            main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
            main.workspace.main_instance.project.am_event()
            main.workspace.main_instance.join_all_jobs()
            func = main.workspace.main_instance.project.kb.functions["main"]
            self.assertIsNotNone(func)

            # find the binsync plugin
            # noinspection PyTypeChecker
            binsync_plugin = next(
                iter([p for p in main.workspace.plugins.active_plugins if "Binsync" in str(p)])
            )  # type: BinsyncPlugin

            # configure, and connect
            config = SyncConfig(main.workspace.main_instance, binsync_plugin.controller)
            config._user_edit.setText("")
            config._repo_edit.setText("")
            QTest.keyClicks(config._user_edit, user_1)
            QTest.keyClicks(config._repo_edit, sync_dir_path)
            # always init for first user
            QTest.mouseClick(config._initrepo_checkbox, Qt.MouseButton.LeftButton)
            QTest.mouseClick(config._ok_button, Qt.MouseButton.LeftButton)

            self.assertTrue(binsync_plugin.controller.sync.connected)
            self.assertEqual(binsync_plugin.controller.sync.client.master_user, user_1)

            # trigger a variable rename in decompilation
            disasm_view = main.workspace._get_or_create_disassembly_view()
            disasm_view._t_flow_graph_visible = True
            disasm_view.display_function(func)
            disasm_view.decompile_current_function()
            main.workspace.main_instance.join_all_jobs()
            pseudocode_view = main.workspace._get_or_create_pseudocode_view()
            for _, item in pseudocode_view.codegen.map_pos_to_node.items():
                if (
                    isinstance(item.obj, angr.analyses.decompiler.structured_codegen.c.CVariable)
                    and isinstance(item.obj.variable, angr.sim_variable.SimStackVariable)
                    and item.obj.variable.offset == var_offset
                ):
                    var_node = item.obj
                    break
            else:
                self.fail("The CVariable instance is not found.")
            rnode = RenameNode(code_view=pseudocode_view, node=var_node)
            rnode._name_box.setText("")
            QTest.keyClicks(rnode._name_box, new_var_name)
            QTest.mouseClick(rnode._ok_button, Qt.MouseButton.LeftButton)

            # find the variable in the var manager
            var_man = main.workspace.main_instance.pseudocode_variable_kb.variables.get_function_manager(func.addr)
            for var in var_man._unified_variables:
                if isinstance(var, angr.sim_variable.SimStackVariable) and var.offset == var_offset:
                    renamed_var = var
                    break
            else:
                self.fail("Renamed variable is not found")

            self.assertTrue(renamed_var.renamed)
            self.assertEqual(renamed_var.name, new_var_name)

            time.sleep(10)
            # reset the repo
            os.remove(sync_dir_path + "/.git/binsync.lock")

            # ====== USER 2 ======
            # setup GUI
            main = MainWindow(show=False)
            main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
            main.workspace.main_instance.project.am_event()
            main.workspace.main_instance.join_all_jobs()
            func = main.workspace.main_instance.project.kb.functions["main"]
            self.assertIsNotNone(func)

            # find the binsync plugin
            # noinspection PyTypeChecker
            binsync_plugin = next(
                iter([p for p in main.workspace.plugins.active_plugins if "Binsync" in str(p)])
            )  # type: BinsyncPlugin

            # configure, and connect
            config = SyncConfig(main.workspace.main_instance, binsync_plugin.controller)
            config._user_edit.setText("")
            config._repo_edit.setText("")
            QTest.keyClicks(config._user_edit, user_2)
            QTest.keyClicks(config._repo_edit, sync_dir_path)
            QTest.mouseClick(config._ok_button, Qt.MouseButton.LeftButton)

            self.assertTrue(binsync_plugin.controller.sync.connected)
            self.assertEqual(binsync_plugin.controller.sync.client.master_user, user_2)
            self.assertIn(user_1, [u.name for u in binsync_plugin.controller.sync.users()])

            # pull down the changes
            # TODO: this could be more GUI based
            sync_menu = SyncMenu(binsync_plugin.controller, [func])
            sync_menu._do_action("Sync", user_1, func)

            time.sleep(2)

            # decompile the function
            binsync_plugin.controller.decompile_function(func)

            for var in var_man._unified_variables:
                if isinstance(var, angr.sim_variable.SimStackVariable) and var.offset == var_offset:
                    renamed_var = var
                    break
            else:
                self.fail("Renamed variable is not found")

            self.assertTrue(renamed_var.renamed)
            self.assertEqual(renamed_var.name, new_var_name)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
