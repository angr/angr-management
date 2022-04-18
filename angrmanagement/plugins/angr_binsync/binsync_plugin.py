import logging

import binsync
from binsync.common.ui import set_ui_version

from ...plugins import BasePlugin
from ...ui.workspace import Workspace
from .control_panel_view import ControlPanelView
from .controller import AngrBinSyncController

set_ui_version("PySide2")
# pylint: disable=wrong-import-position,wrong-import-order
from binsync.common.ui.config_dialog import SyncConfig


l = logging.getLogger(__name__)

class BinSyncPlugin(BasePlugin):
    """
    Controller plugin for BinSync
    """
    def __init__(self, workspace: Workspace):
        """
        The entry point for the BinSync plugin. This class is respobsible for both initializing the GUI and
        deiniting it as well. The BinSync plugin also starts the BinsyncController, which is a threaded class
        that pushes and pulls changes every so many seconds.

        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace)

        # init the Sync View on load
        self.controller = AngrBinSyncController(self.workspace)
        self.control_panel_view = ControlPanelView(workspace, 'right', self.controller)

        self.controller.control_panel = self.control_panel_view

        self.sync_menu = None
        self.selected_funcs = []

    #
    # BinSync Deinit
    #

    def teardown(self):
        # destroy the sync view on deinit
        self.workspace.remove_view(self.control_panel_view)

    #
    # BinSync GUI Hooks
    #

    MENU_BUTTONS = ('Configure Binsync...', 'Toggle Binsync Panel')
    MENU_CONFIG_ID = 0
    MENU_TOGGLE_PANEL_ID = 1

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.instance.project.am_none:
            return

        mapping = {
            self.MENU_CONFIG_ID: self.open_sync_config_dialog,
            self.MENU_TOGGLE_PANEL_ID: self.toggle_sync_panel
        }

        # call option mapped to each menu pos
        mapping.get(idx)()


    def open_sync_config_dialog(self):
        if self.workspace.instance.project.am_none:
            # project does not exist yet
            return

        sync_config = SyncConfig(self.controller)
        sync_config.exec_()

        if self.controller.check_client() and self.control_panel_view not in self.workspace.view_manager.views:
            self.workspace.add_view(self.control_panel_view)

    def toggle_sync_panel(self):
        self.controller.toggle_headless()

        if self.control_panel_view.isVisible():
            self.control_panel_view.close()
            return

        self.workspace.add_view(self.control_panel_view)

    #
    #   BinSync Decompiler Hooks
    #

    # pylint: disable=unused-argument
    def handle_stack_var_renamed(self, func, offset, old_name, new_name):
        decompilation = self.controller.decompile_function(func)
        stack_var = self.controller.find_stack_var_in_codegen(decompilation, offset)
        var_type = AngrBinSyncController.stack_var_type_str(decompilation, stack_var)

        self.controller.make_controller_cmd(
            self.controller.push_stack_variable, func.addr, offset, new_name, var_type, stack_var.size
        )
        return False

    # pylint: disable=unused-argument
    def handle_stack_var_retyped(self, func, offset, old_type, new_type):
        decompilation = self.controller.decompile_function(func)
        stack_var = self.controller.find_stack_var_in_codegen(decompilation, offset)

        self.controller.make_controller_cmd(
            self.controller.push_stack_variable, func.addr, offset, stack_var.name, new_type, stack_var.size
        )
        return False

    # pylint: disable=unused-argument
    def handle_func_arg_renamed(self, func, offset, old_name, new_name):
        decompilation = self.controller.decompile_function(func)
        func_args = AngrBinSyncController.get_func_args(decompilation)
        func_type = decompilation.cfunc.functy.returnty.c_repr()
        bs_args = {
            i: binsync.FunctionArgument(i, var_info[0].name, var_info[1], var_info[0].size)
            for i, var_info in func_args.items()
        }

        self.controller.make_controller_cmd(
            self.controller.push_function_header,
            func.addr, func.name, **{"ret_type": func_type, "args": bs_args}
        )
        return False

    # pylint: disable=unused-argument
    def handle_func_arg_retyped(self, func, offset, old_type, new_type):
        decompilation = self.controller.decompile_function(func)
        func_args = AngrBinSyncController.get_func_args(decompilation)
        func_type = decompilation.cfunc.functy.returnty.c_repr()
        bs_args = {
            i: binsync.FunctionArgument(i, var_info[0].name, var_info[1], var_info[0].size)
            for i, var_info in func_args.items()
        }

        self.controller.make_controller_cmd(
            self.controller.push_function_header,
            func.addr, func.name, **{"ret_type": func_type, "args": bs_args}
        )
        return False

    # pylint: disable=unused-argument,no-self-use
    def handle_global_var_renamed(self, address, old_name, new_name):
        return False

    # pylint: disable=unused-argument,no-self-use
    def handle_global_var_retyped(self, address, old_type, new_type):
        return False

    # pylint: disable=unused-argument
    def handle_function_renamed(self, func, old_name, new_name):
        self.controller.make_controller_cmd(
            self.controller.push_function_header,
            func.addr, new_name
        )
        return False

    # pylint: disable=unused-argument,no-self-use
    def handle_function_retyped(self, func, old_type, new_type):
        return False

    # pylint: disable=unused-argument
    def handle_comment_changed(self, address, old_cmt, new_cmt, created: bool, decomp: bool):
        func_addr = self.controller.get_func_addr_from_addr(address)
        self.controller.make_controller_cmd(
            self.controller.push_comment, address, new_cmt, decomp, **{"func_addr": func_addr}
        )
        return False
