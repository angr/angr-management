from angrmanagement.plugins import BasePlugin

from ...ui.workspace import Workspace
from .ui.config_dialog import SyncConfig
from .ui.info_panel import InfoView
from .ui.sync_menu import SyncMenu
from .controller import BinsyncController

# check to see if BinSync is installed
try:
    import binsync
except ImportError:
    binsync = None


class BinsyncPlugin(BasePlugin):
    def __init__(self, workspace: Workspace):
        """
        The entry point for the BinSync plugin. This class is respobsible for both initializing the GUI and
        deiniting it as well. The BinSync plugin also starts the BinsyncController, which is a threaded class
        that pushes and pulls changes every so many seconds.

        @param workspace:   an AM workspace (usually found in instance)
        """
        super().__init__(workspace)

        # init the Sync View on load
        self.controller = BinsyncController(self.workspace)
        self.info_view = InfoView(workspace, 'right', self.controller)
        self.workspace.add_view(self.info_view, self.info_view.caption, self.info_view.category)
        self.controller.info_panel = self.info_view

        self.sync_menu = None
        self.selected_funcs = []

    #
    # BinSync Deinit
    #

    def teardown(self):
        # destroy the sync view on deinit
        self.workspace.remove_view(self.info_view)

    #
    # BinSync GUI Hooks
    #

    MENU_BUTTONS = ('Configure Binsync...',)
    MENU_CONFIG_ID = 0

    def handle_click_menu(self, idx):
        # sanity check on menu selection
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.instance.project.am_none:
            return

        mapping = {
            self.MENU_CONFIG_ID: self.open_sync_config_dialog
        }

        # call option mapped to each menu pos
        mapping.get(idx)()

    def open_sync_config_dialog(self):
        if self.workspace.instance.project.am_none:
            # project does not exist yet
            return

        sync_config = SyncConfig(self.workspace.instance, self.controller)
        sync_config.exec_()

    def build_context_menu_functions(self, funcs): # pylint: disable=unused-argument
        # if not connected to a repo, give no options
        if self.workspace.instance.kb.sync.connected:
            self.sync_menu = SyncMenu(self.controller, funcs)
            yield ("Binsync Action", self.sync_menu.open_sync_menu)

    #
    #   BinSync Decompiler Hooks
    #

    def handle_variable_rename(self, func, offset: int, old_name: str, new_name: str, type_: str, size: int):
        self.controller.make_controller_cmd(self.controller.push_stack_variable,
                                            func.addr, offset, new_name, type_, size)
        return False

    def handle_function_rename(self, func, old_name: str, new_name: str):
        self.controller.make_controller_cmd(self.controller.push_func,
                                            func)
        return False

    def handle_comment_changed(self, addr: int, cmt: str, new: bool, decomp: bool):
        self.controller.make_controller_cmd(self.controller.push_comment, addr, cmt, decomp)
        return False


# Don't allow BinSync to init if it's not installed
if binsync is None:
    del BinsyncPlugin
