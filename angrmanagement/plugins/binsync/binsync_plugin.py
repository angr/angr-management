from angrmanagement.plugins import BasePlugin

from ...ui.workspace import Workspace
from .sync_config import SyncConfig
from .info_view import InfoView
from .sync_menu import SyncMenu

from .sync_ctrl import Controller

# check to see if BinSync is installed
try:
    import binsync
except ImportError:
    binsync = None


class BinsyncPlugin(BasePlugin):
    def __init__(self, workspace: Workspace):
        super().__init__(workspace)

        # init the Sync View on load
        self.sync_view = InfoView(workspace, 'right')
        self.workspace.add_view(self.sync_view, self.sync_view.caption, self.sync_view.category)

        self.controller = Controller(self.workspace)
        self.sync_menu = None
        self.selected_funcs = []

    #
    # BinSync Deinit
    #

    def teardown(self):
        # destroy the sync view on deinit
        self.workspace.remove_view(self.sync_view)

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

        sync_config = SyncConfig(self.workspace.instance)
        sync_config.exec_()

    def build_context_menu_functions(self, funcs): # pylint: disable=unused-argument
        # if not connected to a repo, give no options
        if self.workspace.instance.kb.sync.connected:
            self.sync_menu = SyncMenu(self.controller, funcs)
            yield ("Binsync Action", self.sync_menu.open_sync_menu)

    #
    #   BinSync Decompiler Hooks
    #

    def handle_variable_rename(self, func, offset: int, old_name: str, new_name: str):
        # if offset:
        #     print(f"{hex(func.addr)}: renamed variable[{hex(offset)}]: {old_name}->{new_name}")
        return False

    def handle_function_rename(self, func, old_name: str, new_name: str):
        # print(f"{hex(func.addr)}: renamed function: {old_name}->{new_name}")
        return False

    def handle_comment_changed(self, addr: int, cmt: str, new: bool, decomp: bool):
        # print(f"{hex(addr)}: comment changed to {cmt} in {'decomp' if decomp else 'disass'}")
        return False


# Don't allow BinSync to init if it's not installed
if binsync is None:
    del BinsyncPlugin
