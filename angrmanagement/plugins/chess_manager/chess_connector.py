from PySide2.QtWidgets import QInputDialog, QLineEdit, QDialog

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace

from .backend_selector_dialog import QBackendSelectorDialog


class ChessConnector(BasePlugin):
    DISPLAY_NAME = "CHESS Connector"
    REQUIRE_WORKSPACE = False

    def __init__(self, workspace):
        super().__init__(workspace)

        self.slacrs_backend_str: str = None

    def on_workspace_initialized(self, workspace: 'Workspace'):
        pass

    #
    # Custom menu actions
    #

    MENU_BUTTONS = [
        'Connect to CHECRS backend...',
    ]
    CONNECT_TO_BACKEND = 0

    def handle_click_menu(self, idx):
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        dialog = QBackendSelectorDialog(self.workspace,
                                        backend_str=self.slacrs_backend_str,
                                        parent=self.workspace.main_window)
        dialog.exec_()

        server_url = dialog.backend_str

        if server_url:
            self.slacrs_backend_str = server_url
