from typing import TYPE_CHECKING
import os
import threading
import time

from PySide2.QtWidgets import QPushButton
from PySide2.QtGui import QPixmap, Qt, QIcon

from angrmanagement.logic.threads import gui_thread_schedule_async
from angrmanagement.config import Conf, save_config
from angrmanagement.config.config_entry import ConfigurationEntry
from angrmanagement.plugins import BasePlugin

from .backend_selector_dialog import QBackendSelectorDialog

try:
    import slacrs
except ImportError:
    slacrs = None

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class ChessConnector(BasePlugin):
    """
    Implements the CHESS connector plugin.
    """

    DISPLAY_NAME = "CHESS Connector"
    REQUIRE_WORKSPACE = False

    def __init__(self, workspace):
        super().__init__(workspace)

        image_file_root = os.path.dirname(__file__)

        status_bar_height = int(workspace.main_window.statusBar().height() * 0.75)
        self._connected_pixmap = QPixmap(os.path.join(image_file_root, "connected.png")).scaled(
            status_bar_height,
            status_bar_height,
            Qt.AspectRatioMode.IgnoreAspectRatio,
            Qt.SmoothTransformation
        )
        self._connecting_pixmap = QPixmap(os.path.join(image_file_root, "connecting.png")).scaled(
            status_bar_height,
            status_bar_height,
            Qt.AspectRatioMode.IgnoreAspectRatio,
            Qt.SmoothTransformation
        )
        self._disconnected_pixmap = QPixmap(os.path.join(image_file_root, "disconnected.png")).scaled(
            status_bar_height,
            status_bar_height,
            Qt.AspectRatioMode.IgnoreAspectRatio,
            Qt.SmoothTransformation
        )

        self._status_button = QPushButton()
        self._status_button.setFlat(True)
        self._status_button.clicked.connect(self._on_status_button_clicked)

        self.connected: bool = False
        self.backend_disconnected()

        self.active = True

        th = threading.Thread(
            target=self.checrs_connection_monitor,
            args=(),
        )
        th.setDaemon(True)
        th.start()

    def teardown(self):
        self.active = False

    def backend_disconnected(self):
        self.connected = False
        self._status_button.setIcon(QIcon(self._disconnected_pixmap))
        self._status_button.setToolTip("Disconnected from CHECRS backend. Retry every 5 seconds...")
        self.workspace.main_window.app.processEvents()

    def backend_connected(self):
        self.connected = True
        self._status_button.setIcon(QIcon(self._connected_pixmap))
        self._status_button.setToolTip("Connected to CHECRS backend")
        self.workspace.main_window.app.processEvents()

    def backend_connecting(self):
        if not self.connected:
            # only change the icon to connecting if we are previously not connected
            self._status_button.setIcon(QIcon(self._connecting_pixmap))
            self._status_button.setToolTip("Connecting to CHECRS backend")
            self.workspace.main_window.app.processEvents()

    def status_bar_permanent_widgets(self):
        yield self._status_button

    def on_workspace_initialized(self, workspace: 'Workspace'):
        pass

    def _on_status_button_clicked(self):
        self.set_checrs_backend_str()

    def checrs_connection_monitor(self):
        first_run = True
        while self.active:
            if first_run:
                first_run = False
            else:
                time.sleep(5)

            if slacrs is None or not hasattr(Conf, "checrs_backend_str") or not Conf.checrs_backend_str:
                gui_thread_schedule_async(self.backend_disconnected)
                continue

            try:
                gui_thread_schedule_async(self.backend_connecting)
                engine = slacrs.Slacrs.connect_to_db(Conf.checrs_backend_str)
                connection = engine.connect()
                connection.close()  # close it immediately
            except Exception:  # pylint:disable=broad-except
                gui_thread_schedule_async(self.backend_disconnected)
                continue

            gui_thread_schedule_async(self.backend_connected)

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
        self.set_checrs_backend_str()

    def set_checrs_backend_str(self):
        dialog = QBackendSelectorDialog(self.workspace,
                                        backend_str=Conf.checrs_backend_str,
                                        parent=self.workspace.main_window)
        dialog.exec_()

        server_url = dialog.backend_str

        if server_url is not None:
            # if it's empty, it means the user wants to disconnect from CHECRS
            Conf.checrs_backend_str = server_url
            save_config()

    CONFIG_ENTRIES = [
        ConfigurationEntry("checrs_backend_str", str, "", default_value=""),
    ]
