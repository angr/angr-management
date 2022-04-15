# pylint:disable=ungrouped-imports
from typing import Optional, TYPE_CHECKING
import os
import threading
import time

from PySide2.QtWidgets import QPushButton, QMessageBox
from PySide2.QtGui import QPixmap, Qt, QIcon

from angrmanagement.logic.threads import gui_thread_schedule_async
from angrmanagement.config import Conf, save_config
from angrmanagement.config.config_entry import ConfigurationEntry
from angrmanagement.plugins import BasePlugin
from angrmanagement.daemon.client import DaemonClient

from .backend_selector_dialog import QBackendSelectorDialog
from .target_selector import QTargetSelectorDialog
from .summary_view import SummaryView

try:
    import slacrs
except ImportError:
    slacrs = None

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace
    from slacrs import Slacrs


class ChessConnector(BasePlugin):
    """
    Implements the CHESS connector plugin.
    """

    DISPLAY_NAME = "CHESS Connector"
    REQUIRE_WORKSPACE = True

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

        self.target_id: Optional[str] = None
        self.target_image_id: Optional[str] = None
        self.target_description: Optional[str] = None
        self._target_description_label = QPushButton()
        self._target_description_label.setFlat(True)
        self._target_description_label.clicked.connect(self.set_chess_target)
        self.target_id_updated()

        self._slacrs_instance: Optional['Slacrs'] = None
        self._slacrs_database_str: Optional[str] = None

        self.connected: bool = False
        self.backend_disconnected()

        self.active = True

        th = threading.Thread(
            target=self.checrs_connection_monitor,
            args=(),
        )
        th.setDaemon(True)
        th.start()

        self.summary_view = SummaryView(self.workspace, "center", self)
        self.workspace.add_view(self.summary_view)

    def teardown(self):
        self.active = False
        self.summary_view.teardown()

    def slacrs_instance(self, database: Optional[str]=None):
        if not database:
            # load the default database str
            database = Conf.checrs_backend_str

        # again, if database_str is empty, return nothing
        if not database:
            return None

        if database == self._slacrs_database_str and self._slacrs_instance is not None:
            return self._slacrs_instance

        self._slacrs_instance = slacrs.Slacrs(database=database)
        # if it works out, remember the database str
        self._slacrs_database_str = database

        return self._slacrs_instance

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

    def target_id_updated(self):
        if self.target_id and self.target_image_id:
            desc = self.target_description if self.target_description else f"(no description) {self.target_id}"
            self._target_description_label.setText(desc)
            self._target_description_label.setToolTip(f"Target ID: {self.target_id}\n"
                                                      f"Target image ID: {self.target_image_id}")

            DaemonClient.register_binary(self.workspace.instance.project.loader.main_object.binary,
                                         self.target_id)
        else:
            self._target_description_label.setText("No associated CHESS target")
            self._target_description_label.setToolTip("")

    def status_bar_permanent_widgets(self):
        yield self._target_description_label
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

            engine = None
            try:
                gui_thread_schedule_async(self.backend_connecting)
                engine = slacrs.Slacrs.connect_to_db(Conf.checrs_backend_str)
                connection = engine.connect()
                connection.close()  # close it immediately
            except Exception:  # pylint:disable=broad-except
                gui_thread_schedule_async(self.backend_disconnected)
                continue
            finally:
                if engine is not None:
                    engine.dispose()

            gui_thread_schedule_async(self.backend_connected)

    #
    # Custom menu actions
    #

    MENU_BUTTONS = [
        'Connect to CHECRS backend...',
        'Set associated CHESS target...'
    ]
    CONNECT_TO_BACKEND = 0
    SET_CHESS_TARGET = 1

    def handle_click_menu(self, idx):
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return
        mapping = {
            ChessConnector.CONNECT_TO_BACKEND: self.set_checrs_backend_str,
            ChessConnector.SET_CHESS_TARGET: self.set_chess_target,
        }
        mapping[idx]()

    def set_checrs_backend_str(self):
        dialog = QBackendSelectorDialog(self.workspace,
                                        backend_str=Conf.checrs_backend_str,
                                        rest_backend_str=Conf.checrs_rest_endpoint_url,
                                        chess_connector=self,
                                        parent=self.workspace.main_window)
        dialog.exec_()

        server_url = dialog.backend_str
        if server_url is not None:
            # if it's empty, it means the user wants to disconnect from CHECRS
            Conf.checrs_backend_str = server_url
            save_config()

        rest_backend_url = dialog.rest_backend_str
        if rest_backend_url is not None:
            Conf.checrs_rest_endpoint_url = rest_backend_url
            save_config()

    def set_chess_target(self):

        if not self.connected:
            QMessageBox.critical(self.workspace.main_window,
                                 "Backend is not connected",
                                 "Your angr management instance is not connected to CHECRS backend. Please set a "
                                 "correct connection string before setting the CHESS target.",
                                 QMessageBox.Ok)
            return

        if self.workspace.instance.project.am_none:
            QMessageBox.critical(self.workspace.main_window,
                                 "No binary is loaded",
                                 "Please load a binary before associating it to a CHESS target.",
                                 QMessageBox.Ok)
            return

        dialog = QTargetSelectorDialog(self.workspace,
                                       parent=self.workspace.main_window)
        dialog.exec_()

        if dialog.ok:
            if dialog.target_id:
                self.target_id = dialog.target_id
                self.target_image_id = dialog.target_image_id
                self.target_description = dialog.target_description
            else:
                self.target_id = None
                self.target_image_id = None
                self.target_description = None
            self.target_id_updated()

    CONFIG_ENTRIES = [
        ConfigurationEntry("checrs_backend_str", str, "", default_value=""),
        ConfigurationEntry("checrs_rest_endpoint_url", str, "", default_value=""),
    ]

    def angrdb_store_entries(self):
        yield "chess_target_id", self.target_id if self.target_id else ""
        yield "chess_target_description", self.target_description if self.target_description else ""
        yield "chess_target_image_id", self.target_image_id if self.target_image_id else ""

    def angrdb_load_entry(self, key, value):
        if key == "chess_target_id":
            self.target_id = value
            self.target_id_updated()
        elif key == "chess_target_image_id":
            self.target_image_id = value
            self.target_id_updated()
        elif key == "chess_target_description":
            self.target_description = value
            self.target_id_updated()
