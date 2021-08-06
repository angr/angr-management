from typing import Optional, TYPE_CHECKING

import sqlalchemy
import requests

from PySide2.QtGui import Qt
from PySide2.QtWidgets import QDialog, QLineEdit, QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QMessageBox

try:
    import slacrs
except ImportError:
    slacrs = None

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace
    from .chess_connector import ChessConnector


class QBackendSelectorDialog(QDialog):
    """
    Implements a CHESS backend URL input dialog.
    """
    def __init__(self, workspace: 'Workspace', backend_str: Optional[str]=None, rest_backend_str: Optional[str]=None,
                 chess_connector: 'ChessConnector'=None, parent=None):
        super().__init__(parent)

        self.workspace = workspace

        self._input: QLineEdit = None
        self._rest_endpoint_input: QLineEdit = None
        self._test_button: QPushButton = None
        self._test_rest_button: QPushButton = None
        self._ok_button: QPushButton = None
        self._cancel_button: QPushButton = None
        self._status_label: QLabel = None

        self.chess_connector = chess_connector
        self.backend_str: Optional[str] = backend_str
        self.rest_backend_str: Optional[str] = rest_backend_str

        self.setWindowTitle("Connect to CHECRS backend")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self._init_widgets()

    def _init_widgets(self):

        # input
        input_label = QLabel("CHECRS backend URL:")
        self._input = QLineEdit("sqlite://" if not self.backend_str else self.backend_str)
        self._input.setMinimumWidth(400)
        self._test_button = QPushButton("Test...")
        self._test_button.clicked.connect(self._on_test_button_clicked)
        input_layout = QHBoxLayout()
        input_layout.addWidget(input_label)
        input_layout.addWidget(self._input)
        input_layout.addWidget(self._test_button)

        # REST endpoint URL
        rest_label = QLabel("CHECRS REST backend URL:")
        self._rest_endpoint_input = QLineEdit("http://" if not self.rest_backend_str else self.rest_backend_str)
        self._rest_endpoint_input.setMinimumWidth(400)
        self._test_rest_button = QPushButton("Test...")
        self._test_rest_button.clicked.connect(self._on_test_rest_button_clicked)
        rest_layout = QHBoxLayout()
        rest_layout.addWidget(rest_label)
        rest_layout.addWidget(self._rest_endpoint_input)
        rest_layout.addWidget(self._test_rest_button)

        # status
        self._status_label = QLabel()

        # buttons
        self._ok_button = QPushButton("OK")
        self._ok_button.clicked.connect(self._on_ok_button_clicked)
        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self._on_cancel_button_clicked)
        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self._ok_button)
        buttons_layout.addWidget(self._cancel_button)

        layout = QVBoxLayout()
        layout.addLayout(input_layout)
        layout.addLayout(rest_layout)
        layout.addWidget(self._status_label)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

    def test_connection(self, connection_str: str) -> bool:
        if not connection_str:
            return False

        if slacrs is None:
            raise ImportError("The slacrs module is not installed")

        slacrs_instance = self.chess_connector.slacrs_instance(database=connection_str)
        if slacrs_instance is None:
            raise RuntimeError("Cannot create Slacrs instance.")

        # test connection
        session = slacrs_instance.session()
        session.query(sqlalchemy.false()).filter(sqlalchemy.false())
        session.close()

        return True

    @staticmethod
    def test_rest_connection(rest_backend: str) -> bool:
        if not rest_backend:
            return False

        r = requests.head(rest_backend)
        if r.status_code == 404:
            return True

        # unexpected
        return False

    #
    # Events
    #

    def _on_test_button_clicked(self):
        self._test_button.setEnabled(False)

        connection_str = self._input.text().strip(" ")
        self._status_label.setText(f"Testing connection to {connection_str}...")
        self.workspace.main_window.app.processEvents()

        try:
            r = self.test_connection(connection_str)
        except Exception as ex:  # pylint:disable=broad-except
            self._status_label.setText(f"Failed to connect to {connection_str}. Exception: {str(ex)}.")
            r = None

        if r is False:
            self._status_label.setText(f"Failed to connect to {connection_str}.")
        elif r is True:
            self._status_label.setText(f"Successfully connected to {connection_str}.")

        self._test_button.setEnabled(True)

    def _on_test_rest_button_clicked(self):
        self._test_rest_button.setEnabled(False)

        backend = self._rest_endpoint_input.text().strip(" ")
        self._status_label.setText(f"Testing connection to REST backend {backend}...")
        self.workspace.main_window.app.processEvents()

        try:
            r = self.test_rest_connection(backend)
        except Exception as ex:  # pylint:disable=broad-except
            self._status_label.setText(f"Failed to connect to REST backend {backend}. Exception: {str(ex)}.")
            r = None

        if r is False:
            self._status_label.setText(f"Failed to connect to REST backend {backend}.")
        elif r is True:
            self._status_label.setText(f"Successfully connected to REST backend {backend}.")

        self._test_rest_button.setEnabled(True)

    def _on_ok_button_clicked(self):

        # Test the connection
        self._ok_button.setEnabled(False)
        connection_str = self._input.text().strip(" ")

        # special case: if connection_str is empty, it means the user wants to disconnect from CHECRS
        if connection_str:
            self._status_label.setText(f"Testing connection to {connection_str}...")
            self.workspace.main_window.app.processEvents()

            try:
                r = self.test_connection(connection_str)
            except Exception:  # pylint:disable=broad-except
                r = False

            if not r:
                QMessageBox.critical(self,
                                     "Connection failed",
                                     f"Cannot connect to CHECRS backend {connection_str}. Please check if the backend "
                                     f"string is correct.")
                self._status_label.setText("")
                self._ok_button.setEnabled(True)
                return

        self.backend_str = connection_str

        rest_backend_str = self._rest_endpoint_input.text()
        if rest_backend_str and rest_backend_str[-1] != "/":
            rest_backend_str += "/"

        self.rest_backend_str = rest_backend_str
        self.close()

    def _on_cancel_button_clicked(self):
        self.backend_str = None
        self.rest_backend_str = None
        self.close()
