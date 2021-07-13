from typing import Optional, TYPE_CHECKING

from PySide2.QtWidgets import QDialog, QLineEdit, QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QMessageBox

try:
    import slacrs
except ImportError:
    slacrs = None

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class QBackendSelectorDialog(QDialog):
    """
    Implements a CHESS backend URL input dialog.
    """
    def __init__(self, workspace: 'Workspace', backend_str: Optional[str]=None, parent=None):
        super().__init__(parent)

        self.workspace = workspace

        self._input: QLineEdit = None
        self._test_button: QPushButton = None
        self._ok_button: QPushButton = None
        self._cancel_button: QPushButton = None
        self._status_label: QLabel = None

        self.backend_str: Optional[str] = backend_str

        self._init_widgets()

    def _init_widgets(self):

        # input
        input_label = QLabel("CHECRS backend URL:")
        self._input = QLineEdit(self.backend_str)
        self._input.setMinimumWidth(300)
        self._test_button = QPushButton("Test connection")
        self._test_button.clicked.connect(self._on_test_button_clicked)
        input_layout = QHBoxLayout()
        input_layout.addWidget(input_label)
        input_layout.addWidget(self._input)
        input_layout.addWidget(self._test_button)

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
        layout.addWidget(self._status_label)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

    @staticmethod
    def test_connection(connection_str: str) -> bool:
        if not connection_str:
            return False

        if slacrs is None:
            raise ImportError("The slacrs module is not installed")

        _ = slacrs.Slacrs(database=connection_str, exit_on_connection_failure=False)

        return True

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
        self.close()

    def _on_cancel_button_clicked(self):
        self.backend_str = None
        self.close()
