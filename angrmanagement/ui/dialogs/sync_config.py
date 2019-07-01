
import os

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox

try:
    import binsync
except ImportError:
    binsync = None


class SyncConfig(QDialog):
    def __init__(self, instance, parent=None):
        super().__init__(parent)

        if binsync is None:
            QMessageBox(self).critical(None, 'Dependency error',
                                       "binsync is not installed. Please install binsync first.")
            self.close()

        # initialization
        self._instance = instance

        self._main_layout = QVBoxLayout()
        self._user_edit = None
        self._repo_edit = None

        self._init_widgets()

        self.setLayout(self._main_layout)

        self.show()

    #
    # Private methods
    #

    def _init_widgets(self):

        # user label
        user_label = QLabel(self)
        user_label.setText("User name")

        self._user_edit = QLineEdit(self)
        self._user_edit.setText("user0_angrm")

        user_layout = QHBoxLayout()
        user_layout.addWidget(user_label)
        user_layout.addWidget(self._user_edit)

        # binsync label
        binsync_label = QLabel(self)
        binsync_label.setText("Git repo")

        # repo path
        self._repo_edit = QLineEdit(self)

        # layout
        repo_layout = QHBoxLayout()
        repo_layout.addWidget(binsync_label)
        repo_layout.addWidget(self._repo_edit)

        # buttons
        ok_button = QPushButton(self)
        ok_button.setText("OK")
        ok_button.clicked.connect(self._on_ok_clicked)

        cancel_button = QPushButton(self)
        cancel_button.setText("Cancel")
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        # main layout
        self._main_layout.addLayout(user_layout)
        self._main_layout.addLayout(repo_layout)
        self._main_layout.addLayout(buttons_layout)

    #
    # Event handlers
    #

    def _on_ok_clicked(self):
        proj = self._instance.project
        user = self._user_edit.text()
        path = self._repo_edit.text()

        if not user:
            QMessageBox(self).critical(None, "Invalid user name",
                                       "User name cannot be empty."
                                       )
            return

        if not os.path.isdir(path):
            QMessageBox(self).critical(None, "Repo does not exist",
                                       "The specified sync repo does not exist."
                                       )
            return

        # TODO: Add a user ID to angr management
        self._instance.sync.connect(user, path)
        self._instance.workspace.view_manager.first_view_in_category('sync').reload()
        self.close()

    def _on_cancel_clicked(self):
        self.close()
