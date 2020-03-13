
from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QListView, QStackedWidget, QWidget, \
    QGroupBox, QLabel, QCheckBox, QPushButton, QLineEdit
from PySide2.QtCore import QSize

from ...logic.url_scheme import AngrUrlScheme


class Integration(QWidget):
    """
    The integration page.
    """
    def __init__(self, parent=None):
        super().__init__(parent)

        self._url_scheme_chk = None  # type:QCheckBox
        self._url_scheme_text = None  # type:QLineEdit

        self._init_widgets()
        self._load_config()

    def _init_widgets(self):

        # os integratio
        os_integration = QGroupBox("OS integration")
        self._url_scheme_chk = QCheckBox("Register angr URL scheme (angr://).")
        self._url_scheme_text = QLineEdit()
        self._url_scheme_text.setReadOnly(True)
        url_scheme_lbl = QLabel("Currently registered to:")

        os_layout = QVBoxLayout()
        os_layout.addWidget(self._url_scheme_chk)
        os_layout.addWidget(url_scheme_lbl)
        os_layout.addWidget(self._url_scheme_text)

        os_integration.setLayout(os_layout)

        layout = QVBoxLayout()
        layout.addWidget(os_integration)
        layout.addStretch()
        self.setLayout(layout)

    def _load_config(self):
        scheme = AngrUrlScheme()
        try:
            registered, register_as = scheme.is_url_scheme_registered()
            self._url_scheme_chk.setChecked(registered)
            self._url_scheme_text.setText(register_as)
        except NotImplementedError:
            # the current OS is not supported
            self._url_scheme_chk.setDisabled(True)

    def save_config(self):
        scheme = AngrUrlScheme()
        try:
            registered, register_as = scheme.is_url_scheme_registered()
            if registered != self._url_scheme_chk.isChecked():
                # we need to do something
                if self._url_scheme_chk.isChecked():
                    scheme.register_url_scheme()
                else:
                    scheme.unregister_url_scheme()
        except NotImplementedError:
            # the current OS is not supported
            pass


class Preferences(QDialog):
    def __init__(self, workspace, parent=None):
        super().__init__(parent)

        self.workspace = workspace

        self._pages = [ ]

        self._init_widgets()

    def _init_widgets(self):

        # contents
        contents = QListWidget()
        contents.setViewMode(QListView.IconMode)
        contents.setIconSize(QSize(96, 84))
        contents.setMovement(QListView.Static)
        contents.setMaximumWidth(128)
        contents.setSpacing(12)

        self._pages.append(Integration())

        pages = QStackedWidget()
        for page in self._pages:
            pages.addWidget(page)

        # buttons
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self._on_ok_clicked)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self._on_cancel_clicked)

        button_layout = QHBoxLayout()
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)

        # layout
        top_layout = QHBoxLayout()
        top_layout.addWidget(contents)
        top_layout.addWidget(pages)

        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addLayout(button_layout)

        self.setLayout(main_layout)

    def _on_ok_clicked(self):
        for page in self._pages:
            page.save_config()
        self.close()

    def _on_cancel_clicked(self):
        self.close()
