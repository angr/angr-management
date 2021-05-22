from PySide2.QtGui import QColor
from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QListView, QStackedWidget, QWidget, \
    QGroupBox, QLabel, QCheckBox, QPushButton, QLineEdit, QListWidgetItem, QScrollArea, QFrame
from PySide2.QtCore import QSize

from ..widgets.qcolor_option import QColorOption
from ...config.config_manager import ENTRIES
from ...config import Conf
from ...logic.url_scheme import AngrUrlScheme


class Page(QWidget):
    def save_config(self):
        raise NotImplementedError

    NAME = NotImplemented


class Integration(Page):
    """
    The integration page.
    """
    NAME = 'OS Integration'
    def __init__(self, parent=None):
        super().__init__(parent)

        self._url_scheme_chk = None  # type:QCheckBox
        self._url_scheme_text = None  # type:QLineEdit

        self._init_widgets()
        self._load_config()

    def _init_widgets(self):

        # os integration
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


class Colors(Page):
    NAME = "Colors"

    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self._to_save = []

        self._init_widgets()

    def _init_widgets(self):
        layout = QVBoxLayout()

        for ce in ENTRIES:
            if ce.type_ is not QColor:
                continue
            row = QColorOption(getattr(Conf, ce.name), ce.name)
            layout.addWidget(row)

            self._to_save.append((ce, row))

        frame = QFrame()
        frame.setLayout(layout)
        scroll = QScrollArea()
        scroll.setWidget(frame)

        layout2 = QHBoxLayout()
        layout2.addWidget(scroll)
        self.setLayout(layout2)

    def save_config(self):
        for ce, row in self._to_save:
            setattr(Conf, ce.name, row.color.am_obj)

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

        def item_changed(item: QListWidgetItem):
            pageno = item.data(1)  # type: Page
            pages.setCurrentIndex(pageno)

        contents.itemClicked.connect(item_changed)

        self._pages.append(Integration())
        self._pages.append(Colors())

        pages = QStackedWidget()
        for idx, page in enumerate(self._pages):
            pages.addWidget(page)
            list_item = QListWidgetItem(page.NAME)
            list_item.setData(1, idx)
            contents.addItem(list_item)

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
