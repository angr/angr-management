from PySide2.QtGui import QColor
from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QListView, QStackedWidget, QWidget, \
    QGroupBox, QLabel, QCheckBox, QPushButton, QLineEdit, QListWidgetItem, QScrollArea, QFrame, QComboBox, \
    QSizePolicy, QDialogButtonBox
from PySide2.QtCore import QSize

from ..widgets.qcolor_option import QColorOption
from ...config.config_manager import ENTRIES
from ...config.color_schemes import COLOR_SCHEMES
from ...config import Conf, save_config
from ...logic.url_scheme import AngrUrlScheme
from ..css import refresh_theme


class Page(QWidget):
    """
    Base class for pages.
    """

    def save_config(self):
        raise NotImplementedError()

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
            registered, _ = scheme.is_url_scheme_registered()
            if registered != self._url_scheme_chk.isChecked():
                # we need to do something
                if self._url_scheme_chk.isChecked():
                    scheme.register_url_scheme()
                else:
                    scheme.unregister_url_scheme()
        except NotImplementedError:
            # the current OS is not supported
            pass


class ThemeAndColors(Page):
    """
    Theme and Colors preferences page.
    """

    NAME = "Theme and Colors"

    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self._to_save = {}
        self._schemes_combo: QComboBox = None

        self._init_widgets()

    def _init_widgets(self):
        page_layout = QVBoxLayout()

        scheme_loader_layout = QHBoxLayout()
        color_scheme_lbl = QLabel("Load Theme:")
        color_scheme_lbl.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        scheme_loader_layout.addWidget(color_scheme_lbl)

        self._schemes_combo = QComboBox(self)
        current_theme_idx = 0
        for idx, name in enumerate(["Current"] + list(sorted(COLOR_SCHEMES))):
            if name == Conf.theme_name:
                current_theme_idx = idx
            self._schemes_combo.addItem(name)
        self._schemes_combo.setCurrentIndex(current_theme_idx)
        scheme_loader_layout.addWidget(self._schemes_combo)
        load_btn = QPushButton("Load")
        load_btn.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        load_btn.clicked.connect(self._on_load_scheme_clicked)
        scheme_loader_layout.addWidget(load_btn)
        page_layout.addLayout(scheme_loader_layout)

        edit_colors_layout = QVBoxLayout()
        for ce in ENTRIES:
            if ce.type_ is not QColor:
                continue
            row = QColorOption(getattr(Conf, ce.name), ce.name)
            edit_colors_layout.addWidget(row)
            self._to_save[ce.name] = (ce, row)

        frame = QFrame()
        frame.setLayout(edit_colors_layout)

        scroll = QScrollArea()
        scroll.setWidget(frame)

        scroll_layout = QHBoxLayout()
        scroll_layout.addWidget(scroll)

        page_layout.addLayout(scroll_layout)

        self.setLayout(page_layout)

    def _load_color_scheme(self, name):
        for prop, value in COLOR_SCHEMES[name].items():
            row = self._to_save[prop][1]
            row.set_color(value)

    def _on_load_scheme_clicked(self):
        self._load_color_scheme(self._schemes_combo.currentText())
        self.save_config()

    def save_config(self):
        # pylint: disable=assigning-non-slot
        Conf.theme_name = self._schemes_combo.currentText()
        for ce, row in self._to_save.values():
            setattr(Conf, ce.name, row.color.am_obj)
        refresh_theme()


class Preferences(QDialog):
    """
    Application preferences dialog.
    """

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
        self._pages.append(ThemeAndColors())

        pages = QStackedWidget()
        for idx, page in enumerate(self._pages):
            pages.addWidget(page)
            list_item = QListWidgetItem(page.NAME)
            list_item.setData(1, idx)
            contents.addItem(list_item)

        # buttons
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Close | QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.Ok).setText('Save')
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)

        # layout
        top_layout = QHBoxLayout()
        top_layout.addWidget(contents)
        top_layout.addWidget(pages)

        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addWidget(buttons)

        self.setLayout(main_layout)

    def _on_ok_clicked(self):
        for page in self._pages:
            page.save_config()
        save_config()
        self.close()
