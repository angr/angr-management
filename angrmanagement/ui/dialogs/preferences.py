from datetime import datetime

from bidict import bidict
from PySide6.QtCore import QSize
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf, save_config
from angrmanagement.config.color_schemes import COLOR_SCHEMES
from angrmanagement.config.config_manager import ENTRIES
from angrmanagement.logic.url_scheme import AngrUrlScheme
from angrmanagement.ui.css import refresh_theme
from angrmanagement.ui.widgets.qcolor_option import QColorOption
from angrmanagement.ui.widgets.qfont_option import QFontOption


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

    NAME = "OS Integration"

    def __init__(self, parent=None):
        super().__init__(parent)

        self._url_scheme_chk: QCheckBox
        self._url_scheme_text: QLineEdit

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


class Style(Page):
    """
    Preference pane for UI style choices
    """

    NAME = "Style"

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self._init_widgets()

    def _init_widgets(self):
        page_layout = QVBoxLayout(self)

        # Log format
        log_format_layout = QHBoxLayout()
        log_format_lbl = QLabel("Log datetime Format String:")
        log_format_lbl.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        log_format_layout.addWidget(log_format_lbl)

        self.log_format_entry = QComboBox(self)
        fmt: str = Conf.log_timestamp_format
        ts = datetime.now()
        # pylint: disable=use-sequence-for-iteration
        self._fmt_map = bidict({ts.strftime(i): i for i in {fmt, "%X", "%c"}})  # set also dedups
        for i in self._fmt_map.keys():
            self.log_format_entry.addItem(i)
        # pylint: disable=unsubscriptable-object
        self.log_format_entry.setCurrentText(self._fmt_map.inverse[fmt])
        self.log_format_entry.setEditable(True)
        log_format_layout.addWidget(self.log_format_entry)
        page_layout.addLayout(log_format_layout)

        # Font options
        self._font_options = [
            QFontOption("Application Font", "ui_default_font", self),
            # TODO: other app fonts, things which set them respect updates to them in Conf
            # QFontOption("Tab View Font", "tabular_view_font", self),
            # QFontOption("Disassembly Font", "disasm_font", self),
            # QFontOption("SymExc Font", "symexec_font", self),
            # QFontOption("Code Font", "code_font", self),
        ]
        font_layout = QVBoxLayout()
        for i in self._font_options:
            font_layout.addWidget(i)
        page_layout.addLayout(font_layout)

        page_layout.addStretch()

    def save_config(self):
        fmt = self.log_format_entry.currentText()
        if fmt:
            Conf.log_timestamp_format = self._fmt_map.get(fmt, fmt)
        for i in self._font_options:
            i.update()


class Preferences(QDialog):
    """
    Application preferences dialog.
    """

    def __init__(self, workspace, parent=None):
        super().__init__(parent)

        self.workspace = workspace

        self._pages = []

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
            pageno: Page = item.data(1)
            pages.setCurrentIndex(pageno)

        contents.itemClicked.connect(item_changed)

        self._pages.append(Integration())
        self._pages.append(ThemeAndColors())
        self._pages.append(Style())

        pages = QStackedWidget()
        for idx, page in enumerate(self._pages):
            pages.addWidget(page)
            list_item = QListWidgetItem(page.NAME)
            list_item.setData(1, idx)
            contents.addItem(list_item)

        # buttons
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Close | QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.Ok).setText("Save")
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
        refresh_theme()  # Apply updates to theme
        self.close()
