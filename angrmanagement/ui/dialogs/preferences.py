from __future__ import annotations

import enum
from datetime import datetime
from itertools import chain
from typing import TYPE_CHECKING

from bidict import bidict
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QListWidget,
    QListWidgetItem,
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
from angrmanagement.utils.layout import add_to_grid

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class Page(QWidget):
    """
    Base class for pages.
    """

    def save_config(self):
        raise NotImplementedError

    NAME = NotImplemented


class Integration(Page):
    """
    The integration page.
    """

    NAME = "OS Integration"

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        self._url_scheme_chk: QCheckBox
        self._url_scheme_text: QLineEdit

        self._init_widgets()
        self._load_config()

    def _init_widgets(self) -> None:
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

    def _load_config(self) -> None:
        scheme = AngrUrlScheme()
        try:
            registered, register_as = scheme.is_url_scheme_registered()
            self._url_scheme_chk.setChecked(registered)
            self._url_scheme_text.setText(register_as)
        except NotImplementedError:
            # the current OS is not supported
            self._url_scheme_chk.setDisabled(True)

    def save_config(self) -> None:
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

    def __init__(self, parent=None) -> None:
        super().__init__(parent=parent)

        self._colors_to_save = {}
        self._conf_to_save = {}
        self._schemes_combo: QComboBox = None

        self._init_widgets()

    def _init_widgets(self) -> None:
        page_layout = QVBoxLayout()

        scheme_loader_layout = QHBoxLayout()
        color_scheme_lbl = QLabel("Load Theme:")
        color_scheme_lbl.setSizePolicy(QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed))
        scheme_loader_layout.addWidget(color_scheme_lbl)

        self._schemes_combo = QComboBox(self)
        current_theme_idx = 0
        for idx, name in enumerate(["Current"] + sorted(COLOR_SCHEMES)):
            if name == Conf.theme_name:
                current_theme_idx = idx
            self._schemes_combo.addItem(name)
        self._schemes_combo.setCurrentIndex(current_theme_idx)
        self._schemes_combo.currentTextChanged.connect(self._on_scheme_selected)
        scheme_loader_layout.addWidget(self._schemes_combo)
        page_layout.addLayout(scheme_loader_layout)

        edit_colors_layout = QVBoxLayout()
        for ce in ENTRIES:
            if ce.type_ is QColor:
                row = QColorOption(getattr(Conf, ce.name), ce.name)
                edit_colors_layout.addWidget(row)
                self._colors_to_save[ce.name] = (ce, row)
            elif issubclass(ce.type_, enum.Enum):
                self._conf_to_save[ce.name] = ce.value

        frame = QFrame()
        frame.setLayout(edit_colors_layout)

        scroll = QScrollArea()
        scroll.setWidget(frame)

        scroll_layout = QHBoxLayout()
        scroll_layout.addWidget(scroll)

        page_layout.addLayout(scroll_layout)

        self.setLayout(page_layout)

    def _load_color_scheme(self, name: str) -> None:
        for prop, value in COLOR_SCHEMES[name].items():
            if prop in self._colors_to_save:
                row = self._colors_to_save[prop][1]
                row.set_color(value)
            if prop in self._conf_to_save:
                self._conf_to_save[prop] = value

    def _on_scheme_selected(self, text: str) -> None:
        self._load_color_scheme(text)
        self.save_config()
        refresh_theme()

    def save_config(self) -> None:
        # pylint: disable=assigning-non-slot
        Conf.theme_name = self._schemes_combo.currentText()
        for ce, row in self._colors_to_save.values():
            setattr(Conf, ce.name, row.color.am_obj)
        for name, value in self._conf_to_save.items():
            setattr(Conf, name, value)


class Style(Page):
    """
    Preference pane for UI style choices
    """

    NAME = "Style"

    def __init__(self, parent=None) -> None:
        super().__init__(parent=parent)
        self._init_widgets()

    def _init_widgets(self) -> None:
        page_layout = QVBoxLayout(self)

        # Log format
        log_format_layout = QHBoxLayout()
        log_format_lbl = QLabel("Log datetime Format String:")
        log_format_lbl.setSizePolicy(QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed))
        log_format_layout.addWidget(log_format_lbl)

        self.log_format_entry = QComboBox(self)
        fmt: str = Conf.log_timestamp_format
        ts = datetime.now()
        self._fmt_map = bidict({ts.strftime(i): i for i in [fmt, "%X", "%c"]})
        # fmt must be in _fmt_map.inverse for this to work
        if fmt not in self._fmt_map.inverse:
            fmt = self._fmt_map[ts.strftime(fmt)]
        for i in self._fmt_map:
            self.log_format_entry.addItem(i)
        # pylint: disable=unsubscriptable-object
        self.log_format_entry.setCurrentText(self._fmt_map.inverse[fmt])
        self.log_format_entry.setEditable(True)
        log_format_layout.addWidget(self.log_format_entry)
        page_layout.addLayout(log_format_layout)

        # Font options
        fonts_group_box = QGroupBox("Fonts")
        fonts_layout = QGridLayout()
        fonts_group_box.setLayout(fonts_layout)
        page_layout.addWidget(fonts_group_box)
        entries = [
            ("Application Font", "ui_default_font"),
            ("Tabular View Font", "tabular_view_font"),
            ("Disassembly Font", "disasm_font"),
            ("SymExc Font", "symexec_font"),
            ("Code Font", "code_font"),
        ]
        self._fonts_widgets = [(QLabel(f"{name}:"), QFontOption(key, self)) for name, key in entries]
        add_to_grid(fonts_layout, 2, chain(*self._fonts_widgets))

        page_layout.addStretch()

    def save_config(self) -> None:
        fmt = self.log_format_entry.currentText()
        if fmt:
            Conf.log_timestamp_format = self._fmt_map.get(fmt, fmt)
        for _, font_picker in self._fonts_widgets:
            font_picker.update()


class Preferences(QDialog):
    """
    Application preferences dialog.
    """

    def __init__(self, workspace: Workspace, parent=None) -> None:
        super().__init__(parent)

        self.workspace = workspace

        self._pages = []

        self._init_widgets()

    def _init_widgets(self) -> None:
        # contents
        contents = QListWidget()
        contents.setViewMode(QListView.ViewMode.ListMode)
        contents.setMovement(QListView.Movement.Static)
        # set the width to match the width of the content
        contents.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)

        def item_changed(item: QListWidgetItem) -> None:
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
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Save")
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

    def _on_ok_clicked(self) -> None:
        for page in self._pages:
            page.save_config()
        save_config()
        refresh_theme()  # Apply updates to theme
        self.close()
