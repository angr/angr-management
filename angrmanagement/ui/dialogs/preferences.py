from __future__ import annotations

import enum
from datetime import datetime
from itertools import chain
from typing import TYPE_CHECKING

from bidict import bidict
from PySide6.QtCore import QSize
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QListWidget,
    QListWidgetItem,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf, save_config
from angrmanagement.config.color_schemes import BASE_SCHEME, COLOR_SCHEMES
from angrmanagement.config.config_manager import ENTRIES
from angrmanagement.logic.url_scheme import AngrUrlScheme
from angrmanagement.ui.css import refresh_theme
from angrmanagement.ui.widgets.qfont_option import QFontOption
from angrmanagement.ui.widgets.qproperty_editor import (
    ColorPropertyItem,
    GroupPropertyItem,
    PropertyModel,
    QPropertyEditor,
)
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
            self._url_scheme_text.setText(str(register_as) if registered else "")
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


CUSTOM_SCHEME_NAME = "Custom"


class ThemeAndColors(Page):
    """
    Theme and Colors preferences page.
    """

    NAME = "Theme and Colors"
    _schemes_combo: QComboBox
    _base_scheme: QLabel

    def __init__(self, parent=None) -> None:
        super().__init__(parent=parent)

        self._colors_to_save = {}
        self._conf_to_save = {}

        self._init_widgets()

    def _init_widgets(self) -> None:
        page_layout = QGridLayout(self)
        page_layout.setColumnStretch(1, 1)

        page_layout.addWidget(QLabel("Load Theme:"), 0, 0)
        self._schemes_combo = QComboBox(self)
        current_theme_idx = 0
        for idx, name in enumerate(sorted(COLOR_SCHEMES) + [CUSTOM_SCHEME_NAME]):
            if name == Conf.theme_name:
                current_theme_idx = idx
            self._schemes_combo.addItem(name)
        self._schemes_combo.setCurrentIndex(current_theme_idx)
        self._schemes_combo.currentTextChanged.connect(self._on_scheme_selected)
        page_layout.addWidget(self._schemes_combo, 0, 1)

        page_layout.addWidget(QLabel("Base Theme:"), 1, 0)
        self._base_scheme = QLabel(Conf.base_theme_name)
        page_layout.addWidget(self._base_scheme, 1, 1)

        root = GroupPropertyItem("root")
        for ce in ENTRIES:
            if ce.type_ is QColor:
                prop = ColorPropertyItem(ce.name, getattr(Conf, ce.name))
                root.addChild(prop)
                self._colors_to_save[ce.name] = (ce, prop)
            elif issubclass(ce.type_, enum.Enum):
                self._conf_to_save[ce.name] = ce.value

        self._model = PropertyModel(root)
        self._tree = QPropertyEditor()
        self._tree.set_description_visible(False)
        self._tree.setModel(self._model)
        page_layout.addWidget(self._tree, 2, 0, 1, 2)

    def _load_color_scheme(self, name: str) -> None:
        if name not in COLOR_SCHEMES:
            return

        self._model.beginResetModel()
        scheme = COLOR_SCHEMES[name] if name == BASE_SCHEME else {**COLOR_SCHEMES[BASE_SCHEME], **COLOR_SCHEMES[name]}
        for prop, value in scheme.items():
            if prop in self._colors_to_save:
                row = self._colors_to_save[prop][1]
                row.value = value
            if prop in self._conf_to_save:
                self._conf_to_save[prop] = value
        self._model.endResetModel()

    def _on_scheme_selected(self, text: str) -> None:
        if text != CUSTOM_SCHEME_NAME:
            self._load_color_scheme(text)
            self._base_scheme.setText(text)

    def save_config(self) -> None:
        # pylint: disable=assigning-non-slot
        Conf.theme_name = self._schemes_combo.currentText()
        Conf.base_theme_name = self._base_scheme.text()
        for ce, row in self._colors_to_save.values():
            setattr(Conf, ce.name, row.value)
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
            pageno: int = item.data(1)
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
        splitter = QSplitter()
        splitter.addWidget(contents)
        splitter.addWidget(pages)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        main_layout = QVBoxLayout()
        main_layout.addWidget(splitter)
        main_layout.addWidget(buttons)

        self.setLayout(main_layout)

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(800, 800)

    def _on_ok_clicked(self) -> None:
        for page in self._pages:
            page.save_config()
        save_config()
        refresh_theme()  # Apply updates to theme
        self.close()
