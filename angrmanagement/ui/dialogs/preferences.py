from __future__ import annotations

from itertools import chain
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, QSortFilterProxyModel, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QCheckBox,
    QComboBox,
    QCompleter,
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
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf, save_config
from angrmanagement.config.color import Color
from angrmanagement.present.preferences import (
    FONT_ENTRIES,
    color_entry_names,
    current_theme_values,
    generate_auth_token,
    known_model_names,
    log_format_choices,
    save_integration,
    save_llm,
    save_log_format,
    save_mcp,
    save_theme,
    scheme_entry_values,
    sync_llm_client,
    theme_choices,
    url_scheme_state,
)
from angrmanagement.present.theme import CUSTOM_SCHEME_NAME
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
        self._daemon_chk = QCheckBox("Always use local RPC daemon")
        url_scheme_lbl = QLabel("Currently registered to:")

        os_layout = QVBoxLayout()
        os_layout.addWidget(self._url_scheme_chk)
        os_layout.addWidget(self._daemon_chk)
        os_layout.addWidget(url_scheme_lbl)
        os_layout.addWidget(self._url_scheme_text)

        os_integration.setLayout(os_layout)

        layout = QVBoxLayout()
        layout.addWidget(os_integration)
        layout.addStretch()
        self.setLayout(layout)

    def _load_config(self) -> None:
        supported, registered, register_as = url_scheme_state()
        if supported:
            self._url_scheme_chk.setChecked(registered)
            self._url_scheme_text.setText(register_as)
        else:
            # the current OS is not supported
            self._url_scheme_chk.setDisabled(True)

        self._daemon_chk.setChecked(Conf.use_daemon)

    def save_config(self) -> None:
        save_integration(self._url_scheme_chk.isChecked(), self._daemon_chk.isChecked())


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
        for idx, name in enumerate(theme_choices()):
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
        for name in color_entry_names():
            prop = ColorPropertyItem(name, getattr(Conf, name))
            root.addChild(prop)
            self._colors_to_save[name] = prop
        # start from the current values, so saving keeps them unless a colour scheme sets these entries
        self._conf_to_save = dict(current_theme_values()[1])

        self._model = PropertyModel(root)
        self._tree = QPropertyEditor()
        self._tree.set_description_visible(False)
        self._tree.setModel(self._model)
        page_layout.addWidget(self._tree, 2, 0, 1, 2)

    def _load_color_scheme(self, name: str) -> None:
        scheme = scheme_entry_values(name)
        if not scheme:
            return

        self._model.beginResetModel()
        for prop, value in scheme.items():
            if prop in self._colors_to_save:
                row = self._colors_to_save[prop]
                # the schemes hold neutral values; the property editor edits QColors
                row.value = value.to_qcolor() if isinstance(value, Color) else value
            if prop in self._conf_to_save:
                self._conf_to_save[prop] = value
        self._model.endResetModel()

    def _on_scheme_selected(self, text: str) -> None:
        if text != CUSTOM_SCHEME_NAME:
            self._load_color_scheme(text)
            self._base_scheme.setText(text)

    def save_config(self) -> None:
        save_theme(
            self._schemes_combo.currentText(),
            self._base_scheme.text(),
            {name: row.value for name, row in self._colors_to_save.items()},
            self._conf_to_save,
        )


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
        self._fmt_map, shown = log_format_choices()
        for i in self._fmt_map:
            self.log_format_entry.addItem(i)
        self.log_format_entry.setCurrentText(shown)
        self.log_format_entry.setEditable(True)
        log_format_layout.addWidget(self.log_format_entry)
        page_layout.addLayout(log_format_layout)

        # Font options
        fonts_group_box = QGroupBox("Fonts")
        fonts_layout = QGridLayout()
        fonts_group_box.setLayout(fonts_layout)
        page_layout.addWidget(fonts_group_box)
        self._fonts_widgets = [(QLabel(f"{name}:"), QFontOption(key, self)) for name, key in FONT_ENTRIES]
        add_to_grid(fonts_layout, 2, chain(*self._fonts_widgets))

        page_layout.addStretch()

    def save_config(self) -> None:
        save_log_format(self.log_format_entry.currentText(), self._fmt_map)
        for _, font_picker in self._fonts_widgets:
            font_picker.update()


class LLMSettings(Page):
    """
    LLM configuration page.
    """

    NAME = "LLM"

    def __init__(self, workspace: Workspace | None = None, parent=None) -> None:
        super().__init__(parent)
        self.workspace = workspace

        self._model_combo: QComboBox
        self._api_key_edit: QLineEdit
        self._api_base_edit: QLineEdit
        self._preload_chk: QCheckBox
        self._auto_rename_vars_chk: QCheckBox
        self._auto_rename_func_chk: QCheckBox
        self._auto_retype_vars_chk: QCheckBox
        self._auto_summarize_chk: QCheckBox

        self._init_widgets()
        self._load_config()

    def _init_widgets(self) -> None:
        group = QGroupBox("LLM Configuration")
        layout = QGridLayout()

        layout.addWidget(QLabel("Model:"), 0, 0)
        self._model_combo = QComboBox()
        self._model_combo.setEditable(True)
        self._model_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self._model_combo.lineEdit().setPlaceholderText("e.g. gpt-4o, claude-sonnet-4-20250514, ollama/llama3")

        # Populate with known pydantic-ai model names
        model_names = known_model_names()
        source_model = QStandardItemModel()
        for name in model_names:
            source_model.appendRow(QStandardItem(name))

        # Set up a case-insensitive filter proxy so the completer matches anywhere in the string
        proxy = QSortFilterProxyModel()
        proxy.setSourceModel(source_model)
        proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        completer = QCompleter(proxy, self)
        completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        completer.setMaxVisibleItems(15)
        self._model_combo.setCompleter(completer)

        # Also populate the combo box dropdown itself
        self._model_combo.setModel(source_model)

        layout.addWidget(self._model_combo, 0, 1)

        layout.addWidget(QLabel("API Key:"), 1, 0)
        self._api_key_edit = QLineEdit()
        self._api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_edit.setPlaceholderText("Optional (uses env var if empty)")
        layout.addWidget(self._api_key_edit, 1, 1)

        layout.addWidget(QLabel("API Base URL:"), 2, 0)
        self._api_base_edit = QLineEdit()
        self._api_base_edit.setPlaceholderText("Optional (for custom endpoints)")
        layout.addWidget(self._api_base_edit, 2, 1)

        group.setLayout(layout)

        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        self._preload_chk = QCheckBox("Auto-refine callees after decompilation")
        options_layout.addWidget(self._preload_chk)
        self._auto_rename_vars_chk = QCheckBox("Auto-rename variables after decompilation")
        options_layout.addWidget(self._auto_rename_vars_chk)
        self._auto_rename_func_chk = QCheckBox("Auto-rename function after decompilation")
        options_layout.addWidget(self._auto_rename_func_chk)
        self._auto_retype_vars_chk = QCheckBox("Auto-retype variables after decompilation")
        options_layout.addWidget(self._auto_retype_vars_chk)
        self._auto_summarize_chk = QCheckBox("Auto-summarize function after decompilation")
        options_layout.addWidget(self._auto_summarize_chk)
        options_group.setLayout(options_layout)

        page_layout = QVBoxLayout()
        page_layout.addWidget(group)
        page_layout.addWidget(options_group)
        page_layout.addStretch()
        self.setLayout(page_layout)

    def _load_config(self) -> None:
        self._model_combo.setCurrentText(Conf.llm_model)
        self._api_key_edit.setText(Conf.llm_api_key)
        self._api_base_edit.setText(Conf.llm_api_base)
        self._preload_chk.setChecked(Conf.llm_preload_callees)
        self._auto_rename_vars_chk.setChecked(Conf.llm_auto_rename_variables)
        self._auto_rename_func_chk.setChecked(Conf.llm_auto_rename_function)
        self._auto_retype_vars_chk.setChecked(Conf.llm_auto_retype_variables)
        self._auto_summarize_chk.setChecked(Conf.llm_auto_summarize)

    def save_config(self) -> None:
        save_llm(
            {
                "llm_model": self._model_combo.currentText(),
                "llm_api_key": self._api_key_edit.text(),
                "llm_api_base": self._api_base_edit.text(),
                "llm_preload_callees": self._preload_chk.isChecked(),
                "llm_auto_rename_variables": self._auto_rename_vars_chk.isChecked(),
                "llm_auto_rename_function": self._auto_rename_func_chk.isChecked(),
                "llm_auto_retype_variables": self._auto_retype_vars_chk.isChecked(),
                "llm_auto_summarize": self._auto_summarize_chk.isChecked(),
            },
            self.workspace,
        )

    def _sync_llm_client_to_project(self) -> None:
        sync_llm_client(self.workspace)


class MCPSettings(Page):
    """
    MCP server configuration page.
    """

    NAME = "MCP Server"

    def __init__(self, workspace: Workspace | None = None, parent=None) -> None:
        super().__init__(parent)
        self.workspace = workspace

        self._port_spin: QSpinBox
        self._autostart_chk: QCheckBox
        self._history_limit_spin: QSpinBox
        self._auth_chk: QCheckBox
        self._token_edit: QLineEdit

        self._init_widgets()
        self._load_config()

    def _init_widgets(self) -> None:
        group = QGroupBox("MCP Server")
        layout = QGridLayout()

        layout.addWidget(
            QLabel(
                "The MCP server lets an AI agent analyze the loaded binary and show results "
                "(such as updated decompilation) live in angr management.\n"
                "Start and stop it from the AI menu. It listens on localhost only."
            ),
            0,
            0,
            1,
            2,
        )

        layout.addWidget(QLabel("Port:"), 1, 0)
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        layout.addWidget(self._port_spin, 1, 1)

        self._autostart_chk = QCheckBox("Start the MCP server automatically on launch")
        layout.addWidget(self._autostart_chk, 2, 0, 1, 2)

        layout.addWidget(QLabel("History limit:"), 3, 0)
        self._history_limit_spin = QSpinBox()
        self._history_limit_spin.setRange(0, 1_000_000)
        self._history_limit_spin.setSpecialValueText("Unlimited")  # shown when the value is 0
        self._history_limit_spin.setToolTip(
            "Maximum number of tool calls kept in the MCP History view (0 = unlimited)."
        )
        layout.addWidget(self._history_limit_spin, 3, 1)

        group.setLayout(layout)

        auth_group = QGroupBox("Authentication")
        auth_layout = QGridLayout()

        self._auth_chk = QCheckBox("Require a bearer token to connect")
        self._auth_chk.toggled.connect(self._on_auth_toggled)
        auth_layout.addWidget(self._auth_chk, 0, 0, 1, 3)

        auth_layout.addWidget(QLabel("Token:"), 1, 0)
        self._token_edit = QLineEdit()
        self._token_edit.setPlaceholderText("Leave empty to generate one when the server starts")
        auth_layout.addWidget(self._token_edit, 1, 1)
        generate_btn = QPushButton("Generate")
        generate_btn.clicked.connect(self._on_generate_token)
        auth_layout.addWidget(generate_btn, 1, 2)

        auth_group.setLayout(auth_layout)

        page_layout = QVBoxLayout()
        page_layout.addWidget(group)
        page_layout.addWidget(auth_group)
        page_layout.addStretch()
        self.setLayout(page_layout)

    def _on_auth_toggled(self, checked: bool) -> None:
        self._token_edit.setEnabled(checked)

    def _on_generate_token(self) -> None:
        self._token_edit.setText(generate_auth_token())

    def _load_config(self) -> None:
        self._port_spin.setValue(Conf.mcp_server_port)
        self._autostart_chk.setChecked(Conf.mcp_server_autostart)
        self._history_limit_spin.setValue(max(0, Conf.mcp_server_history_limit))
        self._auth_chk.setChecked(Conf.mcp_server_auth_enabled)
        self._token_edit.setText(Conf.mcp_server_auth_token)
        self._token_edit.setEnabled(Conf.mcp_server_auth_enabled)

    def save_config(self) -> None:
        save_mcp(
            {
                "mcp_server_port": self._port_spin.value(),
                "mcp_server_autostart": self._autostart_chk.isChecked(),
                "mcp_server_history_limit": self._history_limit_spin.value(),
                "mcp_server_auth_enabled": self._auth_chk.isChecked(),
                "mcp_server_auth_token": self._token_edit.text(),
            }
        )


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
        self._pages.append(LLMSettings(workspace=self.workspace))
        self._pages.append(MCPSettings(workspace=self.workspace))

        pages = QStackedWidget()
        for idx, page in enumerate(self._pages):
            pages.addWidget(page)
            list_item = QListWidgetItem(page.NAME)
            list_item.setData(1, idx)
            contents.addItem(list_item)

        contents.setMinimumWidth(contents.sizeHint().width())

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
        splitter.setCollapsible(0, False)
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
