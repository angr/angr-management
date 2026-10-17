from __future__ import annotations

import binascii
import os
from typing import Any

import archinfo
import cle
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFileIconProvider,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

try:
    import pypcode
except ImportError:
    pypcode = None

from angrmanagement.data.load_options import (
    CART_BACKEND_NAME,
    CART_ENCKEY_ARGNAME,
    NO_OUTER_BACKEND,
    LoadSelection,
    available_archs,
    available_backends,
    available_simos,
    build_load_options,
    loaded_addresses,
    requested_dependencies,
    split_arches,
    suggested_backend_name,
    suggested_outer_backend_name,
    suggested_simos_name,
    symbol_path_rows,
)
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule
from angrmanagement.ui.dialogs.set_encryption_key import SetEncryptionKeyDialog, key_to_hex
from angrmanagement.utils.cart_config import CART_CONFIG_KEY_OPTION, CART_CONFIG_PATH, load_cart_config_key


class LoadBinaryError(Exception):
    """
    An error loading the binary.
    """


class ArchTreeWidgetItem(QTreeWidgetItem):
    """
    A custom tree-view widget item for the architecture selection TreeView.
    """

    def __init__(self, name: str, arch) -> None:
        super().__init__()
        self.name = name
        self.arch = arch
        self.setText(0, name)


DEPENDENCIES_TAB_INDEX = 1

# the cart constants moved to angrmanagement.data.load_options; they stay importable from here
__all__ = ["CART_BACKEND_NAME", "CART_ENCKEY_ARGNAME", "ArchTreeWidgetItem", "LoadBinary", "LoadBinaryError"]


class LoadBinary(QDialog):
    """
    Dialog displaying loading options for a binary.
    """

    PE_DEBUG_SYMBOLS_TABLE_COL_TYPE = 0
    PE_DEBUG_SYMBOLS_TABLE_COL_CACHE = 1
    PE_DEBUG_SYMBOLS_TABLE_COL_PATH = 2

    def __init__(
        self,
        partial_ld: cle.Loader,
        suggested_backend: type[cle.Backend] | None = None,
        suggested_os_name: str | None = None,
        suggested_main_opts: dict | None = None,
        suggested_original_backend: type[cle.Backend] | None = None,
        suggested_main_filename: str | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)

        # initialization
        # objects unpacked by an outer backend have no path on disk, in which case we fall back to the name the outer
        # backend gave them
        self.file_path: str | None = (
            partial_ld.main_object.binary if suggested_main_filename is None else suggested_main_filename
        )
        self.partial_ld = partial_ld
        self.md5 = None
        self.sha256 = None
        self.option_widgets = {}
        self.suggested_backend = suggested_backend
        self.suggested_os_name = suggested_os_name
        self.suggested_main_opts = suggested_main_opts or {}
        self.suggested_original_backend = suggested_original_backend
        self.suggested_main_filename = suggested_main_filename
        self.available_backends: dict[str, cle.Backend] = available_backends()
        self.available_simos = available_simos()
        self.arch = partial_ld.main_object.arch
        self.available_archs = available_archs()
        # _try_loading will try its best to fill in the following two properties from partial_ld
        self._base_addr: int | None = None
        self._entry_addr: int | None = None
        self._offset: int = 0

        self._base_addr_checkbox = None
        self._entry_addr_checkbox = None
        self._offset_checkbox = None
        self._symbol_search_tab_index = None
        # the key the outer backend should use. it may already have been supplied by whoever performed the partial
        # load, in which case the user is only overriding it.
        self._enckey: bytes | None = self.suggested_main_opts.get(CART_ENCKEY_ARGNAME)

        # return values
        self.load_options = None
        self.simos = None

        self.setWindowTitle("Load a new binary")

        # checksums
        if hasattr(partial_ld.main_object, "md5") and partial_ld.main_object.md5 is not None:
            self.md5 = binascii.hexlify(partial_ld.main_object.md5).decode("ascii")
        if hasattr(partial_ld.main_object, "sha256") and partial_ld.main_object.sha256 is not None:
            self.sha256 = binascii.hexlify(partial_ld.main_object.sha256).decode("ascii")

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self._try_loading(partial_ld)

        self._set_base_addr()

        self.setLayout(self.main_layout)

    @property
    def filename(self):
        return os.path.basename(self.file_path) if self.file_path else ""

    #
    # Private methods
    #

    def _try_loading(self, partial_ld: cle.Loader) -> None:
        deps = requested_dependencies(partial_ld)

        # dependencies

        dep_list: QListWidget = self.option_widgets["dep_list"]
        for dep in deps:
            dep_item = QListWidgetItem(dep)
            dep_item.setData(Qt.ItemDataRole.CheckStateRole, Qt.CheckState.Unchecked)
            dep_list.addItem(dep_item)

        # update the dependencies tab text
        self.tab.setTabText(DEPENDENCIES_TAB_INDEX, f"Dependencies ({len(deps)})")

        self._base_addr, self._entry_addr, self._offset = loaded_addresses(partial_ld)

    def _set_base_addr(self) -> None:
        # special handling for blobs. note that suggested_backend is a class, not an instance.
        if self.suggested_backend is not None and issubclass(self.suggested_backend, cle.Blob):
            self._toggle_base_addr_textbox(True)
            self._toggle_entry_addr_textbox(True)
            self._toggle_offset_textbox(True)
            self.option_widgets["entry_addr"].setText("0x0")
            self.option_widgets["base_addr"].setText("0x0")
            self.option_widgets["offset"].setText("0x0")
        else:
            self._toggle_base_addr_textbox(False)
            self._toggle_entry_addr_textbox(False)
            self._toggle_offset_textbox(False)

            if self._entry_addr is not None:
                self.option_widgets["entry_addr"].setText(hex(self._entry_addr))
            if self._base_addr is not None:
                self.option_widgets["base_addr"].setText(hex(self._base_addr))
            if self._offset is not None:
                self.option_widgets["offset"].setText(hex(self._offset))

    def _init_widgets(self) -> None:
        layout = QGridLayout()
        layout.setColumnStretch(1, 1)
        self.main_layout.addLayout(layout)

        # filename

        filename_caption = QLabel(self)
        filename_caption.setText("File name:")

        filename = QLabel(self)
        filename.setText(self.filename if self.filename else "<Unknown>")

        layout.addWidget(filename_caption, 0, 0, Qt.AlignmentFlag.AlignRight)
        layout.addWidget(filename, 0, 1)

        # md5

        if self.md5 is not None:
            md5_caption = QLabel(self)
            md5_caption.setText("MD5:")
            md5 = QLineEdit(self)
            md5.setText(self.md5)
            md5.setReadOnly(True)

            layout.addWidget(md5_caption, 1, 0, Qt.AlignmentFlag.AlignRight)
            layout.addWidget(md5, 1, 1)

        # sha256

        if self.sha256 is not None:
            sha256_caption = QLabel(self)
            sha256_caption.setText("SHA256:")
            sha256 = QLineEdit(self)
            sha256.setText(self.sha256)
            sha256.setReadOnly(True)

            layout.addWidget(sha256_caption, 2, 0, Qt.AlignmentFlag.AlignRight)
            layout.addWidget(sha256, 2, 1)

        # central tab

        self.tab = QTabWidget()
        self._init_central_tab(self.tab)

        self.main_layout.addWidget(self.tab)

        # buttons

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self._on_cancel_clicked)
        self.main_layout.addWidget(buttons)

    def _init_central_tab(self, tab) -> None:
        self._init_load_options_tab(tab)
        # Add symbol search options tab for PE files
        if isinstance(self.partial_ld.main_object, cle.PE):
            self._init_symbol_search_tab(tab)

    def _init_load_options_tab(self, tab):
        #
        # Outer backend selection
        #

        outer_backend_layout = QHBoxLayout()
        outer_backend_caption = QLabel()
        outer_backend_caption.setText("Outer backend:")
        outer_backend_caption.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        outer_backend_layout.addWidget(outer_backend_caption)

        outer_backend_dropdown = QComboBox()
        outer_backend_dropdown.addItem(NO_OUTER_BACKEND)
        for backend_name, backend in self.available_backends.items():
            if getattr(backend, "is_outer", False) is True:
                outer_backend_dropdown.addItem(backend_name)
        outer_name = suggested_outer_backend_name(self.suggested_original_backend)
        outer_backend_dropdown.setCurrentText(outer_name if outer_name is not None else NO_OUTER_BACKEND)
        outer_backend_dropdown.currentTextChanged.connect(self._on_outer_backend_changed)
        outer_backend_layout.addWidget(outer_backend_dropdown)

        enckey_button = QPushButton("Encryption key...")
        enckey_button.clicked.connect(self._on_set_enckey_clicked)
        outer_backend_layout.addWidget(enckey_button)

        enckey_label = QLabel()
        enckey_layout = QHBoxLayout()
        enckey_layout.addStretch()
        enckey_layout.addWidget(enckey_label)

        self.option_widgets["outer_backend"] = outer_backend_dropdown
        self.option_widgets["enckey_button"] = enckey_button
        self.option_widgets["enckey_label"] = enckey_label
        self._update_enckey_widgets()

        #
        # Backend selection
        #

        backend_layout = QHBoxLayout()
        backend_caption = QLabel()
        backend_caption.setText("Backend:")
        backend_caption.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        backend_layout.addWidget(backend_caption)

        backend_dropdown = QComboBox()
        for backend_name, backend in self.available_backends.items():
            if getattr(backend, "is_outer", False) is False:
                backend_dropdown.addItem(backend_name)
        inner_name = suggested_backend_name(self.suggested_backend)
        if inner_name is not None:
            backend_dropdown.setCurrentText(inner_name)
        backend_layout.addWidget(backend_dropdown)

        self.option_widgets["backend"] = backend_dropdown

        #
        # OS selection
        #
        os_layout = QHBoxLayout()
        os_caption = QLabel()
        os_caption.setText("OS:")
        os_caption.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        os_layout.addWidget(os_caption)

        os_dropdown = QComboBox()
        for simos_name in self.available_simos:
            os_dropdown.addItem(simos_name)
        os_dropdown.setCurrentText(suggested_simos_name(self.suggested_os_name, self.available_simos))
        os_layout.addWidget(os_dropdown)

        self.option_widgets["os"] = os_dropdown

        #
        # Architecture selection
        #

        arch_layout = QVBoxLayout()
        arch_caption = QLabel(self)
        arch_caption.setText("Architecture:")
        arch_caption.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        arch_layout.addWidget(arch_caption)

        # initialize the architecture tree widget
        arch_tree = QTreeWidget(self)
        arch_tree.setHeaderHidden(True)
        recommended_arch_node = QTreeWidgetItem()
        recommended_arch_node.setText(0, "Suggested architectures")
        recommended_arch_node.setIcon(0, QFileIconProvider().icon(QFileIconProvider.IconType.Folder))
        other_arch_node = QTreeWidgetItem()
        other_arch_node.setText(0, "Other architectures")
        other_arch_node.setIcon(0, QFileIconProvider().icon(QFileIconProvider.IconType.Folder))

        ideal_arch, recommended_arches, other_arches = self._split_arches(self.available_archs)
        if ideal_arch is not None:
            recommended_arches = [ideal_arch] + recommended_arches
        ideal_arch_item = None

        for arch in recommended_arches:
            if isinstance(arch, archinfo.Arch):
                item = ArchTreeWidgetItem(f"{arch.bits}b {arch.name} ({arch.memory_endness[-2:]})", arch)
                recommended_arch_node.addChild(item)
            elif pypcode and isinstance(arch, pypcode.ArchLanguage):
                item = ArchTreeWidgetItem(f"{arch.id} (P-code Engine)", arch)
                recommended_arch_node.addChild(item)
            else:
                raise AssertionError("Unexpected arch type")
            if arch is ideal_arch:
                ideal_arch_item = item

        for arch in other_arches:
            if isinstance(arch, archinfo.Arch):
                item = ArchTreeWidgetItem(f"{arch.bits}b {arch.name} ({arch.memory_endness[-2:]})", arch)
                other_arch_node.addChild(item)
            elif pypcode and isinstance(arch, pypcode.ArchLanguage):
                item = ArchTreeWidgetItem(f"{arch.id} (P-code Engine)", arch)
                other_arch_node.addChild(item)
            else:
                raise AssertionError("Unexpected arch type")

        arch_tree.addTopLevelItem(recommended_arch_node)
        arch_tree.addTopLevelItem(other_arch_node)

        if recommended_arches:
            # expand recommended architectures
            recommended_arch_node.setExpanded(True)
            if ideal_arch_item is not None:
                arch_tree.setCurrentItem(ideal_arch_item)
        else:
            # expand other architectures
            other_arch_node.setExpanded(True)

        arch_layout.addWidget(arch_tree)
        self.option_widgets["arch"] = arch_tree

        blob_layout = QGridLayout()

        # load address
        base_addr_checkbox = QCheckBox()
        base_addr_checkbox.setChecked(False)
        base_addr_checkbox.setText("Base address:")
        blob_layout.addWidget(base_addr_checkbox, 1, 0)
        base_addr = QLineEdit(self)
        blob_layout.addWidget(base_addr, 1, 1)
        base_addr_checkbox.clicked.connect(self._on_base_addr_checkbox_clicked)
        self._base_addr_checkbox = base_addr_checkbox
        self.option_widgets["base_addr"] = base_addr

        # entry address
        entry_addr_checkbox = QCheckBox()
        entry_addr_checkbox.setChecked(False)
        entry_addr_checkbox.setText("Entry address:")
        blob_layout.addWidget(entry_addr_checkbox, 2, 0)
        entry_addr = QLineEdit(self)
        blob_layout.addWidget(entry_addr, 2, 1)
        entry_addr_checkbox.clicked.connect(self._on_entry_addr_checkbox_clicked)
        self._entry_addr_checkbox = entry_addr_checkbox
        self.option_widgets["entry_addr"] = entry_addr

        # offset amount
        offset_checkbox = QCheckBox()
        offset_checkbox.setChecked(False)
        offset_checkbox.setText("Offset:")
        blob_layout.addWidget(offset_checkbox, 3, 0)
        offset = QLineEdit(self)
        blob_layout.addWidget(offset, 3, 1)
        offset_checkbox.clicked.connect(self._on_offset_checkbox_clicked)
        self._offset_checkbox = offset_checkbox
        self.option_widgets["offset"] = offset

        # load debug symbols
        load_debug_info = QCheckBox()
        load_debug_info.setText("Load debug information if available")
        load_debug_info.setChecked(True)
        self.option_widgets["load_debug_info"] = load_debug_info

        layout = QVBoxLayout()
        layout.addLayout(outer_backend_layout)
        layout.addLayout(enckey_layout)
        layout.addLayout(backend_layout)
        layout.addLayout(os_layout)
        layout.addLayout(blob_layout)
        layout.addLayout(arch_layout)
        layout.addWidget(load_debug_info)

        frame = QFrame(self)
        frame.setLayout(layout)
        tab.addTab(frame, "Overview")

        # auto load libs
        auto_load_libs = QCheckBox()
        auto_load_libs.setText("Automatically load all libraries (slow, not recommended)")
        auto_load_libs.setChecked(False)
        self.option_widgets["auto_load_libs"] = auto_load_libs

        # dependencies list
        dep_group = QGroupBox("Dependencies")
        dep_list = QListWidget()
        self.option_widgets["dep_list"] = dep_list

        sublayout = QVBoxLayout()
        sublayout.addWidget(dep_list)
        dep_group.setLayout(sublayout)

        layout = QVBoxLayout()
        layout.addWidget(auto_load_libs)
        layout.addWidget(dep_group, stretch=1)

        frame = QFrame(self)
        frame.setLayout(layout)
        tab.addTab(frame, "Dependencies")

    def _init_symbol_search_tab(self, tab) -> None:
        """
        Initialize the symbol search options tab for PE files.
        """
        layout = QVBoxLayout()

        # Checkbox for allowing symbol download from Internet
        allow_download_checkbox = QCheckBox()
        allow_download_checkbox.setText("Allow downloading debug symbols from the Internet")
        allow_download_checkbox.setChecked(True)
        self.option_widgets["allow_symbol_download"] = allow_download_checkbox
        layout.addWidget(allow_download_checkbox)

        # table for symbol paths
        symbol_paths_table = QTableWidget(self)
        symbol_paths_table.setColumnCount(3)
        symbol_paths_table.setHorizontalHeaderLabels(["Type", "Cache", "Server"])
        symbol_paths_table.horizontalHeader().setSectionResizeMode(
            LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_TYPE, QHeaderView.ResizeMode.ResizeToContents
        )
        symbol_paths_table.horizontalHeader().setSectionResizeMode(
            LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_CACHE, QHeaderView.ResizeMode.ResizeToContents
        )
        symbol_paths_table.horizontalHeader().setSectionResizeMode(
            LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_PATH, QHeaderView.ResizeMode.Stretch
        )
        symbol_paths_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.option_widgets["symbol_paths_table"] = symbol_paths_table
        layout.addWidget(symbol_paths_table)

        # Buttons for managing symbol paths
        button_layout = QHBoxLayout()

        add_entry_button = QPushButton("Add...")
        add_entry_button.clicked.connect(self._on_add_symbol_path_entry_clicked)
        button_layout.addWidget(add_entry_button)

        remove_entry_button = QPushButton("Remove Selected")
        remove_entry_button.clicked.connect(self._on_remove_symbol_path_entry_clicked)
        button_layout.addWidget(remove_entry_button)

        button_layout.addStretch()

        parse_env_button = QPushButton("Enter Symbol Path...")
        parse_env_button.clicked.connect(self._on_parse_symbol_path_clicked)
        button_layout.addWidget(parse_env_button)

        layout.addLayout(button_layout)

        frame = QFrame(self)
        frame.setLayout(layout)
        self._symbol_search_tab_index = tab.addTab(frame, "Debug Symbols")

        # Initially disable the tab if debug info is not checked
        self._update_symbol_search_tab_enabled()

        # Connect the load_debug_info checkbox to enable/disable the tab
        load_debug_info = self.option_widgets["load_debug_info"]
        load_debug_info.toggled.connect(self._update_symbol_search_tab_enabled)

        # Parse the symbol path string from the environment variable
        nt_symbol_path = os.environ.get("_NT_SYMBOL_PATH", "")
        if nt_symbol_path:
            self._parse_symbol_path_str_and_populate_symbol_paths_table(nt_symbol_path)

    def _update_symbol_search_tab_enabled(self) -> None:
        """
        Enable or disable the symbol search tab based on the load_debug_info checkbox state.
        """
        if self._symbol_search_tab_index is None:
            return

        load_debug_info = self.option_widgets.get("load_debug_info")
        if load_debug_info is None:
            return

        is_enabled = load_debug_info.isChecked()

        # Enable/disable the tab widget (this grays it out)
        self.tab.setTabEnabled(self._symbol_search_tab_index, is_enabled)

    def _on_parse_symbol_path_clicked(self) -> None:
        """
        Handle the "Enter symbol path string" button click.
        Parses a symbol path string (like _NT_SYMBOL_PATH) and populates the table.
        """
        text, ok = QInputDialog.getText(
            self,
            "Enter Symbol Path String",
            "Enter symbol path string (e.g., from _NT_SYMBOL_PATH):",
            text=os.environ.get("_NT_SYMBOL_PATH", ""),
        )
        if not ok or not text:
            return

        self._parse_symbol_path_str_and_populate_symbol_paths_table(text)

    def _parse_symbol_path_str_and_populate_symbol_paths_table(self, text: str) -> None:
        rows = symbol_path_rows(text)

        symbol_paths_table: QTableWidget = self.option_widgets["symbol_paths_table"]
        symbol_paths_table.setRowCount(len(rows))
        symbol_paths_table.clearContents()

        for row, (entry_type, cache, path) in enumerate(rows):
            # Path type
            type_item = QTableWidgetItem(entry_type)
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            symbol_paths_table.setItem(row, LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_TYPE, type_item)

            cache_item = QTableWidgetItem(cache)
            symbol_paths_table.setItem(row, LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_CACHE, cache_item)
            path_item = QTableWidgetItem(path)
            symbol_paths_table.setItem(row, LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_PATH, path_item)

    def _on_add_symbol_path_entry_clicked(self) -> None:
        """
        Handle the "Add Entry" button click.
        Opens a dialog to add a new symbol path entry manually.
        """
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Symbol Path Entry")
        dialog.setModal(True)

        layout = QVBoxLayout()

        # Type selection
        type_layout = QHBoxLayout()
        type_label = QLabel("Type:")
        type_combo = QComboBox()
        type_combo.addItems(["local", "srv"])
        type_layout.addWidget(type_label)
        type_layout.addWidget(type_combo)
        layout.addLayout(type_layout)

        # Cache path (for srv types)
        cache_layout = QHBoxLayout()
        cache_label = QLabel("Cache Path:")
        cache_edit = QLineEdit()
        cache_browse_button = QPushButton("Browse...")
        cache_browse_button.clicked.connect(lambda: self._browse_directory(cache_edit))
        cache_layout.addWidget(cache_label)
        cache_layout.addWidget(cache_edit)
        cache_layout.addWidget(cache_browse_button)
        layout.addLayout(cache_layout)

        # Server/Path (for local and srv types)
        path_layout = QHBoxLayout()
        path_label = QLabel("Path/Server:")
        path_edit = QLineEdit()
        path_browse_button = QPushButton("Browse...")
        path_browse_button.clicked.connect(lambda: self._browse_directory(path_edit))
        path_layout.addWidget(path_label)
        path_layout.addWidget(path_edit)
        path_layout.addWidget(path_browse_button)
        layout.addLayout(path_layout)

        # Update visibility based on type
        def update_fields() -> None:
            entry_type = type_combo.currentText()
            cache_enabled = entry_type == "srv"
            cache_edit.setEnabled(cache_enabled)
            # Only enable cache browse button for "srv" type
            cache_browse_button.setEnabled(cache_enabled)
            # Disable path browse button for "srv" type (because we expect a URL)
            path_browse_enabled = entry_type == "local"
            path_browse_button.setEnabled(path_browse_enabled)
            if entry_type == "local":
                path_label.setText("Path:")
            elif entry_type == "srv":
                path_label.setText("Server:")

        type_combo.currentTextChanged.connect(update_fields)
        update_fields()

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)

        if dialog.exec_() == QDialog.DialogCode.Accepted:
            entry_type = type_combo.currentText()
            cache_path = cache_edit.text().strip()
            path = path_edit.text().strip()

            # Validate input
            if entry_type == "srv":
                if not path:
                    QMessageBox.warning(self, "Invalid Input", "Server URL is required for symbol server entries.")
                    return
            elif entry_type == "local":
                if not path:
                    QMessageBox.warning(self, "Invalid Input", "Path is required for local entries.")
                    return
            else:
                QMessageBox.warning(self, "Invalid Input", "Invalid entry type.")
                return

            # Add the entry to the table
            symbol_paths_table: QTableWidget = self.option_widgets["symbol_paths_table"]
            row = symbol_paths_table.rowCount()
            symbol_paths_table.insertRow(row)

            # Type
            type_item = QTableWidgetItem(entry_type)
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            symbol_paths_table.setItem(row, LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_TYPE, type_item)

            # Cache
            cache_item = QTableWidgetItem(cache_path if entry_type == "srv" else "")
            symbol_paths_table.setItem(row, LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_CACHE, cache_item)

            # Path/Server
            path_item = QTableWidgetItem(path)
            symbol_paths_table.setItem(row, LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_PATH, path_item)

    def _browse_directory(self, path_edit: QLineEdit) -> None:
        """
        Open a directory selection dialog and populate the path_edit field with the selected directory.
        """
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Directory",
            path_edit.text() if path_edit.text() else os.getcwd(),
            QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontResolveSymlinks,
        )
        if directory:
            # convert the separator from '/' to '\\' on Windows
            if os.name == "nt":
                directory = directory.replace("/", "\\")

            path_edit.setText(directory)

    def _on_remove_symbol_path_entry_clicked(self) -> None:
        """
        Handle the "Remove Selected" button click.
        Removes the selected rows from the symbol paths table.
        """
        symbol_paths_table: QTableWidget = self.option_widgets["symbol_paths_table"]
        selected_rows = set()

        # Get all selected rows
        for item in symbol_paths_table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select one or more rows to remove.")
            return

        # Remove rows in reverse order to maintain indices
        for row in sorted(selected_rows, reverse=True):
            symbol_paths_table.removeRow(row)

    def _split_arches(self, all_arches) -> tuple[Any, list, list]:
        """
        Split a list of architectures into three categories: The (probably) ideal architecture, recommended
        architectures, and other architectures.
        """
        return split_arches(self.partial_ld, all_arches)

    def _update_enckey_widgets(self) -> None:
        """
        Only offer the encryption key controls for outer backends that take one.
        """
        supported = self.option_widgets["outer_backend"].currentText() == CART_BACKEND_NAME

        self.option_widgets["enckey_button"].setEnabled(supported)

        label: QLabel = self.option_widgets["enckey_label"]
        label.setVisible(supported)
        if self._enckey is None:
            label.setText("Using the default encryption key")
        else:
            label.setText("Encryption key: " + key_to_hex(self._enckey))

    def _prompt_for_enckey(self) -> bytes | None:
        """
        Ask the user for an encryption key. Returns None if the user cancelled.
        """
        prompt = f"Set the encryption key that the {CART_BACKEND_NAME} backend should use."
        # the key already in use wins over the one the cart tool is configured with
        enckey = self._enckey
        if enckey is None:
            enckey = load_cart_config_key()
            if enckey is not None:
                prompt += f"\nPre-filled with {CART_CONFIG_KEY_OPTION} from {CART_CONFIG_PATH}."

        dialog = SetEncryptionKeyDialog(
            prompt_msg=prompt,
            initial_text="" if enckey is None else key_to_hex(enckey),
            parent=self,
        )
        dialog.exec_()
        return dialog.result

    def _toggle_base_addr_textbox(self, enabled: bool) -> None:
        self.option_widgets["base_addr"].setEnabled(enabled)

    def _toggle_entry_addr_textbox(self, enabled: bool) -> None:
        self.option_widgets["entry_addr"].setEnabled(enabled)

    def _toggle_offset_textbox(self, enabled: bool) -> None:
        self.option_widgets["offset"].setEnabled(enabled)

    #
    # Event handlers
    #

    def _on_base_addr_checkbox_clicked(self) -> None:
        self._toggle_base_addr_textbox(self._base_addr_checkbox.isChecked())

    def _on_entry_addr_checkbox_clicked(self) -> None:
        self._toggle_entry_addr_textbox(self._entry_addr_checkbox.isChecked())

    def _on_offset_checkbox_clicked(self) -> None:
        self._toggle_offset_textbox(self._offset_checkbox.isChecked())

    def _on_outer_backend_changed(self, text: str) -> None:  # pylint:disable=unused-argument
        self._update_enckey_widgets()

    def _on_set_enckey_clicked(self) -> None:
        enckey = self._prompt_for_enckey()
        if enckey is not None:
            self._enckey = enckey
            self._update_enckey_widgets()

    def _on_ok_clicked(self) -> None:
        force_load_libs = []
        skip_libs = set()

        dep_list: QListWidget = self.option_widgets["dep_list"]
        for i in range(dep_list.count()):
            item: QListWidgetItem = dep_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                force_load_libs.append(item.text())
            else:
                skip_libs.add(item.text())

        # self.load_options and self.simos are set only once every field is valid, so a selection that failed
        # validation and was then cancelled is not loaded
        auto_load_libs = self.option_widgets["auto_load_libs"].isChecked()
        load_debug_info = self.option_widgets["load_debug_info"].isChecked()

        outer_backend_dropdown: QComboBox = self.option_widgets["outer_backend"]
        outer_backend: str | None = outer_backend_dropdown.currentText()
        if outer_backend == NO_OUTER_BACKEND:
            outer_backend = None
        elif not outer_backend or outer_backend not in self.available_backends:
            QMessageBox.critical(None, "Incorrect backend selection", "Please select a backend before continue.")
            return

        backend_dropdown: QComboBox = self.option_widgets["backend"]
        backend: str = backend_dropdown.currentText()
        if not backend or backend not in self.available_backends:
            QMessageBox.critical(None, "Incorrect backend selection", "Please select a backend before continue.")
            return

        os_dropdown: QComboBox = self.option_widgets["os"]
        cur_simos_name: str = os_dropdown.currentText()
        if not cur_simos_name or cur_simos_name not in self.available_simos:
            QMessageBox.critical(None, "Incorrect OS selection", "Please select a OS before continue.")
            return

        arch_tree: QTreeWidget = self.option_widgets["arch"]
        item = arch_tree.currentItem()
        if not isinstance(item, ArchTreeWidgetItem):
            QMessageBox.critical(
                None, "Incorrect architecture selection", "Please select an architecture before continue."
            )
            return

        addresses = {}
        for key, checkbox, caption, message in (
            ("base_addr", self._base_addr_checkbox, "Incorrect base address", "Please input a valid base address."),
            (
                "entry_addr",
                self._entry_addr_checkbox,
                "Incorrect entry point address",
                "Please input a valid entry point address.",
            ),
            ("offset", self._offset_checkbox, "Incorrect offset", "Please input a valid offset."),
        ):
            if checkbox is not None and checkbox.isChecked():
                try:
                    addresses[key] = int(self.option_widgets[key].text(), 16)
                except ValueError:
                    QMessageBox.critical(None, caption, message)
                    return

        allow_symbol_download = True
        rows = []
        if "allow_symbol_download" in self.option_widgets:
            allow_symbol_download = self.option_widgets["allow_symbol_download"].isChecked()
        if "symbol_paths_table" in self.option_widgets:
            symbol_paths_table: QTableWidget = self.option_widgets["symbol_paths_table"]
            for row in range(symbol_paths_table.rowCount()):
                rows.append(
                    tuple(
                        symbol_paths_table.item(row, col).text()
                        for col in (
                            LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_TYPE,
                            LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_CACHE,
                            LoadBinary.PE_DEBUG_SYMBOLS_TABLE_COL_PATH,
                        )
                    )
                )

        selection = LoadSelection(
            backend=backend,
            simos_name=cur_simos_name,
            arch=item.arch,
            outer_backend=outer_backend,
            auto_load_libs=auto_load_libs,
            load_debug_info=load_debug_info,
            force_load_libs=force_load_libs,
            skip_libs=skip_libs,
            base_addr=addresses.get("base_addr"),
            entry_addr=addresses.get("entry_addr"),
            offset=addresses.get("offset"),
            allow_symbol_download=allow_symbol_download,
            symbol_path_rows=rows,
            enckey=self._enckey,
        )
        result = build_load_options(
            self.partial_ld,
            selection,
            suggested_main_opts=self.suggested_main_opts,
            suggested_main_filename=self.suggested_main_filename,
            confirm_symbol_download=LoadBinary._allow_symbol_download,
            symbol_download_progress=LoadBinary._symbol_download_progress,
        )
        self.load_options = result.load_options
        self.simos = result.simos

        self.close()

    @staticmethod
    def _allow_symbol_download(url: str) -> bool:
        """
        Callback function called by cle to confirm a symbol download.
        This will be called from a background thread, so we need to use gui_thread_schedule.
        """

        def _show_confirmation_dialog() -> bool:
            msgbox = QMessageBox(GlobalInfo.main_window)
            msgbox.setWindowTitle("Confirm Symbol Download")
            msgbox.setText(f"Download debug symbols from:\n{url}")
            msgbox.setInformativeText("Do you want to proceed?")
            msgbox.setIcon(QMessageBox.Icon.Question)
            msgbox.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            msgbox.setDefaultButton(QMessageBox.StandardButton.Yes)
            result = msgbox.exec_()
            return result == QMessageBox.StandardButton.Yes

        # Schedule on GUI thread and wait for result
        result = gui_thread_schedule(_show_confirmation_dialog, ())
        return result if result is not None else False

    @staticmethod
    def _symbol_download_progress(downloaded_bytes: int, total_bytes: int | None) -> bool:
        """
        Callback function called by cle to report download progress.
        This will be called from a background thread, so we need to use gui_thread_schedule.
        Returns False to cancel the download.
        """

        def _update_progress_dialog() -> bool:
            main_window = GlobalInfo.main_window
            if main_window is None:
                return True

            progress_dialog = main_window._progress_dialog
            if progress_dialog is None:
                return True

            # Show the progress dialog if it's not visible
            if not progress_dialog.isVisible():
                progress_dialog.show()

            # Calculate percentage
            if total_bytes is not None and total_bytes > 0:
                percentage = int((downloaded_bytes / total_bytes) * 100)
                progress_dialog.setMaximum(100)
                progress_dialog.setValue(percentage)
                progress_dialog.setLabelText(
                    f"Downloading debug symbols: {downloaded_bytes:,} / {total_bytes:,} bytes ({percentage}%)"
                )
            else:
                # Unknown total, show indeterminate progress
                progress_dialog.setMaximum(0)  # Indeterminate mode
                progress_dialog.setLabelText(f"Downloading debug symbols: {downloaded_bytes:,} bytes...")

            # Check if user cancelled
            return not progress_dialog.wasCanceled()

        # Schedule on GUI thread and wait for result
        result = gui_thread_schedule(_update_progress_dialog, ())
        return result if result is not None else True

    def _on_cancel_clicked(self) -> None:
        self.close()

    @staticmethod
    def run(
        partial_ld: cle.Loader,
        suggested_backend=None,
        suggested_os_name: str | None = None,
        suggested_main_opts: dict | None = None,
        **kwargs,
    ) -> tuple[dict | None, type | None]:
        try:
            dialog = LoadBinary(
                partial_ld,
                suggested_backend=suggested_backend,
                suggested_os_name=suggested_os_name,
                suggested_main_opts=suggested_main_opts,
                parent=GlobalInfo.main_window,
                **kwargs,
            )
            dialog.setModal(True)
            dialog.exec_()
            return dialog.load_options, dialog.simos
        except LoadBinaryError:
            pass
        return None, None

    @staticmethod
    def binary_loading_failed(filename) -> None:
        """Tell the user that ``filename`` did not load. LoadBinaryJob now says so through the UI services itself."""
        GlobalInfo.ui_services.message("critical", "Failed to load binary", f"angr failed to load binary {filename}.")
