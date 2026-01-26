from __future__ import annotations

import binascii
import os
from typing import Any

import archinfo
import cle
from angr.calling_conventions import unify_arch_name
from angr.simos import os_mapping
from cle.backends.pe.symbolserver import SymbolPathParser
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
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
    QWidget,
)

try:
    import pypcode
except ImportError:
    pypcode = None

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule


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


class LoadBinary(QDialog):
    """
    Dialog displaying loading options for a binary.
    """

    def __init__(
        self,
        partial_ld,
        suggested_backend: cle.Backend | None = None,
        suggested_os_name: str | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)

        # initialization
        self.file_path = partial_ld.main_object.binary
        self.partial_ld = partial_ld
        self.md5 = None
        self.sha256 = None
        self.option_widgets = {}
        self.suggested_backend = suggested_backend
        self.suggested_os_name = suggested_os_name
        self.available_backends: dict[str, cle.Backend] = cle.ALL_BACKENDS
        self.available_simos = {}
        self.arch = partial_ld.main_object.arch
        self.available_archs = archinfo.all_arches[::]
        # _try_loading will try its best to fill in the following two properties from partial_ld
        self._base_addr: int | None = None
        self._entry_addr: int | None = None

        self._base_addr_checkbox = None
        self._entry_addr_checkbox = None
        self._symbol_search_tab_index = None

        if pypcode:
            for a in pypcode.Arch.enumerate():
                self.available_archs.extend(sorted(a.languages, key=lambda lang: lang.id))

        # return values
        self.load_options = None
        self.simos = None

        for _, simos in os_mapping.items():
            self.available_simos[simos.__name__] = simos
        self.available_simos["Unknown"] = None

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
        return os.path.basename(self.file_path)

    #
    # Private methods
    #

    def _try_loading(self, partial_ld) -> None:
        deps = []
        for ident in sorted(partial_ld.requested_names):
            deps.append(ident)

        # dependencies

        dep_list: QListWidget = self.option_widgets["dep_list"]
        for dep in deps:
            dep_item = QListWidgetItem(dep)
            dep_item.setData(Qt.ItemDataRole.CheckStateRole, Qt.CheckState.Unchecked)
            dep_list.addItem(dep_item)

        # update the dependencies tab text
        self.tab.setTabText(DEPENDENCIES_TAB_INDEX, f"Dependencies ({len(deps)})")

        if partial_ld.main_object is not None:
            if isinstance(partial_ld.main_object, cle.MetaELF | cle.PE | cle.MachO | cle.CGC):
                self._base_addr = partial_ld.main_object.mapped_base
                self._entry_addr = partial_ld.main_object.entry
            else:
                if hasattr(partial_ld.main_object, "mapped_base"):
                    self._base_addr = partial_ld.main_object.mapped_base
                if hasattr(partial_ld.main_object, "entry"):
                    self._entry_addr = partial_ld.main_object.entry

            # don't know what to do with other backends...

    def _set_base_addr(self) -> None:
        # special handling for blobs
        if isinstance(self.suggested_backend, cle.Blob):
            self._toggle_base_addr_textbox(True)
            self._toggle_entry_addr_textbox(True)
            self.option_widgets["entry_addr"].setText("0x0")
            self.option_widgets["base_addr"].setText("0x0")
        else:
            self._toggle_base_addr_textbox(False)
            self._toggle_entry_addr_textbox(False)

            if self._entry_addr is not None:
                self.option_widgets["entry_addr"].setText(hex(self._entry_addr))
            if self._base_addr is not None:
                self.option_widgets["base_addr"].setText(hex(self._base_addr))

    def _init_widgets(self) -> None:
        layout = QGridLayout()
        self.main_layout.addLayout(layout)

        # filename

        filename_caption = QLabel(self)
        filename_caption.setText("File name:")

        filename = QLabel(self)
        filename.setText(self.filename)

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
        # Backend selection
        #
        backend_layout = QHBoxLayout()
        backend_caption = QLabel()
        backend_caption.setText("Backend:")
        backend_caption.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        backend_layout.addWidget(backend_caption)

        backend_dropdown = QComboBox()
        suggested_backend_name = None
        for backend_name, backend in self.available_backends.items():
            backend_dropdown.addItem(backend_name)
            if backend is self.suggested_backend:
                suggested_backend_name = backend_name
        if suggested_backend_name is not None:
            backend_dropdown.setCurrentText(suggested_backend_name)
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
        if "Unknown" in self.available_simos:
            os_dropdown.setCurrentText("Unknown")
        if self.suggested_os_name is not None:
            suggested_os = os_mapping[self.suggested_os_name].__name__
            if suggested_os in self.available_simos:
                os_dropdown.setCurrentText(suggested_os)
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

        # load debug symbols
        load_debug_info = QCheckBox()
        load_debug_info.setText("Load debug information if available")
        load_debug_info.setChecked(True)
        self.option_widgets["load_debug_info"] = load_debug_info

        layout = QVBoxLayout()
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

        # Three-column table for symbol paths
        symbol_paths_table = QTableWidget(self)
        symbol_paths_table.setColumnCount(4)
        symbol_paths_table.setHorizontalHeaderLabels(["Enabled", "Type", "Cache", "Server"])
        symbol_paths_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        symbol_paths_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        symbol_paths_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        symbol_paths_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        symbol_paths_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.option_widgets["symbol_paths_table"] = symbol_paths_table
        layout.addWidget(symbol_paths_table)

        # Button for parsing environment variables
        parse_env_button = QPushButton("Enter symbol path string")
        parse_env_button.clicked.connect(self._on_parse_symbol_path_clicked)
        layout.addWidget(parse_env_button)

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

        # Also enable/disable all widgets inside the tab
        frame = self.tab.widget(self._symbol_search_tab_index)
        if frame:
            for widget in frame.findChildren(QWidget):
                widget.setEnabled(is_enabled)

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
        entries = SymbolPathParser.parse(text)

        symbol_paths_table: QTableWidget = self.option_widgets["symbol_paths_table"]
        symbol_paths_table.setRowCount(len(entries))

        for row, entry in enumerate(entries):
            # Enabled checkbox
            enabled_item = QTableWidgetItem()
            enabled_item.setCheckState(Qt.CheckState.Checked)
            symbol_paths_table.setItem(row, 0, enabled_item)

            # Path type
            type_item = QTableWidgetItem(entry.entry_type)
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            symbol_paths_table.setItem(row, 1, type_item)

            # Path
            match entry.entry_type:
                case "local":
                    cache = ""
                    path = entry.local_path
                case "srv" | "symsrv":
                    cache = entry.cache_path
                    path = entry.server_url
                case "cache":
                    cache = entry.cache_path
                    path = ""
            cache_item = QTableWidgetItem(cache)
            symbol_paths_table.setItem(row, 2, cache_item)
            path_item = QTableWidgetItem(path)
            symbol_paths_table.setItem(row, 3, path_item)

    def _split_arches(self, all_arches) -> tuple[Any, list, list]:
        """
        Split a list of architectures into three categories: The (probably) ideal architecture, recommended
        architectures, and other architectures.
        """
        the_arch = None
        recommended_arches = []
        other_arches = []

        self_arch_str = str(self.arch)

        for arch in all_arches:
            if isinstance(arch, archinfo.Arch):
                if str(arch) == self_arch_str:
                    the_arch = arch
                elif arch.name == self.arch.name:
                    recommended_arches.append(arch)
                else:
                    other_arches.append(arch)
            elif pypcode and isinstance(arch, pypcode.ArchLanguage):
                if self.arch is not None:
                    if self.arch.name == arch.id:
                        the_arch = arch
                    elif self.arch.name.lower() in arch.id.lower() or self.arch.name == unify_arch_name(arch.id):
                        recommended_arches.append(arch)
                    else:
                        other_arches.append(arch)
            else:
                raise TypeError(f"Unknown architecture type {type(arch)}")

        return the_arch, recommended_arches, other_arches

    def _toggle_base_addr_textbox(self, enabled: bool) -> None:
        self.option_widgets["base_addr"].setEnabled(enabled)

    def _toggle_entry_addr_textbox(self, enabled: bool) -> None:
        self.option_widgets["entry_addr"].setEnabled(enabled)

    #
    # Event handlers
    #

    def _on_base_addr_checkbox_clicked(self) -> None:
        self._toggle_base_addr_textbox(self._base_addr_checkbox.isChecked())

    def _on_entry_addr_checkbox_clicked(self) -> None:
        self._toggle_entry_addr_textbox(self._entry_addr_checkbox.isChecked())

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

        self.load_options = {}
        self.load_options["auto_load_libs"] = self.option_widgets["auto_load_libs"].isChecked()
        self.load_options["load_debug_info"] = self.option_widgets["load_debug_info"].isChecked()

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

        arch = item.arch
        if pypcode and isinstance(arch, pypcode.ArchLanguage):
            arch = archinfo.ArchPcode(arch.id)
        self.load_options["arch"] = arch

        self.load_options["main_opts"] = {
            "backend": backend,
        }

        self.simos = self.available_simos[cur_simos_name]

        if self._base_addr_checkbox.isChecked():
            try:
                base_addr = int(self.option_widgets["base_addr"].text(), 16)
            except ValueError:
                QMessageBox.critical(None, "Incorrect base address", "Please input a valid base address.")
                return
            self.load_options["main_opts"]["base_addr"] = base_addr

        if self._entry_addr_checkbox.isChecked():
            try:
                entry_addr = int(self.option_widgets["entry_addr"].text(), 16)
            except ValueError:
                QMessageBox.critical(None, "Incorrect entry point address", "Please input a valid entry point address.")
                return
            self.load_options["main_opts"]["entry_point"] = entry_addr

        if force_load_libs:
            self.load_options["force_load_libs"] = force_load_libs
        if skip_libs:
            self.load_options["skip_libs"] = skip_libs

        # Collect symbol search options for PE files
        if isinstance(self.partial_ld.main_object, cle.PE):
            if "allow_symbol_download" in self.option_widgets:
                self.load_options["main_opts"]["download_debug_symbols"] = self.option_widgets[
                    "allow_symbol_download"
                ].isChecked()

            if "symbol_paths_table" in self.option_widgets:
                symbol_paths_table: QTableWidget = self.option_widgets["symbol_paths_table"]
                symbol_paths = []
                for row in range(symbol_paths_table.rowCount()):
                    enabled_item = symbol_paths_table.item(row, 0)
                    type_item = symbol_paths_table.item(row, 1)
                    cache_item = symbol_paths_table.item(row, 2)
                    path_item = symbol_paths_table.item(row, 3)
                    if enabled_item and path_item and enabled_item.checkState() == Qt.CheckState.Checked:
                        # build symbol path string
                        match type_item.text():
                            case "local":
                                symbol_paths.append(path_item.text())
                            case "srv" | "symsrv":
                                if path_item.text():
                                    if cache_item.text():
                                        symbol_paths.append(f"srv*{cache_item.text()}*{path_item.text()}")
                                    else:
                                        symbol_paths.append(f"srv*{path_item.text()}")
                            case "cache":
                                if cache_item.text():
                                    symbol_paths.append(f"cache*{cache_item.text()}")
                if symbol_paths:
                    self.load_options["main_opts"]["symbol_paths"] = ";".join(symbol_paths)

            # Add confirmation and progress callbacks
            self.load_options["main_opts"]["download_debug_symbol_confirm"] = LoadBinary._allow_symbol_download
            self.load_options["main_opts"]["download_debug_symbol_progress"] = LoadBinary._symbol_download_progress

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
        partial_ld, suggested_backend=None, suggested_os_name: str | None = None
    ) -> tuple[dict | None, dict | None]:
        try:
            dialog = LoadBinary(
                partial_ld,
                suggested_backend=suggested_backend,
                suggested_os_name=suggested_os_name,
                parent=GlobalInfo.main_window,
            )
            dialog.setModal(True)
            dialog.exec_()
            return dialog.load_options, dialog.simos
        except LoadBinaryError:
            pass
        return None, None

    @staticmethod
    def binary_loading_failed(filename) -> None:
        # TODO: Normalize the path for Windows
        QMessageBox.critical(None, "Failed to load binary", f"angr failed to load binary {filename}.")
