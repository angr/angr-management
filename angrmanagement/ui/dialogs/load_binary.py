import binascii
import os
from typing import Any, Dict, List, Optional, Tuple

import archinfo
import cle
from angr.calling_conventions import unify_arch_name
from angr.simos import os_mapping
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
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSizePolicy,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

try:
    import pypcode
except ImportError:
    pypcode = None

from angrmanagement.logic import GlobalInfo


class LoadBinaryError(Exception):
    """
    An error loading the binary.
    """


class ArchTreeWidgetItem(QTreeWidgetItem):
    """
    A custom tree-view widget item for the architecture selection TreeView.
    """

    def __init__(self, name, arch):
        super().__init__()
        self.name = name
        self.arch = arch
        self.setText(0, name)


class LoadBinary(QDialog):
    """
    Dialog displaying loading options for a binary.
    """

    def __init__(
        self, partial_ld, suggested_backend: Optional[cle.Backend] = None, suggested_os_name=None, parent=None
    ):
        super().__init__(parent)

        # initialization
        self.file_path = partial_ld.main_object.binary
        self.md5 = None
        self.sha256 = None
        self.option_widgets = {}
        self.suggested_backend = suggested_backend
        self.suggested_os_name = suggested_os_name
        self.available_backends: Dict[str, cle.Backend] = cle.ALL_BACKENDS
        self.available_simos = {}
        self.arch = partial_ld.main_object.arch
        self.available_archs = archinfo.all_arches[::]
        # _try_loading will try its best to fill in the following two properties from partial_ld
        self._base_addr: Optional[int] = None
        self._entry_addr: Optional[int] = None

        self._base_addr_checkbox = None
        self._entry_addr_checkbox = None

        if pypcode:
            for a in pypcode.Arch.enumerate():
                self.available_archs.extend(sorted(a.languages, key=lambda lang: lang.id))

        # return values
        self.load_options = None
        self.simos = None

        for _, simos in os_mapping.items():
            self.available_simos[simos.__name__] = simos

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

    def _try_loading(self, partial_ld):
        deps = []
        processed_objects = set()
        for ident, obj in partial_ld._satisfied_deps.items():
            if obj is partial_ld._kernel_object or obj is partial_ld._extern_object or obj is partial_ld.main_object:
                continue
            if obj in processed_objects:
                continue
            deps.append(ident)
            processed_objects.add(obj)

        # dependencies

        dep_list: QListWidget = self.option_widgets["dep_list"]
        for dep in deps:
            dep_item = QListWidgetItem(dep)
            dep_item.setData(Qt.CheckStateRole, Qt.Unchecked)
            dep_list.addItem(dep_item)

        if partial_ld.main_object is not None:
            if isinstance(partial_ld.main_object, cle.MetaELF):
                self._base_addr = partial_ld.main_object.mapped_base
                self._entry_addr = partial_ld.main_object.entry
            elif isinstance(partial_ld.main_object, cle.PE):
                self._base_addr = partial_ld.main_object.mapped_base
                self._entry_addr = partial_ld.main_object.entry
            elif isinstance(partial_ld.main_object, cle.MachO):
                self._base_addr = partial_ld.main_object.mapped_base
                self._entry_addr = partial_ld.main_object.entry
            elif isinstance(partial_ld.main_object, cle.CGC):
                self._base_addr = partial_ld.main_object.mapped_base
                self._entry_addr = partial_ld.main_object.entry
            else:
                if hasattr(partial_ld.main_object, "mapped_base"):
                    self._base_addr = partial_ld.main_object.mapped_base
                if hasattr(partial_ld.main_object, "entry"):
                    self._entry_addr = partial_ld.main_object.entry

            # don't know what to do with other backends...

    def _set_base_addr(self):
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

    def _init_widgets(self):
        layout = QGridLayout()
        self.main_layout.addLayout(layout)

        # filename

        filename_caption = QLabel(self)
        filename_caption.setText("File name:")

        filename = QLabel(self)
        filename.setText(self.filename)

        layout.addWidget(filename_caption, 0, 0, Qt.AlignRight)
        layout.addWidget(filename, 0, 1)

        # md5

        if self.md5 is not None:
            md5_caption = QLabel(self)
            md5_caption.setText("MD5:")
            md5 = QLineEdit(self)
            md5.setText(self.md5)
            md5.setReadOnly(True)

            layout.addWidget(md5_caption, 1, 0, Qt.AlignRight)
            layout.addWidget(md5, 1, 1)

        # sha256

        if self.sha256 is not None:
            sha256_caption = QLabel(self)
            sha256_caption.setText("SHA256:")
            sha256 = QLineEdit(self)
            sha256.setText(self.sha256)
            sha256.setReadOnly(True)

            layout.addWidget(sha256_caption, 2, 0, Qt.AlignRight)
            layout.addWidget(sha256, 2, 1)

        # central tab

        tab = QTabWidget()
        self._init_central_tab(tab)

        self.main_layout.addWidget(tab)

        # buttons

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self._on_cancel_clicked)
        self.main_layout.addWidget(buttons)

    def _init_central_tab(self, tab):
        self._init_load_options_tab(tab)

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
        if self.suggested_os_name is not None:
            os_dropdown.setCurrentText(os_mapping[self.suggested_os_name].__name__)
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
        tab.addTab(frame, "Loading Options")

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

    def _split_arches(self, all_arches) -> Tuple[Any, List, List]:
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
                    elif self.arch.name.lower() in arch.id.lower():
                        recommended_arches.append(arch)
                    elif self.arch.name == unify_arch_name(arch.id):
                        recommended_arches.append(arch)
                    else:
                        other_arches.append(arch)
            else:
                raise TypeError(f"Unknown architecture type {type(arch)}")

        return the_arch, recommended_arches, other_arches

    def _toggle_base_addr_textbox(self, enabled: bool):
        self.option_widgets["base_addr"].setEnabled(enabled)

    def _toggle_entry_addr_textbox(self, enabled: bool):
        self.option_widgets["entry_addr"].setEnabled(enabled)

    #
    # Event handlers
    #

    def _on_base_addr_checkbox_clicked(self):
        self._toggle_base_addr_textbox(self._base_addr_checkbox.isChecked())

    def _on_entry_addr_checkbox_clicked(self):
        self._toggle_entry_addr_textbox(self._entry_addr_checkbox.isChecked())

    def _on_ok_clicked(self):
        force_load_libs = []
        skip_libs = set()

        dep_list: QListWidget = self.option_widgets["dep_list"]
        for i in range(dep_list.count()):
            item: QListWidgetItem = dep_list.item(i)
            if item.checkState() == Qt.Checked:
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

        self.close()

    def _on_cancel_clicked(self):
        self.close()

    @staticmethod
    def run(
        partial_ld, suggested_backend=None, suggested_os_name=None
    ) -> Tuple[Optional[Dict], Optional[Dict], Optional[Dict]]:
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
        return None, None, None

    @staticmethod
    def binary_arch_detect_failed(filename: str, archinfo_msg: str):
        # TODO: Normalize the path for Windows
        QMessageBox.warning(None, "Architecture selection failed", f"{archinfo_msg} for binary:\n\n{filename}")

    @staticmethod
    def binary_loading_failed(filename):
        # TODO: Normalize the path for Windows
        QMessageBox.critical(None, "Failed to load binary", f"angr failed to load binary {filename}.")
