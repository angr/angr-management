from typing import Tuple, Dict, Optional
import os
import binascii
import logging
import archinfo
from cle import Blob

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget, QCheckBox, QFrame, QGroupBox, \
    QListWidgetItem, QListWidget, QMessageBox, QLineEdit, QGridLayout, QComboBox, QSizePolicy, QDialogButtonBox
from PySide2.QtCore import Qt


l = logging.getLogger('dialogs.load_binary')


class LoadBinaryError(Exception):
    """
    An error loading the binary.
    """


class LoadBinary(QDialog):
    """
    Dialog displaying loading options for a binary.
    """

    def __init__(self, partial_ld, parent=None):
        super().__init__(parent)

        # initialization
        self.file_path = partial_ld.main_object.binary
        self.md5 = None
        self.sha256 = None
        self.option_widgets = { }
        self.is_blob = isinstance(partial_ld.main_object, Blob)
        self.arch = partial_ld.main_object.arch

        # return values
        self.load_options = None

        self.setWindowTitle('Load a new binary')

        # checksums
        if hasattr(partial_ld.main_object, 'md5') and partial_ld.main_object.md5 is not None:
            self.md5 = binascii.hexlify(partial_ld.main_object.md5).decode("ascii")
        if hasattr(partial_ld.main_object, 'sha256') and partial_ld.main_object.sha256 is not None:
            self.sha256 = binascii.hexlify(partial_ld.main_object.sha256).decode("ascii")

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self._try_loading(partial_ld)

        self.setLayout(self.main_layout)

    @property
    def filename(self):
        return os.path.basename(self.file_path)

    #
    # Private methods
    #

    def _try_loading(self, partial_ld):
        deps = [ ]
        processed_objects = set()
        for ident, obj in partial_ld._satisfied_deps.items():
            if obj is partial_ld._kernel_object or \
                    obj is partial_ld._extern_object or \
                    obj is partial_ld.main_object:
                continue
            if obj in processed_objects:
                continue
            deps.append(ident)
            processed_objects.add(obj)

        # dependencies

        dep_list = self.option_widgets['dep_list']  # type: QListWidget
        for dep in deps:
            dep_item = QListWidgetItem(dep)
            dep_item.setData(Qt.CheckStateRole, Qt.Unchecked)
            dep_list.addItem(dep_item)

    def _init_widgets(self):

        layout = QGridLayout()
        self.main_layout.addLayout(layout)

        # filename

        filename_caption = QLabel(self)
        filename_caption.setText('File name:')

        filename = QLabel(self)
        filename.setText(self.filename)

        layout.addWidget(filename_caption, 0, 0, Qt.AlignRight)
        layout.addWidget(filename, 0, 1)

        # md5

        if self.md5 is not None:
            md5_caption = QLabel(self)
            md5_caption.setText('MD5:')
            md5 = QLineEdit(self)
            md5.setText(self.md5)
            md5.setReadOnly(True)

            layout.addWidget(md5_caption, 1, 0, Qt.AlignRight)
            layout.addWidget(md5, 1, 1)

        # sha256

        if self.sha256 is not None:
            sha256_caption = QLabel(self)
            sha256_caption.setText('SHA256:')
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
        arch_layout = QHBoxLayout()
        arch_caption = QLabel(self)
        arch_caption.setText('Architecture:')
        arch_caption.setSizePolicy(QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed))
        arch_layout.addWidget(arch_caption)
        arch_combo = QComboBox(self)
        for arch in archinfo.all_arches:
            addendum = ' (P-code Engine)' if hasattr(arch, 'pcode_arch') else ''
            arch_combo.addItem(f'{arch.bits}b {arch.name} ({arch.memory_endness[-2:]}){addendum}', str(arch))
        index = arch_combo.findData(str(self.arch))
        arch_combo.setCurrentIndex(index)
        arch_layout.addWidget(arch_combo)
        self.option_widgets['arch'] = arch_combo

        if self.is_blob:
            blob_layout = QGridLayout()

            # load address
            base_addr_caption = QLabel(self)
            base_addr_caption.setText('Base Address:')
            blob_layout.addWidget(base_addr_caption, 1, 0)
            base_addr = QLineEdit(self)
            base_addr.setText('0')
            blob_layout.addWidget(base_addr, 1, 1)
            self.option_widgets['base_addr'] = base_addr

            # entry address
            entry_addr_caption = QLabel(self)
            entry_addr_caption.setText('Entry Address:')
            blob_layout.addWidget(entry_addr_caption, 2, 0)
            entry_addr = QLineEdit(self)
            entry_addr.setText('0')
            blob_layout.addWidget(entry_addr, 2, 1)
            self.option_widgets['entry_addr'] = entry_addr

        # load debug symbols
        load_debug_info = QCheckBox()
        load_debug_info.setText("Load debug information if available")
        load_debug_info.setChecked(True)
        self.option_widgets['load_debug_info'] = load_debug_info

        # auto load libs

        auto_load_libs = QCheckBox()
        auto_load_libs.setText("Automatically load all libraries (slow, not recommended)")
        auto_load_libs.setChecked(False)
        self.option_widgets['auto_load_libs'] = auto_load_libs

        # dependencies list

        dep_group = QGroupBox("Dependencies")
        dep_list = QListWidget()
        self.option_widgets['dep_list'] = dep_list

        sublayout = QVBoxLayout()
        sublayout.addWidget(dep_list)
        dep_group.setLayout(sublayout)

        layout = QVBoxLayout()
        if self.is_blob:
            layout.addLayout(blob_layout)
        layout.addLayout(arch_layout)
        layout.addWidget(load_debug_info)
        layout.addWidget(auto_load_libs)
        layout.addWidget(dep_group)
        layout.addStretch(0)

        frame = QFrame(self)
        frame.setLayout(layout)
        tab.addTab(frame, "Loading Options")

    #
    # Event handlers
    #

    def _on_ok_clicked(self):

        force_load_libs = [ ]
        skip_libs = set()

        dep_list = self.option_widgets['dep_list']  # type: QListWidget
        for i in range(dep_list.count()):
            item = dep_list.item(i)  # type: QListWidgetItem
            if item.checkState() == Qt.Checked:
                force_load_libs.append(item.text())
            else:
                skip_libs.add(item.text())

        self.load_options = { }
        self.load_options['auto_load_libs'] = self.option_widgets['auto_load_libs'].isChecked()
        self.load_options['load_debug_info'] = self.option_widgets['load_debug_info'].isChecked()
        self.load_options['arch'] = archinfo.all_arches[self.option_widgets['arch'].currentIndex()]

        if self.is_blob:
            self.load_options['main_opts'] = {
                'backend': 'blob',
                'base_addr': int(self.option_widgets['base_addr'].text(), 16),
                'entry_point': int(self.option_widgets['entry_addr'].text(), 16),
            }

        if force_load_libs:
            self.load_options['force_load_libs'] = force_load_libs
        if skip_libs:
            self.load_options['skip_libs'] = skip_libs

        self.close()

    def _on_cancel_clicked(self):
        self.close()

    @staticmethod
    def run(partial_ld) -> Tuple[Optional[Dict],Optional[Dict],Optional[Dict]]:
        try:
            dialog = LoadBinary(partial_ld)
            dialog.setModal(True)
            dialog.exec_()
            return dialog.load_options
        except LoadBinaryError:
            pass
        return None, None, None

    @staticmethod
    def binary_arch_detect_failed(filename:str, archinfo_msg:str):
        # TODO: Normalize the path for Windows
        QMessageBox.warning(None,
                            "Architecture selection failed",
                            f"{archinfo_msg} for binary:\n\n{filename}")

    @staticmethod
    def binary_loading_failed(filename):
        # TODO: Normalize the path for Windows
        QMessageBox.critical(None,
                             "Failed to load binary",
                             f"angr failed to load binary {filename}.")
