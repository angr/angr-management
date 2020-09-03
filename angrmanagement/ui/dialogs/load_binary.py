import os
import binascii
import logging
import archinfo
from cle import Blob

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget, QPushButton, QCheckBox, QFrame, \
    QGroupBox, QListWidgetItem, QListWidget, QMessageBox, QLineEdit, QGridLayout, QComboBox
from PySide2.QtCore import Qt


l = logging.getLogger('dialogs.load_binary')


class LoadBinaryError(Exception):
    pass


class LoadBinary(QDialog):
    def __init__(self, partial_ld, parent=None):
        super(LoadBinary, self).__init__(parent)

        # initialization
        self.file_path = partial_ld.main_object.binary
        self.md5 = None
        self.sha256 = None
        self.option_widgets = { }
        self.is_blob = isinstance(partial_ld.main_object, Blob)

        # return values
        self.cfg_args = None
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

        ok_button = QPushButton(self)
        ok_button.setText('OK')
        ok_button.clicked.connect(self._on_ok_clicked)

        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        self.main_layout.addLayout(buttons_layout)

    def _init_central_tab(self, tab):
        self._init_load_options_tab(tab)
        self._init_cfg_options_tab(tab)

    def _init_load_options_tab(self, tab):
        if self.is_blob:
            blob_layout = QGridLayout()

            # architecture selection
            arch_caption = QLabel(self)
            arch_caption.setText('Architecture:')
            blob_layout.addWidget(arch_caption, 0, 0)
            arch = QComboBox(self)
            for a in archinfo.all_arches:
                arch.addItem(f'{a.bits}b {a.name} ({a.memory_endness[-2:]})')
            blob_layout.addWidget(arch, 0, 1)
            self.option_widgets['arch'] = arch

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
        layout.addWidget(load_debug_info)
        layout.addWidget(auto_load_libs)
        layout.addWidget(dep_group)
        layout.addStretch(0)

        frame = QFrame(self)
        frame.setLayout(layout)
        tab.addTab(frame, "Loading Options")

    def _init_cfg_options_tab(self, tab):
        resolve_indirect_jumps = QCheckBox(self)
        resolve_indirect_jumps.setText('Resolve indirect jumps')
        resolve_indirect_jumps.setChecked(True)
        self.option_widgets['resolve_indirect_jumps'] = resolve_indirect_jumps

        collect_data_refs = QCheckBox(self)
        collect_data_refs.setText('Collect data references (one per data item) and guess data types')
        collect_data_refs.setChecked(True)
        self.option_widgets['data_references'] = collect_data_refs

        xrefs = QCheckBox(self)
        xrefs.setText('Collect cross references')
        xrefs.setChecked(True)
        self.option_widgets['cross_references'] = xrefs

        layout = QVBoxLayout()
        layout.addWidget(resolve_indirect_jumps)
        layout.addWidget(collect_data_refs)
        layout.addWidget(xrefs)
        layout.addStretch(0)
        frame = QFrame(self)
        frame.setLayout(layout)
        tab.addTab(frame, 'CFG Options')

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

        if self.is_blob:
            self.load_options['main_opts'] = {
                'backend': 'blob',
                'arch': archinfo.all_arches[self.option_widgets['arch'].currentIndex()],
                'base_addr': int(self.option_widgets['base_addr'].text(), 16),
                'entry_point': int(self.option_widgets['entry_addr'].text(), 16),
            }

        if force_load_libs:
            self.load_options['force_load_libs'] = force_load_libs
        if skip_libs:
            self.load_options['skip_libs'] = skip_libs

        self.cfg_args = {
            'resolve_indirect_jumps': self.option_widgets['resolve_indirect_jumps'].isChecked(),
            'data_references': self.option_widgets['data_references'].isChecked(),
            'cross_references': self.option_widgets['cross_references'].isChecked(),
        }

        self.close()

    def _on_cancel_clicked(self):
        self.cfg_args = None
        self.close()

    @staticmethod
    def run(partial_ld):
        try:
            dialog = LoadBinary(partial_ld)
            dialog.setModal(True)
            dialog.exec_()

            if dialog.cfg_args is not None:
                # load the binary
                return dialog.load_options, dialog.cfg_args
        except LoadBinaryError:
            pass
        return None, None

    @staticmethod
    def binary_loading_failed(filename):
        # TODO: Normalize the path for Windows
        QMessageBox.critical(None,
                             "Failed to load binary",
                             "angr failed to load binary %s." % filename)
