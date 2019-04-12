import os
import logging

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget, QPushButton, QCheckBox, QFrame, QGroupBox, QListWidgetItem, QListWidget
from PySide2.QtCore import Qt

from ...plugins import PluginManager

_l = logging.getLogger(__name__)


class LoadPluginsError(Exception):
    pass


class LoadPlugins(QDialog):
    def __init__(self, plugin_mgr, parent=None):
        super(LoadPlugins, self).__init__(parent)

        # initialization
        self._pm = plugin_mgr
        self.option_widgets = { }

        # # return values
        # self.cfg_args = None
        # self.load_options = None

        self.setWindowTitle('Load a plugin')
        self.main_layout = QVBoxLayout()

        self._init_widgets()
        self._populate_list()
        self.setLayout(self.main_layout)

    # @property
    # def filename(self):
    #     return os.path.basename(self.file_path)

    #
    # Private methods
    #

    def _populate_list(self):
        plugin_list = self.option_widgets['plugin_list']  # type: QListWidget
        all_plugins = {**self._pm.default_plugins, **self._pm.user_plugins}
        #for plugin_name in all_plugins.keys():
        for plugin_name, plugin_cls in all_plugins.items():
            plugin_item = QListWidgetItem(plugin_name)
            checked = Qt.Checked if plugin_name in self._pm.loaded_plugins.keys() else Qt.Unchecked
            plugin_item.setData(Qt.CheckStateRole, checked)
            plugin_list.addItem(plugin_item)

    def _init_widgets(self):

        # # filename
        #
        # filename_caption = QLabel(self)
        # filename_caption.setText('File name:')
        #
        # filename = QLabel(self)
        # filename.setText(self.filename)
        #
        # filename_layout = QHBoxLayout()
        # filename_layout.addWidget(filename_caption)
        # filename_layout.addWidget(filename)
        # self.main_layout.addLayout(filename_layout)

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
        f = self._init_load_options_tab()
        self.main_layout.addWidget(f)

    def _init_load_options_tab(self):

        # auto load libs

        # auto_load_libs = QCheckBox(self)
        # auto_load_libs.setText("Automatically load all libraries")
        # auto_load_libs.setChecked(False)
        # self.option_widgets['auto_load_libs'] = auto_load_libs

        # dependencies list

        plugin_group = QGroupBox("Plugins")
        plugin_list = QListWidget(self)
        self.option_widgets['plugin_list'] = plugin_list

        sublayout = QVBoxLayout()
        sublayout.addWidget(plugin_list)
        plugin_group.setLayout(sublayout)

        layout = QVBoxLayout()
        #layout.addWidget(auto_load_libs)
        layout.addWidget(plugin_group)
        layout.addStretch(0)

        frame = QFrame(self)
        frame.setLayout(layout)
        return frame

    #
    # Event handlers
    #

    def _on_ok_clicked(self):

        # force_load_libs = [ ]
        # skip_libs = set()
        #
        # dep_list = self.option_widgets['dep_list']  # type: QListWidget
        # for i in range(dep_list.count()):
        #     item = dep_list.item(i)  # type: QListWidgetItem
        #     if item.checkState() == Qt.Checked:
        #         force_load_libs.append(item.text())
        #     else:
        #         skip_libs.add(item.text())
        #
        # self.load_options = { }
        # self.load_options['auto_load_libs'] = self.option_widgets['auto_load_libs'].isChecked()
        # if force_load_libs:
        #     self.load_options['force_load_libs'] = force_load_libs
        # if skip_libs:
        #     self.load_options['skip_libs'] = skip_libs
        #
        # self.cfg_args = {
        #     'resolve_indirect_jumps': self.option_widgets['resolve_indirect_jumps'].isChecked(),
        #     'collect_data_references': self.option_widgets['collect_data_refs'].isChecked(),
        # }

        self.close()

    def _on_cancel_clicked(self):
        self.close()
