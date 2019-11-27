import logging
from typing import Type, List

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QFrame, QGroupBox, QListWidgetItem, \
    QListWidget, QFileDialog, QMessageBox
from PySide2.QtCore import Qt

from angrmanagement.plugins import load_plugins_from_file

_l = logging.getLogger(__name__)


class QPluginListWidgetItem(QListWidgetItem):
    def __init__(self, plugin_cls, **kwargs):
        super().__init__(**kwargs)
        self.plugin_class = plugin_cls  # type: Type[BasePlugin]
        self.setText(plugin_cls.get_display_name())


# TODO: Add plugin settings, reloading, etc.

class LoadPlugins(QDialog):
    def __init__(self, plugin_mgr, parent=None):
        super(LoadPlugins, self).__init__(parent)

        self._pm = plugin_mgr  # type: PluginManager
        self._installed_plugin_list = None  # type: QListWidget

        self.setWindowTitle('Installed Plugins')
        self.main_layout = QVBoxLayout()

        self._init_widgets()
        self._populate_installed_plugin_list()
        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_plugin_list(self):
        plugin_group = QGroupBox("Plugins")
        self._installed_plugin_list = QListWidget(self)

        sublayout = QVBoxLayout()
        sublayout.addWidget(self._installed_plugin_list)
        plugin_group.setLayout(sublayout)

        layout = QVBoxLayout()
        # layout.addWidget(auto_load_libs)
        layout.addWidget(plugin_group)
        layout.addStretch(0)

        frame = QFrame(self)
        frame.setLayout(layout)

        self.main_layout.addWidget(frame)

    def _populate_installed_plugin_list(self):
        for cls in self._pm.loaded_plugins:
            plugin_item = QPluginListWidgetItem(plugin_cls=cls)
            if self._pm.get_plugin_instance(cls) is not None:
                plugin_item.setCheckState(Qt.Checked)
            else:
                plugin_item.setCheckState(Qt.Unchecked)
            self._installed_plugin_list.addItem(plugin_item)

    def _init_widgets(self):
        load_button = QPushButton(self)
        load_button.setText("Load Plugin")
        load_button.clicked.connect(self._on_load_clicked)
        self.main_layout.addWidget(load_button)

        self._init_plugin_list()

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

    #
    # Event handlers
    #

    def _on_ok_clicked(self):
        list_items = self._installed_plugin_list.findItems('*', Qt.MatchWildcard)  # type: List[QPluginListWidgetItem]
        for i in list_items:
            checked = i.checkState() == Qt.Checked

            if checked and self._pm.get_plugin_instance(i.plugin_class) is None:
                self._pm.activate_plugin(i.plugin_class)
            elif not checked and self._pm.get_plugin_instance(i.plugin_class) is not None:
                self._pm.deactivate_plugin(i.plugin_class)
            else:
                self._pm.load_plugin(i.plugin_class)

        self.close()

    def _on_cancel_clicked(self):
        self.close()

    def _on_load_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open a plugin (select __init__.py for packages)", "", "Python files (*.py)")
        if not file_path:
            return
        plugins = load_plugins_from_file(file_path)

        if not plugins:
            QMessageBox.warning(self, "Error", "File contained no plugins")
            return

        errors = [x for x in plugins if isinstance(x, Exception)]
        if errors:
            QMessageBox.warning(self, "Error", "Loading errored with %s" % errors[0])
            return

        for plugin in plugins:
            plugin_item = QPluginListWidgetItem(plugin_cls=plugin)
            plugin_item.setCheckState(Qt.Unchecked)
            self._installed_plugin_list.addItem(plugin_item)
