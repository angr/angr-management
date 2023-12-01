import logging
from pathlib import Path
from typing import TYPE_CHECKING, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from angrmanagement.plugins import load_plugin_description

if TYPE_CHECKING:
    from angrmanagement.plugins import PluginDescription, PluginManager


_l = logging.getLogger(__name__)


class QPluginListWidgetItem(QListWidgetItem):
    """
    Plugin list item.
    """

    def __init__(self, plugin_desc, **kwargs):
        super().__init__(**kwargs)
        self.plugin_desc: PluginDescription = plugin_desc
        self.setText(plugin_desc.name)


# TODO: Add plugin settings, reloading, etc.


class LoadPlugins(QDialog):
    """
    Dialog to display loaded plugins, enable/disable plugins, and load new plugins.
    """

    def __init__(self, plugin_mgr, parent=None):
        super().__init__(parent)

        self._pm: PluginManager = plugin_mgr
        self._installed_plugin_list: QListWidget

        self.setWindowTitle("Installed Plugins")
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
        layout.addWidget(plugin_group)

        frame = QFrame(self)
        frame.setLayout(layout)

        self.main_layout.addWidget(frame)

    def _populate_installed_plugin_list(self):
        for _, desc in self._pm.loaded_plugins.items():
            plugin_item = QPluginListWidgetItem(plugin_desc=desc)
            if self._pm.get_plugin_instance_by_name(desc.shortname) is not None:
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

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)
        self.main_layout.addWidget(buttons)

    #
    # Event handlers
    #

    def _on_ok_clicked(self):
        list_items: List[QPluginListWidgetItem] = self._installed_plugin_list.findItems("*", Qt.MatchWildcard)
        for i in list_items:
            checked = i.checkState() == Qt.Checked

            if checked and self._pm.get_plugin_instance_by_name(i.plugin_desc.shortname) is None:
                self._pm.activate_plugin_by_name(i.plugin_desc.shortname)
            elif not checked and self._pm.get_plugin_instance_by_name(i.plugin_desc.shortname) is not None:
                self._pm.deactivate_plugin_by_name(i.plugin_desc.shortname)

        self._pm.save_enabled_plugins_to_config()
        self.close()

    def _on_load_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open a plugin description file (plugin.toml)", "", "Toml files (*.toml)"
        )
        if not file_path:
            return
        plugins = load_plugin_description(str(Path(file_path).parent))

        if not plugins:
            QMessageBox.warning(self, "Error", "File contained no plugin descriptions")
            return

        for plugin in plugins:
            plugin_item = QPluginListWidgetItem(plugin_desc=plugin)
            plugin_item.setCheckState(Qt.Unchecked)
            self._pm.loaded_plugins[plugin.shortname] = plugin
            self._installed_plugin_list.addItem(plugin_item)
