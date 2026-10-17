from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGroupBox,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)

from angrmanagement.logic import GlobalInfo
from angrmanagement.present.plugins import (
    PLUGIN_FILE_QUESTION,
    add_plugins_from_file,
    apply_plugin_choices,
    plugin_rows,
)

if TYPE_CHECKING:
    from angrmanagement.plugins import PluginDescription, PluginManager


_l = logging.getLogger(__name__)


class QPluginListWidgetItem(QListWidgetItem):
    """
    Plugin list item.
    """

    def __init__(self, plugin_desc, **kwargs) -> None:
        super().__init__(**kwargs)
        self.plugin_desc: PluginDescription = plugin_desc
        self.setText(plugin_desc.name)


# TODO: Add plugin settings, reloading, etc.


class LoadPlugins(QDialog):
    """
    Dialog to display loaded plugins, enable/disable plugins, and load new plugins.
    """

    def __init__(self, plugin_mgr, parent=None) -> None:
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

    def _init_plugin_list(self) -> None:
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

    def _populate_installed_plugin_list(self) -> None:
        for desc, active in plugin_rows(self._pm):
            plugin_item = QPluginListWidgetItem(plugin_desc=desc)
            plugin_item.setCheckState(Qt.CheckState.Checked if active else Qt.CheckState.Unchecked)
            self._installed_plugin_list.addItem(plugin_item)

    def _init_widgets(self) -> None:
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

    def _on_ok_clicked(self) -> None:
        list_items: list[QPluginListWidgetItem] = self._installed_plugin_list.findItems("*", Qt.MatchFlag.MatchWildcard)
        apply_plugin_choices(
            self._pm, {i.plugin_desc.shortname: i.checkState() == Qt.CheckState.Checked for i in list_items}
        )
        self.close()

    def _on_load_clicked(self) -> None:
        files = GlobalInfo.ui_services.pick_open_files(*PLUGIN_FILE_QUESTION, False)
        if not files:
            return
        plugins = add_plugins_from_file(self._pm, files[0])
        if not plugins:
            GlobalInfo.ui_services.message("warning", "Error", "File contained no plugin descriptions")
            return
        for plugin in plugins:
            plugin_item = QPluginListWidgetItem(plugin_desc=plugin)
            plugin_item.setCheckState(Qt.CheckState.Unchecked)
            self._installed_plugin_list.addItem(plugin_item)
