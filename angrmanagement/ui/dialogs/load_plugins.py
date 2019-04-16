import os
import logging
from typing import Union, Type

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QFrame, QGroupBox, QListWidgetItem, QListWidget
from PySide2.QtCore import Qt

from ...plugins import PluginManager, BasePlugin

_l = logging.getLogger(__name__)


class QPluginListWidgetItem(QListWidgetItem):
    def __init__(self, plugin_cls, **kwargs):
        super().__init__(**kwargs)
        self._plugin_cls = plugin_cls  # type: Type[BasePlugin]
        self.setText(plugin_cls.get_display_name())

    @property
    def plugin_class(self):
        return self._plugin_cls


class LoadPluginsError(Exception):
    pass

# TODO: Implement an unload, which also de-registers callbacks.

# TODO: Add plugin settings, forced reloading, etc.

# TODO: Implement ability to start a loaded plugin that has _autostart=False

# TODO: Add load order/precedence. If two plugins hook insn_backcolor, etc, only the last
#       one to get loaded will actually get called.


class LoadPlugins(QDialog):
    def __init__(self, plugin_mgr, parent=None):
        super(LoadPlugins, self).__init__(parent)

        self._pm = plugin_mgr
        self._installed_plugin_list = None  # type: Union[None, QListWidget]

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
        for name, cls in self._pm.installed_plugins.items():
            plugin_item = QPluginListWidgetItem(plugin_cls=cls)
            checked = Qt.Checked if name in self._pm.enabled_plugins.keys() else Qt.Unchecked
            plugin_item.setCheckState(checked)
            self._installed_plugin_list.addItem(plugin_item)

    def _init_widgets(self):
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
        # TODO: Unload unchecked plugins. Load checked ones.
        list_items = self._installed_plugin_list.findItems('*', Qt.MatchWildcard)  # type: List[QPluginListWidgetItem]
        for i in list_items:
            checked = i.checkState() == Qt.Checked

            if checked and i.plugin_class.__name__ not in self._pm.enabled_plugins.keys():
                _l.info("Loading plugin: {}".format(i.get_display_name()))
                plugin = self._pm.enable_plugin(i.plugin_class.__name__)
                plugin.autostart()
            elif not checked and i.plugin_class.__name__ in self._pm.enabled_plugins.keys():
                _l.info("Disabling plugin: {}".format(i.get_display_name()))
                self._pm.disable_plugin(i.plugin_class.__name__)

        self.close()

    def _on_cancel_clicked(self):
        self.close()
