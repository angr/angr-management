from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDockWidget

from angrmanagement.ui.toolbars import DebugToolbar, FeatureMapToolbar, FileToolbar

if TYPE_CHECKING:
    from collections.abc import Mapping

    from angrmanagement.ui.main_window import MainWindow
    from angrmanagement.ui.toolbars.toolbar import Toolbar
    from angrmanagement.ui.toolbars.toolbar_action import ToolbarAction


class ToolbarManager:
    """
    Manages toolbars shown on the main window.
    """

    def __init__(self, main_window: MainWindow) -> None:
        self._main_window: MainWindow = main_window
        self.active: Mapping[type[Toolbar], Toolbar] = {}
        self.all_toolbars = [FileToolbar, DebugToolbar, FeatureMapToolbar]
        #: plugin TOOLBAR_BUTTONS actions; they live on the File toolbar whenever it is shown
        self.plugin_actions: list[ToolbarAction] = []

    @staticmethod
    def get_name_for_toolbar_class(toolbar_cls: type[Toolbar]) -> str:
        return {FileToolbar: "File", DebugToolbar: "Debug", FeatureMapToolbar: "Feature Map"}[toolbar_cls]

    def add_plugin_action(self, action: ToolbarAction) -> None:
        """Add a plugin's toolbar button to the File toolbar (now, if it is shown, and whenever it is shown again)."""
        self.plugin_actions.append(action)
        file_toolbar = self.active.get(FileToolbar)
        if file_toolbar is not None:
            file_toolbar.add(action)

    def remove_plugin_action(self, action: ToolbarAction) -> None:
        if action in self.plugin_actions:
            self.plugin_actions.remove(action)
        file_toolbar = self.active.get(FileToolbar)
        if file_toolbar is not None and action in file_toolbar.actions:
            file_toolbar.remove(action)

    def show_toolbar_by_class(self, cls: type[Toolbar]) -> None:
        if cls not in self.active:
            tb = cls(self._main_window)
            if cls is FileToolbar:
                for action in self.plugin_actions:
                    tb.add(action)
            self.active[cls] = tb
            qtb = tb.qtoolbar()
            if isinstance(qtb, QDockWidget):
                self._main_window.addDockWidget(Qt.DockWidgetArea.TopDockWidgetArea, qtb)
            else:
                self._main_window.addToolBar(Qt.ToolBarArea.TopToolBarArea, qtb)
        else:
            self.active[cls].qtoolbar().show()

    def hide_toolbar_by_class(self, cls: type[Toolbar]) -> None:
        if cls in self.active:
            tb = self.active.pop(cls)
            qtb = tb.qtoolbar()
            if isinstance(qtb, QDockWidget):
                self._main_window.removeDockWidget(qtb)
            else:
                self._main_window.removeToolBar(qtb)
            tb.shutdown()

    def set_toolbar_visible_by_class(self, cls: type[Toolbar], visible: bool) -> None:
        if visible:
            self.show_toolbar_by_class(cls)
        else:
            self.hide_toolbar_by_class(cls)

    def show_all(self) -> None:
        for cls in self.all_toolbars:
            self.show_toolbar_by_class(cls)

    def hide_all(self) -> None:
        for cls in self.all_toolbars:
            self.hide_toolbar_by_class(cls)
