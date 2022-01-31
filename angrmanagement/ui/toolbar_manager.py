from typing import Type, Mapping

from PySide2.QtCore import Qt
from angrmanagement.ui.toolbars import FileToolbar, DebugToolbar
from angrmanagement.ui.toolbars.toolbar import Toolbar


class ToolbarManager:
    """
    Manages toolbars shown on the main window.
    """

    def __init__(self, main_window):
        self._main_window: 'MainWindow' = main_window
        self.active: Mapping[Type[Toolbar], Toolbar] = {}
        self.all_toolbars = [FileToolbar, DebugToolbar]

    @staticmethod
    def get_name_for_toolbar_class(toolbar_cls: Type[Toolbar]) -> str:
        return {
            FileToolbar: 'File',
            DebugToolbar: 'Debug'
        }[toolbar_cls]

    def show_toolbar_by_class(self, cls: Type[Toolbar]):
        if cls not in self.active:
            tb = cls(self._main_window)
            self.active[cls] = tb
            self._main_window.addToolBar(Qt.TopToolBarArea, tb.qtoolbar())

    def hide_toolbar_by_class(self, cls: Type[Toolbar]):
        if cls in self.active:
            tb = self.active.pop(cls)
            self._main_window.removeToolBar(tb.qtoolbar())

    def set_toolbar_visible_by_class(self, cls: Type[Toolbar], visible: bool):
        if visible:
            self.show_toolbar_by_class(cls)
        else:
            self.hide_toolbar_by_class(cls)

    def show_all(self):
        for cls in self.all_toolbars:
            self.show_toolbar_by_class(cls)

    def hide_all(self):
        for cls in self.all_toolbars:
            self.hide_toolbar_by_class(cls)
