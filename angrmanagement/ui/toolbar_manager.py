from typing import TYPE_CHECKING, Mapping, Type

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDockWidget

from angrmanagement.ui.toolbars import DebugToolbar, FeatureMapToolbar, FileToolbar

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow
    from angrmanagement.ui.toolbars.toolbar import Toolbar


class ToolbarManager:
    """
    Manages toolbars shown on the main window.
    """

    def __init__(self, main_window):
        self._main_window: MainWindow = main_window
        self.active: Mapping[Type[Toolbar], Toolbar] = {}
        self.all_toolbars = [FileToolbar, DebugToolbar, FeatureMapToolbar]

    @staticmethod
    def get_name_for_toolbar_class(toolbar_cls: Type["Toolbar"]) -> str:
        return {FileToolbar: "File", DebugToolbar: "Debug", FeatureMapToolbar: "Feature Map"}[toolbar_cls]

    def show_toolbar_by_class(self, cls: Type["Toolbar"]):
        if cls not in self.active:
            tb = cls(self._main_window)
            self.active[cls] = tb
            qtb = tb.qtoolbar()
            if isinstance(qtb, QDockWidget):
                self._main_window.addDockWidget(Qt.TopDockWidgetArea, qtb)
            else:
                self._main_window.addToolBar(Qt.TopToolBarArea, qtb)
        else:
            self.active[cls].qtoolbar().show()

    def hide_toolbar_by_class(self, cls: Type["Toolbar"]):
        if cls in self.active:
            tb = self.active.pop(cls)
            qtb = tb.qtoolbar()
            if isinstance(qtb, QDockWidget):
                self._main_window.removeDockWidget(qtb)
            else:
                self._main_window.removeToolBar(qtb)
            tb.shutdown()

    def set_toolbar_visible_by_class(self, cls: Type["Toolbar"], visible: bool):
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
