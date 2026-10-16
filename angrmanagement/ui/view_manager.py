from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any

import PySide6QtAds as QtAds
from bidict import bidict
from PySide6.QtWidgets import QSizePolicy

from angrmanagement.logic.view_manager import BaseViewManager, default_position

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

    from .views.view import BaseView


def qt_view_classes() -> dict[str, Any]:
    """The Qt view class of each view category."""
    from . import views  # pylint:disable=import-outside-toplevel

    return {
        "disassembly": views.DisassemblyView,
        "pseudocode": views.CodeView,
        "hex": views.HexView,
        "functions": views.FunctionsView,
        "strings": views.StringsView,
        "search": views.SearchView,
        "patches": views.PatchesView,
        "types": views.TypesView,
        "comments": views.CommentsView,
        "bookmarks": views.BookmarksView,
        "signatures": views.SignaturesView,
        "traces": views.TracesView,
        "tracemap": views.TraceMapView,
        "symexec": views.SymexecView,
        "states": views.StatesView,
        "registers": views.RegistersView,
        "stack": views.StackView,
        "breakpoints": views.BreakpointsView,
        "call_explorer": views.CallExplorerView,
        "console": views.ConsoleView,
        "log": views.LogView,
        "jobs": views.JobsView,
        "mcp_history": views.MCPHistoryView,
        "proximity": views.ProximityView,
        "dependencies": views.DependencyView,
        "data_dependency": views.DataDepView,
        "pattern": views.PatternView,
    }


class ViewManager(BaseViewManager):
    """
    Manages views, docked with Qt Advanced Docking System.
    """

    DOCKING_POSITIONS = {
        "center": QtAds.CenterDockWidgetArea,
        "left": QtAds.LeftDockWidgetArea,
        "right": QtAds.RightDockWidgetArea,
        "top": QtAds.TopDockWidgetArea,
        "bottom": QtAds.BottomDockWidgetArea,
    }

    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)
        self.docks = []
        self.view_to_dock = bidict()
        self._view_classes: dict[str, Any] | None = None
        self.main_window.dock_manager.focusedDockWidgetChanged.connect(self._on_dock_widget_focus_changed)

    @property
    def main_window(self):
        return self.workspace._main_window

    @property
    def view_classes(self) -> dict[str, Any]:
        if self._view_classes is None:
            self._view_classes = qt_view_classes()
        return self._view_classes

    def view_categories(self):
        return self.view_classes.keys()

    def create_view(self, category: str, position: str | None = None) -> BaseView | None:
        view_class = self.view_classes.get(category)
        if view_class is None:
            return None
        view = view_class(self.workspace, position or default_position(category), self.workspace.main_instance)
        self.add_view(view)
        return view

    def main_window_initialized(self) -> None:
        """
        Invoked by the main window after it has finished initialization. Views can override
        BaseView.mainWindowInitializedEvent() to support delayed initialization or loading.
        """
        for view in self.views:
            view.mainWindowInitializedEvent()

    def add_view(self, view: BaseView) -> None:
        """
        Add a view to this workspace.

        :param view:            The view to add.
        :return:                None
        """
        self._update_view_index_in_category(view)
        self.views_by_category[view.category].append(view)
        self.views_by_activation.append(view)

        dw = QtAds.CDockWidget(view.caption)
        dw.setFeature(QtAds.CDockWidget.DockWidgetDeleteOnClose, True)
        dw.closed.connect(functools.partial(self._on_dock_widget_closed, dw))
        dw.setWidget(view)
        if view.icon:
            dw.setIcon(view.icon)

        area = self.DOCKING_POSITIONS.get(view.default_docking_position, QtAds.RightDockWidgetArea)
        area_widget = self.main_window.dock_manager.addDockWidgetTab(area, dw)
        self.main_window.init_shortcuts_on_dock(dw)

        self.views.append(view)
        self.docks.append(dw)
        self.view_to_dock[view] = dw

        if view.default_docking_position == "center":
            policy = QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            policy.setHorizontalStretch(1)
            policy.setVerticalStretch(1)
            area_widget.setSizePolicy(policy)

    def focus_view(self, view: BaseView) -> None:
        view.setFocus()

    def _on_dock_widget_focus_changed(self, _, new: QtAds.CDockWidget | None) -> None:
        """
        Handle dock focus events.
        """
        self.handle_focus_changed(self.view_to_dock.inverse.get(new, None))

    def _on_dock_widget_closed(self, dock: QtAds.CDockWidget) -> None:
        """
        Handle dock widget close event.
        """
        if dock not in self.docks:
            return

        self.docks.remove(dock)
        view = self.view_to_dock.inverse.pop(dock, None)
        if view:
            view.close()
            self.remove_view(view)

    def remove_view(self, view: BaseView) -> None:
        """
        Remove a view from this workspace
        """
        if view not in self.views:
            return

        self.views.remove(view)
        self.views_by_category[view.category].remove(view)
        dock = self.view_to_dock.pop(view, None)
        if dock:
            dock.closeDockWidget()
        self.views_by_activation.remove(view)

    def raise_view(self, view: BaseView) -> None:
        """
        Find the dock widget of a view, and then bring that dock widget to front.
        """
        self._promote_view(view)

        # find the dock widget by the view
        dock = self.view_to_dock.get(view, None)
        if dock is None:
            return

        if dock.isAutoHide():
            dock.toggleView(True)
        if not dock.isTabbed():
            dock.show()
        dock.raise_()
        view.focusWidget()

    def _adjust_current_tab_idx(self, offset: int) -> None:
        """
        Select tab in same dock area with index equal to index of most recently activated center view plus `offset`.
        """
        view = self.get_most_recently_focused_view_by_docking_area("center")
        if view is None:
            return
        area = self.view_to_dock[view].dockAreaWidget()
        idx = area.currentIndex()
        if idx < 0:
            return
        area.setCurrentIndex((idx + offset) % area.dockWidgetsCount())

    def next_tab(self) -> None:
        """
        Shift to the next tab
        """
        self._adjust_current_tab_idx(1)

    def previous_tab(self) -> None:
        """
        Shift to the previous tab
        """
        self._adjust_current_tab_idx(-1)
