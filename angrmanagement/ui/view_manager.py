from __future__ import annotations

import functools
from collections import defaultdict
from typing import TYPE_CHECKING

import PySide6QtAds as QtAds
from bidict import bidict
from PySide6.QtWidgets import QSizePolicy

from angrmanagement.ui.views.view import InstanceView

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.ui.workspace import Workspace

    from .views.view import BaseView


class ViewManager:
    """
    Manages views.
    """

    DOCKING_POSITIONS = {
        "center": QtAds.CenterDockWidgetArea,
        "left": QtAds.LeftDockWidgetArea,
        "right": QtAds.RightDockWidgetArea,
        "top": QtAds.TopDockWidgetArea,
        "bottom": QtAds.BottomDockWidgetArea,
    }

    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self.views: list[BaseView] = []
        self.docks = []
        self.view_to_dock = bidict()
        self.views_by_category: dict[str, list[BaseView]] = defaultdict(list)
        self.views_by_activation: list[BaseView] = []
        self.main_window.dock_manager.focusedDockWidgetChanged.connect(self._on_dock_widget_focus_changed)

    @property
    def main_window(self):
        return self.workspace._main_window

    def main_window_initialized(self) -> None:
        """
        Invoked by the main window after it has finished initialization. Views can override
        BaseView.mainWindowInitializedEvent() to support delayed initialization or loading.
        """
        for view in self.views:
            view.mainWindowInitializedEvent()

    def _update_view_index_in_category(self, view: BaseView) -> None:
        """
        Set lowest available index value in category for a view not yet added.
        """
        existing_views = self.views_by_category[view.category]
        if view in existing_views:
            return
        existing_ids = {view.index for view in existing_views}
        max_id = max(existing_ids) if existing_ids else 0
        candidates = set(range(1, max_id + 2)) - existing_ids
        view.index = min(candidates)

    def _promote_view(self, view: BaseView) -> None:
        """
        Move view to first position in views_by_activation.
        """
        self.views_by_activation.remove(view)
        self.views_by_activation.insert(0, view)

    def add_view(self, view: BaseView) -> None:
        """
        Add a view to this workspace.

        :param view:            The view to add.
        :return:                None
        """
        self._update_view_index_in_category(view)
        self.views_by_category[view.category].append(view)
        self.views_by_activation.insert(0, view)

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

    @property
    def most_recently_focused_view(self) -> BaseView | None:
        if self.views_by_activation:
            return self.views_by_activation[0]
        return None

    def get_most_recently_focused_view_by_docking_area(self, area: str) -> BaseView | None:
        for view in self.views_by_activation:
            if view.default_docking_position == area:
                return view
        return None

    def _on_dock_widget_focus_changed(self, _, new: QtAds.CDockWidget | None) -> None:
        """
        Handle dock focus events.
        """
        view = self.view_to_dock.inverse.get(new, None)
        if view:
            self._promote_view(view)
        if isinstance(view, InstanceView):
            view.on_focused()

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

    def get_center_docks(self) -> Sequence[QtAds.CDockWidget]:
        """
        Get the center dockable views
        """
        return [
            dock
            for dock in self.docks
            if dock.widget() is not None and dock.widget().default_docking_position == "center"
        ]

    def first_view_in_category(self, category: str) -> BaseView | None:
        """
        Return the first view in a specific category.
        """
        if self.views_by_category[category]:
            return self.views_by_category[category][0]
        return None

    def current_view_in_category(self, category: str) -> BaseView | None:
        """
        Return the current in a specific category.
        """
        for view in self.views_by_activation:
            if view.category == category:
                return view
        return None

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

    @property
    def current_tab(self) -> BaseView | None:
        return self.get_most_recently_focused_view_by_docking_area("center")

    def _handle_raise_view(self, view: BaseView) -> None:
        self.workspace.plugins.handle_raise_view(view)
