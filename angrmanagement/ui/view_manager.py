import functools
from collections import defaultdict
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence

import PySide6QtAds as QtAds
from bidict import bidict

from .views.view import ViewStatePublisherMixin

if TYPE_CHECKING:
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

    def __init__(self, workspace):
        self.workspace = workspace
        self.views: List[BaseView] = []
        self.docks = []
        self.view_to_dock = bidict()
        self.views_by_category: Dict[str, List[BaseView]] = defaultdict(list)
        self.most_recently_focused_view: Optional[BaseView] = None
        self.main_window.dock_manager.focusedDockWidgetChanged.connect(self._on_dock_widget_focus_changed)

    @property
    def main_window(self):
        return self.workspace._main_window

    def main_window_initialized(self):
        """
        Invoked by the main window after it has finished initialization. Views can override
        BaseView.mainWindowInitializedEvent() to support delayed initialization or loading.
        """
        for view in self.views:
            view.mainWindowInitializedEvent()

    def _update_view_index_in_category(self, view: "BaseView"):
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

    def add_view(self, view: "BaseView"):
        """
        Add a view to this workspace.

        :param view:            The view to add.
        :return:                None
        """
        self._update_view_index_in_category(view)
        self.views_by_category[view.category].append(view)

        dw = QtAds.CDockWidget(view.caption)
        dw.setFeature(QtAds.CDockWidget.DockWidgetDeleteOnClose, True)
        dw.closed.connect(functools.partial(self._on_dock_widget_closed, dw))
        dw.setWidget(view)

        area = self.DOCKING_POSITIONS.get(view.default_docking_position, QtAds.RightDockWidgetArea)
        self.main_window.dock_manager.addDockWidgetTab(area, dw)

        self.views.append(view)
        self.docks.append(dw)
        self.view_to_dock[view] = dw

    def _on_dock_widget_focus_changed(self, _, new):
        """
        Handle dock focus events.
        """
        view = self.view_to_dock.inverse.get(new, None)
        self.most_recently_focused_view = view
        if isinstance(view, ViewStatePublisherMixin):
            view.on_focused()

    def _on_dock_widget_closed(self, dock):
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

    def remove_view(self, view: "BaseView"):
        """
        Remove a view from this workspace

        :param view: The view to remove.
        """
        if view not in self.views:
            return

        self.views.remove(view)
        self.views_by_category[view.category].remove(view)
        dock = self.view_to_dock.pop(view, None)
        if dock:
            dock.closeDockWidget()

    def raise_view(self, view: "BaseView"):
        """
        Find the dock widget of a view, and then bring that dock widget to front.

        :param BaseView view: The view to raise.
        :return:              None
        """

        # find the dock widget by the view
        dock = self.view_to_dock.get(view, None)
        if dock is None:
            return

        if not dock.isTabbed():
            dock.show()
        dock.raise_()
        view.focusWidget()
        self.most_recently_focused_view = view

    def get_center_views(self) -> Sequence[QtAds.CDockWidget]:
        """
        Get the right dockable views

        :return:    Right Dockable Views
        """

        docks = []
        for dock in self.docks:
            if dock.widget() is not None:
                if dock.widget().default_docking_position == "center":
                    docks.append(dock)
        return docks

    def first_view_in_category(self, category: str) -> Optional["BaseView"]:
        """
        Return the first view in a specific category.

        :param str category:    The category of the view.
        :return:                The view.
        """

        if self.views_by_category[category]:
            return self.views_by_category[category][0]
        return None

    def current_view_in_category(self, category: str) -> Optional["BaseView"]:
        """
        Return the current in a specific category.

        :param str category:    The category of the view.
        :return:                The view.
        """
        current_tab_id = self.get_current_tab_id()
        if current_tab_id is None:
            return None

        current = self.get_center_views()[current_tab_id]
        view = self.view_to_dock.inverse[current]
        if category.capitalize() in view.caption and view.caption == current.windowTitle():
            return view
        return None

    def get_current_tab_id(self) -> Optional[int]:
        """
        Get Current Tab ID

        :return:    The current tab ID, or None if no current tab exists in the central view area.
        """

        for i, view in enumerate(self.get_center_views()):
            if not view.isHidden():
                return i
        return None

    def next_tab(self):
        """
        Shift to the next tab

        :return:    None
        """

        center_dockable_views = self.get_center_views()
        current_tab_id = self.get_current_tab_id()
        if current_tab_id is None:
            return
        center_dockable_views[(current_tab_id + 1) % len(center_dockable_views)].raise_()

    def previous_tab(self):
        """
        Shift to the previous tab

        :return:    None
        """

        center_dockable_views = self.get_center_views()
        current_tab_id = self.get_current_tab_id()
        if current_tab_id is None:
            return
        center_dockable_views[(current_tab_id - 1) % len(center_dockable_views)].raise_()  # this mod is superfluous

    @property
    def current_tab(self) -> Optional["BaseView"]:
        current_tab_id = self.get_current_tab_id()
        if current_tab_id is None:
            return None
        return self.get_center_views()[current_tab_id].widget()

    def _handle_raise_view(self, view: "BaseView"):
        self.workspace.plugins.handle_raise_view(view)
