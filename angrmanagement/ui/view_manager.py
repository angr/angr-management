from collections import defaultdict
from typing import Dict, List, Optional, Sequence
import logging
import functools

from PySide2.QtCore import Qt

from angrmanagement.ui.views.view import BaseView

from .widgets.qsmart_dockwidget import QSmartDockWidget


_l = logging.getLogger(__name__)


class ViewManager:
    """
    Manages views.
    """

    DOCKING_POSITIONS = {
        # 'center': None,
        'left': Qt.LeftDockWidgetArea,
        'right': Qt.RightDockWidgetArea,
        'top': Qt.TopDockWidgetArea,
        'bottom': Qt.BottomDockWidgetArea,
    }

    def __init__(self, workspace):
        self.workspace = workspace
        self.views = [ ]
        self.docks = [ ]
        self.view_to_dock = { }
        self.dock_to_view = { }
        self.views_by_category: Dict[str,List[BaseView]] = defaultdict(list)

    @property
    def main_window(self):
        return self.workspace._main_window

    def _update_view_index_in_category(self, view: BaseView):
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

    def add_view(self, view: BaseView):
        """
        Add a view to this workspace.

        :param view:            The view to add.
        :return:                None
        """
        self._update_view_index_in_category(view)
        self.views_by_category[view.category].append(view)

        dock = QSmartDockWidget(view.caption, parent=view,
                                on_close=functools.partial(self.remove_view, view),
                                on_raise=functools.partial(self._handle_raise_view, view))
        dock_area = self.DOCKING_POSITIONS.get(view.default_docking_position, Qt.RightDockWidgetArea)
        if view.default_docking_position == 'center':
            self.main_window.central_widget.addDockWidget(dock_area, dock)
            retab = True
        else:
            self.main_window.addDockWidget(dock_area, dock)
            retab = False
        dock.setWidget(view)

        self.views.append(view)
        self.docks.append(dock)
        self.view_to_dock[view] = dock
        self.dock_to_view[dock] = view

        if retab:
            self.tabify_center_views()

    def remove_view(self, view: BaseView):
        """
        Remove a view from this workspace

        :param view:            The view to remove.
        """

        if view not in self.views_by_category[view.category]:
            return
        self.views_by_category[view.category].remove(view)

        # find the correct dock
        dock: Optional[QSmartDockWidget] = None
        for d in self.docks:
            if d.windowTitle() == view.caption:
                dock = d

        # sanity check on the dock
        if dock is None:
            _l.warning("Warning: removed view does not exist as a dock!")
            return

        if view.default_docking_position == 'center':
            self.main_window.central_widget.removeDockWidget(dock)
            retab = True
        else:
            self.main_window.removeDockWidget(dock)
            retab = False

        self.views.remove(view)
        self.docks.remove(dock)
        self.view_to_dock.pop(view)

        if retab:
            self.tabify_center_views()

    def raise_view(self, view: BaseView):
        """
        Find the dock widget of a view, and then bring that dock widget to front.

        :param BaseView view: The view to raise.
        :return:              None
        """

        # find the dock widget by the view
        dock = self.view_to_dock.get(view, None)
        if dock is None:
            return

        dock.show()
        dock.raise_()
        view.focusWidget()

    def get_center_views(self) -> Sequence[QSmartDockWidget]:
        """
        Get the right dockable views

        :return:    Right Dockable Views
        """

        docks = []
        for dock in self.docks:
            if dock.widget() is not None:
                if dock.widget().default_docking_position == 'center':
                    docks.append(dock)
        return docks

    def first_view_in_category(self, category: str) -> Optional['BaseView']:
        """
        Return the first view in a specific category.

        :param str category:    The category of the view.
        :return:                The view.
        """

        if self.views_by_category[category]:
            return self.views_by_category[category][0]
        return None

    def current_view_in_category(self, category: str) -> Optional['BaseView']:
        """
        Return the current in a specific category.

        :param str category:    The category of the view.
        :return:                The view.
        """
        current_tab_id = self.get_current_tab_id()
        if current_tab_id is None:
            return None

        current = self.get_center_views()[current_tab_id]
        view = self.dock_to_view[current]
        if category.capitalize() in view.caption and view.caption == current.windowTitle():
            return view
        return None

    def tabify_center_views(self):
        """
        Tabify all right-side dockable views.

        :return:    None
        """
        center_dockable_views = self.get_center_views()
        for d0, d1 in zip(center_dockable_views, center_dockable_views[1:]):
            self.workspace._main_window.central_widget.tabifyDockWidget(d0, d1)

    def get_current_tab_id(self) -> Optional[int]:
        """
        Get Current Tab ID

        :return:    The current tab ID, or None if no current tab exists in the central view area.
        """

        center_dockable_views = self.get_center_views()
        for i in range(1,len(center_dockable_views)+1):
            if center_dockable_views[i-1].visibleRegion().isEmpty() is False:
                return i-1
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
        if (current_tab_id + 1) < len(center_dockable_views):
            center_dockable_views[current_tab_id + 1].raise_()
        else:
            # Start from 1 again to prevent Index Out Of Range error
            center_dockable_views[(current_tab_id + 1) % (len(center_dockable_views))].raise_()

    def previous_tab(self):
        """
        Shift to the next tab

        :return:    None
        """

        current_tab_id = self.get_current_tab_id()
        if current_tab_id is None:
            return

        center_dockable_views = self.get_center_views()
        center_dockable_views[current_tab_id - 1].raise_()

    @property
    def current_tab(self) -> Optional['BaseView']:
        current_tab_id = self.get_current_tab_id()
        if current_tab_id is None:
            return None
        return self.get_center_views()[current_tab_id].widget()

    def _handle_raise_view(self, view: BaseView):
        self.workspace.plugins.handle_raise_view(view)

    def handle_center_tab_click(self, index: int):
        center_docks = self.get_center_views()
        dock = center_docks[index]
        view = self.dock_to_view[dock]
        self._handle_raise_view(view)
