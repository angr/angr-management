from collections import defaultdict
from typing import Dict, List, Optional, TYPE_CHECKING
import logging
import functools

from PySide2.QtCore import Qt

from .widgets.qsmart_dockwidget import QSmartDockWidget

if TYPE_CHECKING:
    from angrmanagement.ui.views.view import BaseView

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

    def add_view(self, view, caption, category):
        """
        Add a view to this workspace.

        :param view:            The view to add.
        :param str caption:     The caption of the view.
        :param str category:    The category of the view.
        :return:                None
        """

        self.views_by_category[category].append(view)

        dock = QSmartDockWidget(caption, parent=view, on_close=functools.partial(self.remove_view, view), on_raise=functools.partial(self._handle_raise_view, view))
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

    def remove_view(self, view):
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

    def raise_view(self, view):
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

    def get_center_views(self):
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

    def first_view_in_category(self, category) -> Optional['BaseView']:
        """
        Return the first view in a specific category.

        :param str category:    The category of the view.
        :return:                The view.
        """

        if self.views_by_category[category]:
            return self.views_by_category[category][0]
        return None

    def current_view_in_category(self, category) -> Optional['BaseView']:
        """
        Return the current in a specific category.

        :param str category:    The category of the view.
        :return:                The view.
        """

        current = self.get_center_views()[self.get_current_tab_id()]
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

    def get_current_tab_id(self):
        """
        Get Current Tab ID

        :return:    Tab ID (int)
        """

        center_dockable_views = self.get_center_views()
        for i in range(1,len(center_dockable_views)+1):
            if center_dockable_views[i-1].visibleRegion().isEmpty() is False:
                return i-1
        return 1

    def next_tab(self):
        """
        Shift to the next tab

        :return:    None
        """

        center_dockable_views = self.get_center_views()
        currentTab = self.get_current_tab_id()
        if (currentTab + 1) < len(center_dockable_views):
            center_dockable_views[currentTab + 1].raise_()
        else:
            # Start from 1 again to prevent Index Out Of Range error
            center_dockable_views[(currentTab + 1) % (len(center_dockable_views))].raise_()

    def previous_tab(self):
        """
        Shift to the next tab

        :return:    None
        """

        center_dockable_views = self.get_center_views()
        center_dockable_views[self.get_current_tab_id()-1].raise_()

    @property
    def current_tab(self):
        return self.get_center_views()[self.get_current_tab_id()].widget()

    def _handle_raise_view(self, view):
        self.workspace.plugins.handle_raise_view(view)

    def handle_center_tab_click(self, index):
        center_docks = self.get_center_views()
        dock = center_docks[index]
        view = self.dock_to_view[dock]
        self._handle_raise_view(view)
