from collections import defaultdict

from PySide2.QtCore import Qt

from ..data.object_container import ObjectContainer
from .widgets.qsmart_dockwidget import QSmartDockWidget


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
        self.views_by_category = defaultdict(list)

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

        dock = QSmartDockWidget(caption, parent=view)
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

        dock.raise_()

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

    def first_view_in_category(self, category):
        """
        Return the first view in a specific category.

        :param str category:    The category of the view.
        :return:                The view.
        """

        if self.views_by_category[category]:
            return self.views_by_category[category][0]
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
