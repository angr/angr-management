from collections import defaultdict

from PySide2.QtCore import Qt
from .widgets.qsmart_dockwidget import QSmartDockWidget


class ViewManager:
    """
    Manages views.
    """
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

        docking_positions = {
            'left': Qt.LeftDockWidgetArea,
            'right': Qt.RightDockWidgetArea,
            'top': Qt.TopDockWidgetArea,
            'bottom': Qt.BottomDockWidgetArea,
        }

        self.views_by_category[category].append(view)

        dock = QSmartDockWidget(caption, parent=view)
        dock_area = docking_positions.get(view.default_docking_position, Qt.RightDockWidgetArea)
        if view.default_docking_position == 'right':
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
            self.tabify_right_views()

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

    def get_right_views(self):
        """
        Get the right dockable views

        :return:    Right Dockable Views
        """

        return [dock for dock in self.docks if dock.widget().default_docking_position == 'right']

    def first_view_in_category(self, category):
        """
        Return the first view in a specific category.

        :param str category:    The category of the view.
        :return:                The view.
        """

        if self.views_by_category[category]:
            return self.views_by_category[category][0]
        return None

    def tabify_right_views(self):
        """
        Tabify all right-side dockable views.

        :return:    None
        """

        right_dockable_views = self.get_right_views()
        for d0, d1 in zip(right_dockable_views, right_dockable_views[1:]):
            self.workspace._main_window.central_widget.tabifyDockWidget(d0, d1)
        right_dockable_views[0].raise_()

    def get_current_tab_id(self):
        """
        Get Current Tab ID
        
        :return:    Tab ID (int)
        """
        
        right_dockable_views = self.get_right_views()
        for i in range(1,7):
            if right_dockable_views[i-1].visibleRegion().isEmpty() is False:
                return i
        return 1

    def next_tab(self):
        """
        Shift to the next tab

        :return:    None
        """

        right_dockable_views = self.get_right_views()
        right_dockable_views[self.get_current_tab_id()].raise_()

    def previous_tab(self):
        """
        Shift to the next tab

        :return:    None
        """

        right_dockable_views = self.get_right_views()
        right_dockable_views[self.get_current_tab_id()-2].raise_()