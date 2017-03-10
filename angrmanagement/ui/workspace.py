
from collections import defaultdict

from PySide.QtGui import QDockWidget, QFont, QFontMetricsF
from PySide.QtCore import Qt

from angrmanagement.ui.views import FunctionsView, DisassemblyView, SymexecView, StatesView, StringsView


class Workspace(object):
    def __init__(self, main_window):

        self._main_window = main_window
        self._instance = None
        self.views_by_category = defaultdict(list)
        self.views = [ ]
        self.dockable_views = [ ]
        self.view_to_dockable = { }

        #
        # Some generic configurations. move to "configurations" module later
        #
        self.disasm_font = QFont("courier new", 10)
        self.disasm_font_height = QFontMetricsF(self.disasm_font).height()
        self.disasm_font_width = QFontMetricsF(self.disasm_font).width('A')


        default_tabs = [
            FunctionsView(self, 'left'),
            DisassemblyView(self, 'right'),
            SymexecView(self, 'right'),
            StatesView(self, 'right'),
            StringsView(self, 'right'),
        ]

        for tab in default_tabs:
            self.add_view(tab, tab.caption, tab.category)

    #
    # Properties
    #

    @property
    def instance(self):
        return self._instance

    #
    # Public methods
    #

    def add_view(self, view, caption, category):

        docking_positions = {
            'left': Qt.LeftDockWidgetArea,
            'right': Qt.RightDockWidgetArea,
            'top': Qt.TopDockWidgetArea,
            'bottom': Qt.BottomDockWidgetArea,
        }

        self.views_by_category[category].append(view)

        dock = QDockWidget(caption, view)
        dock_area = docking_positions.get(view.default_docking_position, Qt.RightDockWidgetArea)
        self._main_window.addDockWidget(dock_area, dock)
        dock.setWidget(view)

        self.views.append(view)
        self.dockable_views.append(dock)
        self.view_to_dockable[view] = dock

    def raise_view(self, view):
        """
        Find the dock widget of a view, and then bring that dockable to front.

        :param BaseView view: The view to raise.
        :return:              None
        """

        # find the dock widget by the view
        dockable = self.view_to_dockable.get(view, None)
        if dockable is None:
            return

        dockable.raise_()

    def set_instance(self, instance):
        if self._instance is not None:
            raise Exception('You cannot set instance to this workspace. It already has an instance associated.')

        self._instance = instance
        self._instance.workspace = self

    def reload(self):
        for view in self.views:
            view.reload()
