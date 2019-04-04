
import logging
from collections import defaultdict

from PySide2.QtCore import Qt

from PySide2.QtWidgets import QSplitter, QMainWindow

from angr.knowledge_plugins import Function
from angr import StateHierarchy

from ..data.instance import ObjectContainer
from ..data.jobs import CodeTaggingJob
from ..config import Conf
from .views import FunctionsView, DisassemblyView, SymexecView, StatesView, StringsView, ConsoleView, CodeView
from .widgets.qsmart_dockwidget import QSmartDockWidget

_l = logging.getLogger(__name__)


class Workspace:
    def __init__(self, main_window, instance):

        self._main_window = main_window
        self._instance = instance
        instance.workspace = self
        self.views_by_category = defaultdict(list)
        self.views = [ ]
        self.dockable_views = [ ]
        self.dockable_views2 = [ ]
        self.view_to_dockable = { }
        self.last_unsplit_view = None
        self.split_tab_id = None
        self.is_split = 0

        #
        # Initialize font configurations
        #
        Conf.init_font_config()

        self.default_tabs = [
            FunctionsView(self, 'left'),
            DisassemblyView(self, 'right'),
            CodeView(self, 'right'),
            SymexecView(self, 'right'),
            StatesView(self, 'right'),
            StringsView(self, 'right'),
            ConsoleView(self, 'bottom'),
        ]

        # self.splitter = QSplitter()
        # self._main_window.central_widget.addDockWidget(dock_area, self.splitter)

        # self.add_view(default_tabs[1], default_tabs[1].caption,)

        for tab in self.default_tabs:
            self.add_view(tab, tab.caption, tab.category)


        # for tab2 in default_tabs:
        #     self.add_view2(tab2, tab2.caption, tab2.category)

    #
    # Properties
    #

    @property
    def instance(self):
        return self._instance

    #
    # Events
    #

    def on_function_selected(self, function):

        self.views_by_category['disassembly'][0].display_function(function)

    def on_cfg_generated(self):

        # display the main function if it exists, otherwise display the function at the entry point
        if self.instance.cfg is not None:
            the_func = self.instance.cfg.kb.functions.function(name='main')
            if the_func is None:
                the_func = self.instance.cfg.kb.functions.function(addr=self.instance.cfg.project.entry)

            if the_func is not None:
                self.on_function_selected(the_func)

        self.instance.add_job(
            CodeTaggingJob(
                on_finish=self.on_function_tagged,
            )
        )

    def on_function_tagged(self):
        pass

    #
    # Public methods
    #


    def split_view(self):
        id = self._main_window.getCurrentTabId()
        if self.is_split == 0:
            print("Split view called")
            docking_positions = {
                'left': Qt.LeftDockWidgetArea,
                'right': Qt.RightDockWidgetArea,
                'top': Qt.TopDockWidgetArea,
                'bottom': Qt.BottomDockWidgetArea,
            }

            self._main_window.central_widget.removeDockWidget(self.dockable_views[id])
            # print(self._main_window.right_dockable_views)
            # self._main_window._tabify()
            #if self.last_unsplit_view is not None:
            #    self._main_window.central_widget.removeDockWidget(self.last_unsplit_view)
            dock_area = docking_positions.get(self.default_tabs[id].default_docking_position, Qt.RightDockWidgetArea)
            dock = QSmartDockWidget(self.default_tabs[id].caption, parent=self.default_tabs[id])
            # self.dockable_views[id] = dock
            self._main_window.central_widget2.addDockWidget(dock_area, dock)
            dock.setWidget(self.default_tabs[id])
            self.is_split = 1
            self.split_tab_id = id
            self.last_unsplit_view = dock
            # print(len(self.dockable_views))

    # def readd_views(self):
    #     # Remove everything
    #     self._main_window.central_widget = QMainWindow()

    #     for tab in self.default_tabs:
    #         self.add_view(self, tab.)



    def add_view(self, view, caption, category):

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
            self._main_window.central_widget.addDockWidget(dock_area, dock)
        else:
            self._main_window.addDockWidget(dock_area, dock)
        dock.setWidget(view)

        self.views.append(view)
        self.dockable_views.append(dock)
        self.view_to_dockable[view] = dock


    # def readd_views(self):
    #     # Remove everything
    #     self._main_window.central_widget = QMainWindow()
    #     self._main_window.central_widget2 = QMainWindow()
    #     self.views = [ ]
    #     self.dockable_views = [ ]

    #     for tab in self.default_tabs:
    #         self.add_view(tab, tab.caption, tab.category)
        
    #     #self._main_window._tabify()


    def unsplit_view(self):
        if self.is_split == 1:
            id = self.split_tab_id
            print("Unsplit view called")
            docking_positions = {
                'left': Qt.LeftDockWidgetArea,
                'right': Qt.RightDockWidgetArea,
                'top': Qt.TopDockWidgetArea,
                'bottom': Qt.BottomDockWidgetArea,
            }

            # self._main_window.central_widget2.removeDockWidget(self.dockable_views[id])
            # split_dock_area = docking_positions.get(self.default_tabs[id].default_docking_position, Qt.RightDockWidgetArea)
            # dock = QSmartDockWidget(self.default_tabs[id].caption, parent=self.default_tabs[id])

        #     self.right_dockable_views = [dock for dock in self.dockable_views 
        #     if dock.widget() is not None and dock.widget().default_docking_position == 'right']

            #for i in range(1,len(self.dockable_views)):
            self._main_window.central_widget2.removeDockWidget(self.last_unsplit_view)

            # for i in range(1,len(self.dockable_views)):
            #     self._main_window.central_widget.removeDockWidget(self.dockable_views[i])

            # k = 0
            # for tab in self.default_tabs:
            #     if k != id:
            #         dock = QSmartDockWidget(tab.caption, parent=tab)
            #         dock_area = docking_positions.get(tab.default_docking_position, Qt.RightDockWidgetArea)
            #         if tab.default_docking_position == 'right':
            #             self._main_window.central_widget.addDockWidget(dock_area, dock)
            #             dock.setWidget(tab)
            #             self.dockable_views[k] = dock
            #     k = k + 1

            # self.is_split = 0

            # for i in range(0, len(self.right_dockable_views)):
            #     print("Splitting " + self.right_dockable_views[i].caption)

            #for d0, d1 in zip(self.right_dockable_views, self.right_dockable_views[1:]):
            #    print("Splitting " + d0.widget().caption)
            #    self._main_window.central_widget.splitDockWidget(d0, d1, Qt.Horizontal)

            dock_area = docking_positions.get(self.default_tabs[id].default_docking_position, Qt.RightDockWidgetArea)

            dock = QSmartDockWidget(self.default_tabs[id].caption, parent=self.default_tabs[id])

            self._main_window.central_widget.addDockWidget(dock_area, dock)

            dock.setWidget(self.default_tabs[id])
            
            self.dockable_views[id] = dock

            #self.last_unsplit_view = dock
            self._main_window._tabify()
            self.is_split = 0
            #self._main_window._tabify()
    

    def add_view2(self, view, caption, category):

        docking_positions2 = {
            'left': Qt.LeftDockWidgetArea,
            'right': Qt.RightDockWidgetArea,
            'top': Qt.TopDockWidgetArea,
            'bottom': Qt.BottomDockWidgetArea,
        }

        dock2 = QSmartDockWidget(caption, parent=view)
        dock_area2 = docking_positions2.get(view.default_docking_position, Qt.RightDockWidgetArea)

        if view.default_docking_position == 'right':
            self._main_window.central_widget2.addDockWidget(dock_area2, dock2)
        else:
            self._main_window.addDockWidget(dock_area2, dock2)
            self._main_window.removeDockWidget(dock2)
        
        dock2.setWidget(view)

        self.dockable_views2.append(dock2)


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

    def reload(self):
        # import time
        # start = time.time()
        for view in self.views:
            try:
                view.reload()
            except Exception:
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)
                pass
        # elapsed = time.time() - start
        # print("Reloading took %f seconds." % elapsed)

    def viz(self, obj):
        """
        Visualize the given object.

        - For integers, open the disassembly view and jump to that address
        - For Function objects, open the disassembly view and jump there
        - For strings, look up the symbol of that name and jump there
        """

        if type(obj) is int:
            self.jump_to(obj)
        elif type(obj) is str:
            sym = self.instance.project.loader.find_symbol(obj)
            if sym is not None:
                self.jump_to(sym.rebased_addr)
        elif type(obj) is Function:
            self.jump_to(obj.addr)

    def jump_to(self, addr):
        if self.views_by_category['disassembly']:
            self.views_by_category['disassembly'][0].jump_to(addr)
            self.raise_view(self.views_by_category['disassembly'][0])
            self.views_by_category['disassembly'][0].setFocus()
        else:
            tab = DisassemblyView(self, 'right')
            self.add_view(tab, tab.caption, tab.category)
            tab.jump_to(addr)

    def decompile_current_function(self):
        self.views_by_category['disassembly'][0].decompile_current_function()

    def decompile_function(self, func):
        pseudocode = self.views_by_category['pseudocode'][0]
        pseudocode.function = func
        self.raise_view(pseudocode)
        pseudocode.setFocus()

    def create_simulation_manager(self, state, state_name):

        inst = self.instance
        hierarchy = StateHierarchy()
        simgr = inst.project.factory.simulation_manager(state, hierarchy=hierarchy)
        simgr_container = ObjectContainer(simgr, name=state_name)
        inst.simgrs.append(simgr_container)
        inst.simgrs.am_event(src='new_path')

        symexec_view = self.views_by_category['symexec'][0]
        symexec_view.select_simgr(simgr_container)

        self.raise_view(symexec_view)
