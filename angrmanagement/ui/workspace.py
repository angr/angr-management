
import logging
from collections import defaultdict

from PySide2.QtCore import Qt

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
        self.view_to_dockable = { }

        #
        # Initialize font configurations
        #
        Conf.init_font_config()

        default_tabs = [
            FunctionsView(self, 'left'),
            DisassemblyView(self, 'right'),
            CodeView(self, 'right'),
            SymexecView(self, 'right'),
            StatesView(self, 'right'),
            StringsView(self, 'right'),
            ConsoleView(self, 'bottom'),
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
    # Events
    #

    def on_function_selected(self, func):

        self.views_by_category['disassembly'][0].display_function(func)

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
