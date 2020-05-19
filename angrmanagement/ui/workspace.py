from typing import TYPE_CHECKING
import logging
import traceback

from PySide2.QtCore import Qt, QSettings

from angr.knowledge_plugins import Function
from angr import StateHierarchy

from ..data.instance import ObjectContainer
from ..data.jobs import CodeTaggingJob, PrototypeFindingJob, VariableRecoveryJob
from .views import (FunctionsView, DisassemblyView, SymexecView, StatesView, StringsView, ConsoleView, CodeView,
                    InteractionView, SyncView, PatchesView, )
from .widgets.qsmart_dockwidget import QSmartDockWidget
from .view_manager import ViewManager

from ..utils import has_binsync
from ..plugins import PluginManager

if TYPE_CHECKING:
    from ..data.instance import Instance


_l = logging.getLogger(__name__)


class Workspace:
    def __init__(self, main_window, instance):

        self._main_window = main_window
        self._instance = instance
        self.is_split = False
        self.split_tab_id = 0
        instance.workspace = self

        self.view_manager: ViewManager = ViewManager(self)
        self.plugins = PluginManager(self)

        self.current_screen = ObjectContainer(None, name="current_screen")

        #
        # Initialize font configurations
        #

        self.default_tabs = [
            FunctionsView(self, 'left'),
            DisassemblyView(self, 'center'),
            CodeView(self, 'center'),
            SymexecView(self, 'center'),
            StatesView(self, 'center'),
            StringsView(self, 'center'),
            PatchesView(self, 'center'),
            InteractionView(self, 'center'),
            ConsoleView(self, 'bottom'),
        ]

        if has_binsync():
            self.default_tabs.append(SyncView(self, 'right'))

        #
        # Save initial splitter state
        #

        self.splitter_state = QSettings()
        self.splitter_state.setValue("splitterSizes", self._main_window.central_widget_main.saveState())

        for tab in self.default_tabs:
            self.add_view(tab, tab.caption, tab.category)

    #
    # Properties
    #

    @property
    def instance(self) -> 'Instance':
        return self._instance

    #
    # Events
    #

    def on_function_selected(self, func):

        self._get_or_create_disassembly_view().display_function(func)
        codeview = self.view_manager.first_view_in_category('pseudocode')
        if codeview is not None and codeview.is_shown():
            self.decompile_function(func, codeview)

    def on_cfg_generated(self):

        self.instance.add_job(
            PrototypeFindingJob(
                on_finish=self._on_prototype_found,
            )
        )

        # display the main function if it exists, otherwise display the function at the entry point
        if self.instance.cfg is not None:
            the_func = self.instance.kb.functions.function(name='main')
            if the_func is None:
                the_func = self.instance.kb.functions.function(addr=self.instance.project.entry)

            if the_func is not None:
                self.on_function_selected(the_func)

    def _on_prototype_found(self):
        self.instance.add_job(
            VariableRecoveryJob(
                on_finish=self.on_variable_recovered,
            )
        )

    def on_variable_recovered(self):
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
        """
        Split the view into two panes and shift
        the current tab into the second pane

        :return:    None
        """

        window_id = self.view_manager.get_current_tab_id()
        if self.is_split is False:
            self._main_window.central_widget.removeDockWidget(self.view_manager.docks[window_id])
            dock_area = ViewManager.DOCKING_POSITIONS.get(self.default_tabs[window_id].default_docking_position,
                                                          Qt.RightDockWidgetArea)
            dock = QSmartDockWidget(self.default_tabs[window_id].caption, parent=self.default_tabs[window_id])
            self._main_window.central_widget2.show()
            self._main_window.central_widget2.addDockWidget(dock_area, dock)
            dock.setWidget(self.default_tabs[window_id])
            self.is_split = True
            self.split_tab_id = window_id
            self.last_unsplit_view = dock
            self._main_window.central_widget_main.setStretchFactor(1,1)

    def add_view(self, view, caption, category):
        self.view_manager.add_view(view, caption, category)

    def unsplit_view(self):
        """
        Unsplit view if it is already split

        :return:    None
        """

        if self.is_split is True:
            window_id = self.split_tab_id
            self._main_window.central_widget2.hide()
            self._main_window.central_widget2.removeDockWidget(self.last_unsplit_view)
            dock_area = ViewManager.DOCKING_POSITIONS.get(self.default_tabs[window_id].default_docking_position,
                                                          Qt.RightDockWidgetArea)
            dock = QSmartDockWidget(self.default_tabs[window_id].caption, parent=self.default_tabs[window_id])
            self._main_window.central_widget.addDockWidget(dock_area, dock)
            dock.setWidget(self.default_tabs[window_id])
            self.view_manager.docks[window_id] = dock
            self._main_window.central_widget_main.setStretchFactor(1,0)
            self._main_window.central_widget_main.restoreState(self.splitter_state.value("splitterSizes"))
            self.view_manager.tabify_center_views()
            self.is_split = False

    def toggle_split(self):
        """
        Toggles the split state
        
        :return:    None
        """

        if self.is_split is False:
            self.split_view()
        else:
            self.unsplit_view()

    def raise_view(self, view):
        """
        Find the dock widget of a view, and then bring that dockable to front.

        :param BaseView view: The view to raise.
        :return:              None
        """

        self.view_manager.raise_view(view)

    def reload(self, categories=None):

        if categories is None:
            views = self.view_manager.views
        else:
            views = [ ]
            for category in categories:
                views.extend(self.view_manager.views_by_category.get(category, [ ]))

        for view in views:
            try:
                view.reload()
            except Exception:
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)
                pass

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

    def jump_to(self, addr, view=None):
        if view is None or view.category != "disassembly":
            view = self._get_or_create_disassembly_view()

        view.jump_to(addr)
        self.raise_view(view)
        view.setFocus()

    def set_comment(self, addr, comment_text):

        kb = self.instance.project.kb
        if comment_text is None and addr in kb.comments:
            del kb.comments[addr]
        kb.comments[addr] = comment_text

        # callback first
        if self.instance.set_comment_callback:
            self.instance.set_comment_callback(addr=addr, comment_text=comment_text)

        disasm_view = self._get_or_create_disassembly_view()
        if disasm_view._flow_graph.disasm is not None:
            # redraw
            disasm_view.current_graph.refresh()

    def decompile_current_function(self, view=None):
        if view is None or view.category != "disassembly":
            view = self._get_or_create_disassembly_view()

        view.decompile_current_function()

    def decompile_function(self, func, view=None):
        """
        Decompile a function and switch to the pseudocode view.

        :param Function func:   The function to decompile.
        :param view:    The pseudocode view to raise.
        :return:        None
        """

        if view is None or view.category != "pseudocode":
            view = self._get_or_create_pseudocode_view()

        view.function = func
        self.raise_view(view)
        view.setFocus()

    def create_simulation_manager(self, state, state_name, view=None):

        inst = self.instance
        hierarchy = StateHierarchy()
        simgr = inst.project.factory.simulation_manager(state, hierarchy=hierarchy)
        simgr_container = ObjectContainer(simgr, name=state_name)
        inst.simgrs.append(simgr_container)
        inst.simgrs.am_event(src='new_path')

        if view is None:
            view = self._get_or_create_symexec_view()
        view.select_simgr(simgr_container)

        self.raise_view(view)

    def interact_program(self, img_name, view=None):
        if view is None or view.category != 'interaction':
            view = self._get_or_create_interaction_view()
        view.initialize(img_name)

        self.raise_view(view)
        view.setFocus()

    def log(self, msg):
        if isinstance(msg, Exception):
            msg = ''.join(traceback.format_exception(type(msg), msg, msg.__traceback__))

        console = self.view_manager.first_view_in_category('console')
        if console is None:
            print(msg)
        else:
            console.print_text(msg)
            console.print_text('\n')

    #
    # Private methods
    #

    def _get_or_create_disassembly_view(self):
        # Take the first disassembly view
        view = self.view_manager.first_view_in_category("disassembly")

        if view is None:
            # Create a new disassembly view
            view = DisassemblyView(self, 'right')
            self.add_view(view, view.caption, view.category)

        return view

    def _get_or_create_pseudocode_view(self):
        # Take the first pseudo-code view
        view = self.view_manager.first_view_in_category("pseudocode")

        if view is None:
            # Create a new pseudo-code view
            view = CodeView(self, 'right')
            self.add_view(view, view.caption, view.category)

        return view

    def _get_or_create_symexec_view(self):
        # Take the first symexec view
        view = self.view_manager.first_view_in_category("symexec")

        if view is None:
            # Create a new symexec view
            view = CodeView(self, 'right')
            self.add_view(view, view.caption, view.category)

        return view

    def _get_or_create_interaction_view(self):
        view = self.view_manager.first_view_in_category("interaction")
        if view is None:
            # Create a new interaction view
            view = InteractionView(self, 'right')
            self.add_view(view, view.caption, view.category)
        return view

    #
    # UI-related Callback Setters & Manipulation
    #

    from typing import Callable
    from angr.knowledge_plugins.functions.function import Function as angrFunc
    from .menus.disasm_insn_context_menu import DisasmInsnContextMenu

    def set_cb_function_backcolor(self, callback: Callable[[angrFunc], None]):
        fv = self.view_manager.first_view_in_category('functions')  # type: FunctionsView
        if fv:
            fv.backcolor_callback = callback

    def set_cb_insn_backcolor(self, callback: Callable[[int, bool], None]):
        dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.insn_backcolor_callback = callback

    def set_cb_label_rename(self, callback):
        dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.label_rename_callback = callback

    def add_disasm_insn_ctx_menu_entry(self, text, callback: Callable[[DisasmInsnContextMenu], None], add_separator_first=True):
        dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        if dv._insn_menu:
            dv._insn_menu.add_menu_entry(text, callback, add_separator_first)

    def remove_disasm_insn_ctx_menu_entry(self, text, remove_preceding_separator=True):
        dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        if dv._insn_menu:
            dv._insn_menu.remove_menu_entry(text, remove_preceding_separator)

    def set_cb_set_comment(self, callback):
        dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.set_comment_callback = callback
