
import logging
from collections import defaultdict

from PySide2.QtCore import Qt

from angr.knowledge_plugins import Function
from angr import StateHierarchy

from ..data.instance import ObjectContainer
from ..data.jobs import CodeTaggingJob
from ..config import Conf
from .views import FunctionsView, DisassemblyView, SymexecView, StatesView, StringsView, ConsoleView, CodeView, InteractionView
from .widgets.qsmart_dockwidget import QSmartDockWidget
from .view_manager import ViewManager

_l = logging.getLogger(__name__)


class Workspace:
    def __init__(self, main_window, instance):

        self._main_window = main_window
        self._instance = instance
        instance.workspace = self

        self.view_manager = ViewManager(self)

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
            InteractionView(self, 'right'),
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

        self._get_or_create_disassembly_view().display_function(func)

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
        self.view_manager.add_view(view, caption, category)

    def raise_view(self, view):
        """
        Find the dock widget of a view, and then bring that dockable to front.

        :param BaseView view: The view to raise.
        :return:              None
        """

        self.view_manager.raise_view(view)

    def reload(self):
        for view in self.view_manager.views:
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

    def decompile_current_function(self, view=None):
        if view is None or view.category != "disassembly":
            view = self._get_or_create_disassembly_view()

        view.decompile_current_function()

    def decompile_function(self, func, view=None):
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
            view = Interaction(self, 'right')
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

    def add_disasm_insn_ctx_menu_entry(self, text, callback: Callable[[DisasmInsnContextMenu], None]):
        dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        if dv._insn_menu:
            dv._insn_menu.add_menu_entry(text, callback)

    def set_cb_set_comment(self, callback):
        dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.set_comment_callback = callback
