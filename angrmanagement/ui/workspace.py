from typing import TYPE_CHECKING, Callable
import logging
import traceback

from angr.knowledge_plugins.functions.function import Function
from angr import StateHierarchy

from ..config import Conf
from ..data.instance import ObjectContainer
from ..data.jobs import CodeTaggingJob, PrototypeFindingJob, VariableRecoveryJob, FlirtSignatureRecognitionJob
from .views import (FunctionsView, DisassemblyView, SymexecView, StatesView, StringsView, ConsoleView, CodeView,
                    InteractionView, PatchesView, DependencyView, ProximityView, TypesView, HexView, LogView)
from .view_manager import ViewManager
from .menus.disasm_insn_context_menu import DisasmInsnContextMenu

from ..plugins import PluginManager

if TYPE_CHECKING:
    from ..data.instance import Instance
    from angrmanagement.ui.main_window import MainWindow


_l = logging.getLogger(__name__)


class Workspace:
    """
    This class implements the angr management workspace.
    """
    def __init__(self, main_window, instance):

        self.main_window: 'MainWindow' = main_window
        self._instance = instance
        instance.workspace = self

        self.view_manager: ViewManager = ViewManager(self)
        self.plugins: PluginManager = PluginManager(self)

        self.current_screen = ObjectContainer(None, name="current_screen")

        #
        # Initialize font configurations
        #

        self.default_tabs = [
            FunctionsView(self, 'left'),
            DisassemblyView(self, 'center'),
            HexView(self, 'center'),
            ProximityView(self, 'center'),
            CodeView(self, 'center'),
        ]
        if Conf.has_operation_mango:
            self.default_tabs.append(
                DependencyView(self, 'center')
            )
        self.default_tabs += [
            StringsView(self, 'center'),
            PatchesView(self, 'center'),
            SymexecView(self, 'center'),
            StatesView(self, 'center'),
            InteractionView(self, 'center'),
            ConsoleView(self, 'bottom'),
            LogView(self, 'bottom'),
        ]

        for tab in self.default_tabs:
            self.add_view(tab)

    #
    # Properties
    #

    @property
    def _main_window(self) -> 'MainWindow':
        return self.main_window

    @property
    def instance(self) -> 'Instance':
        return self._instance

    #
    # Events
    #

    def on_function_selected(self, func: Function):
        """
        Callback function triggered when a new function is selected in the function view.

        :param func:    The function that is selected.
        :return:        None
        """

        # Ask all current views to display this function

        current_view = self.view_manager.current_tab
        if current_view is None or not current_view.FUNCTION_SPECIFIC_VIEW:
            # we don't have a current view or the current view does not have function-specific content. create a
            # disassembly view to display the selected function.
            disasm_view = self._get_or_create_disassembly_view()
            disasm_view.display_function(func)
            self.view_manager.raise_view(disasm_view)
        else:
            # ask the current view to display this function
            current_view.function = func

    def on_cfg_generated(self):

        self.instance.add_job(
            FlirtSignatureRecognitionJob(
                on_finish=self._on_flirt_signature_recognized,
            )
        )

        # display the main function if it exists, otherwise display the function at the entry point
        if self.instance.cfg is not None:
            the_func = self.instance.kb.functions.function(name='main')
            if the_func is None:
                the_func = self.instance.kb.functions.function(addr=self.instance.project.entry)

            if the_func is not None:
                self.on_function_selected(the_func)

            # Initialize the linear viewer
            if len(self.view_manager.views_by_category['disassembly']) == 1:
                view = self.view_manager.first_view_in_category('disassembly')
            else:
                view = self.view_manager.current_view_in_category('disassembly')
            if view is not None:
                view._linear_viewer.initialize()

            # Reload the pseudocode view
            view = self.view_manager.first_view_in_category('pseudocode')
            if view is not None:
                view.reload()

            # Reload the strings view
            view = self.view_manager.first_view_in_category('strings')
            if view is not None:
                view.reload()

    def _on_flirt_signature_recognized(self):
        self.instance.add_job(
            PrototypeFindingJob(
                on_finish=self._on_prototype_found,
            )
        )

    def _on_prototype_found(self):
        self.instance.add_job(
            VariableRecoveryJob(
                on_finish=self.on_variable_recovered,
                **self.instance.variable_recovery_args,
            )
        )

    def on_variable_recovered(self):
        self.instance.add_job(
            CodeTaggingJob(
                on_finish=self.on_function_tagged,
            )
        )

    def on_function_tagged(self):
        # reload disassembly view
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            view = self.view_manager.first_view_in_category('disassembly')
        else:
            view = self.view_manager.current_view_in_category('disassembly')

        if view is not None:
            view: DisassemblyView
            if view.current_function.am_obj is not None:
                view.reload()

    #
    # Public methods
    #

    def new_disassembly_view(self) -> DisassemblyView:
        """
        Add a new disassembly view.
        """
        new_view = DisassemblyView(self, 'center')
        self.add_view(new_view)
        self.raise_view(new_view)
        if self.instance.binary_path is not None:
            self.on_cfg_generated()
        # TODO move new_view tab to front of dock
        return new_view

    def add_view(self, view):
        self.view_manager.add_view(view)

    def remove_view(self, view):
        self.view_manager.remove_view(view)

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
            except Exception:  # pylint:disable=broad-except
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)

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

    def jump_to(self, addr, view=None, use_animation=False):
        if view is None or view.category != 'disassembly':
            view = self._get_or_create_disassembly_view()

        view.jump_to(addr, use_animation=use_animation)
        self.raise_view(view)
        view.setFocus()

    def set_comment(self, addr, comment_text):
        kb = self.instance.project.kb
        exists = addr in kb.comments

        # callback
        if comment_text is None and exists:
            self.plugins.handle_comment_changed(addr, "", False, False)
            del kb.comments[addr]
        else:
            self.plugins.handle_comment_changed(addr, comment_text, not exists, False)
            kb.comments[addr] = comment_text

        # callback first
        # TODO: can this be removed?
        if self.instance.set_comment_callback:
            self.instance.set_comment_callback(addr=addr, comment_text=comment_text)

        disasm_view = self._get_or_create_disassembly_view()
        if disasm_view._flow_graph.disasm is not None:
            # redraw
            disasm_view.current_graph.refresh()

    def decompile_current_function(self):
        current = self.view_manager.current_tab
        if isinstance(current, CodeView):
            current.decompile()
        else:
            view = self._get_or_create_disassembly_view()
            view.decompile_current_function()

    def view_proximity_for_current_function(self, view=None):
        if view is None or view.category != "proximity":
            view = self._get_or_create_proximity_view()

        disasm_view = self._get_or_create_disassembly_view()
        if disasm_view.current_function is not None:
            view.function = disasm_view.current_function.am_obj

        self.raise_view(view)

    def decompile_function(self, func: Function, curr_ins=None, view=None):
        """
        Decompile a function a switch to decompiled view. If curr_ins is
        defined, then also switch cursor focus to the position associated
        with the asm instruction addr

        :param func: The function to decompile
        :param curr_ins: The instruction the cursor was at before switching to decompiled view
        :param view: The decompiled qt text view
        :return:
        """

        if view is None or view.category != "pseudocode":
            view = self._get_or_create_pseudocode_view()

        view.function.am_obj = func
        view.function.am_event(focus=True, focus_addr=curr_ins)

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

    def show_linear_disassembly_view(self):
        view = self._get_or_create_disassembly_view()
        view.display_linear_viewer()
        self.raise_view(view)
        view.setFocus()

    def show_graph_disassembly_view(self):
        view = self._get_or_create_disassembly_view()
        view.display_disasm_graph()
        self.raise_view(view)
        view.setFocus()

    def create_and_show_linear_disassembly_view(self):
        """
        Create a new disassembly view and select the Linear disassembly mode.
        """
        view = self.new_disassembly_view()
        view.display_linear_viewer()
        self.raise_view(view)
        view.setFocus()

    def create_and_show_graph_disassembly_view(self):
        """
        Create a new disassembly view and select the Graph disassembly mode.
        """
        view = self.new_disassembly_view()
        view.display_disasm_graph()
        self.raise_view(view)
        view.setFocus()

    def create_and_show_hex_view(self):
        """
        Create and show a new hex view.
        """
        view = self._create_hex_view()
        self.raise_view(view)
        view.setFocus()

    def show_pseudocode_view(self):
        """
        Create code view if it does not exist, then show code view.
        """
        view = self._get_or_create_pseudocode_view()
        self.raise_view(view)
        view.setFocus()

    def show_hex_view(self):
        view = self._get_or_create_hex_view()
        self.raise_view(view)
        view.setFocus()

    def show_symexec_view(self):
        view = self._get_or_create_symexec_view()
        self.raise_view(view)
        view.setFocus()

    def show_states_view(self):
        view = self._get_or_create_states_view()
        self.raise_view(view)
        view.setFocus()

    def show_strings_view(self):
        view = self._get_or_create_strings_view()
        self.raise_view(view)
        view.setFocus()

    def show_patches_view(self):
        view = self._get_or_create_patches_view()
        self.raise_view(view)
        view.setFocus()

    def show_interaction_view(self):
        view = self._get_or_create_interaction_view()
        self.raise_view(view)
        view.setFocus()

    def show_types_view(self):
        view = self._get_or_create_types_view()
        self.raise_view(view)
        view.setFocus()

    def show_functions_view(self):
        view = self._get_or_create_functions_view()
        self.raise_view(view)
        view.setFocus()

    def show_console_view(self):
        view = self._get_or_create_console_view()
        self.raise_view(view)
        view.setFocus()

    def show_log_view(self):
        view = self._get_or_create_log_view()
        self.raise_view(view)
        view.setFocus()

    #
    # Private methods
    #

    def _get_or_create_disassembly_view(self) -> DisassemblyView:
        view = self.view_manager.current_view_in_category('disassembly')
        if view is None:
            view = self.view_manager.first_view_in_category('disassembly')
        if view is None:
            view = DisassemblyView(self, 'center')
            self.add_view(view)
            view.reload()

        return view

    def _create_hex_view(self) -> HexView:
        """
        Create a new hex view.
        """
        view = HexView(self, 'center')
        self.add_view(view)
        return view

    def _get_or_create_hex_view(self) -> HexView:
        view = self.view_manager.first_view_in_category('hex')

        if view is None:
            view = self._create_hex_view()

        return view

    def _get_or_create_pseudocode_view(self):
        # Take the first pseudo-code view
        view = self.view_manager.first_view_in_category("pseudocode")

        if view is None:
            # Create a new pseudo-code view
            view = CodeView(self, 'center')
            self.add_view(view)

        return view

    def _get_or_create_symexec_view(self):
        # Take the first symexec view
        view = self.view_manager.first_view_in_category("symexec")

        if view is None:
            # Create a new symexec view
            view = SymexecView(self, 'center')
            self.add_view(view)

        return view

    def _get_or_create_states_view(self):
        # Take the first states view
        view = self.view_manager.first_view_in_category("states")

        if view is None:
            # Create a new states view
            view = StatesView(self, 'center')
            self.add_view(view)

        return view

    def _get_or_create_strings_view(self):
        # Take the first strings view
        view = self.view_manager.first_view_in_category("strings")

        if view is None:
            # Create a new states view
            view = StringsView(self, 'center')
            self.add_view(view)

        return view

    def _get_or_create_patches_view(self):
        # Take the first strings view
        view = self.view_manager.first_view_in_category("patches")

        if view is None:
            # Create a new states view
            view = PatchesView(self, 'center')
            self.add_view(view)

        return view

    def _get_or_create_interaction_view(self):
        view = self.view_manager.first_view_in_category("interaction")
        if view is None:
            # Create a new interaction view
            view = InteractionView(self, 'center')
            self.add_view(view)
        return view

    def _get_or_create_types_view(self):
        view = self.view_manager.first_view_in_category("types")
        if view is None:
            # Create a new interaction view
            view = TypesView(self, 'center')
            self.add_view(view)
        return view

    def _get_or_create_proximity_view(self) -> ProximityView:
        # Take the first proximity view
        view = self.view_manager.first_view_in_category("proximity")

        if view is None:
            # Create a new proximity view
            view = ProximityView(self, 'center')
            self.add_view(view)

        return view

    def _get_or_create_console_view(self) -> ConsoleView:
        # Take the first console view
        view = self.view_manager.first_view_in_category("console")

        if view is None:
            # Create a new console view
            view = ConsoleView(self, 'bottom')
            self.add_view(view)

        return view

    def _get_or_create_log_view(self) -> LogView:
        # Take the first log view
        view = self.view_manager.first_view_in_category("log")

        if view is None:
            # Create a new log view
            view = LogView(self, 'bottom')
            self.add_view(view)

        return view


    def _get_or_create_functions_view(self) -> FunctionsView:
        # Take the first functions view
        view = self.view_manager.first_view_in_category("functions")

        if view is None:
            # Create a new functions view
            view = FunctionsView(self, 'left')
            self.add_view(view)

        return view

    #
    # UI-related Callback Setters & Manipulation
    #

    # TODO: should these be removed? Nobody is using them and there is equivalent functionality elsewhere.

    def set_cb_function_backcolor(self, callback: Callable[[Function], None]):
        fv = self.view_manager.first_view_in_category('functions')  # type: FunctionsView
        if fv:
            fv.backcolor_callback = callback

    def set_cb_insn_backcolor(self, callback: Callable[[int, bool], None]):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.insn_backcolor_callback = callback

    def set_cb_label_rename(self, callback):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.label_rename_callback = callback

    def add_disasm_insn_ctx_menu_entry(self, text, callback: Callable[[DisasmInsnContextMenu], None], add_separator_first=True):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv._insn_menu:
            dv._insn_menu.add_menu_entry(text, callback, add_separator_first)

    def remove_disasm_insn_ctx_menu_entry(self, text, remove_preceding_separator=True):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv._insn_menu:
            dv._insn_menu.remove_menu_entry(text, remove_preceding_separator)

    def set_cb_set_comment(self, callback):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.set_comment_callback = callback
