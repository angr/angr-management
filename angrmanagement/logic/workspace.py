"""
The workspace without a toolkit.

:class:`BaseWorkspace` is what every frontend's workspace shares: the instance, the job, analysis and command managers,
plugins, and the reactions to analysis events, navigation, comments, patches, traces and the debugger. It reaches
views only through ``self.view_manager`` (an :class:`~angrmanagement.logic.view_manager.BaseViewManager`), which
creates them by category, and it asks the user things only through ``GlobalInfo.ui_services``. A frontend subclasses
it with its view manager, its default views and anything that needs its toolkit.

Views are looked up by category and used by what they offer: a frontend without a pseudocode view simply has none,
and the methods that would use one do nothing.
"""

from __future__ import annotations

import logging
import os
import time
import traceback
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, cast

from angr import StateHierarchy
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.patches import Patch
from cle import SymbolType

from angrmanagement.config import Conf
from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.data.instance import Instance, ObjectContainer
from angrmanagement.data.jobs import CFGGenerationJob, LLMRefineJob, LoadBinaryJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.data.trace import BintraceTrace, Trace
from angrmanagement.plugins import PluginManager
from angrmanagement.present.base import is_function_view
from angrmanagement.utils import locate_function
from angrmanagement.utils.daemon_thread import start_daemon_thread

from . import GlobalInfo
from .analysis_manager import AnalysisManager
from .commands import CommandManager
from .debugger import DebuggerWatcher
from .debugger.bintrace import BintraceDebugger
from .debugger.simgr import SimulationDebugger
from .jobmanager import JobCancelled, JobManager
from .threads import gui_thread_schedule_async, needs_gui_thread
from .view_manager import BaseViewManager, default_position

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.annotations import CommentKind
    from angrmanagement.data.jobs.job import Job

_l = logging.getLogger(__name__)

#: The file types offered when the user picks a binary to open.
BINARY_FILE_FILTER = (
    "All executables (*)"
    ";;Windows PE files (*.exe)"
    ";;Core Dumps (*.core)"
    ";;angr database (*.adb)"
    ";;Archives (*.zip *.tar *.tar.gz *.tgz *.tar.bz2 *.tbz2 *.tar.xz *.txz)"
)


def recent_directory() -> str:
    """The directory of the most recently opened file, if it still exists, else ``""``."""
    if Conf.recent_files:
        recent_dir = os.path.dirname(Conf.recent_files[-1])
        if os.path.isdir(recent_dir):
            return recent_dir
    return ""


def _container(obj: Any) -> ObjectContainer:
    """``obj``, an attribute of the instance, typed as the ObjectContainer it is."""
    return cast("ObjectContainer", obj)


def _call(view: Any, method: str, *args, **kwargs) -> Any:
    """Call ``view.method(*args, **kwargs)`` if the view exists and has the method."""
    func = getattr(view, method, None) if view is not None else None
    if func is None:
        return None
    return func(*args, **kwargs)


class BaseWorkspace:
    """
    The workspace of angr management, whatever draws it.

    :param main_window: The frontend's main window object, if it has one.
    :param instance:    The instance to work on; a new one by default.
    """

    job_manager: JobManager
    view_manager: BaseViewManager

    #: The view manager class; a frontend sets its own.
    VIEW_MANAGER_CLASS: type[BaseViewManager] = BaseViewManager

    def __init__(self, main_window=None, instance: Instance | None = None) -> None:
        self.main_window = main_window
        self.job_manager = JobManager(self)  # pyright: ignore[reportArgumentType]
        self.job_manager.job_starting.connect(self.on_job_started)
        self.job_manager.job_exception.connect(self._handle_job_exception)

        self.command_manager: CommandManager = CommandManager()
        self.view_manager = self._create_view_manager()
        # PluginManager is typed for the Qt workspace; it only needs what this class provides until a plugin runs
        self.plugins: PluginManager = PluginManager(self)  # pyright: ignore[reportArgumentType]
        self._first_cfg_generation_callback_completed: bool = False
        # one-shot: when set, the next auto-triggered initial analysis skips the options dialog and
        # runs with default settings. Used by programmatic loads (e.g. the MCP load_binary tool).
        self._suppress_analysis_options_dialog: bool = False
        # whether the user manually navigated anywhere while a CFG generation job was running
        self._user_navigated_during_cfg: bool = False
        self._nav_tracking_suppress_count: int = 0

        self._main_instance = instance if instance is not None else Instance()

        self.analysis_manager: AnalysisManager = AnalysisManager(self)
        self.analysis_manager.cfg_generated.connect(self.on_cfg_generated)
        self.analysis_manager.cc_recovered.connect(self.on_cc_recovered)
        self.analysis_manager.variable_recovered.connect(self.on_variable_recovered)
        self.analysis_manager.functions_tagged.connect(self.on_function_tagged)

        # Configure callbacks on main_instance
        self.main_instance.project.am_subscribe(self._instance_project_initalization)
        _container(self.main_instance.simgrs).am_subscribe(self._update_simgr_debuggers)
        self.main_instance.handle_comment_changed_callback = self.plugins.handle_comment_changed

        self.current_screen = ObjectContainer(None, name="current_screen")

        # history of MCP tool calls made by an AI agent; persists across project loads. Holds a
        # list of angrmanagement.mcp.history.MCPCallRecord and is appended to by the MCP server.
        self.mcp_history = ObjectContainer([], name="mcp_history")

        self._dbg_watcher = DebuggerWatcher(self.on_debugger_state_updated, self.main_instance.debugger_mgr.debugger)

        _container(self.main_instance.patches).am_subscribe(self._on_patch_event)

    def _create_view_manager(self) -> BaseViewManager:
        return self.VIEW_MANAGER_CLASS(self)

    #
    # Properties
    #

    @property
    def _main_window(self):
        return self.main_window

    @property
    def main_instance(self) -> Instance:
        return self._main_instance

    @property
    def interactive(self) -> bool:
        """Whether there is a user to ask, for example about the analysis options."""
        return False

    #
    # Events
    #

    def on_job_started(self, job) -> None:
        if isinstance(job, CFGGenerationJob):
            start_daemon_thread(self._refresh_cfg, "Progressively Refreshing CFG", args=(job,))

    def _refresh_cfg(self, cfg_job) -> None:
        """
        Reload once and then refresh in a loop, while the CFG job is running
        """
        reloaded = False
        while True:
            if not _container(self.main_instance.cfg).am_none:
                if reloaded:
                    gui_thread_schedule_async(
                        self.refresh,
                        kwargs={
                            "categories": ["disassembly", "functions"],
                        },
                    )
                else:
                    gui_thread_schedule_async(
                        self.reload,
                        kwargs={
                            "categories": ["disassembly", "functions"],
                        },
                    )
                    reloaded = True

            time.sleep(0.3)
            if cfg_job.state not in {JobState.PENDING, JobState.RUNNING}:
                break

    @contextmanager
    def _nav_tracking_suppressed(self):
        """
        Suppress user-navigation tracking while performing programmatic navigation.
        """
        self._nav_tracking_suppress_count += 1
        try:
            yield
        finally:
            self._nav_tracking_suppress_count -= 1

    def _cfg_job_active(self) -> bool:
        return any(
            isinstance(job, CFGGenerationJob) and job.state in {JobState.PENDING, JobState.RUNNING}
            for job in self.job_manager.jobs
        )

    def note_user_navigation(self) -> None:
        """
        Record that the user manually navigated somewhere. Only tracked while a CFG generation job is running, so
        that when the job completes we know to ask before navigating away.
        """
        if self._nav_tracking_suppress_count == 0 and self._cfg_job_active():
            self._user_navigated_during_cfg = True

    def on_cfg_recovery_started(self, cfb) -> None:
        """
        Called on the GUI thread as soon as a CFG generation job creates its temporary CFBlanket. Publish the blanket
        so that views can render the not-yet-analyzed binary and, for the initial CFG recovery, show the entry point
        in the linear disassembly view so that the user can start analyzing right away.
        """
        self._user_navigated_during_cfg = False
        self.main_instance.cfb = cfb
        _container(self.main_instance.cfb).am_event()

        if not self._first_cfg_generation_callback_completed and not self.main_instance.project.am_none:
            with self._nav_tracking_suppressed():
                view = self._get_or_create_view("disassembly")
                if view is None:
                    return
                self.raise_view(view)
                _call(view, "display_linear_viewer", prefer=True)
                _call(view, "jump_to", self.main_instance.project.entry)

    def on_cfg_generated(self) -> None:
        kb = self.main_instance.kb
        if not _container(self.main_instance.cfg).am_none and kb is not None:
            if not self._first_cfg_generation_callback_completed:
                self._first_cfg_generation_callback_completed = True
                the_func = kb.functions.function(name="main")
                if the_func is None:
                    the_func = kb.functions.function(addr=self.main_instance.project.entry)
                if the_func is not None:
                    self._navigate_to_function_after_cfg(the_func)

            # Reload the pseudocode view
            _call(self.view_manager.first_view_in_category("pseudocode"), "reload")

            # Reload the strings view
            _call(self.view_manager.first_view_in_category("strings"), "reload")

            # Clear the proximity view
            _call(self.view_manager.first_view_in_category("proximity"), "clear")

    def _navigate_to_function_after_cfg(self, func: Function) -> None:
        """
        Navigate to the given function and switch to the graph view after CFG recovery completes. If the user
        manually navigated anywhere during the recovery, ask before yanking the view away.
        """
        if self._user_navigated_during_cfg:
            self._ask_navigate_to_function_after_cfg(func)
            return
        self._do_navigate_to_function_after_cfg(func)

    def _ask_navigate_to_function_after_cfg(self, func: Function) -> None:
        def on_answer(answer: str) -> None:
            if answer == "Yes":
                self._do_navigate_to_function_after_cfg(func)

        # modeless: a modal question here would block whoever waits on the job queue (e.g., a headless test) forever
        GlobalInfo.ui_services.question_async(
            "CFG recovery finished",
            f"CFG recovery finished. Jump to {func.name} and switch to graph view?",
            ["Yes", "No"],
            "Yes",
            on_answer,
        )

    def _do_navigate_to_function_after_cfg(self, func: Function) -> None:
        self._user_navigated_during_cfg = False
        with self._nav_tracking_suppressed():
            view = self.view_manager.first_view_in_category("disassembly")
            _call(view, "display_disasm_graph", prefer=True)
            self.on_function_selected(func)

    def on_debugger_state_updated(self) -> None:
        """
        Jump to debugger target PC in active disassembly view.
        """
        # FIXME: the disassembly view should subscribe to debugger updates, but for that we will need to expose
        #        a mechanism for the view to select between states. For now we simply have a global debugger
        #        selection.
        dbg = self._dbg_watcher.debugger
        if not dbg.am_none:
            state = dbg.simstate
            if state is not None:
                addr = state.solver.eval(state.regs.pc)
                view = self.view_manager.current_view_in_category(
                    "disassembly"
                ) or self.view_manager.first_view_in_category("disassembly")
                if view:
                    view.jump_to(addr, True)

    def on_function_selected(self, func: Function) -> None:
        """
        Callback function triggered when a new function is selected in the function view.

        :param func:    The function that is selected.
        :return:        None
        """

        # Ask all current views to display this function
        current_view = self.view_manager.current_tab
        if current_view is None or not is_function_view(current_view):
            # we don't have a current view or the current view does not have function-specific content. create a
            # disassembly view to display the selected function.
            disasm_view = self._get_or_create_view("disassembly")
            if disasm_view is None:
                return
            _call(disasm_view, "display_function", func)
            self.view_manager.raise_view(disasm_view)
        else:
            # ask the current view to display this function
            current_view.function = func

    def on_function_tagged(self) -> None:
        # reload disassembly view
        if len(self.view_manager.views_by_category["disassembly"]) == 1:
            view = self.view_manager.first_view_in_category("disassembly")
        else:
            view = self.view_manager.current_view_in_category("disassembly")

        current_function = getattr(view, "current_function", None)
        if view is not None and current_function is not None and current_function.am_obj is not None:
            view.reload()

    def on_flirt_signatures_applied(self) -> None:
        _call(self.view_manager.first_view_in_category("functions"), "reset_cache_and_refresh")
        _call(self.view_manager.first_view_in_category("disassembly"), "reload")
        _call(self.view_manager.first_view_in_category("pseudocode"), "reload")

    def on_function_updated(self) -> None:
        _call(self.view_manager.first_view_in_category("functions"), "reset_cache_and_refresh")

    def on_cc_recovered(self, func_addr: int) -> None:
        """
        Called when the calling convention of a given function is available.

        :param int func_addr:   Address of the function whose calling convention information is available.
        """
        _call(self.view_manager.first_view_in_category("disassembly"), "on_cc_recovered", func_addr)

    def on_variable_recovered(self, func_addr: int) -> None:
        """
        Called when variable information of the given function is available.

        :param int func_addr:   Address of the function whose variable information is available.
        """
        _call(self.view_manager.first_view_in_category("disassembly"), "on_variable_recovered", func_addr)

    def _on_patch_event(self, **kwargs) -> None:
        kb = self.main_instance.kb
        if _container(self.main_instance.cfg).am_none or kb is None:
            return

        update_cfg = False
        for k in ("added", "removed"):
            for patch in kwargs.get(k, set()):
                self.main_instance.cfg.clear_region_for_reflow(
                    patch.addr, len(patch.new_bytes), self.main_instance.project.kb
                )
                update_cfg = True

        if update_cfg:
            self.analysis_manager.generate_cfg(
                cfg_args={
                    "force_smart_scan": False,
                    "force_complete_scan": False,
                    "model": kb.cfgs.get_most_accurate(),
                    # FIXME: We don't want to force scan the entire binary, just the patched region. Add an
                    #        option for it.
                }
            )

    #
    # Views
    #

    def new_disassembly_view(self):
        """
        Add a new disassembly view.
        """
        disassembly_view = self.view_manager.first_view_in_category("disassembly")
        jump_history = getattr(disassembly_view, "jump_history", None)
        current_addr = jump_history.current if jump_history is not None else None

        view = self.view_manager.create_view("disassembly", "center")
        if view is None:
            return None
        self.raise_view(view)
        _call(getattr(view, "_linear_viewer", None), "initialize")
        if current_addr is not None:
            view.jump_to(current_addr)
        # TODO move view tab to front of dock
        return view

    def add_view(self, view) -> None:
        self.view_manager.add_view(view)

    def remove_view(self, view) -> None:
        self.view_manager.remove_view(view)

    def raise_view(self, view) -> None:
        """
        Find the dock widget of a view, and then bring that dockable to front.

        :param BaseView view: The view to raise.
        :return:              None
        """

        self.view_manager.raise_view(view)

    def reload(self, categories: list[str] | None = None) -> None:
        """
        Ask all or specified views to reload the underlying data and regenerate the UI. This is usually expensive.

        :param categories:  Specify a list of view categories that should be reloaded.
        :return:            None
        """

        for view in self._views_in(categories):
            try:
                view.reload()
            except Exception:  # pylint:disable=broad-except
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)

    def refresh(self, categories: list[str] | None = None) -> None:
        """
        Ask all or specified views to refresh based on changes in the underlying data and refresh the UI if needed. This
        may be called frequently so it must be extremely fast.

        :param categories:  Specify a list of view categories that should be reloaded.
        :return:            None
        """

        for view in self._views_in(categories):
            try:
                self._refresh_view(view)
            except Exception:  # pylint:disable=broad-except
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)

    def _refresh_view(self, view) -> None:  # pylint:disable=no-self-use
        """Refresh one view; a frontend whose widgets have their own ``refresh()`` calls something else."""
        view.refresh()

    def _views_in(self, categories: list[str] | None) -> list[Any]:
        if categories is None:
            return list(self.view_manager.views)
        views = []
        for category in categories:
            views.extend(self.view_manager.views_by_category.get(category, []))
        return views

    def show_view(self, category: str, type_: Any = None, position: str | None = None) -> Any:
        """
        Show the view of ``category``, creating it if there is none, and give it the focus.

        :param type_:       A view class to create when the frontend has none registered for ``category`` (a plugin's
                            own view, for example).
        :param position:    Where to dock a new view; the category's default when None.
        :returns:           The view, or None if this frontend has no view of that category.
        """
        view = self._get_or_create_view(category, type_, position=position)
        if view is None:
            return None
        self.raise_view(view)
        self.view_manager.focus_view(view)
        return view

    def _get_or_create_view(self, category: str, view_type: Any = None, position: str | None = None) -> Any:
        view = self.view_manager.current_view_in_category(category)
        if view is None:
            view = self.view_manager.first_view_in_category(category)
        if view is None:
            if position is None:
                position = default_position(category)
            view = self.view_manager.create_view(category, position)
            if view is None and view_type is not None:
                view = view_type(self, position, self._main_instance)
                self.add_view(view)
        return view

    def show_linear_disassembly_view(self) -> None:
        view = self._get_or_create_view("disassembly", position="center")
        if view is None:
            return
        _call(view, "display_linear_viewer")
        self.raise_view(view)
        self.view_manager.focus_view(view)

    def show_graph_disassembly_view(self) -> None:
        view = self._get_or_create_view("disassembly", position="center")
        if view is None:
            return
        _call(view, "display_disasm_graph")
        self.raise_view(view)
        self.view_manager.focus_view(view)

    def create_and_show_linear_disassembly_view(self) -> None:
        """
        Create a new disassembly view and select the Linear disassembly mode.
        """
        view = self.new_disassembly_view()
        if view is None:
            return
        _call(view, "display_linear_viewer")
        self.raise_view(view)
        self.view_manager.focus_view(view)

    def create_and_show_graph_disassembly_view(self) -> None:
        """
        Create a new disassembly view and select the Graph disassembly mode.
        """
        view = self.new_disassembly_view()
        if view is None:
            return
        _call(view, "display_disasm_graph")
        self.raise_view(view)
        self.view_manager.focus_view(view)

    def create_and_show_hex_view(self):
        return self.view_manager.create_view("hex", "center")

    def show_pseudocode_view(self) -> None:
        self.show_view("pseudocode")

    def show_hex_view(self) -> None:
        self.show_view("hex")

    def show_symexec_view(self) -> None:
        self.show_view("symexec")

    def show_states_view(self) -> None:
        self.show_view("states")

    def show_strings_view(self) -> None:
        self.show_view("strings")

    def show_search_view(self) -> None:
        view = self._get_or_create_view("search")
        if view is None:
            return
        view.reload()
        self.raise_view(view)
        _call(view, "focus_query_box")

    def show_patches_view(self) -> None:
        self.show_view("patches")

    def show_types_view(self) -> None:
        self.show_view("types")

    def show_functions_view(self) -> None:
        self.show_view("functions", position="left")

    def show_traces_view(self) -> None:
        self.show_view("traces")

    def show_signatures_view(self) -> None:
        self.show_view("signatures")

    def show_trace_map_view(self) -> None:
        self.show_view("tracemap", position="top")

    def show_registers_view(self) -> None:
        self.show_view("registers", position="right")

    def show_stack_view(self) -> None:
        self.show_view("stack", position="right")

    def show_breakpoints_view(self) -> None:
        self.show_view("breakpoints")

    def show_comments_view(self) -> None:
        self.show_view("comments", position="bottom")

    def show_bookmarks_view(self) -> None:
        self.show_view("bookmarks", position="bottom")

    def show_call_explorer_view(self) -> None:
        self.show_view("call_explorer")

    def show_console_view(self) -> None:
        self.show_view("console", position="bottom")

    def show_log_view(self) -> None:
        self.show_view("log", position="bottom")

    def show_jobs_view(self) -> None:
        self.show_view("jobs", position="bottom")

    def show_mcp_history_view(self) -> None:
        self.show_view("mcp_history", position="bottom")

    #
    # Navigation
    #

    def viz(self, obj) -> None:
        """
        Visualize the given object.

        - For integers, open the disassembly view and jump to that address
        - For Function objects, open the disassembly view and jump there
        - For strings, look up the symbol of that name and jump there
        """

        if isinstance(obj, int):
            self.jump_to(obj)
        elif isinstance(obj, str):
            sym = self.main_instance.project.loader.find_symbol(obj)
            if sym is not None:
                self.jump_to(sym.rebased_addr)
        elif isinstance(obj, Function):
            self.jump_to(obj.addr)

    @needs_gui_thread
    def jump_to(self, addr: int, view=None, use_animation: bool = False) -> None:
        if view is None or view.category != "disassembly":
            view = self._get_or_create_view("disassembly")
        if view is None:
            return

        self.raise_view(view)
        self.view_manager.focus_view(view)
        view.jump_to(addr, use_animation=use_animation)

    def current_address(self) -> int | None:
        """
        The address the user is looking at, taken from the focused view and falling back to any
        disassembly or pseudocode view that has a cursor.
        """
        views = [self.view_manager.most_recently_focused_view]
        views += self.view_manager.views_by_category["disassembly"]
        views += self.view_manager.views_by_category["pseudocode"]
        for view in views:
            if view is None:
                continue
            if view.category == "disassembly":
                addr = _call(view, "_instruction_address_in_selection")
                if addr is not None:
                    return addr
            elif view.category == "pseudocode" and not view.addr.am_none:
                return view.addr.am_obj
        return None

    def toggle_bookmark(self, addr: int | None = None) -> None:
        """
        Add or remove a bookmark at ``addr``, defaulting to the current address.
        """
        if self.main_instance.project.am_none:
            return
        if addr is None:
            addr = self.current_address()
        if addr is None:
            return
        self.main_instance.annotations.toggle_bookmark(addr)
        self.refresh(["disassembly", "pseudocode"])

    def goto_next_bookmark(self) -> None:
        """
        Jump to the next bookmark by address, wrapping around at the end.
        """
        bookmark = self.main_instance.annotations.next_bookmark(self.current_address())
        if bookmark is not None:
            self.jump_to(bookmark.addr)

    #
    # Breakpoints and the debugger
    #

    def add_breakpoint(self, obj: str | int, type_: str | None = None, size: int | None = None) -> None:
        """
        Convenience function to add a breakpoint.

        Examples:
        - `workspace.add_breakpoint(0x1234)` sets an execution breakpoint on address 0x1234
        - `workspace.add_breakpoint('main')` sets an execution breakpoint on `main` function
        - `workspace.add_breakpoint('global_value')` sets a write breakpoint on `global_value`
        - `workspace.add_breakpoint('global_value', 'read', 1)` sets a 1-byte read breakpoint on `global_value`
        """
        if isinstance(obj, int):
            addr = obj
        elif isinstance(obj, str):
            sym = self.main_instance.project.loader.find_symbol(obj)
            if sym is None:
                _l.error("Couldn't resolve '%s'", obj)
                return
            addr = sym.rebased_addr
            if not size:
                size = sym.size
            if not type_:
                type_ = "execute" if sym.type == SymbolType.TYPE_FUNCTION else "write"
        elif isinstance(obj, Function):
            addr = obj.addr
            if not type_:
                type_ = "execute"
        else:
            _l.error("Unexpected target object type. Expected int | str | Function")
            return

        if not size:
            size = 1

        bp_type_map = {
            None: BreakpointType.Execute,
            "execute": BreakpointType.Execute,
            "write": BreakpointType.Write,
            "read": BreakpointType.Read,
        }
        if type_ not in bp_type_map:
            _l.error("Unknown breakpoint type '%s'. Expected %s", type_, " | ".join(bp_type_map.keys()))
            return

        bp = Breakpoint(bp_type_map[type_], addr, size)
        self.main_instance.breakpoint_mgr.add_breakpoint(bp)

    def toggle_exec_breakpoint(self) -> None:
        if self.main_instance is None:
            return

        view = self.view_manager.first_view_in_category("disassembly")
        current_graph = getattr(view, "current_graph", None)
        infodock = getattr(current_graph, "infodock", None)
        if infodock is not None:
            selected_insns = infodock.selected_insns
            if selected_insns:
                for insn in selected_insns:
                    self.main_instance.breakpoint_mgr.toggle_exec_breakpoint(insn)

    def step_forward(self, until_addr: int | None = None) -> None:
        if self.main_instance is None:
            return

        self.main_instance.debugger_mgr.debugger.step_forward(until_addr=until_addr)

    def continue_forward(self) -> None:
        if self.main_instance is None:
            return

        self.main_instance.debugger_mgr.debugger.continue_forward()

    #
    # Comments
    #

    def set_comment(self, addr: int, comment_text, kind: CommentKind | None = None) -> None:
        self.main_instance.set_comment(addr, comment_text, kind=kind)
        self.refresh_after_comment_change(addr)

    def refresh_after_comment_change(self, addr: int) -> None:
        """
        Redraw whatever displays the comment at ``addr``: the disassembly, and the pseudocode view
        of the containing function if one is open.
        """
        disasm_view = self._get_or_create_view("disassembly")
        flow_graph = getattr(disasm_view, "_flow_graph", None)
        if flow_graph is not None and flow_graph.disasm is not None:
            disasm_view.current_graph.refresh()

        kb = self.main_instance.kb
        if kb is None:
            return
        func = kb.functions.floor_func(addr)
        if func is None:
            return
        for view in self.view_manager.views_by_category["pseudocode"]:
            if view.function.am_obj is not None and view.function.addr == func.addr and not view.codegen.am_none:
                view.codegen.am_event()

    #
    # Projects and databases
    #

    def close_project(self) -> None:
        """
        Unload the currently loaded project, returning the workspace to an empty state. The data
        views clear themselves in response to the container-reset events. Does nothing if no
        project is loaded.
        """
        from .headless_workspace import close_project  # pylint:disable=import-outside-toplevel,cyclic-import

        close_project(self.main_instance)

    def save_database(self, file_path: str) -> bool:
        """
        Dump the current project and its knowledge base to an angr database (.adb) file.

        :returns: True on success, False if no project is loaded.
        """
        from .headless_workspace import save_database  # pylint:disable=import-outside-toplevel,cyclic-import

        return save_database(self, file_path)

    def load_database(self, file_path: str, on_loaded=None):
        """
        Load an angr database (.adb) into the workspace via a background job. When the load
        finishes, the project/CFG/CFB containers are populated and views are refreshed, then the
        optional ``on_loaded(file_path)`` callback is invoked.
        """
        from .headless_workspace import load_database  # pylint:disable=import-outside-toplevel,cyclic-import

        return load_database(self, file_path, lambda job, *args: self._on_database_loaded(job, on_loaded, *args))

    def _on_database_loaded(self, job, on_loaded, *args, **kwargs) -> None:  # pylint:disable=unused-argument
        from .headless_workspace import apply_loaded_database  # pylint:disable=import-outside-toplevel,cyclic-import

        if not apply_loaded_database(self, job):
            return

        if on_loaded is not None:
            on_loaded(job.file_path)

    #
    # Analyses
    #

    def run_analysis(self, use_default_options: bool = False) -> None:
        if self.main_instance.project.am_none:
            return

        if self.main_instance.analysis_configuration is None:
            self.main_instance.analysis_configuration = self.analysis_manager.get_default_analyses_configuration()

        # Ask for the options only when there is a user and the caller has not opted into the default settings
        # (headless runs and programmatic loads use the defaults directly).
        if self.interactive and not use_default_options:
            configuration = self._ask_analysis_options(self.main_instance.analysis_configuration)
            if configuration is None:
                return
            self.main_instance.analysis_configuration = configuration

        self.analysis_manager.run_analysis()

    def _ask_analysis_options(self, configuration):
        return GlobalInfo.ui_services.analysis_options(self, configuration)

    def decompile_current_function(self) -> None:
        current = self.view_manager.current_tab
        if current is not None and current.category == "pseudocode" and hasattr(current, "decompile"):
            current.decompile()
        else:
            view = self._get_or_create_view("disassembly")
            _call(view, "decompile_current_function")

    def decompile_function(self, func: Function, curr_ins=None, view=None) -> None:
        """
        Decompile a function and switch to decompiled view. If curr_ins is
        defined, then also switch cursor focus to the position associated
        with the asm instruction addr

        :param func: The function to decompile
        :param curr_ins: The instruction the cursor was at before switching to decompiled view
        :param view: The decompiled qt text view
        :return:
        """

        if view is None or view.category != "pseudocode":
            view = self._get_or_create_view("pseudocode")
        if view is None:
            return

        view.function.am_obj = func
        view.function.am_event(focus=True, focus_addr=curr_ins)

    def view_data_dependency_graph(self, analysis_params: dict) -> None:
        view = self._get_or_create_view("data_dependency")
        if view is None:
            return
        view.analysis_params = analysis_params
        self.raise_view(view)

    def view_proximity_for_current_function(self, view=None) -> None:
        if view is None or view.category != "proximity":
            view = self._get_or_create_view("proximity")
        if view is None:
            return

        disasm_view = self._get_or_create_view("disassembly")
        current_function = getattr(disasm_view, "current_function", None)
        if current_function is not None:
            view.function = current_function.am_obj

        self.raise_view(view)

    def define_code(self, addr: int) -> None:
        cfg = self.main_instance.cfg
        kb = self.main_instance.kb
        if _container(cfg).am_none or kb is None:
            _l.error("Run initial CFG analysis before defining code")
            return

        func = locate_function(self.main_instance, addr)
        if func is not None:
            _l.warning("Address %#x is already defined as code", addr)
            return

        function_starts = [addr]

        # Attempt flow into preceding function
        func = cfg.find_function_for_reflow_into_addr(addr)
        if func:
            function_starts = [func.addr]
            cfg.clear_region_for_reflow(func.addr)

        # Truncate existing memory data
        if addr in cfg.memory_data:
            del cfg.memory_data[addr]
        for md in cfg.memory_data.values():
            if md.size and md.addr < addr < (md.addr + md.size):
                md.size = addr - md.addr

        self.analysis_manager.generate_cfg(
            cfg_args={
                "symbols": False,
                "function_prologues": False,
                "start_at_entry": False,
                "force_smart_scan": False,
                "force_complete_scan": False,
                "function_starts": function_starts,
                "model": kb.cfgs.get_most_accurate(),
                "treat_functions_as_complete": self.main_instance.cfg_resume_state is None,
            }
        )

    def undefine_code(self, addr: int) -> None:
        cfg = self.main_instance.cfg
        kb = self.main_instance.kb
        if _container(cfg).am_none or kb is None:
            _l.error("Run initial CFG analysis before undefining code")
            return

        func = locate_function(self.main_instance, addr)
        if func is None:
            _l.warning("Could not determine function for addr %#x", addr)
            return

        md = MemoryData(addr, 1, MemoryDataSort.Integer)  # FIXME: Type, expand size
        cfg.memory_data[md.addr] = md.copy()
        cfg.clear_region_for_reflow(func.addr)

        self.analysis_manager.generate_cfg(
            cfg_args={
                "symbols": False,
                "function_prologues": False,
                "start_at_entry": False,
                "force_smart_scan": False,
                "force_complete_scan": False,
                "function_starts": [func.addr],
                "model": kb.cfgs.get_most_accurate(),
                "treat_functions_as_complete": self.main_instance.cfg_resume_state is None,
            }
        )

    def can_resume_cfg_recovery(self, addr: int | None = None) -> bool:
        """
        Determine whether CFG recovery may be resumed right now, optionally from the given address. Resuming requires
        an existing (possibly partial) CFG model and no CFG generation job in flight; resuming from an address that is
        already part of the CFG is a no-op and is therefore not allowed.
        """
        cfg = self.main_instance.cfg
        if not isinstance(cfg, ObjectContainer) or cfg.am_none:
            return False
        if self.main_instance.project.am_none or self._cfg_job_active():
            return False
        if addr is not None:
            if self.main_instance.project.loader.find_object_containing(addr) is None:
                return False
            if self.main_instance.cfg.get_any_node(addr, anyaddr=True) is not None:
                return False
        return True

    def resume_cfg_recovery(self, addr: int) -> None:
        """
        Resume CFG recovery from the given address only: recovery continues outward from this address on top of the
        existing (partial) CFG model, without re-seeding symbols, prologues, or gap scanning.
        """
        kb = self.main_instance.kb
        if kb is None or not self.can_resume_cfg_recovery(addr):
            return

        self.analysis_manager.generate_cfg(
            cfg_args={
                "symbols": False,
                "function_prologues": False,
                "eh_frame": False,
                "start_at_entry": False,
                "force_smart_scan": False,
                "force_complete_scan": False,
                "function_starts": [addr],
                "model": kb.cfgs.get_most_accurate(),
                # the model stays partial after a strict resume; do not let post-analysis conclude
                # returning=False for truncated functions (it would poison a later full resume)
                "treat_functions_as_complete": self.main_instance.cfg_resume_state is None,
            }
        )

    def resume_cfg_recovery_full(self) -> None:
        """
        Resume full CFG recovery: re-inject the state that a cancelled CFG generation job did not get to process and
        let global scanning (symbols, prologues, smart scan) finish the rest of the binary on top of the existing
        (partial) CFG model.
        """
        kb = self.main_instance.kb
        if kb is None or not self.can_resume_cfg_recovery():
            return

        cfg_args = {
            "start_at_entry": False,
            "model": kb.cfgs.get_most_accurate(),
        }
        if self.main_instance.cfg_resume_state is not None:
            # re-create the unprocessed jobs with their original function context; this reproduces the result of an
            # uninterrupted recovery
            cfg_args["resume_state"] = self.main_instance.cfg_resume_state
        self.analysis_manager.generate_cfg(cfg_args=cfg_args)

    def show_function_info(self, function: str | int | Function) -> None:
        func = self.main_instance.project.kb.functions[function] if isinstance(function, str | int) else function
        GlobalInfo.ui_services.function_info(func)

    def patch(self, addr: int, asm: str, pad: bool = True) -> None:
        block = self.main_instance.project.factory.block(addr)
        insn = block.disassembly.insns[0]
        original_bytes: bytes = self.main_instance.project.loader.memory.load(insn.address, insn.size)
        ks = self.main_instance.project.arch.keystone
        new_bytes = (ks.asm(asm, addr, as_bytes=True)[0] or b"") if len(asm) else b""

        # Pad to original instruction length
        byte_length_delta = len(original_bytes) - len(new_bytes)
        if byte_length_delta > 0:
            if pad:
                nop_instruction_bytes = self.main_instance.project.arch.nop_instruction
                new_bytes += (byte_length_delta // len(nop_instruction_bytes)) * nop_instruction_bytes
                byte_length_delta = len(original_bytes) - len(new_bytes)
                if byte_length_delta:
                    _l.warning("Unable to completely pad remainder")
        elif byte_length_delta < 0:
            _l.warning("Patch exceeds original instruction length")

        pm = self.main_instance.project.kb.patches
        patch = Patch(addr, new_bytes)
        pm.add_patch_obj(patch)
        _container(self.main_instance.patches).am_event(added={patch})

    #
    # Patterns
    #

    def on_patterns_changed(self) -> None:
        """The project's patterns changed: refresh every view that lists them."""
        for view in self.view_manager.views:
            if view.category == "pattern":
                _call(view, "reload_library")
            elif view.category == "pseudocode":
                _call(view, "reload_patterns")

    def edit_pattern(self, stored):
        """Open a stored pattern in the pattern view."""
        view = self._get_or_create_view("pattern")
        if view is None:
            return None
        view.load_stored(stored)
        self.raise_view(view)
        return view

    def highlight_in_disassembly(self, addrs):
        """Paint the instructions at ``addrs`` in the disassembly view and show the first."""
        view = self._get_or_create_view("disassembly")
        if view is None:
            return None
        _call(view, "highlight_pattern_addrs", addrs)
        if addrs:
            view.jump_to(min(addrs))
        self.raise_view(view)
        # its Clear highlights clears this one too
        _call(self.view_manager.first_view_in_category("pseudocode"), "_update_clear_highlights")
        return view

    def show_pattern_discovery(self):
        """Open the pattern view on its Discover tab, where a discovery run is set up and started."""
        if self.main_instance.project.am_none:
            GlobalInfo.ui_services.message("warning", "Discover Patterns", "No project is loaded.")
            return None
        view = self._get_or_create_view("pattern")
        if view is None:
            return None
        _call(view, "show_discover_tab")
        self.raise_view(view)
        return view

    def discover_patterns(self):
        """Look for families of similar code in the function shown in the pseudocode view.

        Shows a message box and does nothing else if no function is decompiled there.
        """
        title = "Discover Patterns"
        if self.main_instance.project.am_none:
            GlobalInfo.ui_services.message("warning", title, "No project is loaded.")
            return None
        code_view = self.view_manager.first_view_in_category("pseudocode")
        if code_view is None or code_view._function.am_none or code_view.codegen.am_none:
            GlobalInfo.ui_services.message(
                "warning",
                title,
                "No function is currently decompiled in the pseudocode view.\n\nDecompile a function (F5) first.",
            )
            return None
        view = self._get_or_create_view("pattern")
        if view is None:
            return None
        self.raise_view(view)
        view.discover(code_view._function.am_obj)
        return view

    #
    # LLM
    #

    def _llm_refine_current_function(self, mode: str) -> None:
        """Run LLM refinement on the currently decompiled function.

        Shows an error dialog if no LLM client is configured or no function is
        currently decompiled.
        """
        services = GlobalInfo.ui_services
        if self.main_instance.project.am_none:
            services.message("warning", "LLM Refine", "No project is loaded.")
            return

        project = self.main_instance.project.am_obj
        if project is None or project.llm_client is None:
            services.message(
                "warning",
                "LLM Refine",
                "No LLM client configured.\n\nGo to File → Preferences → LLM to set a model.",
            )
            return

        code_view = self.view_manager.first_view_in_category("pseudocode")
        if code_view is None or code_view._function.am_none:
            services.message("warning", "LLM Refine", "No function is currently decompiled.")
            return

        func = code_view._function.am_obj

        def on_finish(*_args, **_kwargs):
            code_view.codegen.am_event(already_regenerated=True)

        job = LLMRefineJob(self.main_instance, func, mode=mode, on_finish=on_finish)
        self.job_manager.add_job(job)

    def llm_refine_all(self) -> None:
        self._llm_refine_current_function("all")

    def llm_suggest_variable_names(self) -> None:
        self._llm_refine_current_function("variable_names")

    def llm_suggest_function_name(self) -> None:
        self._llm_refine_current_function("function_name")

    def llm_suggest_variable_types(self) -> None:
        self._llm_refine_current_function("variable_types")

    def llm_summarize_function(self) -> None:
        self._llm_refine_current_function("summarize")

    #
    # Symbolic execution and traces
    #

    def create_simulation_manager(self, state, state_name: str, view=None) -> None:
        inst = self.main_instance
        hierarchy = StateHierarchy()
        simgr = inst.project.factory.simulation_manager(state, hierarchy=hierarchy)
        simgr_container = ObjectContainer(simgr, name=state_name)
        simgrs = _container(inst.simgrs)
        simgrs.append(simgr_container)
        simgrs.am_event(src="new_path")

        if view is None:
            view = self._get_or_create_view("symexec")
        if view is None:
            return
        view.select_simgr(simgr_container)

        self.raise_view(view)

    def create_trace_debugger(self) -> None:
        current_trace = _container(self.main_instance.current_trace)
        if current_trace.am_none:
            _l.error("No trace available")
            return

        if isinstance(current_trace.am_obj, BintraceTrace):
            dbg = BintraceDebugger(current_trace.am_obj, self)
            dbg.init()
            self.main_instance.debugger_list_mgr.add_debugger(dbg)
            self.main_instance.debugger_mgr.set_debugger(dbg)

    def is_current_trace(self, trace: Trace | None) -> bool:
        return _container(self.main_instance.current_trace).am_obj is trace

    def set_current_trace(self, trace: Trace | None) -> None:
        current_trace = _container(self.main_instance.current_trace)
        current_trace.am_obj = trace
        current_trace.am_event()

    def remove_trace(self, trace: Trace) -> None:
        if self.is_current_trace(trace):
            self.set_current_trace(None)
        traces = _container(self.main_instance.traces)
        traces.remove(trace)
        traces.am_event(trace_removed=trace)
        # Note: Debuggers and other objects may retain trace

    def load_trace_from_path(self, path: str) -> None:
        if not BintraceTrace.trace_backend_enabled():
            GlobalInfo.ui_services.message(
                "critical", "Error", "bintrace is not installed. Please install the bintrace package."
            )
            return

        _l.info("Opening trace %s", path)
        trace = BintraceTrace.load_trace(path)

        def on_complete(*args, **kwargs) -> None:  # pylint:disable=unused-argument
            if not self.main_instance.project.am_none:
                traces = _container(self.main_instance.traces)
                traces.append(trace)
                traces.am_event(trace_added=trace)
                self.set_current_trace(trace)
                self.show_traces_view()

        if self.main_instance.project.am_none:
            GlobalInfo.ui_services.message("info", "Creating project", "Creating new project from trace.")
            self.create_project_from_trace(trace, on_complete)
        else:
            on_complete()

    def create_project_from_trace(self, trace: Trace, on_complete: Callable) -> None:
        services = GlobalInfo.ui_services
        thing = None
        load_options = trace.get_project_load_options()

        if load_options is None:
            services.message(
                "warning", "Error", "Failed to determine load options for binary from trace. Please select binary."
            )
            load_options = {}
        else:
            thing = load_options["thing"]
            load_options = load_options["load_options"]
            if not os.path.exists(thing):
                services.message(
                    "warning",
                    "Unable to find target binary!",
                    f"Unable to find the traced binary at: \n\n{thing}\n\nPlease select target binary.",
                )
                thing = None

        if not thing:
            thing = self._pick_binary()

        if not thing:
            on_complete()
            return

        self.main_instance.binary_path = thing
        self.main_instance.original_binary_path = thing
        job = LoadBinaryJob(self.main_instance, thing, load_options=load_options, on_finish=on_complete)
        self.job_manager.add_job(job)

    def _pick_binary(self) -> str | None:  # pylint:disable=no-self-use
        """Ask the user for a binary to open."""
        picked = GlobalInfo.ui_services.pick_open_files("Open a binary", recent_directory(), BINARY_FILE_FILTER, False)
        return picked[0] if picked else None

    #
    # The console
    #

    def log(self, msg) -> None:
        if isinstance(msg, BaseException):
            msg = "".join(traceback.format_exception(type(msg), msg, msg.__traceback__))

        console = self.view_manager.first_view_in_category("console")
        if console is None or not getattr(console, "ipython_widget_available", False):
            print(msg)
        else:
            console.print_text(msg)
            console.print_text("\n")

    def append_code_to_console(self, hook_code_string: str) -> None:
        console = self._get_or_create_view("console")
        _call(console, "set_input_buffer", hook_code_string)

    #
    # Instance Callbacks
    #

    def _instance_project_initalization(self, **kwargs) -> None:  # pylint:disable=unused-argument
        if self.main_instance.project.am_none:
            return

        # trigger more analyses if we don't have at least one CFG available
        kb = self.main_instance.kb
        if kb is not None and not kb.cfgs.cfgs:
            # consume the one-shot suppression flag set by programmatic loads
            use_default_options = self._suppress_analysis_options_dialog
            self._suppress_analysis_options_dialog = False
            gui_thread_schedule_async(self.run_analysis, kwargs={"use_default_options": use_default_options})

        self.plugins.handle_project_initialization()

    def _handle_job_exception(self, job: Job, ex: BaseException) -> None:
        self.log(f'Exception while running job "{job.name}":')
        self.log(ex)
        self.log("Type %debug to debug it")

        if isinstance(ex, JobCancelled):
            # the user asked for it; no need to report it
            return

        msg = "".join(traceback.format_exception(ex))
        # shown without blocking: a failing job must not stall whoever is waiting on the job queue
        gui_thread_schedule_async(
            GlobalInfo.ui_services.notify,
            ("critical", f"Error during job {job.name}", f"An exception occurred when running {job.name}:\n\n{msg}"),
        )

    def _update_simgr_debuggers(self, **kwargs) -> None:  # pylint:disable=unused-argument
        sim_dbg = None
        for dbg in self.main_instance.debugger_list_mgr.debugger_list:
            if isinstance(dbg, SimulationDebugger):
                sim_dbg = dbg
                break

        if len(self.main_instance.simgrs) > 0:
            if sim_dbg is None:
                symexec_view = self._get_or_create_view("symexec")
                if symexec_view is None:
                    return
                dbg = SimulationDebugger(symexec_view._simgrs, self)
                self.main_instance.debugger_list_mgr.add_debugger(dbg)
                self.main_instance.debugger_mgr.set_debugger(dbg)
        elif sim_dbg is not None:
            self.main_instance.debugger_list_mgr.remove_debugger(sim_dbg)
