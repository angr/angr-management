"""
The terminal frontend of angr management: a Textual app.

:class:`AmApp` lays the screen out as the Qt main window does: a menu bar, the five docking areas, and a status bar.
It installs the terminal executor and UI services, makes a :class:`~angrmanagement.tui.workspace.TuiWorkspace`, and
implements the main window's actions (open, save, preferences, the MCP server, ...) with the terminal's own screens.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import pickle
import time
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.app import App
from textual.command import CommandPalette
from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from angrmanagement.config import Conf, save_config
from angrmanagement.config.config_manager import HeadlessFrontendAdapter
from angrmanagement.data.jobs.loading import LoadBinaryJob
from angrmanagement.errors import InvalidURLError, UnexpectedStatusCodeError
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.workspace import BINARY_FILE_FILTER, recent_directory
from angrmanagement.present.keymap import KITTY_KEYBOARD_TIER, Binding, Chord, Keymap, global_keymap
from angrmanagement.present.menus import Menu as PresentMenu
from angrmanagement.present.menus import MenuEntry, MenuSeparator, walk_entries
from angrmanagement.present.shell import DOCUMENTATION_URL, FileMenu, build_main_menus
from angrmanagement.present.symexec import open_new_state
from angrmanagement.present.theme import CUSTOM_SCHEME_NAME, Theme
from angrmanagement.present.xrefs import XRefsModel
from angrmanagement.tui.caps import TerminalCaps, caps_from_environment
from angrmanagement.tui.executor import TextualExecutor
from angrmanagement.tui.new_state import NewStateScreen
from angrmanagement.tui.palette import AmCommandProvider, GotoProvider
from angrmanagement.tui.services import TuiServices
from angrmanagement.tui.theme import all_textual_themes, theme_id
from angrmanagement.tui.view_manager import DockArea
from angrmanagement.tui.widgets.debug_bar import DebugBar
from angrmanagement.tui.widgets.feature_map import FeatureMapStrip
from angrmanagement.tui.widgets.menubar import MenuBar, MenuPopup
from angrmanagement.tui.widgets.statusbar import StatusBar
from angrmanagement.tui.workspace import TuiWorkspace
from angrmanagement.tui.xrefs import XRefsScreen
from angrmanagement.utils.archive import is_archive
from angrmanagement.utils.io import isurl

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from textual import events
    from textual.app import ComposeResult
    from textual.widget import Widget

    from angrmanagement.data.jobs.job import Job
    from angrmanagement.logic.commands import Command
    from angrmanagement.present.symexec import StateSpec

_l = logging.getLogger(__name__)

#: Bindings only the terminal frontend has: its docking areas.
TUI_BINDINGS = Keymap(
    "tui",
    [
        Binding("F12", "toggle_bottom_panel", "Show or hide the bottom area"),
        Binding("Ctrl+Shift+Left", "resize_area('left', -4)", "Narrow the left area"),
        Binding("Ctrl+Shift+Right", "resize_area('left', 4)", "Widen the left area"),
        Binding("Ctrl+Shift+Up", "resize_area('bottom', 2)", "Raise the bottom area"),
        Binding("Ctrl+Shift+Down", "resize_area('bottom', -2)", "Lower the bottom area"),
    ],
)

#: How long apart two Shift presses may be to open the goto palette, as in the Qt frontend.
SHIFT_SHIFT_TIMEOUT = 1.0


class AmApp(App):
    """
    angr management in a terminal.

    :param binary:          A file to open once the app runs.
    :param caps:            What the terminal can do; read from the environment by default.
    :param theme_name:      The colour scheme (Light, Dark, Dracula, Catppuccin Mocha or Custom); the configured one by
                            default.
    :param interactive:     Whether to ask the user; with False every question gets its default, as in a script.
    """

    TITLE = "angr management"
    COMMANDS: ClassVar = App.COMMANDS | {AmCommandProvider}

    CSS = """
    Screen {
        layout: vertical;
    }
    #body {
        height: 1fr;
    }
    #middle {
        width: 1fr;
    }
    #area-left {
        width: 48;
        border-right: vkey $primary 40%;
    }
    #area-right {
        width: 40;
        border-left: vkey $primary 40%;
    }
    #area-bottom {
        border-top: hkey $primary 40%;
    }
    #area-top {
        border-bottom: hkey $primary 40%;
    }
    #bottom-strip {
        height: 1;
        background: $panel;
    }
    #toolbars {
        height: 1;
        background: $panel;
    }

    #center-placeholder {
        height: 1fr;
        width: 1fr;
        content-align: center middle;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        binary: str | None = None,
        caps: TerminalCaps | None = None,
        theme_name: str | None = None,
        interactive: bool = True,
    ) -> None:
        super().__init__()
        self.binary = binary
        self.caps = caps if caps is not None else caps_from_environment()
        self.interactive = interactive
        self.shown_at_start = interactive
        self.scheme_name = theme_name or Conf.theme_name or "Light"
        self.am_theme = (
            Theme.from_scheme(self.scheme_name) if self._known_scheme(self.scheme_name) else Theme.from_conf()
        )
        self.keymap = global_keymap()
        self.keymap.extend(TUI_BINDINGS)
        self._last_shift = 0.0
        self.mcp_server_manager: Any = None

        # install the frontend before the workspace: its job manager and signals need the executor
        self._saved_globals = (
            GlobalInfo._executor,  # pylint:disable=protected-access
            GlobalInfo._ui_services,  # pylint:disable=protected-access
            GlobalInfo.main_window,
            Conf.frontend_adapter,
        )
        self.executor = TextualExecutor()
        self.services = TuiServices(self)
        self.services.interactive = interactive
        GlobalInfo.executor = self.executor
        GlobalInfo.ui_services = self.services
        GlobalInfo.main_window = self  # type: ignore[assignment]
        Conf.set_frontend_adapter(HeadlessFrontendAdapter())

        self.workspace = TuiWorkspace(self)
        self.workspace.register_commands()
        self.menus: list[PresentMenu] = build_main_menus(self, Conf.recent_files, self._view_menu_extras())
        file_menu = self.menus[0]
        assert isinstance(file_menu, FileMenu)
        self._file_menu = file_menu
        self._plugin_menu = self.menus[4]
        self.workspace.main_instance.project.am_subscribe(self._on_project_changed)
        self.menu_bar = MenuBar(self.menus, self.shortcut_text)
        # the Qt window's Debug and Feature Map toolbars, in one row under the menu bar
        self.debug_bar = DebugBar(self.workspace, id="debug-bar")
        self.feature_map = FeatureMapStrip(self.workspace, id="feature-map")
        self.status_bar = StatusBar(
            self.workspace.job_manager.interrupt_current_job, self.caps.summary(), self._plugin_status_texts
        )
        self._bind_keys()

    def _plugin_status_texts(self) -> list[str]:
        plugins = getattr(self.workspace, "plugins", None)
        return plugins.status_bar_texts() if plugins is not None else []

    @staticmethod
    def _known_scheme(name: str) -> bool:
        return name == CUSTOM_SCHEME_NAME or any(scheme == name for scheme, _, _ in all_textual_themes())

    def _view_menu_extras(self) -> list[Any]:
        self._toolbar_entries = {
            name: MenuEntry(
                caption, lambda on, name=name: self.set_toolbar_visible(name, on), checkable=True, checked=True
            )
            for name, caption in (("debug-bar", "Debug"), ("feature-map", "Feature Map"))
        }
        toolbars = PresentMenu(
            "&Toolbars",
            [
                MenuEntry("Show all", lambda: self.set_all_toolbars_visible(True)),
                MenuEntry("Hide all", lambda: self.set_all_toolbars_visible(False)),
                MenuSeparator(),
                *self._toolbar_entries.values(),
            ],
        )
        return [toolbars, MenuEntry("&Bottom Area", self.toggle_bottom_panel, shortcut="F12")]

    def set_toolbar_visible(self, name: str, visible: bool) -> None:
        """Show or hide a toolbar (``debug-bar`` or ``feature-map``); the row goes when both are hidden."""
        self._toolbar_entries[name].checked = visible
        widget = self.debug_bar if name == "debug-bar" else self.feature_map
        widget.display = visible
        if self.is_running:
            self.query_one("#toolbars").display = self.debug_bar.display or self.feature_map.display

    def set_all_toolbars_visible(self, visible: bool) -> None:
        for name in self._toolbar_entries:
            self.set_toolbar_visible(name, visible)

    def _bind_keys(self) -> None:
        for binding in self.keymap.for_tier(self.caps):
            key = binding.textual_key()
            if key is None:
                continue
            action = binding.action
            if binding.args:
                action += "(" + ", ".join(repr(a) for a in binding.args) + ")"
            self.bind(key, action, description=binding.description, show=False)
        # Alt+mnemonic opens a menu, where the terminal reports it and no shortcut has the chord
        taken = {Chord.parse(b.chord) for b in self.keymap.for_tier(self.caps) if not b.is_sequence}
        for idx, menu in enumerate(self.menus):
            if not menu.mnemonic:
                continue
            chord = Chord(menu.mnemonic.upper(), alt=True)
            if chord in taken or (self.caps.tier < KITTY_KEYBOARD_TIER and not chord.legacy_reportable()):
                continue
            self.bind(
                chord.to_textual(), f"open_menu_index({idx})", description=f"Open the {menu.text} menu", show=False
            )

    #
    # The screen
    #

    def compose(self) -> ComposeResult:
        yield self.menu_bar
        with Horizontal(id="toolbars"):
            yield self.debug_bar
            yield self.feature_map
        with Horizontal(id="body"):
            yield DockArea("left")
            with Vertical(id="middle"):
                yield DockArea("top")
                yield Static(
                    Text(
                        "No view is open here.\nF10 opens the menu bar; the command palette is on "
                        f"{self.chord_for('command_palette') or 'Ctrl+P'}.",
                        justify="center",
                    ),
                    id="center-placeholder",
                )
                yield DockArea("center")
                yield DockArea("bottom")
                yield Static("", id="bottom-strip")
            yield DockArea("right")
        yield self.status_bar

    def on_mount(self) -> None:
        self.executor.attach()
        for _scheme, _theme, textual_theme in all_textual_themes():
            self.register_theme(textual_theme)
        self.theme = theme_id(self.scheme_name) if self._known_scheme(self.scheme_name) else theme_id("Light")
        self.theme_changed_signal.subscribe(self, self._on_theme_changed)

        job_manager = self.workspace.job_manager
        job_manager.job_starting.connect(self._on_job_starting)
        job_manager.job_progressed.connect(self._on_job_progress)
        job_manager.job_exception.connect(self._on_job_finished)
        job_manager.job_finished.connect(self._on_job_finished)

        self.workspace.add_default_views()
        self.workspace.view_manager.update_areas()
        self._on_project_changed()
        first = self.workspace.view_manager.first_view_in_category("functions")
        if first is not None:
            self.workspace.view_manager.focus_view(first)
        if self.binary:
            self.load_file(self.binary)

    def on_unmount(self) -> None:
        self.shutdown()

    def shutdown(self) -> None:
        """Stop the MCP server and the job worker, and give back the globals the app installed."""
        # a job waiting for an answer from a screen gets the screen's cancel answer, so the worker can return
        self.executor.close()
        if self.mcp_server_manager is not None:
            with contextlib.suppress(Exception):
                self.mcp_server_manager.stop(timeout=2)
            self.mcp_server_manager = None
        with contextlib.suppress(Exception):
            self.workspace.job_manager.interrupt_current_job()
            self.workspace.job_manager.quit()
        executor, services, main_window, adapter = self._saved_globals
        if GlobalInfo._executor is self.executor:  # pylint:disable=protected-access
            GlobalInfo.executor = executor
        if GlobalInfo._ui_services is self.services:  # pylint:disable=protected-access
            GlobalInfo.ui_services = services
        if GlobalInfo.main_window is self:
            GlobalInfo.main_window = main_window
        if isinstance(Conf.frontend_adapter, HeadlessFrontendAdapter) and adapter is not None:
            Conf.set_frontend_adapter(adapter)
        self.executor.detach()

    def _on_theme_changed(self, theme: Any) -> None:
        name = getattr(theme, "name", "")
        for scheme, am_theme, _textual in all_textual_themes():
            if theme_id(scheme) == name:
                self.scheme_name = scheme
                self.am_theme = am_theme
                for view in self.workspace.view_manager.views:
                    for table in view.query("TableWidget"):
                        table.rebuild()
                break

    #
    # Shortcuts and menus
    #

    def chord_for(self, action: str, *args: Any) -> str | None:
        return self.keymap.chord_for(action, self.caps, tuple(args))

    def shortcut_text(self, shortcut: Any) -> str | None:
        """The chord this terminal binds for a menu entry's Qt shortcut."""
        if shortcut is None:
            return None
        text = shortcut if isinstance(shortcut, str) else str(shortcut.toString())
        return self.keymap.effective_shortcut(text, self.caps) or None

    def shortcut_for_command(self, command: Command) -> str | None:
        """The chord of the menu entry that runs ``command``, if any."""
        for menu in self.menus:
            for _path, entry in walk_entries(menu):
                if getattr(entry.action, "__name__", None) == command.name and entry.shortcut:
                    return self.shortcut_text(entry.shortcut)
        return None

    def menu_names(self) -> list[str]:
        return self.menu_bar.menu_names()

    async def open_menu(self, name: str) -> Widget:
        idx = self.menu_bar.index_of(name)
        if idx is None:
            raise KeyError(name)
        popup = self.menu_bar.open_menu(idx)
        await asyncio.sleep(0)
        assert popup is not None
        return popup

    async def close_menu(self) -> None:
        self.menu_bar.close_menu()
        await asyncio.sleep(0)

    def open_context_menu(self, menu: PresentMenu, offset: tuple[int, int]) -> None:
        if not menu.items():
            return
        self.push_screen(MenuPopup(menu, offset, self.shortcut_text))

    def show_status(self, text: str, timeout: float = 5) -> None:
        if self.status_bar.is_attached:
            self.status_bar.show_message(text, timeout)

    def on_key(self, event: events.Key) -> None:
        # the goto palette on two Shift presses, which only the kitty keyboard protocol reports
        if event.key in ("left_shift", "right_shift", "shift"):
            now = time.monotonic()
            if now - self._last_shift < SHIFT_SHIFT_TIMEOUT:
                self._last_shift = 0.0
                self.action_goto_palette()
            else:
                self._last_shift = now
        else:
            self._last_shift = 0.0

    #
    # Running things that ask the user
    #

    def run_flow(self, flow: Coroutine[Any, Any, Any]) -> None:
        """Run a coroutine that asks the user things, on the UI loop."""
        self.run_worker(flow, exit_on_error=False)

    def run_blocking_action(self, func: Callable[[], Any]) -> None:
        """Run ``func``, which may ask the user and wait, in a thread; what it changes goes back to the UI thread."""
        self.run_worker(func, thread=True, exit_on_error=False)

    #
    # Jobs and the status bar
    #

    def _on_job_starting(self, job: Job) -> None:  # pylint:disable=unused-argument
        self.status_bar.progress("Working...", 0.0, True)

    def _on_job_progress(self, job: Job, percentage: float, text: str = "") -> None:
        self.status_bar.progress(f"{job.name}: {text}" if text else job.name, percentage)

    def _on_job_finished(self, job: Job, *_args) -> None:  # pylint:disable=unused-argument
        self.status_bar.progress_done()

    async def wait_for_jobs(self, idle: float = 0.3, timeout: float = 600) -> bool:
        """Wait until no job has run for ``idle`` seconds; False if ``timeout`` passed first."""
        deadline = time.monotonic() + timeout
        last_busy = time.monotonic()
        while time.monotonic() < deadline:
            if self.workspace.job_manager.jobs:
                last_busy = time.monotonic()
            elif time.monotonic() - last_busy > idle:
                return True
            await asyncio.sleep(0.05)
        return False

    def _on_project_changed(self, **_kwargs) -> None:
        instance = self.workspace.main_instance
        loaded = not instance.project.am_none
        self._file_menu.set_project_loaded(loaded)
        if loaded and instance.project.filename:
            self.sub_title = os.path.basename(instance.project.filename)
        elif loaded:
            self.sub_title = "Loaded from stream"
        else:
            self.sub_title = ""

    #
    # The main window's actions
    #

    def _ensure_no_open_project(self) -> bool:
        instance = self.workspace.main_instance
        if instance.project.am_none:
            return True
        self.services.message(
            "warning",
            "A project is already open",
            "A binary is already loaded. Please close it first (File → Close Project) before opening a new one.",
        )
        return False

    def open_file_button(self) -> None:
        async def flow() -> None:
            if not self._ensure_no_open_project():
                return
            path = await self.services.ask_open_file("Open a binary", recent_directory(), BINARY_FILE_FILTER)
            if path:
                self.load_file(path)

        self.run_flow(flow())

    def load_file(self, file_path: str) -> None:
        """Open ``file_path``: a binary, an angr database or a trace."""
        instance = self.workspace.main_instance
        if isurl(file_path):
            self.run_flow(self._download_and_open(file_path))
            return
        if not os.path.isfile(file_path):
            self.services.message(
                "critical",
                "File not found",
                f"angr management cannot open file {file_path}. Please make sure that the file exists.",
            )
            return
        if file_path.endswith(".trace"):
            self.workspace.load_trace_from_path(file_path)
            return
        if not self._ensure_no_open_project():
            return
        if is_archive(file_path):
            self.services.message(
                "warning", "Archives", "Opening a binary from an archive is not available in the terminal yet."
            )
            return
        instance.binary_path = file_path
        instance.original_binary_path = file_path
        if file_path.endswith(".adb"):
            self.workspace.load_database(file_path, on_loaded=self._recent_file)
        else:
            self._recent_file(file_path)
            self.workspace.job_manager.add_job(LoadBinaryJob(instance, file_path))

    async def _download_and_open(self, url: str) -> None:
        from angrmanagement.utils.io import download_url  # pylint:disable=import-outside-toplevel

        if not self._ensure_no_open_project():
            return
        answer = await self.services.ask_question(
            "Downloading a file",
            f"Do you want to download a file from {url} and open it in angr management?",
            ["Yes", "No"],
            "Yes",
        )
        if answer != "Yes":
            return
        try:
            target = await asyncio.to_thread(download_url, url, None, True, None)
        except InvalidURLError:
            self.services.message("critical", "Downloading failed", "The URL is invalid.")
            return
        except UnexpectedStatusCodeError as ex:
            self.services.message("critical", "Downloading failed", f"Unexpected status code {ex.status_code}.")
            return
        if target:
            self.workspace.main_instance.original_binary_path = url
            self.load_file(str(target))

    @staticmethod
    def _recent_file(file_path: str) -> None:
        file_path = os.path.abspath(file_path)
        Conf.recent_file(file_path)
        with contextlib.suppress(OSError):
            save_config()

    def open_trace_file_button(self) -> None:
        async def flow() -> None:
            path = await self.services.ask_open_file(
                "Open a trace file", Conf.last_used_directory, "All files (*);;Trace files (*.trace);;"
            )
            if path:
                Conf.last_used_directory = os.path.dirname(path)
                self.load_trace_file(path)

        self.run_flow(flow())

    def load_trace_file(self, file_path: str) -> None:
        """Show the data dependencies of the SimState a trace file holds, as the Qt main window does."""
        if isurl(file_path):
            self.services.message(
                "critical",
                "Unsupported Action",
                "Downloading trace files is not yet supported. Please specify a path to a file on disk.",
            )
        elif os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    loaded_sim_state = pickle.load(f)
            except pickle.PickleError:
                self.services.message(
                    "critical", "Unable to load trace file", "Trace file must contain a serialized SimState."
                )
                return
            analysis_params = {"end_state": loaded_sim_state, "start_addr": None, "end_addr": None, "block_addrs": None}
            self.workspace.view_data_dependency_graph(analysis_params)
            self._recent_file(file_path)
        else:
            self.services.message(
                "critical",
                "File not found",
                f"angr management cannot open file {file_path}. Please make sure that the file exists.",
            )

    def load_signature_button(self) -> None:
        sig_mgr = self.workspace.main_instance.signature_mgr
        if sig_mgr is None:
            return
        self.workspace.show_signatures_view()
        view = self.workspace.view_manager.first_view_in_category("signatures")
        if view is not None:
            view.presenter.load_signatures()

    def close_project(self) -> None:
        async def flow() -> None:
            if self.workspace.main_instance.project.am_none:
                return
            answer = await self.services.ask_question(
                "Close project", "Close the current project? Any unsaved analysis will be lost.", ["Yes", "No"], "No"
            )
            if answer == "Yes":
                self.workspace.close_project()

        self.run_flow(flow())

    def load_database(self) -> None:
        async def flow() -> None:
            if not self._ensure_no_open_project():
                return
            path = await self.services.ask_open_file("Load angr database", ".", "angr databases (*.adb)")
            if path:
                self.workspace.load_database(path, on_loaded=self._recent_file)

        self.run_flow(flow())

    def save_database(self) -> None:
        instance = self.workspace.main_instance
        if instance.project.am_none:
            return
        if instance.database_path is None:
            self.save_database_as()
        elif self.workspace.save_database(instance.database_path):
            self.show_status(f"Saved {instance.database_path}")

    def save_database_as(self) -> None:
        async def flow() -> None:
            instance = self.workspace.main_instance
            if instance.project.am_none:
                return
            default = instance.database_path
            if default is None:
                default = os.path.normpath(instance.project.filename or "project") + ".adb"
            path = await self.services.ask_save_file("Save angr database", default, "angr databases (*.adb)")
            if not path:
                return
            if not path.endswith(".adb"):
                path += ".adb"
            if self.workspace.save_database(path):
                self.show_status(f"Saved {path}")

        self.run_flow(flow())

    def save_patched_binary_as(self) -> None:
        async def flow() -> None:
            instance = self.workspace.main_instance
            if instance.project.am_none:
                return
            default = instance.project.loader.main_object.binary + ".patched"
            path = await self.services.ask_save_file("Save patched binary as...", default, "Any file (*)")
            if path:
                data = instance.project.kb.patches.apply_patches_to_binary()
                with open(path, "wb") as f:
                    f.write(data)
                self.show_status(f"Saved {path}")

        self.run_flow(flow())

    def load_trace(self) -> None:
        async def flow() -> None:
            path = await self.services.ask_open_file("Load trace", ".", "bintrace (*.trace)")
            if path:
                self.workspace.load_trace_from_path(path)

        self.run_flow(flow())

    def preferences(self) -> None:
        self.services.message(
            "info",
            "Preferences",
            f"The preferences dialog is not in the terminal yet. The configuration file is {config_file_path()}.\n"
            "The colour scheme can be changed from the command palette (Change theme).",
        )

    def quit(self) -> None:
        self.exit()

    def show_command_palette(self) -> None:
        self.action_command_palette()

    def show_goto_palette(self) -> None:
        self.push_screen(CommandPalette(providers=[GotoProvider], placeholder="Go to function..."))

    def goto_function(self, func) -> None:
        self.workspace.on_function_selected(func)
        view = self.workspace.view_manager.first_view_in_category("functions")
        if view is not None:
            idx = next((i for i, e in enumerate(view.presenter.model.rows) if e.addr == func.addr), None)
            if idx is not None:
                self.workspace.view_manager.raise_view(view)
                view.table_widget.move_cursor(row=idx)

    def view_proximity_for_current_function(self) -> None:
        self.workspace.view_proximity_for_current_function()
        view = self.workspace.view_manager.first_view_in_category("proximity")
        if view is not None:
            self.workspace.view_manager.focus_view(view)

    def run_analysis(self) -> None:
        self.workspace.run_analysis()

    def decompile_current_function(self) -> None:
        self.workspace.decompile_current_function()
        if self.workspace.view_manager.first_view_in_category("pseudocode") is None:
            self.show_status("The pseudocode view is not in the terminal yet")

    def discover_patterns(self) -> None:
        self.workspace.show_pattern_discovery()

    def llm_refine_all(self) -> None:
        self.workspace.llm_refine_all()

    def llm_suggest_variable_names(self) -> None:
        self.workspace.llm_suggest_variable_names()

    def llm_suggest_function_name(self) -> None:
        self.workspace.llm_suggest_function_name()

    def llm_suggest_variable_types(self) -> None:
        self.workspace.llm_suggest_variable_types()

    def llm_summarize_function(self) -> None:
        self.workspace.llm_summarize_function()

    def start_mcp_server(self, interactive: bool = True) -> None:
        from angrmanagement.mcp import MCPServerManager, is_mcp_available  # pylint:disable=import-outside-toplevel

        def report_error(title: str, message: str) -> None:
            if interactive:
                self.services.message("critical", title, message)
            else:
                _l.warning("%s: %s", title, message)
                self.show_status(f"{title}: {message}", 10)

        if not is_mcp_available():
            report_error(
                "MCP server unavailable",
                "The MCP server requires the fastmcp and uvicorn packages. "
                'Install them with "pip install angr-management[llm]".',
            )
            return
        if self.mcp_server_manager is not None and self.mcp_server_manager.running:
            self.show_status(f"The MCP server is already running at {self.mcp_server_manager.url}", 10)
            return
        auth_token = None
        if Conf.mcp_server_auth_enabled:
            auth_token = Conf.mcp_server_auth_token or MCPServerManager.generate_auth_token()
            if not Conf.mcp_server_auth_token:
                Conf.mcp_server_auth_token = auth_token
                with contextlib.suppress(OSError):
                    save_config()
        workspace: Any = self.workspace
        manager = MCPServerManager(workspace, port=Conf.mcp_server_port, auth_token=auth_token)
        try:
            manager.start()
        except RuntimeError as ex:
            report_error("Failed to start MCP server", str(ex))
            return
        self.mcp_server_manager = manager
        auth_note = " (bearer-token auth enabled)" if auth_token else ""
        self.show_status(f"MCP server listening at {manager.url}{auth_note}", 10)

    def stop_mcp_server(self) -> None:
        if self.mcp_server_manager is None or not self.mcp_server_manager.running:
            self.show_status("The MCP server is not running")
            return
        self.mcp_server_manager.stop()
        self.mcp_server_manager = None
        self.show_status("MCP server stopped")

    def copy_mcp_url(self) -> None:
        from angrmanagement.mcp.manager import DEFAULT_HOST, DEFAULT_PATH  # pylint:disable=import-outside-toplevel

        if self.mcp_server_manager is not None and self.mcp_server_manager.running:
            url = self.mcp_server_manager.url
            auth_token = self.mcp_server_manager.auth_token
        else:
            url = f"http://{DEFAULT_HOST}:{Conf.mcp_server_port}{DEFAULT_PATH}"
            auth_token = Conf.mcp_server_auth_token if Conf.mcp_server_auth_enabled else None
        if auth_token:
            text = f"{url}\nAuthorization: Bearer {auth_token}"
            message = "Copied MCP URL and auth token to clipboard"
        else:
            text = url
            message = f"Copied to clipboard: {url}"
        self.services.set_clipboard_text(text)
        self.show_status(message)

    def new_state_editor(self, spec: StateSpec, then: Callable[[StateSpec | None], Any]) -> None:
        """The new state dialog: a modal screen over ``spec``; ``then`` gets it back, or None if cancelled."""
        self.push_screen(NewStateScreen(self.workspace.main_instance, spec), then)

    def open_newstate_dialog(self) -> None:
        open_new_state(self.workspace, self.workspace.main_instance, create_simgr=True)

    def open_load_plugins_dialog(self) -> None:
        self.services.message("info", "Plugins", "Managing plugins is not in the terminal yet.")

    def open_doc_link(self) -> None:
        self.services.open_url(DOCUMENTATION_URL)

    def open_about_dialog(self) -> None:
        from angrmanagement import __version__  # pylint:disable=import-outside-toplevel

        self.services.message("info", "About angr management", f"angr management {__version__}\nhttps://angr.io/")

    def toggle_bottom_panel(self) -> None:
        self.workspace.view_manager.toggle_bottom()

    def show_xrefs(self, **kwargs) -> None:
        """Show cross-references in a screen; choosing one jumps there."""
        model = XRefsModel(self.workspace.main_instance, **kwargs)

        def jump(addr: int | None) -> None:
            if addr is not None:
                self.workspace.jump_to(addr)

        self.push_screen(XRefsScreen(model), callback=jump)

    #
    # Key actions
    #

    def action_open_file(self) -> None:
        self.open_file_button()

    def action_open_trace_file(self) -> None:
        self.open_trace_file_button()

    def action_load_signatures(self) -> None:
        self.load_signature_button()

    def action_close_project(self) -> None:
        self.close_project()

    def action_load_database(self) -> None:
        self.load_database()

    def action_save_database(self) -> None:
        self.save_database()

    def action_save_database_as(self) -> None:
        self.save_database_as()

    def action_preferences(self) -> None:
        self.preferences()

    def action_goto_palette(self) -> None:
        self.show_goto_palette()

    def action_next_tab(self) -> None:
        self.workspace.view_manager.next_tab()

    def action_previous_tab(self) -> None:
        self.workspace.view_manager.previous_tab()

    def action_new_graph_disassembly(self) -> None:
        self.workspace.create_and_show_graph_disassembly_view()
        if self.workspace.view_manager.first_view_in_category("disassembly") is None:
            self.show_status("The disassembly view is not in the terminal yet")

    def action_show_view(self, category: str) -> None:
        """Show the view of ``category`` as the Qt workspace's show_*_view does."""
        if category == "search":
            self.workspace.show_search_view()
            return
        self.workspace.show_view(category)

    def action_run_analysis(self) -> None:
        self.run_analysis()

    def action_decompile(self) -> None:
        self.decompile_current_function()

    def action_proximity(self) -> None:
        self.view_proximity_for_current_function()

    def action_llm_refine_all(self) -> None:
        self.llm_refine_all()

    def action_documentation(self) -> None:
        self.open_doc_link()

    def action_interrupt_job(self) -> None:
        self.workspace.job_manager.interrupt_current_job()

    def action_toggle_exec_breakpoint(self) -> None:
        self.workspace.toggle_exec_breakpoint()

    def action_step_forward(self) -> None:
        self.workspace.step_forward()

    def action_continue_forward(self) -> None:
        self.workspace.continue_forward()

    def action_toggle_bookmark(self) -> None:
        self.workspace.toggle_bookmark()

    def action_next_bookmark(self) -> None:
        self.workspace.goto_next_bookmark()

    def action_open_menu_bar(self) -> None:
        self.menu_bar.open_menu(0)

    def action_open_menu_index(self, idx: int) -> None:
        self.menu_bar.open_menu(idx)

    def action_raise_view_by_index(self, idx: int) -> None:
        self.workspace.view_manager.raise_view_by_index(idx)

    def action_toggle_bottom_panel(self) -> None:
        self.toggle_bottom_panel()

    def action_raise_pane(self, pane_id: str) -> None:
        view = self.workspace.view_manager.view_for_pane(pane_id)
        if view is not None:
            self.workspace.view_manager.raise_view(view)
            self.workspace.view_manager.focus_view(view)

    def action_resize_area(self, area: str, delta: int) -> None:
        self.workspace.view_manager.resize(area, delta)

    #
    # What the screenshot harness and the tests use
    #

    async def open_binary(self, path: str, *, function: str | None = "main") -> None:
        """Load ``path`` without asking anything, run the default analyses, and show ``function``."""
        interactive = self.services.interactive
        self.services.interactive = False
        try:
            self.workspace._suppress_analysis_options_dialog = True  # pylint:disable=protected-access
            instance = self.workspace.main_instance
            instance.binary_path = path
            instance.original_binary_path = path
            self.workspace.job_manager.add_job(LoadBinaryJob(instance, path, load_options={"auto_load_libs": False}))
            await asyncio.sleep(0.1)
            await self.wait_for_jobs()
        finally:
            self.services.interactive = interactive
        kb = self.workspace.main_instance.kb
        func = kb.functions.function(name=function) if (kb is not None and function) else None
        if func is not None:
            self.goto_function(func)

    def capture(self, path: str) -> str:
        """Save the screen as an SVG at ``path``; returns the path."""
        directory, filename = os.path.split(os.path.abspath(path))
        return self.save_screenshot(filename=filename, path=directory)

    def view_widget(self, category: str) -> Widget | None:
        return self.workspace.view_manager.current_view_in_category(category) or (
            self.workspace.view_manager.first_view_in_category(category)
        )


def config_file_path() -> str:
    """Where the configuration is saved."""
    from angrmanagement import config  # pylint:disable=import-outside-toplevel

    return config.config_path or "(not saved)"


__all__ = ["AmApp"]
