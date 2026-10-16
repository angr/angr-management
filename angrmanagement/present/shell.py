"""
The main window's menus and commands, without a toolkit.

:func:`build_main_menus` returns the menu bar of angr management (File, View, Analyze, AI, Plugins, Help), bound to the
methods of a *host*: the frontend's main window object, which has a ``workspace`` and the actions the menus name
(``open_file_button``, ``save_database``, ...). Both frontends build their menu bars from these functions; the Qt menu
classes in ``angrmanagement.ui.menus`` wrap them.
:func:`basic_command_table` is the list of commands the command palette offers in every view.
"""

from __future__ import annotations

import platform
from typing import TYPE_CHECKING, Any

from angrmanagement.logic.commands import BasicCommand

from .menus import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from angrmanagement.logic.commands import CommandManager

DOCUMENTATION_URL = "https://angr-management.readthedocs.io/en/latest/"

#: The menus of the menu bar, in order.
MAIN_MENU_CAPTIONS = ("&File", "&View", "&Analyze", "A&I", "&Plugins", "&Help")


def basic_command_table(host: Any) -> list[tuple[str, Callable[[], Any]]]:
    """The palette commands of the main window: (caption, action) pairs."""
    ws = host.workspace
    return [
        ("AI: LLM Refine All", host.llm_refine_all),
        ("AI: LLM Suggest Variable Names", host.llm_suggest_variable_names),
        ("AI: LLM Suggest Function Name", host.llm_suggest_function_name),
        ("AI: LLM Suggest Variable Types", host.llm_suggest_variable_types),
        ("AI: LLM Summarize Function", host.llm_summarize_function),
        ("AI: Start MCP Server", host.start_mcp_server),
        ("AI: Stop MCP Server", host.stop_mcp_server),
        ("AI: Copy MCP Server URL", host.copy_mcp_url),
        ("Analyze: Decompile", host.decompile_current_function),
        ("Analyze: Run Analysis...", host.run_analysis),
        ("Bookmarks: Go to next bookmark", ws.goto_next_bookmark),
        ("Bookmarks: Toggle bookmark", ws.toggle_bookmark),
        ("File: Close project", host.close_project),
        ("File: Exit", host.quit),
        ("File: Load a new binary...", host.open_file_button),
        ("File: Load a new trace...", host.load_trace),
        ("File: Load angr database...", host.load_database),
        ("File: Load FLIRT signature file...", host.load_signature_button),
        ("File: Preferences...", host.preferences),
        ("File: Save angr database as...", host.save_database_as),
        ("File: Save angr database...", host.save_database),
        ("File: Save patched binary as...", host.save_patched_binary_as),
        ("Help: About", host.open_about_dialog),
        ("Help: Documentation", host.open_doc_link),
        ("View: Bookmarks", ws.show_bookmarks_view),
        ("View: Breakpoints", ws.show_breakpoints_view),
        ("View: Call Explorer", ws.show_call_explorer_view),
        ("View: Comments", ws.show_comments_view),
        ("View: Console", ws.show_console_view),
        ("View: Disassembly (Graph)", ws.show_graph_disassembly_view),
        ("View: Disassembly (Linear)", ws.show_linear_disassembly_view),
        ("View: Functions", ws.show_functions_view),
        ("View: Hex", ws.show_hex_view),
        ("View: Function Signatures", ws.show_signatures_view),
        ("View: Jobs", ws.show_jobs_view),
        ("View: Log", ws.show_log_view),
        ("View: MCP History", ws.show_mcp_history_view),
        ("View: New Disassembly (Graph)", ws.create_and_show_graph_disassembly_view),
        ("View: New Disassembly (Linear)", ws.create_and_show_linear_disassembly_view),
        ("View: New Hex", ws.create_and_show_hex_view),
        ("View: Patches", ws.show_patches_view),
        ("View: Proximity", ws.view_proximity_for_current_function),
        ("View: Pseudocode", ws.show_pseudocode_view),
        ("View: Registers", ws.show_registers_view),
        ("View: Search", ws.show_search_view),
        ("View: Stack", ws.show_stack_view),
        ("View: States", ws.show_states_view),
        ("View: Strings", ws.show_strings_view),
        ("View: Symbolic Execution", ws.show_symexec_view),
        ("View: Trace map", ws.show_trace_map_view),
        ("View: Traces", ws.show_traces_view),
        ("View: Types", ws.show_types_view),
    ]


def register_basic_commands(command_manager: CommandManager, host: Any) -> None:
    """Register :func:`basic_command_table` with ``command_manager``, each named after its action."""
    command_manager.register_commands(
        [BasicCommand(action.__name__, caption, action) for caption, action in basic_command_table(host)]
    )


class RecentMenuEntry(MenuEntry):
    """An entry of the "Load recent" submenu: a path and what opens it."""

    def __init__(self, path: str, open_path: Callable[[str], Any]) -> None:
        self.path = path
        super().__init__(path, lambda: open_path(path), icon="file")


class FileMenu(Menu):
    """The File menu; the entries that need a project are disabled while none is loaded."""

    def __init__(self, parent=None) -> None:
        super().__init__("&File", parent=parent)
        self.project_entries: list[MenuEntry] = []
        self.recent_menu = Menu("Load recent")

    def set_project_loaded(self, loaded: bool) -> None:
        for entry in self.project_entries:
            (entry.enable if loaded else entry.disable)()


def build_file_menu(host: Any, recent_files: Iterable[str] = (), menu: FileMenu | None = None) -> FileMenu:
    """The File menu, with ``recent_files`` (oldest first) in "Load recent"; fills ``menu`` when given."""
    if menu is None:
        menu = FileMenu()
    recent = menu.recent_menu
    for path in reversed(list(recent_files)):
        recent.add(RecentMenuEntry(path, host.load_file))
    project_entries = [
        MenuEntry("&Close project", host.close_project, shortcut="Ctrl+W"),
        MenuEntry("&Save angr database...", host.save_database, shortcut="Ctrl+S", icon="file-save"),
        MenuEntry("S&ave angr database as...", host.save_database_as, shortcut="Ctrl+Shift+S", icon="file-save"),
        MenuEntry("Save patched binary as...", host.save_patched_binary_as),
    ]
    for child in (
        MenuEntry("L&oad a new binary...", host.open_file_button, shortcut="Ctrl+O", icon="file-open"),
        MenuEntry("Load a &trace file...", host.open_trace_file_button, shortcut="Ctrl+Shift+T"),
        MenuEntry("Load a &FLIRT signature file...", host.load_signature_button, shortcut="Ctrl+Alt+F"),
        recent,
        MenuSeparator(),
        project_entries[0],
        MenuEntry("&Load angr database...", host.load_database, shortcut="Ctrl+L", icon="file-open"),
        *project_entries[1:],
        MenuSeparator(),
        MenuEntry("Load a new &trace...", host.load_trace),
        MenuSeparator(),
        MenuEntry(
            "&Preferences...",
            host.preferences,
            shortcut="Ctrl+,",
            role="preferences",
            icon="preferences" if platform.system() != "Darwin" else None,
        ),
        MenuSeparator(),
        MenuEntry("E&xit", host.quit),
    ):
        menu.add(child)
    menu.project_entries = project_entries
    return menu


def build_new_view_menu(host: Any) -> Menu:
    """The View > New submenu."""
    ws = host.workspace
    return Menu(
        "&New",
        [
            MenuEntry("&Linear Disassembly", ws.create_and_show_linear_disassembly_view, icon="disassembly-linear"),
            MenuEntry(
                "&Graph Disassembly",
                ws.create_and_show_graph_disassembly_view,
                shortcut="Ctrl+N",
                icon="disassembly-graph",
            ),
            MenuSeparator(),
            MenuEntry("&Hex", ws.create_and_show_hex_view, icon="hex-view"),
        ],
    )


def build_view_menu(host: Any, extra_entries: Iterable[Any] = (), new_menu: Menu | None = None) -> Menu:
    """The View menu; ``extra_entries`` stand where the Qt menu has its Toolbars submenu."""
    ws = host.workspace
    if new_menu is None:
        new_menu = build_new_view_menu(host)
    return Menu(
        "&View",
        [
            MenuEntry("Command Palette...", host.show_command_palette, shortcut="Ctrl+Shift+P", icon="command-palette"),
            MenuSeparator(),
            *extra_entries,
            MenuSeparator(),
            MenuEntry("Next Tab", ws.view_manager.next_tab, shortcut="Ctrl+Tab"),
            MenuEntry("Previous Tab", ws.view_manager.previous_tab, shortcut="Ctrl+Shift+Tab"),
            MenuSeparator(),
            new_menu,
            MenuSeparator(),
            MenuEntry("&Linear Disassembly", ws.show_linear_disassembly_view, icon="disassembly-linear"),
            MenuEntry("&Graph Disassembly", ws.show_graph_disassembly_view, icon="disassembly-graph"),
            MenuSeparator(),
            MenuEntry("&Hex", ws.show_hex_view, icon="hex-view"),
            MenuEntry("Pro&ximity", host.view_proximity_for_current_function),
            MenuEntry("Pseudo&code", ws.show_pseudocode_view, icon="pseudocode-view"),
            MenuEntry("&Strings", ws.show_strings_view, icon="strings-view"),
            MenuEntry("S&earch", ws.show_search_view, shortcut="Ctrl+Shift+F", icon="search-view"),
            MenuEntry("&Patches", ws.show_patches_view, icon="patches-view"),
            MenuEntry("&Types", ws.show_types_view, icon="types-view"),
            MenuEntry("&Functions", ws.show_functions_view, icon="functions-view"),
            MenuEntry("Co&mments", ws.show_comments_view, icon="comments-view"),
            MenuEntry("Book&marks", ws.show_bookmarks_view, icon="bookmarks-view"),
            MenuEntry("Function Si&gnatures", ws.show_signatures_view),
            MenuEntry("&Traces", ws.show_traces_view, icon="traces-view"),
            MenuEntry("Trace &Map", ws.show_trace_map_view),
            MenuSeparator(),
            MenuEntry("Symbolic &Execution", ws.show_symexec_view),
            MenuEntry("S&ymbolic States", ws.show_states_view),
            MenuEntry("&Registers", ws.show_registers_view),
            MenuEntry("&Stack", ws.show_stack_view),
            MenuEntry("&Breakpoints", ws.show_breakpoints_view),
            MenuEntry("&Call Explorer", ws.show_call_explorer_view),
            MenuSeparator(),
            MenuEntry("&Console", ws.show_console_view, icon="console-view"),
            MenuEntry("&Log", ws.show_log_view, icon="log-view"),
            MenuEntry("&Jobs", ws.show_jobs_view, icon="jobs-view"),
            MenuEntry("&MCP History", ws.show_mcp_history_view, icon="mcp_history-view"),
        ],
    )


def build_analyze_menu(host: Any) -> Menu:
    return Menu(
        "&Analyze",
        [
            MenuEntry("&Run Analysis...", host.run_analysis, shortcut="F4", icon="run-analysis"),
            MenuSeparator(),
            MenuEntry("&Decompile", host.decompile_current_function, shortcut="F5", icon="pseudocode-view"),
            MenuEntry("View in Proximity &Browser", host.view_proximity_for_current_function, shortcut="Ctrl+B"),
            MenuEntry("Discover &Patterns...", host.discover_patterns, icon="pattern-view"),
        ],
    )


def build_ai_menu(host: Any) -> Menu:
    return Menu(
        "A&I",
        [
            MenuEntry("Refine &All", host.llm_refine_all, shortcut="Ctrl+I"),
            MenuSeparator(),
            MenuEntry("Suggest &Variable Names", host.llm_suggest_variable_names),
            MenuEntry("Suggest &Function Name", host.llm_suggest_function_name),
            MenuEntry("Suggest Variable &Types", host.llm_suggest_variable_types),
            MenuEntry("&Summarize Function", host.llm_summarize_function),
            MenuSeparator(),
            MenuEntry("Start &MCP Server", host.start_mcp_server),
            MenuEntry("Sto&p MCP Server", host.stop_mcp_server),
            MenuEntry("&Copy MCP Server URL", host.copy_mcp_url),
        ],
    )


def build_plugin_menu(host: Any) -> Menu:
    return Menu("&Plugins", [MenuEntry("&Manage Plugins...", host.open_load_plugins_dialog, icon="plugins")])


def build_help_menu(host: Any) -> Menu:
    return Menu(
        "&Help",
        [
            MenuEntry("&Documentation", host.open_doc_link, shortcut="Alt+H", icon="docs"),
            MenuSeparator(),
            MenuEntry("&About angr-management", host.open_about_dialog, role="about", icon="about"),
        ],
    )


def build_main_menus(host: Any, recent_files: Iterable[str] = (), view_extra_entries: Iterable[Any] = ()) -> list[Menu]:
    """The menus of the menu bar, in order, bound to ``host``."""
    return [
        build_file_menu(host, recent_files),
        build_view_menu(host, view_extra_entries),
        build_analyze_menu(host),
        build_ai_menu(host),
        build_plugin_menu(host),
        build_help_menu(host),
    ]
