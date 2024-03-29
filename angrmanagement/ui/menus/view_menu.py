from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import QKeySequence

from angrmanagement.ui.icons import icon

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow
    from angrmanagement.ui.toolbars.toolbar import Toolbar


class NewViewMenu(Menu):
    """
    Sub-menu to construct new Views
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&New", parent=main_window)

        self.entries.extend(
            [
                MenuEntry(
                    "&Linear Disassembly",
                    main_window.workspace.create_and_show_linear_disassembly_view,
                    icon=icon("disassembly-linear"),
                ),
                MenuEntry(
                    "&Graph Disassembly",
                    main_window.workspace.create_and_show_graph_disassembly_view,
                    shortcut=QKeySequence("Ctrl+N"),
                    icon=icon("disassembly-graph"),
                ),
                MenuSeparator(),
                MenuEntry("&Hex", main_window.workspace.create_and_show_hex_view, icon=icon("hex-view")),
            ]
        )


class ToolbarMenuEntry(MenuEntry):
    """
    Menu item to control toolbar visibility.
    """

    def __init__(self, toolbar_cls: type[Toolbar], main_window: MainWindow) -> None:
        tm = main_window.toolbar_manager
        super().__init__(tm.get_name_for_toolbar_class(toolbar_cls), self.on_toggle, checkable=True)
        self.main_window = main_window
        self.toolbar_cls = toolbar_cls

    @property
    def is_visibile(self) -> bool:
        qtb = self.main_window.toolbar_manager.active.get(self.toolbar_cls, None)
        return qtb is not None and qtb.qtoolbar().isVisible()

    def on_toggle(self) -> None:
        self.main_window.toolbar_manager.set_toolbar_visible_by_class(self.toolbar_cls, not self.is_visibile)

    def update_checked(self) -> None:
        self.checked = self.is_visibile


class ToolbarMenu(Menu):
    """
    Sub-menu to control toolbar visibility.
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&Toolbars", parent=main_window)
        tm = main_window.toolbar_manager
        self.entries.extend([MenuEntry("Show all", tm.show_all), MenuEntry("Hide all", tm.hide_all), MenuSeparator()])
        for tb_cls in tm.all_toolbars:
            self.entries.append(ToolbarMenuEntry(tb_cls, main_window))
        self.qmenu().aboutToShow.connect(self.update_checked_entries)

    def update_checked_entries(self) -> None:
        for e in self.entries:
            if isinstance(e, ToolbarMenuEntry):
                e.update_checked()


class ViewMenu(Menu):
    """
    Main View menu
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&View", parent=main_window)

        self.entries.extend(
            [
                MenuEntry(
                    "Command Palette...",
                    main_window.show_command_palette,
                    shortcut=QKeySequence("Ctrl+Shift+P"),
                    icon=icon("command-palette"),
                ),
                MenuSeparator(),
                ToolbarMenu(main_window),
                MenuSeparator(),
                MenuEntry("Next Tab", main_window.workspace.view_manager.next_tab, shortcut=QKeySequence("Ctrl+Tab")),
                MenuEntry(
                    "Previous Tab",
                    main_window.workspace.view_manager.previous_tab,
                    shortcut=QKeySequence("Ctrl+Shift+Tab"),
                ),
                MenuSeparator(),
                NewViewMenu(main_window),
                MenuSeparator(),
                MenuEntry(
                    "&Linear Disassembly",
                    main_window.workspace.show_linear_disassembly_view,
                    icon=icon("disassembly-linear"),
                ),
                MenuEntry(
                    "&Graph Disassembly",
                    main_window.workspace.show_graph_disassembly_view,
                    icon=icon("disassembly-graph"),
                ),
                MenuSeparator(),
                MenuEntry("&Hex", main_window.workspace.show_hex_view, icon=icon("hex-view")),
                MenuEntry("Pro&ximity", main_window.view_proximity_for_current_function),
                MenuEntry("Pseudo&code", main_window.workspace.show_pseudocode_view, icon=icon("pseudocode-view")),
                MenuEntry("&Strings", main_window.workspace.show_strings_view, icon=icon("strings-view")),
                MenuEntry("&Patches", main_window.workspace.show_patches_view, icon=icon("patches-view")),
                MenuEntry("&Types", main_window.workspace.show_types_view, icon=icon("types-view")),
                MenuEntry("&Functions", main_window.workspace.show_functions_view, icon=icon("functions-view")),
                MenuEntry("&Traces", main_window.workspace.show_traces_view, icon=icon("traces-view")),
                MenuEntry("&Trace Map", main_window.workspace.show_trace_map_view),
                MenuSeparator(),
                MenuEntry("Symbolic &Execution", main_window.workspace.show_symexec_view),
                MenuEntry("S&ymbolic States", main_window.workspace.show_states_view),
                MenuEntry("&Interaction", main_window.workspace.show_interaction_view),
                MenuEntry("&Registers", main_window.workspace.show_registers_view),
                MenuEntry("&Stack", main_window.workspace.show_stack_view),
                MenuEntry("&Breakpoints", main_window.workspace.show_breakpoints_view),
                MenuEntry("&Call Explorer", main_window.workspace.show_call_explorer_view),
                MenuSeparator(),
                MenuEntry("&Console", main_window.workspace.show_console_view, icon=icon("console-view")),
                MenuEntry("&Log", main_window.workspace.show_log_view, icon=icon("log-view")),
            ]
        )
