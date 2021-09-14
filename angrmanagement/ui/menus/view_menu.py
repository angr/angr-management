from PySide2.QtGui import QKeySequence

from .menu import Menu, MenuEntry, MenuSeparator


class NewViewMenu(Menu):
    """
    Sub-menu to construct new Views
    """

    def __init__(self, main_window):
        super().__init__("&New", parent=main_window)

        self.entries.extend([
            MenuEntry('&Linear Disassembly', main_window.workspace.create_and_show_linear_disassembly_view),
            MenuEntry('&Graph Disassembly', main_window.workspace.create_and_show_graph_disassembly_view,
                      shortcut=QKeySequence("Ctrl+N")),
            MenuSeparator(),
            MenuEntry('&Hex', main_window.workspace.create_and_show_hex_view),
        ])


class ViewMenu(Menu):
    """
    Main View menu
    """

    def __init__(self, main_window):
        super().__init__("&View", parent=main_window)

        self.entries.extend([
            MenuEntry('Next Tab', main_window.workspace.view_manager.next_tab, shortcut=QKeySequence("Ctrl+Tab")),
            MenuEntry('Previous Tab', main_window.workspace.view_manager.previous_tab,
                      shortcut=QKeySequence("Ctrl+Shift+Tab")),
            MenuSeparator(),
            NewViewMenu(main_window),
            MenuSeparator(),
            MenuEntry('&Linear Disassembly', main_window.workspace.show_linear_disassembly_view),
            MenuEntry('&Graph Disassembly', main_window.workspace.show_graph_disassembly_view),
            MenuSeparator(),
            MenuEntry('&Hex', main_window.workspace.show_hex_view),
            MenuEntry('Pro&ximity', main_window.view_proximity_for_current_function),
            MenuEntry('Pseudo&code', main_window.workspace.show_pseudocode_view),
            MenuEntry('&Strings', main_window.workspace.show_strings_view),
            MenuEntry('&Patches', main_window.workspace.show_patches_view),
            MenuEntry('&Types', main_window.workspace.show_types_view),
            MenuEntry('&Functions', main_window.workspace.show_functions_view),
            MenuSeparator(),
            MenuEntry('Symbolic &Execution', main_window.workspace.show_symexec_view),
            MenuEntry('S&ymbolic States', main_window.workspace.show_states_view),
            MenuEntry('&Interaction', main_window.workspace.show_interaction_view),
            MenuSeparator(),
            MenuEntry('&Console', main_window.workspace.show_console_view),
            MenuEntry('&Log', main_window.workspace.show_log_view),
        ])
