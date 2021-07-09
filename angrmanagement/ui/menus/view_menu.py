from PySide2.QtGui import QKeySequence
from PySide2.QtCore import Qt

from .menu import Menu, MenuEntry, MenuSeparator


class ViewMenu(Menu):
    def __init__(self, main_window):
        super(ViewMenu, self).__init__("&View", parent=main_window)

        self.entries.extend([
            MenuEntry('Next Tab', main_window.workspace.view_manager.next_tab, shortcut=QKeySequence("Ctrl+Tab")),
            MenuEntry('Previous Tab', main_window.workspace.view_manager.previous_tab, shortcut=QKeySequence("Ctrl+Shift+Tab")),
            MenuSeparator(),
            MenuEntry('New Disassembly View', main_window.workspace.new_disassembly_view, shortcut=QKeySequence("Ctrl+N")),
            MenuEntry('Split / Unsplit View', main_window.workspace.toggle_split, shortcut=QKeySequence("Ctrl+D")),
            MenuSeparator(),
            MenuEntry('Linear Disassembly', main_window.workspace.show_linear_disassembly_view),
            MenuEntry('Graph Disassembly', main_window.workspace.show_graph_disassembly_view),
            MenuEntry('Symbolic Execution', main_window.workspace.show_symexec_view),
            MenuEntry('Symbolic States', main_window.workspace.show_states_view),
            MenuEntry('Strings', main_window.workspace.show_strings_view),
            MenuEntry('Proximity View', main_window.view_proximity_for_current_function),
            MenuEntry('Patches', main_window.workspace.show_patches_view),
            MenuEntry('Interaction', main_window.workspace.show_interaction_view),
            MenuEntry('Types', main_window.workspace.show_types_view),
            MenuEntry('Functions', main_window.workspace.show_functions_view),
            MenuEntry('Console', main_window.workspace.show_console_view),
        ])
