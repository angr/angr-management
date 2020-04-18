
from .menu import Menu, MenuEntry, MenuSeparator


class DisasmOptionsMenu(Menu):
    def __init__(self, disasm_view):
        super(DisasmOptionsMenu, self).__init__("", parent=disasm_view)

        self._smart_highlighting_action = MenuEntry('Smart &highlighting', self._smart_highlighting, checkable=True,
                                             checked=self.parent.smart_highlighting
                                             )
        self._show_address_action = MenuEntry('Show &address', self._show_address, checkable=True,
                                              checked=self.parent.show_address
                                              )
        self._show_variable_action = MenuEntry('Show &variable', self._show_variable, checkable=True,
                                               checked=self.parent.show_variable)
        self._show_variable_ident_action = MenuEntry('Show variable &identifiers', self._show_variable_identifier,
                                                     checkable=True,
                                                     checked=self.parent.show_variable_identifier
                                                     )
        self._show_exception_edges_action = MenuEntry('Show &exception transition edges', self._show_exception_edges,
                                                      checkable=True,
                                                      checked=self.parent.show_exception_edges,
                                                      )

        self.entries.extend([
            self._smart_highlighting_action,
            self._show_address_action,
            self._show_variable_action,
            self._show_variable_ident_action,
            self._show_exception_edges_action,
        ])

    def _smart_highlighting(self):
        checked = self._smart_highlighting_action.checked
        self.parent.toggle_smart_highlighting(checked)

    def _show_address(self):
        checked = self._show_address_action.checked
        self.parent.toggle_show_address(checked)

    def _show_variable(self):
        checked = self._show_variable_action.checked
        self.parent.toggle_show_variable(checked)

    def _show_variable_identifier(self):
        checked = self._show_variable_ident_action.checked
        self.parent.toggle_show_variable_identifier(checked)

    def _show_exception_edges(self):
        checked = self._show_exception_edges_action.checked
        self.parent.toggle_show_exception_edges(checked)
