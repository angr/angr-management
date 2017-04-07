
from .menu import Menu, MenuEntry, MenuSeparator


class DisasmOptionsMenu(Menu):
    def __init__(self, disasm_view):
        super(DisasmOptionsMenu, self).__init__("", parent=disasm_view)

        self._show_address_action = MenuEntry('Show &address', self._show_address, checkable=True,
                                              checked=self.parent.show_address
                                              )

        self.entries.extend([
            self._show_address_action,
        ])

    def _show_address(self):
        checked = self._show_address_action.checked
        self.parent.toggle_show_address(checked)
