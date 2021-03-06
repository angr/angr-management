from .menu import Menu
from ...logic import GlobalInfo

class FunctionContextMenu(Menu):
    def __init__(self, parent):
        super().__init__("Function", parent=parent)

        self.func = None

        # TODO add Rename, Change Type, xrefs, etc

    def set(self, func):
        self.func = func
        return self

    def qmenu(self, extra_entries=None):
        if extra_entries is None:
            extra_entries = ()
        return super().qmenu(extra_entries=list(GlobalInfo.main_window.workspace.plugins.build_context_menu_function(self.func)) + list(extra_entries))
