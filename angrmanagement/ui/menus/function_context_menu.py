from .menu import Menu
from ...logic import GlobalInfo

class FunctionContextMenu(Menu):
    def __init__(self, parent):
        super().__init__("Function", parent=parent)

        self.funcs = []

        # TODO add Rename, Change Type, xrefs, etc

    def set(self, funcs):
        self.funcs = funcs
        return self

    def qmenu(self, extra_entries=None):
        if extra_entries is None:
            extra_entries = ()
        return super().qmenu(extra_entries=list(GlobalInfo.main_window.workspace.plugins.build_context_menu_functions(self.funcs)) + list(extra_entries))
