
from .toolbar import Toolbar, ToolbarAction


class StatesToolbar(Toolbar):
    def __init__(self, main_window):
        super(StatesToolbar, self).__init__(main_window, 'States')

        self.actions = [
            ToolbarAction(None, "New state", "Create a new state...", main_window.open_newstate_dialog)
        ]
