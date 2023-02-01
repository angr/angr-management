import os

from PySide6.QtGui import QIcon

from angrmanagement.config import IMG_LOCATION

from .toolbar import Toolbar, ToolbarAction


class FunctionTableToolbar(Toolbar):
    def __init__(self, function_table):
        super().__init__(function_table, "Function table options")

        # TODO: An icon would be great
        self._alignment_action = ToolbarAction(
            QIcon(os.path.join(IMG_LOCATION, "toolbar-show-alignment.png")),
            "Show alignment functions",
            "Display alignment function stubs.",
            function_table.toggle_show_alignment_functions,
            checkable=True,
        )

        self.actions = [
            self._alignment_action,
        ]

    def toggle_show_alignment_functions(self):
        self.window.toggle_show_alignment_functions()

        if self._cached_actions and self._alignment_action in self._cached_actions:
            self._cached_actions[self._alignment_action].setChecked(self.window.show_alignment_functions)
