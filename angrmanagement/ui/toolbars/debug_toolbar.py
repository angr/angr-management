from typing import TYPE_CHECKING

from .toolbar import Toolbar, ToolbarAction, ToolbarSplitter

if TYPE_CHECKING:
    from ..main_window import MainWindow


class DebugToolbar(Toolbar):
    def __init__(self, main_window: 'MainWindow'):
        super().__init__(main_window, 'Debug')

        self.actions = [
            ToolbarAction(None, "Run", "Run a target", main_window.run_process),
            ToolbarAction(None, "Attach", "Attach to a target", main_window.attach_process),
            ToolbarAction(None, "Detach", "Detach from a target", main_window.detach_process),
            ToolbarAction(None, "Stop", "Stop the debuggee", main_window.stop_process),
            ToolbarSplitter(),
            ToolbarAction(None, "Step", "Single step", main_window.single_step),
            ToolbarAction(None, "Step over", "Step over", main_window.step_over),
        ]
