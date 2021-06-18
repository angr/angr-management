from typing import TYPE_CHECKING

from .toolbar import Toolbar, ToolbarAction

if TYPE_CHECKING:
    from ..main_window import MainWindow


class AnalysisToolbar(Toolbar):
    def __init__(self, main_window: 'MainWindow'):
        super(AnalysisToolbar, self).__init__(main_window, 'Analysis')

        self.actions = [
            ToolbarAction(None, "Interrupt", "Interrupt Current Job", main_window.interrupt_current_job),
            # ToolbarAction(None, "Recover Variables", "Execute the VariableRecovery analysis.",
            #               main_window.run_variable_recovery,
            #               ),
            # ToolbarAction(None, "Induction Variables", "Execute the InductionVariable analysis.",
            #               main_window.run_induction_variable_analysis,
            #               ),
        ]
