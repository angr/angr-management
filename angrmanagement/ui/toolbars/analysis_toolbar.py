
from .toolbar import Toolbar, ToolbarAction


class AnalysisToolbar(Toolbar):
    def __init__(self, main_window):
        super(AnalysisToolbar, self).__init__(main_window, 'Analysis')

        self.actions = [
            ToolbarAction(None, "Recover Variables", "Execute the VariableRecovery analysis.",
                          main_window.run_variable_recovery,
                          ),
            ToolbarAction(None, "Induction Variables", "Execute the InductionVariable analysis.",
                          main_window.run_induction_variable_analysis,
                          ),
        ]
