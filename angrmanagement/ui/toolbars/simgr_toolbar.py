from typing import TYPE_CHECKING

from angrmanagement.ui import main_window
from .toolbar import Toolbar, ToolbarAction

import qtawesome as qta

if TYPE_CHECKING:
    from ..main_window import MainWindow
    from ..widgets.qsimulation_managers import QSimulationManagers

class SimgrToolbar(Toolbar):
    def __init__(self, main_window: 'MainWindow'):
        super(SimgrToolbar, self).__init__(main_window, 'Simgr')
        self.main_window = main_window
        self.actions = [
            ToolbarAction(qta.icon("fa5s.plus"),"New", "Start a new Simulation...", self.main_window.open_newstate_dialog),
            ToolbarAction(qta.icon("fa5s.play"),"Explore", "", lambda : self.simulation_managers._on_explore_clicked()),   
            ToolbarAction(qta.icon("fa5s.step-forward"), "Step", "", lambda : self.simulation_managers._on_step_clicked()),
            ToolbarAction(qta.icon("fa5s.code-branch"),"Step Until Branch", "", lambda : self.simulation_managers._on_step_until_branch_clicked()),
            ToolbarAction(qta.icon("fa5s.pause"), "Interrupt", "", main_window.interrupt_current_job),
        ]
    
    @property
    def simulation_managers(self) -> 'QSimulationManagers':
        return self.main_window.workspace._get_or_create_symexec_view()._simgrs
