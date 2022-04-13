import functools
import logging
from typing import Optional

from angr import SimState

from ...data.jobs import SimgrExploreJob
from ...ui.widgets.qsimulation_managers import QSimulationManagers
from .debugger import Debugger


_l = logging.getLogger(name=__name__)


class SimulationDebugger(Debugger):
    """
    Simulation debugger.
    """

    def __init__(self, sim_mgrs: QSimulationManagers, workspace: 'Workspace'):
        super().__init__(workspace)
        self._sim_mgr_view: QSimulationManagers = sim_mgrs
        self._sim_mgr = sim_mgrs.simgr
        self._sim_mgr.am_subscribe(self._watch_simgr)
        self._sim_mgr_view.state.am_subscribe(self._watch_state)

    def __str__(self):
        if self._sim_mgr.am_none:
            return 'No Simulation Manager'
        if self.simstate is None:
            return 'Simulation (No active states)'
        else:
            pc = self.simstate.solver.eval(self.simstate.regs.pc)
            return f'Simulation @ {pc:x} ({len(self._sim_mgr.stashes["active"])} active)'

    def _watch_state(self, **_):
        self._on_state_change()

    def _watch_simgr(self, **_):
        self._on_state_change()

    def _on_state_change(self):
        """
        Common handler for state changes.
        """
        self.state_changed.am_event()

    @property
    def simstate(self) -> SimState:
        if not self._sim_mgr_view.state.am_none:
            return self._sim_mgr_view.state.am_obj
        elif not self._sim_mgr.am_none and len(self._sim_mgr.stashes["active"]) > 0:
            return self._sim_mgr.stashes["active"][0]
        else:
            return None

    @property
    def is_running(self) -> bool:
        return not self._sim_mgr.am_none

    @property
    def can_step_forward(self) -> bool:
        return not self._sim_mgr.am_none and self.is_halted and len(self._sim_mgr.stashes['active']) > 0

    def step_forward(self, until_addr: Optional[int] = None):
        if until_addr is not None:
            _l.warning('Step-until not implemented for SimulationDebugger')
        if self.can_step_forward:
            self._sim_mgr_view._on_step_clicked()

    @property
    def can_continue_forward(self) -> bool:
        return self.can_step_forward

    def continue_forward(self):
        if self.can_continue_forward:
            self._sim_mgr_view._on_explore_clicked()

    @property
    def _num_active_explore_jobs(self) -> int:
        return functools.reduce(lambda s, j: s + isinstance(j, SimgrExploreJob), self.instance.jobs, 0)

    @property
    def is_halted(self) -> bool:
        return self._num_active_explore_jobs == 0

    @property
    def can_halt(self) -> bool:
        return not self.is_halted

    def halt(self):
        for job in self.instance.jobs:
            if isinstance(job, SimgrExploreJob):
                job.keyboard_interrupt()
