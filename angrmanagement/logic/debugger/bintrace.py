import os
import logging
from typing import Optional

from angr import SimState

try:
    import bintrace
    from bintrace.debugger_angr import AngrTraceDebugger
except ImportError as e:
    bintrace = None

from ...data.trace import BintraceTrace
from ...data.breakpoint import BreakpointType
from .debugger import Debugger


_l = logging.getLogger(name=__name__)


class BintraceDebugger(Debugger):
    """
    Trace playback debugger.
    """

    def __init__(self, trace: BintraceTrace, workspace: 'Workspace'):
        super().__init__(workspace)
        assert bintrace is not None
        assert isinstance(trace, BintraceTrace)
        self._trace: 'bintrace.Trace' = trace
        self._trace_dbg: AngrTraceDebugger = AngrTraceDebugger(self._trace.trace,
                                                               self.workspace.instance.project.am_obj)
        self._cached_simstate = None

    def __str__(self):
        pc = self.simstate.solver.eval(self.simstate.regs.pc)
        return f'{os.path.basename(self._trace.trace.path)} @ {pc:x}'

    def _on_state_change(self):
        """
        Common handler for state changes.
        """
        self._cached_simstate = None
        self.state_changed.am_event()

    def _sync_breakpoints(self):
        """
        Synchronize breakpoints set in Workspace with trace debugger.
        """
        bp_type_map = {
            BreakpointType.Execute: bintrace.debugger.BreakpointType.Execute,
            BreakpointType.Read: bintrace.debugger.BreakpointType.Read,
            BreakpointType.Write: bintrace.debugger.BreakpointType.Write,
        }
        self._trace_dbg.breakpoints = {
            bintrace.debugger.Breakpoint(bp_type_map[bp.type], bp.addr, bp.size)
            for bp in self.workspace.instance.breakpoint_mgr.breakpoints
        }

    @property
    def simstate(self) -> SimState:
        if self._cached_simstate is None:
            self._cached_simstate = self._trace_dbg.simstate
        return self._cached_simstate

    @property
    def is_running(self) -> bool:
        return True

    @property
    def can_step_backward(self) -> bool:
        return self._trace_dbg.can_step_backward

    def step_backward(self):
        if self.can_step_backward:
            self._trace_dbg.step_backward()
            self._on_state_change()

    @property
    def can_step_forward(self) -> bool:
        return self._trace_dbg.can_step_forward

    def step_forward(self, until_addr: Optional[int] = None):
        if self.can_step_forward:
            self._trace_dbg.step_forward(until_addr=until_addr)
            self._on_state_change()

    @property
    def can_continue_backward(self) -> bool:
        return self._trace_dbg.can_continue_backward

    def continue_backward(self):
        if self.can_continue_backward:
            self._sync_breakpoints()
            self._trace_dbg.continue_backward()
            self._on_state_change()

    @property
    def can_continue_forward(self) -> bool:
        return self._trace_dbg.can_continue_forward

    def continue_forward(self):
        if self.can_continue_forward:
            self._sync_breakpoints()
            self._trace_dbg.continue_forward()
            self._on_state_change()

    @property
    def can_halt(self) -> bool:
        return False  # XXX: Trace playback is "instantaneous", always is halted state.

    @property
    def is_halted(self) -> bool:
        return True

    @property
    def can_stop(self) -> bool:
        return True

    def stop(self):
        pass

    @property
    def is_exited(self) -> bool:
        return False

    def replay_to_nth_event(self, n: int):
        """
        Replay to the Nth event, skipping over stop events and ending on the nearest execution event.
        """
        t = self._trace.trace
        assert 0 <= n < t.get_num_events()

        until = t.get_nth_event(n)
        if until is None:
            _l.error('Could not seek to event %d', n)
            return

        until = t.get_prev_exec_event(until)
        if until is None:
            _l.error('No execution event prior to event %d', n)
            return

        self._trace_dbg.state = t.replay(self._trace_dbg.state, until)
        self._on_state_change()
