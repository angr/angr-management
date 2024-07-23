from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from angrmanagement.data.breakpoint import BreakpointType
from angrmanagement.data.trace import BintraceTrace

from .debugger import Debugger

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angr import SimState
    from angr.knowledge_plugins import Function

    from angrmanagement.ui.workspace import Workspace


try:
    import bintrace
    from bintrace import TraceEvent
    from bintrace.debugger_angr import AngrTraceDebugger
except ImportError:
    bintrace = None
    TraceEvent = "TraceEvent"

_l = logging.getLogger(name=__name__)


class BintraceDebugger(Debugger):
    """
    Trace playback debugger.
    """

    def __init__(self, trace: BintraceTrace, workspace: Workspace) -> None:
        super().__init__(workspace)
        assert bintrace is not None
        assert isinstance(trace, BintraceTrace)
        self._trace: BintraceTrace = trace
        self._btrace: bintrace.Trace = trace.trace
        self._trace_dbg: AngrTraceDebugger = AngrTraceDebugger(
            self._btrace, self.workspace.main_instance.project.am_obj
        )
        self._cached_simstate = None

    def __str__(self) -> str:
        pc = self.simstate.solver.eval(self.simstate.regs.pc)
        return f"{os.path.basename(self._btrace.path)} @ {pc:x}"

    def _on_state_change(self) -> None:
        """
        Common handler for state changes.
        """
        self._cached_simstate = None
        self.state_changed.am_event()

    def _sync_breakpoints(self) -> None:
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
            for bp in self.workspace.main_instance.breakpoint_mgr.breakpoints
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

    def step_backward(self) -> None:
        if self.can_step_backward:
            self._trace_dbg.step_backward()
            self._on_state_change()

    @property
    def can_step_forward(self) -> bool:
        return self._trace_dbg.can_step_forward

    def step_forward(self, until_addr: int | None = None) -> None:
        if self.can_step_forward:
            self._trace_dbg.step_forward(until_addr=until_addr)
            self._on_state_change()

    @property
    def can_continue_backward(self) -> bool:
        return self._trace_dbg.can_continue_backward

    def continue_backward(self) -> None:
        if self.can_continue_backward:
            self._sync_breakpoints()
            self._trace_dbg.continue_backward()
            self._on_state_change()

    @property
    def can_continue_forward(self) -> bool:
        return self._trace_dbg.can_continue_forward

    def continue_forward(self) -> None:
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

    def stop(self) -> None:
        pass

    @property
    def is_exited(self) -> bool:
        return False

    def replay_to_nth_event(self, n: int) -> None:
        """
        Replay to the Nth event, skipping over stop events and ending on the nearest execution event.
        """
        t = self._btrace
        assert 0 <= n < t.get_num_events()

        until = t.get_nth_event(n)
        if until is None:
            _l.error("Could not seek to event %d", n)
            return

        if self._trace_dbg.single_step_range is None:
            step_region_addr, step_region_size = None, 1
        else:
            self._trace_dbg.single_step_range: tuple[int, int]
            step_region_addr, step_region_size = self._trace_dbg.single_step_range

        until = t.get_prev_exec_event(until, addr=step_region_addr, size=step_region_size)
        if until is None:
            _l.error("No execution event prior to event %d", n)
            return

        self._trace_dbg.state = t.replay(self._trace_dbg.state, until)
        self._on_state_change()

    def get_current_function(self):
        if self._trace_dbg.state is None:
            return None
        else:
            return self.get_function_for_event(self._trace_dbg.state.event)

    def replay_to_event(self, until) -> None:
        self._trace_dbg.state = self._btrace.replay(self._trace_dbg.state, until)
        self._on_state_change()

    #
    # Trace Analysis
    #
    # FIXME: Factor this out of debugger
    #

    def get_function_for_event(self, event: TraceEvent) -> Function | None:
        """
        Find currently execution function at `event`.
        """
        # Rewind to last block event
        if event and not isinstance(event, bintrace.FBBlockEvent):
            event = self._btrace.get_prev_bb_event(event, vcpu=self._trace_dbg.vcpu)
        if event is None:
            return None

        # Determine what function we are in currently.
        node = self.workspace.main_instance.cfg.get_node(event.Addr())
        if node is None:
            return None

        kb = self.workspace.main_instance.project.kb
        if node.function_address in kb.functions:
            return kb.functions[node.function_address], event
        else:
            _l.warning("Node %s not found in functions db", node)
            return None

    def get_called_functions(
        self, event: TraceEvent | None = None, only_after_event: bool = False
    ) -> Sequence[tuple[Function, TraceEvent]]:
        """
        Enumerate 1st order outgoing calls of function at `event`.
        """
        if event is None:
            if self._trace_dbg.state:
                event = self._trace_dbg.state.event
            else:
                return []

        # Get current function
        func = self.get_function_for_event(event)
        if func is None:
            _l.warning("Could not determine function for event %s", event)
            return []

        func, event = func
        _l.debug("Function for event %s: %s", event, func.name)

        if not only_after_event:
            # Rewind to function entry
            # FIXME: Does not properly handle nested calls to this function!
            while event.Addr() != func.addr:
                event = self._btrace.get_prev_bb_event(event, vcpu=self._trace_dbg.vcpu)
                if event is None:
                    _l.error("Did not find start of function %s (%#x) in trace", func.name, func.addr)
                    return []

        called_addrs = []
        keep_looking = True
        while keep_looking:
            # Step until next function exit
            called_func_entry_event = self._btrace.get_next_bb_event(event, vcpu=self._trace_dbg.vcpu)
            if called_func_entry_event is None:
                # End of trace
                break

            # FIXME: Possible failure in func.block_addrs_set not matching
            addr = called_func_entry_event.Addr()
            is_a_function_exit = (addr not in func.block_addrs_set) or (addr == func.addr)
            if not is_a_function_exit:
                event = called_func_entry_event
                continue

            # Check exit type
            exit_block_addr = event.Addr()
            b = self.workspace.main_instance.project.factory.block(exit_block_addr)
            if b.vex.jumpkind == "Ijk_Ret":
                _l.debug("Exit is a return to caller")
                break

            called_addrs.append((addr, called_func_entry_event))

            if b.vex.jumpkind != "Ijk_Call":
                _l.debug("Exit is a tail-call")
                break

            # FIXME: fallthru might indicate trace vs cfg inconsistency
            # Seek through events to find return site of this call
            event = called_func_entry_event
            ret_addr = b.instruction_addrs[0] + b.size
            num_nested_calls = 0
            if self.workspace.main_instance.project.arch.name == "AMD64":
                # FIXME Remove this hardcoding
                stack_reg = 7
                expected_sp = called_func_entry_event.Regs(stack_reg) + 8
            else:
                raise AssertionError("FIXME: Stack pointer check for non-x86_64")

            _l.debug("Seeking to return site for call...")
            while True:
                event = self._btrace.get_next_exec_event(event, addr=ret_addr, vcpu=self._trace_dbg.vcpu)
                if event is None:
                    _l.error(
                        "Unexpected end of trace while looking for return site in %s @ %#x "
                        "(call may have caused termination)",
                        func.name,
                        ret_addr,
                    )
                    keep_looking = False
                    break

                # Check the stack pointer at return site to ensure it matches target call
                # and does not actually belong to a nested call
                bb_event = self._btrace.get_prev_bb_event(event, vcpu=self._trace_dbg.vcpu)
                if bb_event.Regs(stack_reg) == expected_sp:
                    _l.debug("Found return block at event %s", bb_event)
                    event = bb_event
                    break
                _l.debug("Skipping over nested call (%d)", num_nested_calls)
                num_nested_calls += 1

        all_funcs = self.workspace.main_instance.project.kb.functions
        return [((all_funcs.get(addr, addr)), e) for (addr, e) in called_addrs]

    def get_called_functions_recursive(
        self, event: TraceEvent | None = None, max_depth: int | None = None, depth: int = 0
    ):
        if max_depth is not None and max_depth == depth:
            return
        for func_or_addr, sub_ev in self.get_called_functions(event):
            yield func_or_addr, sub_ev, depth
            if not isinstance(func_or_addr, int):
                yield from self.get_called_functions_recursive(sub_ev, max_depth=max_depth, depth=(depth + 1))
