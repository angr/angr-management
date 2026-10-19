"""
A trace debugger over a script, for the tests of the views that follow a trace: the call explorer and the trace map.
"""

# pylint: disable=super-init-not-called,non-parent-init-called

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from angrmanagement.logic.debugger import Debugger
from angrmanagement.logic.debugger.bintrace import BintraceDebugger

#: what the debug bar asks a trace debugger: it can go nowhere
STOPPED = {
    "can_step_backward": False,
    "can_step_forward": False,
    "can_continue_backward": False,
    "can_continue_forward": False,
}


class ScriptedTrace(BintraceDebugger):
    """
    A trace of 1000 events, replayed to event 250, with checkpoints at 100 and 600, in which main calls puts (which
    calls write) and 0x401000. :attr:`replayed` lists where it was asked to replay to.
    """

    def __init__(self, workspace) -> None:
        Debugger.__init__(self, workspace)
        self.main = SimpleNamespace(name="main", addr=0x400000)
        self.puts = SimpleNamespace(name="puts", addr=0x400100)
        self.write = SimpleNamespace(name="write", addr=0x400200)
        self.replayed: list[Any] = []
        trace = SimpleNamespace(
            get_num_events=lambda: 1000,
            checkpoints=[SimpleNamespace(event_count=100), SimpleNamespace(event_count=600)],
            get_prev_exec_event=lambda event, vcpu: ("before", event),
            get_next_exec_event=lambda event, vcpu: ("after", event),
        )
        self._btrace = trace  # pyright: ignore[reportAttributeAccessIssue]
        self._trace = SimpleNamespace(trace=trace)  # pyright: ignore[reportAttributeAccessIssue]
        self._trace_dbg = SimpleNamespace(  # pyright: ignore[reportAttributeAccessIssue]
            vcpu=0, state=SimpleNamespace(event_count=250), **STOPPED
        )

    # the real one returns (function, event) too, whatever its annotation says
    def get_current_function(self):  # pyright: ignore[reportIncompatibleMethodOverride]
        return (self.main, "event-main")

    def get_called_functions(self, event=None):  # type: ignore[override]
        calls = {
            None: [(self.puts, "call-puts"), (0x401000, "call-401000")],
            "call-puts": [(self.write, "call-write")],
        }
        return calls.get(event, [])

    def replay_to_event(self, until) -> None:
        self.replayed.append(until)

    def replay_to_nth_event(self, n: int) -> None:
        self.replayed.append(n)
        self._trace_dbg.state.event_count = n
        self.state_changed.am_event()
