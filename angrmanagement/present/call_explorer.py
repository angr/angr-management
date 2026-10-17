"""
The call explorer without a toolkit.

The view follows a trace debugger (:class:`~angrmanagement.logic.debugger.bintrace.BintraceDebugger`): its top level is
the calls the current function made, and each call opens, the first time, to the calls the callee made. Selecting a
call replays the trace to just before it; activating one replays into it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from angrmanagement.logic.debugger import DebuggerWatcher
from angrmanagement.logic.debugger.bintrace import BintraceDebugger

from .base import InstancePresenter

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins import Function

    from angrmanagement.data.instance import Instance

#: The label above the tree when there is no current function.
NO_FUNCTION = "Current function: Unknown"


def call_name(function: int | Function) -> str:
    """A call's name in the tree: the callee's name, or its address when only that is known."""
    return hex(function) if isinstance(function, int) else function.name


def current_function(debugger: Any) -> Function | None:
    """The function the trace debugger is in, or None for any other debugger."""
    if not isinstance(debugger, BintraceDebugger):
        return None
    func: Any = debugger.get_current_function()
    return func[0] if func is not None else None


def replay_before(debugger: Any, event: Any) -> None:
    """Replay the trace to just before the call ``event``."""
    debugger.replay_to_event(debugger._btrace.get_prev_exec_event(event, vcpu=debugger._trace_dbg.vcpu))  # pylint: disable=protected-access


def replay_into(debugger: Any, event: Any) -> None:
    """Replay the trace past the call ``event``, into the callee."""
    debugger.replay_to_event(debugger._btrace.get_next_exec_event(event, vcpu=debugger._trace_dbg.vcpu))  # pylint: disable=protected-access


@dataclass(eq=False)
class CallNode:
    """A call in the tree: the callee (a function, or an address), the trace event, and its calls once opened."""

    function: Any
    event: Any
    populated: bool = False
    expandable: bool = True
    children: list[CallNode] = field(default_factory=list)

    @property
    def name(self) -> str:
        return call_name(self.function)


class CallExplorerPresenter(InstancePresenter):
    """The call explorer: the calls of the trace debugger's current function, opened on demand."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "call_explorer", instance, default_docking_position)
        self.base_caption = "Call Explorer"
        self.label = NO_FUNCTION
        self.roots: list[CallNode] = []
        self._last_updated_func: Any = None
        self._inhibit_update = False
        #: called after the calls shown changed
        self.on_changed: Callable[[], None] | None = None
        self._dbg_manager = instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    def close(self) -> None:
        self._dbg_watcher.shutdown()

    @property
    def debugger(self) -> Any:
        return self._dbg_manager.debugger

    def _changed(self) -> None:
        if self.on_changed is not None:
            self.on_changed()

    def _on_debugger_state_updated(self) -> None:
        """The debugger moved: show the calls of its current function, if that changed."""
        if self._inhibit_update:
            return
        dbg = self._dbg_watcher.debugger
        func = current_function(dbg.am_obj)
        if func is self._last_updated_func:
            return
        self._last_updated_func = func
        if func is not None:
            self.label = f"Current function: {func.name}"
            self.roots = [CallNode(callee, event) for callee, event in dbg.get_called_functions()]
        else:
            self.label = NO_FUNCTION
            self.roots = []
        self._changed()

    def expand(self, node: CallNode) -> None:
        """Open ``node``: the first time, list the calls its callee made."""
        if node.populated:
            return
        dbg = self.debugger
        if dbg.am_none:
            return
        called = dbg.get_called_functions(node.event)
        node.children = [CallNode(callee, event) for callee, event in called]
        node.expandable = len(called) > 0
        node.populated = True
        self._changed()

    def select(self, node: CallNode) -> None:
        """A call was selected: replay to just before it, keeping the tree as it is."""
        original_inhibit = self._inhibit_update
        self._inhibit_update = True
        try:
            replay_before(self.debugger, node.event)
        finally:
            self._inhibit_update = original_inhibit

    def activate(self, node: CallNode) -> None:
        """A call was activated: replay into the callee."""
        # FIXME: Doesn't consider proper selected debugger, assumes bintrace
        replay_into(self.debugger, node.event)


__all__ = [
    "NO_FUNCTION",
    "CallExplorerPresenter",
    "CallNode",
    "call_name",
    "current_function",
    "replay_before",
    "replay_into",
]
