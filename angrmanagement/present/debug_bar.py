"""
The debug toolbar without a toolkit: the step and continue buttons of the current debugger, the launch menu (a new
simulation or a new trace debugger), the stop button, the debugger selector and the debugger's state, as the Qt
debug toolbar has them. The buttons' enabled and shown states follow the debugger's ``can_*`` properties.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from angrmanagement.logic.debugger import DebuggerWatcher

from .base import container
from .menus import Menu, MenuEntry

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.debugger import Debugger

NO_DEBUGGER = "No Debugger"


@dataclass(frozen=True)
class DebugAction:
    """A button of the toolbar: its name, its caption and what it does, said in its tooltip."""

    name: str
    caption: str
    tooltip: str


#: The buttons, in the Qt toolbar's order; a separator stands before ``start``.
DEBUG_ACTIONS = (
    DebugAction("cont_backward", "Continue-Backward", "Reverse-Continue"),
    DebugAction("step_backward", "Step-Backward", "Reverse-Step"),
    DebugAction("cont", "Continue", "Continue"),
    DebugAction("halt", "Halt", "Halt"),
    DebugAction("step", "Step", "Step"),
    DebugAction("step_over", "Step Over", "Step Over"),
    DebugAction("start", "Launch", "New Debugger"),
    DebugAction("stop", "Stop", "Stop Debugging"),
)


def action_states(dbg: Debugger | None) -> dict[str, tuple[bool, bool]]:
    """Whether each button is enabled and whether it is shown, for debugger ``dbg`` (None for none)."""
    active = dbg is not None
    halts = active and dbg.can_halt
    return {
        "step": (active and dbg.can_step_forward, True),
        "step_over": (active and dbg.can_step_forward, True),
        "step_backward": (active and dbg.can_step_backward, True),
        "cont_backward": (active and dbg.can_continue_backward, True),
        # Continue and Halt take turns: Halt while the debugger runs
        "cont": (active and dbg.can_continue_forward, not halts),
        "halt": (halts, halts),
        "start": (True, True),
        "stop": (active and dbg.can_stop, True),
    }


def debugger_text(dbg: Debugger | None) -> str:
    """A debugger as the selector lists it."""
    return NO_DEBUGGER if dbg is None else str(dbg)


def step_over_target(dbg: Debugger) -> int | None:
    """Where Step Over stops: after a block that is a single call, else wherever one step goes."""
    b = dbg.simstate.block()  # type: ignore[attr-defined]
    return b.instruction_addrs[0] + b.size if b.instructions == 1 and b.vex.jumpkind == "Ijk_Call" else None


class DebugBarPresenter:
    """
    The debug toolbar of the main instance. The frontend sets :attr:`on_changed`, called whenever the debugger list,
    the current debugger or its state changed.
    """

    def __init__(self, workspace: Any, instance: Instance | None = None) -> None:
        self.workspace = workspace
        self.instance: Instance = instance if instance is not None else workspace.main_instance
        self.on_changed: Callable[[], Any] | None = None
        self._watcher: DebuggerWatcher | None = None
        self._list = container(self.instance.debugger_list_mgr.debugger_list)

    #
    # Listening, while the toolbar is shown
    #

    def start(self) -> None:
        self._list.am_subscribe(self._changed)
        self._watcher = DebuggerWatcher(self._changed, self.instance.debugger_mgr.debugger)

    def stop_listening(self) -> None:
        self._list.am_unsubscribe(self._changed)
        if self._watcher is not None:
            self._watcher.shutdown()
            self._watcher = None

    def _changed(self, *_args, **_kwargs) -> None:
        if self.on_changed is not None:
            self.on_changed()

    #
    # What the toolbar shows
    #

    @property
    def debugger(self) -> Debugger | None:
        dbg: Any = self.instance.debugger_mgr.debugger.am_obj
        return dbg

    @property
    def debuggers(self) -> list[Debugger]:
        return list(self.instance.debugger_list_mgr.debugger_list)

    def action_states(self) -> dict[str, tuple[bool, bool]]:
        return action_states(self.debugger)

    def state_text(self) -> str:
        """The current debugger's state, or nothing without one."""
        dbg = self.debugger
        return "" if dbg is None else dbg.state_description

    def choices(self) -> list[str]:
        """The selector's entries: no debugger, then each debugger."""
        return [NO_DEBUGGER] + [debugger_text(dbg) for dbg in self.debuggers]

    def current_index(self) -> int:
        dbg = self.debugger
        return 0 if dbg is None else self.debuggers.index(dbg) + 1

    def select_index(self, index: int) -> None:
        """Make the selector's entry ``index`` the current debugger."""
        self.instance.debugger_mgr.set_debugger(None if index == 0 else self.debuggers[index - 1])

    def launch_menu(self) -> Menu:
        """The Launch button's menu: a new simulation (with a project), a new trace debugger (with a trace)."""
        return Menu(
            "New Debugger",
            [
                MenuEntry(
                    "New simulation...",
                    self._open_new_state,
                    enabled=not self.instance.project.am_none,
                ),
                MenuEntry(
                    "New trace debugger",
                    self.workspace.create_trace_debugger,
                    enabled=not container(self.instance.current_trace).am_none,
                ),
            ],
        )

    def _open_new_state(self) -> None:
        # looked up when chosen: a frontend's window may come after the bar
        self.workspace.main_window.open_newstate_dialog()

    #
    # The buttons
    #

    def cont(self) -> None:
        self.instance.debugger_mgr.debugger.continue_forward()

    def cont_backward(self) -> None:
        self.instance.debugger_mgr.debugger.continue_backward()

    def halt(self) -> None:
        self.instance.debugger_mgr.debugger.halt()

    def step(self) -> None:
        self.instance.debugger_mgr.debugger.step_forward()

    def step_over(self) -> None:
        dbg = self.instance.debugger_mgr.debugger
        current: Any = dbg.am_obj
        dbg.step_forward(until_addr=step_over_target(current))

    def step_backward(self) -> None:
        self.instance.debugger_mgr.debugger.step_backward()

    def stop(self) -> None:
        dbg = self.instance.debugger_mgr.debugger
        dbg.stop()
        current: Any = dbg.am_obj
        self.instance.debugger_list_mgr.remove_debugger(current)


__all__ = [
    "DEBUG_ACTIONS",
    "NO_DEBUGGER",
    "DebugAction",
    "DebugBarPresenter",
    "action_states",
    "debugger_text",
    "step_over_target",
]
