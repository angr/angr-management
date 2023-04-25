from typing import TYPE_CHECKING, Callable, Optional

from angrmanagement.data.object_container import EventSentinel, ObjectContainer

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class Debugger:
    """
    Provides a generic interface with common debugger operations to control program execution and inspect program state.
    """

    def __init__(self, workspace: "Workspace"):
        super().__init__()
        self.workspace: Workspace = workspace
        self.instance: Instance = workspace.main_instance
        self.state_changed: EventSentinel = EventSentinel()

    @property
    def state_description(self) -> str:
        """
        Get a string describing the current debugging state.
        """
        return ""

    def init(self):
        """
        Initialize target connection.
        """

    @property
    def is_running(self) -> bool:
        """
        Determine if target is running.
        """
        return False

    @property
    def can_step_backward(self) -> bool:
        """
        Determine if the target can step backward by one machine instruction.
        """
        return False

    def step_backward(self):
        """
        Step backward by one machine instruction.
        """
        raise NotImplementedError

    @property
    def can_step_forward(self) -> bool:
        """
        Determine if the target can step forward by one machine instruction.
        """
        return False

    def step_forward(self, until_addr: Optional[int] = None):
        """
        Step forward by one machine instruction.
        """
        raise NotImplementedError

    @property
    def can_continue_backward(self) -> bool:
        """
        Determine if execution can continue in reverse.
        """
        return False

    def continue_backward(self):
        """
        Continue execution in reverse.
        """
        raise NotImplementedError

    @property
    def can_continue_forward(self) -> bool:
        """
        Determine if execution can continue.
        """
        return False

    def continue_forward(self):
        """
        Continue execution.
        """
        raise NotImplementedError

    @property
    def can_halt(self) -> bool:
        """
        Determine if the target can be interrupted.
        """
        return False

    def halt(self):
        """
        Interrupt the target.
        """
        raise NotImplementedError

    @property
    def is_halted(self) -> bool:
        """
        Determine if the target has been interrupted and is now halted.
        """
        return False

    @property
    def can_stop(self) -> bool:
        """
        Determine if the target can be stopped.
        """
        return False

    def stop(self):
        """
        Stop the target.
        """
        raise NotImplementedError

    @property
    def is_exited(self) -> bool:
        """
        Determine if the target has exited.
        """
        return False


class DebuggerListManager:
    """
    Manages the list of active debuggers.
    """

    def __init__(self):
        self.debugger_list = ObjectContainer([], "List of active debuggers")

    def add_debugger(self, dbg: Debugger):
        self.debugger_list.append(dbg)
        self.debugger_list.am_event(added=dbg)

    def remove_debugger(self, dbg: Debugger):
        self.debugger_list.remove(dbg)
        self.debugger_list.am_event(removed=dbg)


class DebuggerManager:
    """
    Manages one selected active debugger container.
    """

    def __init__(self, debugger_list_mgr: DebuggerListManager):
        self.debugger: ObjectContainer = ObjectContainer(None, "Current debugger")
        debugger_list_mgr.debugger_list.am_subscribe(self._on_debugger_list_event)

    def _on_debugger_list_event(self, **kwargs):
        if "removed" in kwargs:
            self._on_debugger_removed(kwargs["removed"])

    def _on_debugger_removed(self, dbg: Debugger):
        if self.debugger.am_obj is dbg:
            self.set_debugger(None)

    def set_debugger(self, dbg: Optional[Debugger]):
        self.debugger.am_obj = dbg
        self.debugger.am_event()


class DebuggerWatcher:
    """
    Watcher object that subscribes to debugger events whenever debugger changes.
    """

    def __init__(self, state_updated_callback: Callable, debugger: ObjectContainer):
        """
        :param state_updated_callback: Callable to be called whenever the debugger state changes.
        :param debugger: Debugger container to monitor.
        """
        super().__init__()
        self._last_selected_debugger: Optional[Debugger] = None
        self.state_updated_callback: Callable = state_updated_callback
        self.debugger: ObjectContainer = debugger
        self.debugger.am_subscribe(self._on_debugger_updated)
        self._subscribe_to_events()

    def shutdown(self):
        self.debugger.am_unsubscribe(self._on_debugger_updated)
        self._unsubscribe_from_events()

    def _unsubscribe_from_events(self):
        if self._last_selected_debugger:
            self._last_selected_debugger.state_changed.am_unsubscribe(self._on_debugger_state_updated)
            self._last_selected_debugger = None

    def _subscribe_to_events(self):
        if not self.debugger.am_none:
            self.debugger.state_changed.am_subscribe(self._on_debugger_state_updated)
            self._last_selected_debugger = self.debugger.am_obj

    def _on_debugger_updated(self, *args, **kwargs):  # pylint:disable=unused-argument
        self._unsubscribe_from_events()
        self._subscribe_to_events()
        self._on_debugger_state_updated()

    def _on_debugger_state_updated(self):
        self.state_updated_callback()
