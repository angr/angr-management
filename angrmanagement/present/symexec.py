"""
Symbolic execution without a toolkit: the symbolic execution view, the states view, the state inspector's texts and
the new state dialog's model.

- :class:`SimulationManagers` is the Qt ``QSimulationManagers`` panel's state and actions: the simulation managers,
  stepping and exploring through jobs, keeping one active state, the avoid and find addresses, the stash tree with
  its state clipboard, and the stash, state and tree context menus.
- :class:`SymexecPresenter` is the symbolic execution view: the selected simulation manager and state, the panel, and
  the path tree (the states' histories as a graph, :func:`path_tree_graph`, labelled by :func:`state_block_text`).
- :class:`StatesPresenter` and :class:`StatesTableModel` are the states view.
- :func:`register_rows`, :func:`memory_rows`, :func:`constraint_rows`, :func:`fd_choices`, :func:`fd_text`,
  :func:`temp_rows` and :func:`ast_strings` give the state inspector's texts.
- :class:`StateSpec` is what the new state dialog asks for and :func:`build_state` makes the state from it.
"""

from __future__ import annotations

import base64
import contextlib
import logging
import os
import re
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from inspect import isfunction
from typing import TYPE_CHECKING, Any, ClassVar, cast

import angr
import networkx
from angr import claripy
from angr.storage.file import SimFileDescriptor, SimPacketsStream

from angrmanagement.data.jobs import SimgrExploreJob, SimgrStepJob
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.signal import Signal
from angrmanagement.logic.threads import gui_thread_schedule
from angrmanagement.utils import locate_function
from angrmanagement.utils.namegen import NameGenerator

from .base import InstancePresenter, ask_text, container, project_of
from .graphs import GraphBox, TreeGraphPresenter, text_lines
from .keymap import Binding, Keymap
from .menus import Menu, MenuEntry, MenuSeparator
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from angrmanagement.data.instance import Instance

log = logging.getLogger(__name__)

#
# The new state dialog's model
#


class StateMetadata(angr.SimStatePlugin):
    """
    Helper class for metadata.
    """

    def __init__(self) -> None:
        super().__init__()
        self.name: str | None = None  # the state's name
        self.base_name: str | None = None  # the name of the base state this was created from
        self.is_original = False  # is this the original instantiation of this name?
        self.is_base = False  # is this state created with nothing else as a base?

    def copy(self, memo=None):  # pyright: ignore[reportIncompatibleVariableOverride]  # pylint: disable=unused-argument
        c = StateMetadata()
        c.name = self.name
        c.base_name = self.base_name
        c.is_original = False
        c.is_base = False
        return c


StateMetadata.register_default("gui_data")

#: The socket families and types the socket editor offers.
_SOCKET_FAMILIES_WANTED = ["AF_INET", "AF_INET6", "AF_UNIX", "AF_CAN", "AF_PACKET", "AF_RDS"]
SOCKET_FAMILIES = {s: getattr(socket, s) for s in _SOCKET_FAMILIES_WANTED if s in dir(socket)}
SOCKET_TYPES = {"SOCK_STREAM": socket.SOCK_STREAM, "SOCK_DGRAM": socket.SOCK_DGRAM, "SOCK_RAW": socket.SOCK_RAW}


def socket_ident(ident: Sequence[str]) -> tuple:
    """A socket's identifier for angr from the editor's ``family, type, nonce``."""
    return ("socket", SOCKET_FAMILIES[ident[0]], SOCKET_TYPES[ident[1]], 0, int(ident[2]))


def convert_socket_data(data: dict[str, list[str]]) -> dict:
    """
    angr's ``posix.sockets`` from the socket editor's data: for each socket (``"AF_INET, SOCK_STREAM, 1"``) or
    accepted socket (``"Accept, AF_INET, SOCK_STREAM, 1, 1"``), the base64 packets it receives.
    """
    ret = {}
    for k, v in data.items():
        ident = k.split(", ")
        if ident[0] == "Accept":
            key: tuple = ("accept", socket_ident(ident[1:]), int(ident[4]))
        else:
            key = socket_ident(ident)
        content = [claripy.BVV(base64.b64decode(x)) for x in v]
        ret[key] = (SimPacketsStream("socket read", content=content), SimPacketsStream("socket write"))
    return ret


@dataclass
class SocketSpec:
    """A socket of the new state: its identifier (``"AF_INET, SOCK_STREAM, 1"``), packets and accepted sockets."""

    ident: str
    packets: list[str] = field(default_factory=list)
    accepted: list[SocketSpec] = field(default_factory=list)


@dataclass
class SocketsSpec:
    """The new state's sockets, as the socket editor's tree holds them."""

    sockets: list[SocketSpec] = field(default_factory=list)

    def add_socket(self, family: str, type_: str, nonce: str) -> SocketSpec | None:
        """Add a socket; None (nothing added) without a family, a type or a nonce."""
        if family not in SOCKET_FAMILIES or type_ not in SOCKET_TYPES or not nonce.strip():
            return None
        sock = SocketSpec(", ".join([family, type_, nonce.strip()]))
        self.sockets.append(sock)
        return sock

    @staticmethod
    def accept(sock: SocketSpec) -> SocketSpec:
        accepted = SocketSpec(f"Accept, {sock.ident}, {len(sock.accepted) + len(sock.packets) + 1}")
        sock.accepted.append(accepted)
        return accepted

    def get_data(self) -> dict[str, list[str]]:
        ret: dict[str, list[str]] = {}
        for sock in self.sockets:
            for accepted in sock.accepted:
                ret[accepted.ident] = list(accepted.packets)
            if sock.packets:
                ret[sock.ident] = list(sock.packets)
        return ret

    def convert(self) -> dict:
        return convert_socket_data(self.get_data())

    def __bool__(self) -> bool:
        return bool(self.sockets)


#: The new state dialog's templates and modes: caption and value.
TEMPLATES = [("Blank State", "blank"), ("Call state", "call"), ("Entry state", "entry"), ("Full-init state", "full")]
MODES = [("Symbolic", "symbolic"), ("Static", "static"), ("Fast-path", "fastpath"), ("Tracing", "tracing")]


def is_option(o: str) -> bool:
    return all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for ch in o)


def option_groups() -> list[tuple[str, list[str]]]:
    """The new state dialog's option tree: each set of options angr names, then every option under "All options"."""
    groups = []
    for name, members in angr.sim_options.__dict__.items():
        if not isinstance(members, set) or name == "resilience_options":
            continue
        groups.append((name, sorted(members)))
    all_options = {x for x in angr.sim_options.__dict__.values() if isinstance(x, str) and is_option(x)}
    groups.append(("All options", sorted(all_options)))
    return groups


def parse_state_address(instance: Instance, text: str) -> int | None:
    """
    The address of the new state: a label, or a number in hex. (The Qt dialog asked ``kb.labels.lookup`` first and
    took its None for an address, so any hex address made the state at the entry point.)
    """
    project = project_of(instance)
    if project is None:
        return None
    addr = project.kb.labels.lookup(text)
    if addr is not None:
        return addr
    try:
        return int(text, 16)
    except ValueError:
        return None


@dataclass
class StateSpec:
    """
    What the new state dialog asks: the state's name, address (as typed), template, base state, program arguments
    (None until typed), environment and file system mounts (pairs), sockets (a model with ``convert()``), mode and
    options.
    """

    name: str
    address: str
    template: str = "blank"
    base_state: Any = None
    args: str | None = None
    env: list[tuple[str, str]] = field(default_factory=list)
    fs_mounts: list[tuple[str, str]] = field(default_factory=list)
    sockets: Any = None
    mode: str = "symbolic"
    options: set[str] = field(default_factory=set)

    @classmethod
    def defaults(cls, instance: Instance, addr: int | None = None) -> StateSpec:
        """The dialog's first values: a random name, the address or the entry point, a blank symbolic state."""
        project = project_of(instance)
        entry = project.entry if project is not None else 0
        spec = cls(NameGenerator.random_name(), hex(entry) if addr is None else hex(addr))
        spec.set_mode("symbolic")
        return spec

    def set_mode(self, mode: str) -> None:
        """Choose the mode; its default options replace the options chosen."""
        self.mode = mode
        self.options = set(angr.sim_options.modes[mode])

    @property
    def base_allowed(self) -> bool:
        return self.template in ("blank", "call")

    @property
    def args_allowed(self) -> bool:
        return self.template == "entry"

    def arg_list(self, instance: Instance) -> list[bytes] | None:
        """The program's argv as the Qt dialog builds it: the binary's name and the words typed."""
        if self.args is None:
            return None
        project = project_of(instance)
        filename = project.filename if project is not None else None
        return [(filename or "").encode() or b"dummy_filename"] + [x.encode() for x in self.args.split()]

    def problems(self, instance: Instance) -> list[str]:
        """Why the state cannot be made: an empty or taken name, an address that does not parse."""
        out = []
        if not self.name or any(gui_data(s).name == self.name for s in instance.states):
            out.append("name")
        if parse_state_address(instance, self.address) is None:
            out.append("address")
        return out


def build_state(instance: Instance, spec: StateSpec) -> angr.SimState:
    """The state the new state dialog makes from ``spec``, named and with its file systems and sockets."""
    project = project_of(instance)
    assert project is not None
    name = spec.name
    addr = parse_state_address(instance, spec.address)
    base_state = spec.base_state if spec.base_allowed else None
    factory = project.factory
    options = spec.options
    if spec.template in ("blank", "call") and base_state is not None:
        if spec.template == "blank":
            state = factory.blank_state(addr=addr, base_state=base_state, options=options)
        else:
            state = factory.call_state(addr, base_state=base_state, options=options)
        gui_data(state).base_name = gui_data(base_state).name
    else:
        if spec.template == "blank":
            state = factory.blank_state(addr=addr, mode=spec.mode, options=options)
        elif spec.template == "call":
            state = factory.call_state(addr, mode=spec.mode, options=options)
        elif spec.template == "entry":
            state = factory.entry_state(
                mode=spec.mode, options=options, args=spec.arg_list(instance), env=dict(spec.env)
            )
        else:
            state = factory.full_init_state(mode=spec.mode, options=options)
        gui_data(state).base_name = name
        gui_data(state).is_base = True

    gui_data(state).name = name
    gui_data(state).is_original = True

    # mount fs
    for path, real in spec.fs_mounts or ():
        if os.path.isdir(real):
            fs = angr.SimHostFilesystem(real)
            fs.set_state(state)
            state.fs.mount(path, fs)

    if spec.sockets:
        state.posix.sockets = spec.sockets.convert()
    return state


def add_state(workspace, instance: Instance, state: angr.SimState, push: bool = True, create_simgr: bool = False):
    """Put a new state in the instance's states and, if asked, make a simulation manager of it."""
    if push:
        states_list = container(instance.states)
        states_list.append(state)
        states_list.am_event(src="new", state=state)
    if create_simgr:
        workspace.create_simulation_manager(state, gui_data(state).name)


#
# The states view
#


def gui_data(state: angr.SimState) -> StateMetadata:
    """The state's metadata plugin: its name, base state's name, and whether it is an original or a base state."""
    return cast("StateMetadata", state.gui_data)


def state_row(state: angr.SimState) -> list[str]:
    """The states table's cells for ``state``: name, address, changed?, base state, mode and option changes."""
    data = gui_data(state)
    name = str(data.name)
    base_name = str(data.base_name)
    is_changed = "No" if data.is_original else "Yes"
    mode = cast("str", state.mode)
    address = f"{state.addr:x}" if isinstance(state.addr, int) else "Symbolic"
    state_options = {o for o, v in state.options._options.items() if v is True}  # pylint: disable=protected-access
    options_plus = state_options - angr.sim_options.modes[mode]
    options_minus = angr.sim_options.modes[mode] - state_options
    options = " ".join([" ".join("+" + o for o in options_plus), " ".join("-" + o for o in options_minus)])
    return [name, address, is_changed, base_name, mode, options]


def state_style(state: angr.SimState) -> str | None:
    """A base state's style key, an original state's, or None."""
    data = gui_data(state)
    if data.is_base:
        return "symexec.state.base"
    if data.is_original:
        return "symexec.state.original"
    return None


def copied_state_name(current_name: str, all_names: Iterable[str]) -> str:
    """
    A name for a copy of the state ``current_name`` that no state has: ``name copy``, ``name copy 2``, and so on.
    """
    m = re.match(r"^([\s\S]*) copy\s*(\d*)$", current_name)

    if m:
        # ends with copy
        ctr_str = m.group(2)
        ctr = int(ctr_str) + 1 if ctr_str else 1

        current_name = m.group(1)
        name = f"{current_name} copy {ctr}"
    else:
        ctr = 0
        name = current_name + " copy"

    # Increment the counter until there is no conflict with existing names
    names = set(all_names)
    while name in names:
        ctr += 1
        name = f"{current_name} copy {ctr}"
    return name


class StatesTableModel(ListTableModel[angr.SimState]):
    """The states of the instance, one per row, coloured as the Qt states table colours them."""

    COLUMNS: ClassVar[list[Column]] = [
        Column("Name", 20),
        Column("Address", 10),
        Column("Changed?", 8),
        Column("Base State", 20),
        Column("Mode", 10),
        Column("Options", stretch=True),
    ]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, presenter: StatesPresenter | None = None) -> None:
        super().__init__()
        self.presenter = presenter

    def column_text(self, obj: angr.SimState, col: int) -> str:
        return state_row(obj)[col]

    def style_key(self, obj: angr.SimState, col: int) -> str | None:
        return state_style(obj)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.states_menu(list(rows)[0] if rows else None)


class StatesPresenter(InstancePresenter):
    """
    The states view: the instance's states, a new state (through the frontend's new state editor), and duplicating,
    deleting and simulating one.
    """

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "states", instance, default_docking_position)
        self.base_caption = "States"
        self.model = StatesTableModel(self)
        self.states = container(instance.states)
        self.states.am_subscribe(self._watch_states)
        self.reload()

    def close(self) -> None:
        self.states.am_unsubscribe(self._watch_states)

    def _watch_states(self, **_kwargs) -> None:
        self.reload()

    def reload(self) -> None:
        self.model.set_rows(list(self.states))

    def states_menu(self, row: int | None) -> Menu:
        has_row = row is not None and 0 <= row < len(self.states)
        return Menu(
            "",
            [
                MenuEntry("New state...", self.new_state),
                MenuSeparator(),
                MenuEntry("Duplicate state", lambda: self.duplicate(row), enabled=has_row),
                MenuEntry("Delete state", lambda: self.delete(row), enabled=has_row),
                MenuEntry("New simulation manager", lambda: self.new_simulation_manager(row), enabled=has_row),
            ],
        )

    def new_state(self) -> None:
        open_new_state(self.workspace, self.instance)

    def duplicate(self, row: int | None) -> None:
        if row is None:
            return
        state = self.states[row]
        copy = state.copy()
        gui_data(copy).name = copied_state_name(str(gui_data(copy).name), (str(gui_data(s).name) for s in self.states))
        self.states.append(copy)
        self.states.am_event(src="duplicate", state=copy)

    def delete(self, row: int | None) -> None:
        if row is None:
            return
        tmp = self.states.pop(row)
        self.states.am_event(src="delete", state=tmp)

    def new_simulation_manager(self, row: int | None) -> None:
        if row is None:
            return
        state = self.states[row]
        self.workspace.create_simulation_manager(state, NameGenerator.random_name())


def open_new_state(workspace, instance: Instance, addr: int | None = None, create_simgr: bool = False) -> None:
    """
    Ask for a new state with the frontend's new state editor (``new_state_editor(spec, then)`` on the main window)
    and add what it makes.
    """
    if project_of(instance) is None:
        GlobalInfo.ui_services.message("critical", "Cannot create new states", "Please open a binary to analyze first.")
        return
    editor = getattr(workspace.main_window, "new_state_editor", None)
    if editor is None:
        GlobalInfo.ui_services.message("info", "New state", "This frontend has no new state editor.")
        return
    spec = StateSpec.defaults(instance, addr)

    def then(answer: StateSpec | None) -> None:
        if answer is not None:
            state = build_state(instance, answer)
            add_state(workspace, instance, state, push=True, create_simgr=create_simgr)

    editor(spec, then)


#
# The simulation managers panel
#


class ExploreAddresses:
    """An avoid or find list: addresses with a check box each."""

    def __init__(self) -> None:
        self.entries: dict[int, bool] = {}
        self.changed = Signal()

    def add(self, addr: int) -> bool:
        """Add ``addr``, checked; False if it is listed already."""
        if addr in self.entries:
            return False
        self.entries[addr] = True
        self.changed.emit()
        return True

    def remove(self, addr: int) -> None:
        if self.entries.pop(addr, None) is not None:
            self.changed.emit()

    def set_checked(self, addr: int, checked: bool) -> None:
        if addr in self.entries and self.entries[addr] != checked:
            self.entries[addr] = checked
            self.changed.emit()

    def checked(self) -> list[int]:
        return [addr for addr, on in self.entries.items() if on]

    def import_text(self, text: str) -> None:
        """Add the addresses of ``text``, one in hex per line; lines that are not one are skipped."""
        for line in text.splitlines(keepends=False):
            with contextlib.suppress(ValueError):
                self.add(int(line, 16))


def filter_actives(simgr, events: bool = True) -> bool:
    """Keep the first active state of ``simgr`` and stash the others; whether any were stashed."""
    if len(simgr.active) < 2:
        return False

    stashed = simgr.active[1:]
    simgr.stashes["stashed"].extend(stashed)
    simgr.stashes["active"] = simgr.active[:1]
    if events:
        simgr.am_event(src="filter_actives", filtered=stashed)
    return True


def stash_states(simgr, stash_name: str) -> list[Any]:
    """The states of a stash as the stash tree lists them (an errored record shows its state)."""
    out = []
    for state in simgr.stashes[stash_name]:
        if stash_name == "errored" and getattr(state, "state", None):
            state = state.state
        out.append(state)
    return out


def drop_states(simgr, stash_name: str, states: Sequence[Any]) -> None:
    simgr.drop(stash=stash_name, filter_func=lambda state, state_set=list(states): state in state_set)


def paste_states(simgr, stash_name: str, clipboard: Sequence[Any]) -> None:
    simgr.populate(stash_name, list(clipboard))


def move_states(simgr, stash_name: str, lambda_text: str) -> str | None:
    """
    Move the active states the lambda ``lambda_text`` accepts to ``stash_name``; returns why the text was refused
    (it does not evaluate to a function), or None once moved.
    """
    try:
        lambda_func = eval(lambda_text)  # pylint: disable=eval-used
        if not isfunction(lambda_func):
            raise ValueError
    except Exception as e:  # pylint: disable=broad-except
        return str(e) or type(e).__name__
    simgr.move(from_stash="active", to_stash=stash_name, filter_func=lambda_func)
    return None


def create_stash(simgr, stash_name: str) -> str | None:
    """Add an empty stash; returns why not (a blank name, or a name taken), or None."""
    if stash_name.strip() == "":
        return ""
    if stash_name in simgr.stashes:
        return f"A stash with the name {stash_name} already exists in the current simulation manager."
    simgr._stashes[stash_name] = []  # pylint: disable=protected-access
    return None


@dataclass(eq=False)
class StashRow:
    """A row of the stash tree: a stash (``state`` None) or one of its states."""

    stash: str
    state: Any = None

    @property
    def is_stash(self) -> bool:
        return self.state is None


class SimulationManagers:
    """
    The simulation managers panel: what Qt's ``QSimulationManagers`` and its ``QSimulationManagerViewer`` hold,
    without the widgets. ``simgr`` is the container of the selected simulation manager's container and ``state`` the
    container of the selected state; both are the symbolic execution view's.
    """

    def __init__(self, workspace, instance: Instance, simgr: ObjectContainer, state: ObjectContainer) -> None:
        self.workspace = workspace
        self.instance = instance
        self.simgrs = container(instance.simgrs)
        self.simgr = simgr
        self.state = state
        self.avoids = ExploreAddresses()
        self.finds = ExploreAddresses()
        self.keep_one_active = False
        self.state_clipboard: list[Any] = []
        #: the stash tree: which stashes are expanded, which state rows are selected
        self.expanded: set[str] = set()
        self.selected_states: list[Any] = []
        #: the stash tree, the simulation manager list or the lists changed
        self.changed = Signal()
        self.avoids.changed.connect(self._on_explore_addr_changed)
        self.finds.changed.connect(self._on_explore_addr_changed)
        self.simgr.am_subscribe(self._watch_simgr)
        self.simgrs.am_subscribe(self._watch_simgrs)
        self.state.am_subscribe(self._watch_state)

    def close(self) -> None:
        self.simgr.am_unsubscribe(self._watch_simgr)
        self.simgrs.am_unsubscribe(self._watch_simgrs)
        self.state.am_unsubscribe(self._watch_state)

    @property
    def find_addrs(self) -> list[int]:
        return list(set(self.finds.checked()))

    @property
    def avoid_addrs(self) -> list[int]:
        return list(set(self.avoids.checked()))

    def add_avoid_address(self, addr: int) -> None:
        self.avoids.add(addr)

    def add_find_address(self, addr: int) -> None:
        self.finds.add(addr)

    def remove_avoid_address(self, addr: int) -> None:
        self.avoids.remove(addr)

    def remove_find_address(self, addr: int) -> None:
        self.finds.remove(addr)

    #
    # Simulation managers
    #

    def simgr_names(self) -> list[str]:
        return [simgr.am_name for simgr in self.simgrs]

    def current_index(self) -> int:
        for idx, simgr in enumerate(self.simgrs):
            if simgr is self.simgr.am_obj:
                return idx
        return -1

    def select_simgr_index(self, idx: int) -> None:
        simgr = self.simgrs[idx] if 0 <= idx < len(self.simgrs) else None
        if simgr != self.simgr.am_obj:
            self.simgr.am_obj = simgr
            self.simgr.am_event(src="clicked")
            self.changed.emit()

    #
    # Stepping and exploring
    #

    def step(self, until_branch: bool = False) -> None:
        """Step the active states one instruction, or until the number of active states changes."""
        if not self.simgr.am_none:
            self.workspace.job_manager.add_job(
                SimgrStepJob(
                    self.instance,
                    self.simgr.am_obj,
                    until_branch=until_branch,
                    step_callback=self.workspace.plugins.step_callback,
                )
            )

    def explore(self) -> None:
        """Explore toward the checked find addresses, away from the checked avoid addresses."""
        if self.simgr.am_none:
            return

        def _step_callback(simgr):
            self.workspace.plugins.step_callback(simgr)
            if self.keep_one_active:
                filter_actives(simgr, events=False)
            gui_thread_schedule(lambda: self.simgr.am_event(src="post_step"))
            return simgr

        self.workspace.job_manager.add_job(
            SimgrExploreJob.create(
                self.instance,
                self.simgr,
                avoid=self.avoid_addrs,
                find=self.find_addrs,
                step_callback=_step_callback,
            )
        )

    # the names the simulation debugger calls, as on the Qt panel
    def _on_step_clicked(self) -> None:
        self.step()

    def _on_explore_clicked(self) -> None:
        self.explore()

    def _filter_actives(self, simgr, events: bool = True) -> bool:
        if not self.keep_one_active:
            return False
        return filter_actives(simgr, events)

    #
    # Events
    #

    def _watch_simgr(self, **kwargs) -> None:
        if kwargs.get("src") == "job_done" and kwargs.get("job") == "step":
            self._filter_actives(self.simgr)
        self.changed.emit()

    def _watch_simgrs(self, **_kwargs) -> None:
        self.changed.emit()

    def _watch_state(self, **_kwargs) -> None:
        self.changed.emit()

    def _on_explore_addr_changed(self) -> None:
        """The disassembly shows the find and avoid marks: draw it again."""
        view_manager = self.workspace.view_manager
        if len(view_manager.views_by_category["disassembly"]) == 1:
            view = view_manager.first_view_in_category("disassembly")
        else:
            view = view_manager.current_view_in_category("disassembly")
        if view is not None:
            refresh = getattr(view, "refresh_view", None) or view.refresh
            refresh()
        self.changed.emit()

    #
    # The stash tree
    #

    def stash_rows(self) -> list[StashRow]:
        """The tree's rows: each stash, and the states of the expanded ones."""
        if self.simgr.am_none:
            return []
        rows = []
        for stash_name in self.simgr.stashes:
            rows.append(StashRow(stash_name))
            if stash_name in self.expanded:
                rows.extend(StashRow(stash_name, state) for state in stash_states(self.simgr, stash_name))
        return rows

    def row_text(self, row: StashRow) -> str:
        if row.is_stash:
            return f"{row.stash} ({len(self.simgr.stashes[row.stash])})"
        return str(row.state)

    def toggle_stash(self, stash_name: str) -> None:
        self.expanded ^= {stash_name}
        self.changed.emit()

    def select_state(self, state: Any) -> None:
        """Make ``state`` the selected state (as clicking its row does)."""
        if state is not self.state.am_obj:
            self.state.am_obj = state
            self.state.am_event(src="clicked")

    def select_states(self, states: Sequence[Any]) -> None:
        """Select the active states among ``states`` and expand the active stash."""
        if self.simgr.am_none:
            return
        wanted = set(states)
        self.selected_states = [s for s in self.simgr.stashes["active"] if s in wanted]
        self.expanded.add("active")
        self.changed.emit()

    def _selected_by_stash(self) -> dict[str, list[Any]]:
        stash_to_states: dict[str, list[Any]] = defaultdict(list)
        for stash_name in self.simgr.stashes:
            for state in self.simgr.stashes[stash_name]:
                if any(state is s for s in self.selected_states):
                    stash_to_states[stash_name].append(state)
        return stash_to_states

    def copy_selected(self) -> None:
        self.state_clipboard = [state.copy() for state in self.selected_states]

    def cut_selected(self) -> None:
        self.copy_selected()
        self.delete_selected()

    def delete_selected(self) -> None:
        for stash_name, states in self._selected_by_stash().items():
            drop_states(self.simgr, stash_name, states)
        self.selected_states = []
        self.changed.emit()

    def copy_stash(self, stash_name: str) -> None:
        self.state_clipboard = list(stash_states(self.simgr, stash_name))
        self.changed.emit()

    def cut_stash(self, stash_name: str) -> None:
        states = list(self.simgr.stashes[stash_name])
        self.state_clipboard = list(stash_states(self.simgr, stash_name))
        drop_states(self.simgr, stash_name, states)
        self.changed.emit()

    def paste(self, stash_name: str) -> None:
        paste_states(self.simgr, stash_name, self.state_clipboard)
        self.changed.emit()

    def delete_stash(self, stash_name: str) -> None:
        self.simgr._stashes.pop(stash_name)  # pylint: disable=protected-access
        self.expanded.discard(stash_name)
        self.changed.emit()

    def move_to_stash(self, stash_name: str) -> None:
        """Ask for a condition lambda and move the active states it accepts to ``stash_name``."""

        def ask(default: str) -> None:
            ask_text("Move state from active to here", "Condition lambda", default, then)

        def then(answer: str | None) -> None:
            if answer is None:
                return
            error = move_states(self.simgr, stash_name, answer)
            if error is not None:
                GlobalInfo.ui_services.message("critical", "Exception!", error)
                ask(answer)
                return
            self.changed.emit()

        ask("")

    def new_stash(self) -> None:
        """Ask for a name and add an empty stash of that name."""

        def then(answer: str | None) -> None:
            if answer is None:
                return
            error = create_stash(self.simgr, answer)
            if error:
                GlobalInfo.ui_services.message("critical", "Duplicate stash name", error)
            elif error is None:
                self.changed.emit()

        ask_text("Stash name", "Blah", "", then)

    @staticmethod
    def import_addresses(which: ExploreAddresses) -> None:
        """Ask for a list of addresses, one in hex per line, for the avoid or find list."""

        def then(answer: str | None) -> None:
            if answer:
                which.import_text(answer)

        ask_text("Input Address List", "Address in hex (one address each line):", "", then)

    def row_menu(self, row: StashRow | None) -> Menu:
        """The stash tree's context menu: a stash's, a state's, or (off the rows) the new stash entry."""
        if row is None:
            return Menu("", [MenuEntry("Create new stash", self.new_stash)])
        if row.is_stash:
            entries: list[Any] = [
                MenuEntry("Copy states", lambda: self.copy_stash(row.stash)),
                MenuEntry("Cut states", lambda: self.cut_stash(row.stash)),
            ]
            if self.state_clipboard:
                plural = "s" if len(self.state_clipboard) > 1 else ""
                entries.append(MenuEntry("Paste state" + plural, lambda: self.paste(row.stash)))
            entries.append(MenuEntry("Delete stash", lambda: self.delete_stash(row.stash)))
            if row.stash != "active":
                entries.append(MenuEntry("Move states to here", lambda: self.move_to_stash(row.stash)))
            return Menu("", entries)
        if not any(row.state is s for s in self.selected_states):
            self.selected_states = [row.state]
        plural = "s" if len(self.selected_states) > 1 else ""
        entries = [
            MenuEntry("Copy state" + plural, self.copy_selected),
            MenuEntry("Cut state" + plural, self.cut_selected),
            MenuEntry("Delete state" + plural, self.delete_selected),
        ]
        if self.state_clipboard:
            entries.append(MenuEntry("Paste state" + plural, lambda: self.paste(row.stash)))
        return Menu("", entries)


#
# The path tree
#


def path_tree_edges(state_histories: Iterable[Any], hierarchy) -> Iterable[tuple[Any, Any]]:
    """The edges of the path tree: from each history where paths branch to the next branch point (or state) below."""
    work = set(state_histories)
    while len(work) > 0:
        working_history = bot_history = work.pop()
        while hierarchy.history_contains(working_history):
            parent_histories = hierarchy.history_predecessors(working_history)
            if not parent_histories:
                break

            parent_history = parent_histories[0]

            try:
                successors = hierarchy.history_successors(parent_history)
                if len(successors) > 1:
                    yield (parent_history, bot_history)
                    work.add(parent_history)
                    break
                working_history = parent_history
            except KeyError:
                # the parent history is not found in the path mapping
                log.error("Parent history %s is not found", parent_history)
                break


def simgr_histories(simgr) -> list[Any]:
    """The histories of the states of every stash but ``pruned``."""
    return [state.history for (stash, states) in simgr.stashes.items() if stash != "pruned" for state in states]


def path_tree_graph(simgr) -> networkx.DiGraph | None:
    """The path tree of ``simgr``: its states' histories and the branch points between them."""
    if simgr is None:
        return None
    histories = simgr_histories(simgr)
    graph = networkx.DiGraph()
    graph.add_nodes_from(histories)
    graph.add_edges_from(path_tree_edges(histories, simgr._hierarchy))  # pylint: disable=protected-access
    return graph


def state_block_text(instance: Instance, state) -> tuple[str, str, int | None]:
    """A path tree block's two lines, the state's address and its function, and the address (None if symbolic)."""
    try:
        if state.regs._ip.symbolic:  # pylint: disable=protected-access
            return str(state.regs._ip), "Function: Unknown", None  # pylint: disable=protected-access
        addr = state.regs._ip.concrete_value  # pylint: disable=protected-access
    except ReferenceError:
        # The SimState was held via weakref and has been garbage-collected while the path-tree view was still alive
        # (issue #1644). Fall back to a placeholder label instead of letting the graphical update abort halfway.
        return "<state freed>", "Function: Unknown", None

    the_func = locate_function(instance, addr)
    project = project_of(instance)
    if the_func is None:
        # is it a SimProcedure?
        if project is not None and project.is_hooked(addr):
            hooker = project.hooked_by(addr)
            function_str = "SimProcedure " + hooker.__class__.__name__.split(".")[-1]
        else:
            function_str = "Unknown"
    else:
        offset = addr - the_func.addr
        function_str = f"{the_func.name}{offset:+x}" if the_func.name else f"{the_func.addr:#x}{offset:+x}"
    return f"{addr:#x}", f"Function: {function_str}", addr


#
# The state inspector
#

#: The registers the inspector lists, per architecture.
ARCH_REGISTERS: dict[str, dict[str, list[str]]] = {
    "X86": {"common": ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"]},
    "AMD64": {
        "common": [
            *("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "rip"),
            *("r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
        ]
    },
    "MIPS32": {
        "common": [
            *("v0", "v1", "a0", "a1", "a2", "a3"),
            *(f"t{i}" for i in range(10)),
            *(f"s{i}" for i in range(9)),
            *("gp", "sp", "ra", "pc"),
        ]
    },
    "ARM": {"common": [*(f"r{i}" for i in range(13)), "sp", "lr", "pc"]},
    "AARCH64": {"common": [*(f"x{i}" for i in range(31)), "sp", "pc"]},
}
ARCH_REGISTERS["ARMEL"] = ARCH_REGISTERS["ARM"]
ARCH_REGISTERS["ARMHF"] = ARCH_REGISTERS["ARM"]


def ast_strings(ast, display_size: bool = True, byte_format: str | None = None) -> tuple[str, str, bool]:
    """
    How the AST viewer shows ``ast`` (an int or a claripy AST): the size label, the value (hex for a concrete
    value, the variable's name for a symbolic variable, else the AST one level deep), and whether it is symbolic.
    """
    fmt = "%02x" if byte_format is None else byte_format
    if isinstance(ast, int):
        return ("[Unknown]" if display_size else ""), fmt % ast, False
    size = f"[{len(ast) // 8}]" if display_size else ""
    if not ast.symbolic:
        return size, fmt % ast.concrete_value, False
    if isinstance(ast, claripy.ast.BV) and ast.op == "BVS":
        return size, str(ast.args[0]), True
    # the Qt viewer called ast.__repr__(max_depth=1), which claripy's repr no longer takes (TypeError)
    return size, ast.shallow_repr(max_depth=1), True


def register_rows(state) -> list[tuple[str, Any]] | None:
    """The registers the inspector lists and their values; None for an architecture it does not list."""
    regs = ARCH_REGISTERS.get(state.arch.name)
    if regs is None:
        return None
    return [(name, state.registers.load(name, disable_actions=True, inspect=False)) for name in regs["common"]]


def memory_rows(state, addr: int, rows: int = 10, cols: int = 16) -> list[tuple[int, list[Any]]]:
    """The memory viewer's rows from ``addr``: each row's address and its bytes as ASTs."""
    out = []
    for row in range(rows):
        row_addr = addr + row * cols
        out.append(
            (
                row_addr,
                [state.memory.load(row_addr + col, 1, inspect=False, disable_actions=True) for col in range(cols)],
            )
        )
    return out


#: The constraint table's columns.
CONSTRAINT_COLUMNS = ["Constraint", "Cardinality", "Depth", "# Variables"]


def leaf_count(ast) -> int:
    """
    How many different leaves (variables and constants) ``ast`` has: what ``len(list(ast.leaf_asts()))`` counted
    before claripy dropped ``leaf_asts``.
    """
    seen: set[int] = set()
    stack = [ast]
    count = 0
    while stack:
        node = stack.pop()
        if node.is_leaf():
            if hash(node) not in seen:
                seen.add(hash(node))
                count += 1
            continue
        stack.extend(arg for arg in node.args if hasattr(arg, "is_leaf"))
    return count


def constraint_rows(state) -> list[list[str]]:
    """The constraints of ``state``: each one's text, cardinality, depth and number of leaves."""
    return [
        [
            constraint.shallow_repr(),
            str(constraint.cardinality),
            str(constraint.depth),
            str(leaf_count(constraint)),
        ]
        for constraint in state.solver.constraints
    ]


#: The names the file descriptor list gives the standard streams.
STD_FDS = {0: "stdin", 1: "stdout", 2: "stderr"}


def fd_choices(state) -> list[tuple[int, str]]:
    """The file descriptors of ``state`` and the names the list shows."""
    out = []
    for fd, simfile in state.posix.fd.items():
        if fd in STD_FDS:
            out.append((fd, STD_FDS[fd]))
        elif isinstance(simfile, SimFileDescriptor):
            out.append((fd, str(simfile.file.name)))
        else:
            out.append((fd, str(simfile)))
    return out


def fd_text(state, fd: int) -> str:
    """What a file descriptor of ``state`` holds, as text (NUL bytes shown as ``\\x00``)."""
    return state.posix.dumps(fd).decode("ascii", "ignore").replace("\x00", "\\x00")


def temp_rows(state) -> list[tuple[str, Any]]:
    """The VEX temporaries of ``state`` and their values."""
    tmps = {} if state is None else state.scratch.temps
    return [(f"tmp_{tmp_id}", value) for tmp_id, value in tmps.items()]


#
# The symbolic execution view
#


def symexec_keymap() -> Keymap:
    """The symbolic execution view's keys: the path tree's Tab, and the panel's buttons."""
    return Keymap(
        "symexec",
        [
            Binding("Tab", "switch_to_disassembly_view", "Show the selected state's address in the disassembly"),
            Binding("S", "step", "Step actives"),
            Binding("B", "step_until_branch", "Step actives until branch"),
            Binding("E", "explore", "Explore"),
            Binding("Shift+F10", "context_menu", "Context menu"),
        ],
    )


class SymexecPresenter(InstancePresenter):
    """
    The symbolic execution view: the selected simulation manager (``current_simgr``, a container of a simulation
    manager's container) and state (``current_state``), the simulation managers panel (:attr:`simgrs`; the
    workspace's simulation debugger and the disassembly's marks use it as they use the Qt panel), and the path tree.
    """

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "symexec", instance, default_docking_position)
        self.base_caption = "Symbolic Execution"
        self.current_simgr = ObjectContainer(None, name="Active simulation manager")
        self.current_state = ObjectContainer(None, name="Selected state")
        self.simgrs = SimulationManagers(workspace, instance, self.current_simgr, self.current_state)
        self.path_tree = TreeGraphPresenter(self._path_tree_source, self._path_tree_box, "graph")
        self.path_tree_changed = Signal()
        self.current_simgr.am_subscribe(self._watch_simgr)
        self.current_state.am_subscribe(self._watch_state)

    @property
    def keymap(self) -> Keymap:
        return symexec_keymap()

    def close(self) -> None:
        self.simgrs.close()
        self.current_simgr.am_unsubscribe(self._watch_simgr)
        self.current_state.am_unsubscribe(self._watch_state)

    #
    # The path tree
    #

    def _path_tree_source(self) -> networkx.DiGraph | None:
        if self.current_simgr.am_none:
            return None
        return path_tree_graph(self.current_simgr.am_obj)

    def _path_tree_box(self, history) -> GraphBox:
        state = history.state
        label, function, addr = state_block_text(self.instance, state)
        return GraphBox(history, text_lines([label, function]), addr or 0)

    def _watch_simgr(self, **_kwargs) -> None:
        self.path_tree.invalidate()
        self.path_tree_changed.emit()

    def _watch_state(self, **_kwargs) -> None:
        state = self.current_state.am_obj
        self.path_tree.selected = state.history if state is not None else None
        self.path_tree_changed.emit()

    def select_history(self, history) -> None:
        """A path tree block was selected: its state becomes the selected state."""
        state = history.state if history is not None else None
        if state is not None and state is not self.current_state.am_obj:
            self.current_state.am_obj = state
            self.current_state.am_event(src="path_tree")

    def activate_history(self, history) -> None:
        """A path tree block was double clicked: show its address."""
        state = history.state if history is not None else None
        if state is not None:
            self.workspace.viz(state.addr)

    #
    # What the workspace, the disassembly and plugins call
    #

    def select_simgr(self, simgr) -> None:
        self.current_simgr.am_obj = simgr
        self.current_simgr.am_event(src="from above")

    def select_states(self, states) -> None:
        self.simgrs.select_states(states)

    def view_state(self, state) -> None:
        self.current_state.am_obj = state
        self.current_state.am_event(src="view_state")
        # push namespace into the console
        view = self.workspace.view_manager.first_view_in_category("console")
        if view is not None:
            view.push_namespace({"state": state})

    def avoid_addr_in_exec(self, addr: int) -> None:
        self.simgrs.add_avoid_address(addr)

    def find_addr_in_exec(self, addr: int) -> None:
        self.simgrs.add_find_address(addr)

    def remove_avoid_addr_in_exec(self, addr: int) -> None:
        self.simgrs.remove_avoid_address(addr)

    def remove_find_addr_in_exec(self, addr: int) -> None:
        self.simgrs.remove_find_address(addr)

    def step(self) -> None:
        self.simgrs.step()

    def step_until_branch(self) -> None:
        self.simgrs.step(until_branch=True)

    def explore(self) -> None:
        self.simgrs.explore()

    def switch_to_disassembly_view(self) -> None:
        """Show the selected path tree block's (or else the selected state's) address in the disassembly."""
        history = self.path_tree.selected
        state = history.state if history is not None else self.current_state.am_obj
        if state is None or not isinstance(state.addr, int):
            return
        view_manager = self.workspace.view_manager
        if len(view_manager.views_by_category["disassembly"]) == 1:
            disasm_view = view_manager.first_view_in_category("disassembly")
        else:
            disasm_view = view_manager.current_view_in_category("disassembly")
        if disasm_view is None:
            return
        disasm_view.jump_to(state.addr)
        self.workspace.raise_view(disasm_view)


__all__ = [
    "ARCH_REGISTERS",
    "CONSTRAINT_COLUMNS",
    "MODES",
    "TEMPLATES",
    "ExploreAddresses",
    "SOCKET_FAMILIES",
    "SOCKET_TYPES",
    "STD_FDS",
    "SimulationManagers",
    "SocketSpec",
    "SocketsSpec",
    "StateMetadata",
    "StashRow",
    "StateSpec",
    "StatesPresenter",
    "StatesTableModel",
    "SymexecPresenter",
    "add_state",
    "ast_strings",
    "build_state",
    "constraint_rows",
    "convert_socket_data",
    "create_stash",
    "drop_states",
    "copied_state_name",
    "fd_choices",
    "fd_text",
    "filter_actives",
    "gui_data",
    "memory_rows",
    "move_states",
    "open_new_state",
    "option_groups",
    "parse_state_address",
    "paste_states",
    "path_tree_edges",
    "path_tree_graph",
    "register_rows",
    "simgr_histories",
    "socket_ident",
    "stash_states",
    "state_block_text",
    "state_row",
    "temp_rows",
]
