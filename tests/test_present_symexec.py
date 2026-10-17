"""
Symbolic execution without a toolkit, on fauxware: the new state's model and the states it builds, the states table,
the simulation managers panel (stepping, keeping one active state, the stash tree and its clipboard, avoid and find
lists), the path tree, the state inspector's texts and the sockets model.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import os
import unittest
from typing import TYPE_CHECKING, Any

import angr
from angr import claripy

from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.logic.ui_services import HeadlessServices
from angrmanagement.present.menus import Menu, find_entry, walk_entries
from angrmanagement.present.symexec import (
    ExploreAddresses,
    SimulationManagers,
    SocketsSpec,
    StateSpec,
    StatesPresenter,
    SymexecPresenter,
    add_state,
    ast_strings,
    build_state,
    constraint_rows,
    convert_socket_data,
    copied_state_name,
    create_stash,
    fd_choices,
    fd_text,
    filter_actives,
    gui_data,
    memory_rows,
    move_states,
    option_groups,
    parse_state_address,
    path_tree_graph,
    register_rows,
    state_block_text,
    state_row,
    temp_rows,
)

if TYPE_CHECKING:
    from angrmanagement.present.tables import ListTableModel

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


def captions(menu: Menu) -> list[str]:
    return [entry.text for _path, entry in walk_entries(menu)]


class AnsweringServices(HeadlessServices):
    """Headless services that type ``text`` in every prompt and keep the messages."""

    def __init__(self, text: str | None = None) -> None:
        super().__init__()
        self.text = text
        self.messages: list[tuple[str, str]] = []

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:
        answer, self.text = self.text, None
        return answer

    def message(self, level, title: str, text: str) -> None:
        self.messages.append((title, text))


class FauxwareCase(unittest.TestCase):
    project: angr.Project

    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.cfg = cls.project.analyses.CFGFast(normalize=True)
        cls.main = cls.project.kb.functions["main"]

    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance
        self.instance.project.am_obj = self.project
        self.instance.project.am_event()
        self.instance.cfg.am_obj = self.cfg.model
        self.saved_services = GlobalInfo._ui_services
        self.services = AnsweringServices()
        GlobalInfo.ui_services = self.services  # pyright: ignore[reportAttributeAccessIssue]

    def tearDown(self):
        GlobalInfo.ui_services = self.saved_services  # pyright: ignore[reportAttributeAccessIssue]
        self.workspace.job_manager.quit()

    def state_at_main(self, name: str = "s0") -> angr.SimState:
        spec = StateSpec(name, hex(self.main.addr))
        spec.set_mode("symbolic")
        return build_state(self.instance, spec)


class TestNewState(FauxwareCase):
    def test_address_is_a_label_or_hex(self):
        main = self.main.addr
        assert parse_state_address(self.instance, "main") == main
        assert parse_state_address(self.instance, hex(main)) == main
        assert parse_state_address(self.instance, f"{main:x}") == main
        assert parse_state_address(self.instance, "no such thing") is None

    def test_defaults_and_problems(self):
        spec = StateSpec.defaults(self.instance)
        assert spec.address == hex(self.project.entry) and spec.template == "blank" and spec.mode == "symbolic"
        assert spec.options == angr.sim_options.modes["symbolic"]
        assert not spec.problems(self.instance)
        spec.address = "zz"
        spec.name = ""
        assert spec.problems(self.instance) == ["name", "address"]
        spec.set_mode("fastpath")
        assert spec.options == angr.sim_options.modes["fastpath"]
        groups = dict(option_groups())
        assert "resilience_options" not in groups and "All options" in groups
        assert all(option.isupper() or "_" in option for option in groups["All options"])

    def test_states_at_the_address_typed(self):
        # the Qt dialog made every hex address a state at the entry point: kb.labels.lookup returned None for it
        state = self.state_at_main("first")
        assert state.addr == self.main.addr
        data = gui_data(state)
        assert (data.name, data.base_name, data.is_original, data.is_base) == ("first", "first", True, True)
        spec = StateSpec("second", "main", template="call", base_state=state)
        call = build_state(self.instance, spec)
        assert call.addr == self.main.addr and gui_data(call).base_name == "first" and not gui_data(call).is_base

    def test_entry_state_with_args_and_env(self):
        spec = StateSpec("e", hex(self.project.entry), template="entry", args="one two", env=[("HOME", "/x")])
        assert spec.arg_list(self.instance) == [str(self.project.filename).encode(), b"one", b"two"]
        state = build_state(self.instance, spec)
        assert state.addr == self.project.entry
        assert state.posix.environ is not None

    def test_add_state_and_simgr(self):
        state = self.state_at_main("added")
        add_state(self.workspace, self.instance, state, push=True, create_simgr=True)
        assert list(self.instance.states) == [state]
        assert [s.am_name for s in self.instance.simgrs] == ["added"]


class TestStatesTable(FauxwareCase):
    def test_rows_menu_duplicate_delete(self):
        presenter = StatesPresenter(self.workspace, self.instance)
        state = self.state_at_main("alpha")
        add_state(self.workspace, self.instance, state)
        model: ListTableModel = presenter.model
        assert model.row_count == 1
        assert state_row(state)[:5] == ["alpha", f"{self.main.addr:x}", "No", "alpha", "symbolic"]
        assert model.style_key(state, 0) == "symexec.state.base"
        menu = presenter.model.context_menu([0])
        assert menu is not None
        assert captions(menu) == [
            "New state...",
            "Duplicate state",
            "Delete state",
            "New simulation manager",
        ]
        dup = find_entry(menu, "Duplicate state")
        assert dup is not None
        dup.trigger()
        names = [gui_data(s).name for s in self.instance.states]
        assert names == ["alpha", "alpha copy"]
        assert model.row_count == 2 and model.style_key(self.instance.states[1], 0) is None
        assert state_row(self.instance.states[1])[2] == "Yes"
        presenter.duplicate(1)
        assert gui_data(self.instance.states[2]).name == "alpha copy 1"
        presenter.delete(0)
        assert [gui_data(s).name for s in self.instance.states] == ["alpha copy", "alpha copy 1"]
        menu = presenter.states_menu(None)
        entry = find_entry(menu, "Delete state")
        assert entry is not None and not entry.enabled
        presenter.new_simulation_manager(0)
        assert len(self.instance.simgrs) == 1
        presenter.close()

    def test_copied_names(self):
        assert copied_state_name("a", []) == "a copy"
        assert copied_state_name("a", ["a copy"]) == "a copy 1"
        assert copied_state_name("a copy", ["a copy 1"]) == "a copy 2"
        assert copied_state_name("a copy 3", []) == "a copy 4"


class SimgrCase(FauxwareCase):
    def setUp(self):
        super().setUp()
        self.presenter = SymexecPresenter(self.workspace, self.instance)
        state = self.state_at_main("sym")
        simgr = self.project.factory.simulation_manager(state, hierarchy=angr.state_hierarchy.StateHierarchy())
        self.simgr: Any = simgr
        self.simgr_container = ObjectContainer(simgr, name="sym")
        self.instance.simgrs.append(self.simgr_container)
        self.instance.simgrs.am_event(src="new_path")
        self.presenter.select_simgr(self.simgr_container)
        self.panel: SimulationManagers = self.presenter.simgrs

    def tearDown(self):
        self.presenter.close()
        super().tearDown()

    def step(self, until_branch: bool = False) -> None:
        self.panel.step(until_branch)
        self.workspace.job_manager.join_all_jobs()


class TestSimulationManagers(SimgrCase):
    def test_one_step_is_one_instruction(self):
        # the Qt panel's "Step actives" steps one instruction: main's push rbp
        assert self.panel.simgr_names() == ["sym"] and self.panel.current_index() == 0
        self.step()
        simgr = self.simgr
        assert [s.addr for s in simgr.active] == [self.main.addr + 1]
        rows = self.panel.stash_rows()
        assert [self.panel.row_text(r) for r in rows][:2] == ["active (1)", "stashed (0)"]
        self.panel.toggle_stash("active")
        rows = self.panel.stash_rows()
        assert self.panel.row_text(rows[1]) == f"<SimState @ {self.main.addr + 1:#x}>"
        # the path tree has the state's block
        picture = self.presenter.path_tree.picture
        assert [[line.text for line in box.lines] for box in picture.boxes] == [
            [f"{self.main.addr + 1:#x}", "Function: main+1"]
        ]

    def test_step_until_branch_and_keep_one_active(self):
        self.step(until_branch=True)
        simgr = self.simgr
        assert len(simgr.active) != 1
        if len(simgr.active) >= 2:
            self.panel.keep_one_active = True
            assert self.panel._filter_actives(self.simgr_container, events=False)
            assert len(simgr.active) == 1 and len(simgr.stashes["stashed"]) >= 1

    def test_filter_actives(self):
        simgr = self.simgr
        state = simgr.active[0]
        simgr.populate("active", [state.copy(), state.copy()])
        assert filter_actives(self.simgr_container, events=False)
        assert len(simgr.active) == 1 and len(simgr.stashed) == 2
        assert not filter_actives(self.simgr_container)

    def test_stash_clipboard(self):
        simgr = self.simgr
        assert create_stash(simgr, "mine") is None
        assert str(create_stash(simgr, "mine")).startswith("A stash with the name mine already exists")
        assert create_stash(simgr, "  ") == ""
        rows = self.panel.stash_rows()
        mine = next(r for r in rows if r.stash == "mine")
        menu = self.panel.row_menu(mine)
        assert captions(menu) == ["Copy states", "Cut states", "Delete stash", "Move states to here"]
        self.panel.copy_stash("active")
        menu = self.panel.row_menu(mine)
        paste = find_entry(menu, "Paste state")
        assert paste is not None
        paste.trigger()
        assert len(simgr.stashes["mine"]) == 1
        self.panel.toggle_stash("mine")
        state_row_ = next(r for r in self.panel.stash_rows() if r.stash == "mine" and not r.is_stash)
        menu = self.panel.row_menu(state_row_)
        assert captions(menu) == ["Copy state", "Cut state", "Delete state", "Paste state"]
        delete = find_entry(menu, "Delete state")
        assert delete is not None
        delete.trigger()
        assert len(simgr.stashes["mine"]) == 0
        assert captions(self.panel.row_menu(None)) == ["Create new stash"]

    def test_move_states(self):
        simgr = self.simgr
        create_stash(simgr, "moved")
        assert move_states(simgr, "moved", "not a lambda") is not None
        assert move_states(simgr, "moved", "lambda s: True") is None
        assert len(simgr.stashes["moved"]) == 1 and not simgr.active
        self.services.text = "lambda s: True"
        self.panel.move_to_stash("active")  # nothing in active to move: no error

    def test_avoid_and_find_lists(self):
        lists: ExploreAddresses = self.panel.avoids
        self.presenter.avoid_addr_in_exec(0x400700)
        self.presenter.find_addr_in_exec(0x400710)
        assert self.panel.avoid_addrs == [0x400700] and self.panel.find_addrs == [0x400710]
        assert not lists.add(0x400700)
        lists.set_checked(0x400700, False)
        assert not self.panel.avoid_addrs
        lists.import_text("400800\nzz\n0x400900")
        assert list(lists.entries) == [0x400700, 0x400800, 0x400900]
        self.presenter.remove_avoid_addr_in_exec(0x400800)
        self.presenter.remove_find_addr_in_exec(0x400710)
        assert list(lists.entries) == [0x400700, 0x400900] and not self.panel.find_addrs

    def test_select_state_and_path_tree_selection(self):
        state = self.simgr.active[0]
        self.panel.select_state(state)
        assert self.presenter.current_state.am_obj is state
        assert self.presenter.path_tree.selected is state.history
        self.presenter.select_states([state])
        assert self.panel.selected_states == [state] and "active" in self.panel.expanded


class TestPathTree(FauxwareCase):
    def test_branches(self):
        state = self.state_at_main("tree")
        simgr = self.project.factory.simulation_manager(state, hierarchy=angr.state_hierarchy.StateHierarchy())
        while len(simgr.active) < 2 and simgr.active:
            simgr.step()
        graph = path_tree_graph(simgr)
        assert graph is not None
        leaves = [n for n in graph.nodes() if graph.out_degree(n) == 0]
        assert len(leaves) == len(simgr.active) >= 2
        assert graph.number_of_edges() == len(leaves)
        label, function, addr = state_block_text(self.instance, simgr.active[0])
        assert label == f"{addr:#x}" and function.startswith("Function: ")
        assert path_tree_graph(None) is None


class TestInspector(FauxwareCase):
    def test_texts(self):
        state = self.state_at_main("insp")
        regs = register_rows(state)
        assert regs is not None and [name for name, _ in regs][:3] == ["rax", "rcx", "rdx"]
        assert ast_strings(0x41) == ("[Unknown]", "41", False)
        assert ast_strings(claripy.BVV(0x1234, 16)) == ("[2]", "1234", False)
        size, text, symbolic = ast_strings(claripy.BVS("x", 32))
        assert size == "[4]" and text.startswith("x_") and symbolic
        _size, text, symbolic = ast_strings(claripy.BVS("y", 32) + 1, display_size=False)
        assert symbolic and _size == ""
        rows = memory_rows(state, self.main.addr, rows=2, cols=4)
        assert [addr for addr, _ in rows] == [self.main.addr, self.main.addr + 4]
        assert ast_strings(rows[0][1][0], display_size=False)[1] == "55"  # push rbp
        state.solver.add(claripy.BVS("z", 8) == 3)
        # z == 3: a Bool that can be both (cardinality 2), depth 2, two leaves (z and 3)
        assert constraint_rows(state)[-1][1:] == ["2", "2", "2"]
        assert [name for _fd, name in fd_choices(state)][:3] == ["stdin", "stdout", "stderr"]
        stdout: Any = state.posix.get_fd(1)
        stdout.write_data(b"hi\x00")
        assert fd_text(state, 1) == "hi\\x00"
        assert temp_rows(None) == []


class TestSockets(unittest.TestCase):
    def test_model_and_conversion(self):
        sockets = SocketsSpec()
        assert sockets.add_socket("Family", "SOCK_STREAM", "1") is None
        sock = sockets.add_socket("AF_INET", "SOCK_STREAM", "7")
        assert sock is not None and sock.ident == "AF_INET, SOCK_STREAM, 7"
        sock.packets.append("aGk=")
        accepted = sockets.accept(sock)
        assert accepted.ident == "Accept, AF_INET, SOCK_STREAM, 7, 2"
        accepted.packets.append("eW8=")
        assert sockets.get_data() == {"AF_INET, SOCK_STREAM, 7": ["aGk="], accepted.ident: ["eW8="]}
        converted = sockets.convert()
        assert set(converted) == set(convert_socket_data(sockets.get_data()))
        assert len(converted) == 2 and bool(sockets)


if __name__ == "__main__":
    unittest.main()
