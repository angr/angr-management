"""
The terminal symbolic execution views, driven through Textual's pilot on fauxware: a state at main made with the new
state screen, one step, the stash tree, the path tree and the inspector, the states view's menu, the panel's lists and
menus, the new state screen's form and sub-screens, and a snapshot at 200x60.

What Qt shows after one step from a state at main (phase4/probe/qt_symexec_step.py, a Qt run of the same steps):
the stash tree's seven stashes with ``active (1)`` holding ``<SimState @ 0x40071e>``, one row in the states table,
and one path tree block, ``0x40071e`` / ``Function: main+1``.
"""

# pylint: disable=protected-access,missing-class-docstring,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from typing import TYPE_CHECKING, Any

import angr
from textual.widgets import Button, Input, Select, Static

from angrmanagement.present.symexec import gui_data, open_new_state
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.new_state import NewStateScreen, PairsScreen
from angrmanagement.tui.views.symexec import SymexecTuiView
from angrmanagement.tui.widgets.menubar import MenuPopup
from angrmanagement.utils import namegen

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
SIZE = (200, 60)
MAIN = 0x40071D
#: The Qt stash tree after one step, top-level rows.
QT_STASHES = [
    "active (1)",
    "stashed (0)",
    "pruned (0)",
    "unsat (0)",
    "errored (0)",
    "deadended (0)",
    "unconstrained (0)",
]


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def wait_for(pilot: Pilot, condition: Callable[[], bool], rounds: int = 200) -> None:
    for _ in range(rounds):
        if condition():
            await pilot.pause()
            return
        await pilot.pause()
    raise AssertionError("the condition never held")


async def state_at_main(pilot: Pilot) -> SymexecTuiView:
    """Make a state at main with the new state screen and a simulation manager of it, as Execute symbolically does."""
    app: Any = pilot.app
    open_new_state(app.workspace, app.workspace.main_instance, MAIN, create_simgr=True)
    await wait_for(pilot, lambda: isinstance(app.screen, NewStateScreen))
    app.screen.query_one("#ok", Button).press()
    await wait_for(pilot, lambda: app.view_widget("symexec") is not None)
    view = app.view_widget("symexec")
    assert isinstance(view, SymexecTuiView)
    await settle(pilot)
    return view


async def step_once(pilot: Pilot, view: SymexecTuiView) -> None:
    """Press Step actives and wait until the job has stepped main's first instruction and the view shows it."""
    simgr: Any = view.presenter.current_simgr.am_obj
    view.query_one("#step", Button).press()
    await wait_for(pilot, lambda: [s.addr for s in simgr.active] == [MAIN + 1])
    await wait_for(pilot, lambda: not pilot.app.workspace.job_manager.jobs)  # type: ignore[attr-defined]
    await settle(pilot)


def run_app(scenario: Callable[[AmApp, Pilot], Awaitable[None]], tier: int = 2) -> None:
    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=tier), interactive=True)
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await app.open_binary(FAUXWARE, function="main")
            await settle(pilot)
            await scenario(app, pilot)

    asyncio.run(main())


def tree_labels(view: SymexecTuiView) -> list[str]:
    return [str(node.label) for node in view.stash_tree._all_nodes()]


class TestStep(unittest.TestCase):
    def test_a_state_at_main_stepped_once_shows_what_qt_shows(self):
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view = await state_at_main(pilot)
            instance = app.workspace.main_instance
            states = list(instance.states)
            assert len(states) == 1 and states[0].addr == MAIN
            name = gui_data(states[0]).name
            assert str(view.query_one("#simgr", Select).value) == "0"
            await step_once(pilot, view)
            assert tree_labels(view) == QT_STASHES
            view.presenter.simgrs.toggle_stash("active")
            await settle(pilot)
            assert tree_labels(view)[:2] == ["active (1)", "<SimState @ 0x40071e>"]
            picture = view.presenter.path_tree.picture
            assert [[line.text for line in box.lines] for box in picture.boxes] == [["0x40071e", "Function: main+1"]]
            assert "0x40071e" in str(view.graph.canvas)
            # the states view: one row, as in Qt
            assert await app.run_action("show_view('states')")
            await settle(pilot)
            states_view: Any = app.view_widget("states")
            model = states_view.presenter.model
            assert model.row_count == 1
            assert [model.cell(0, col).text for col in range(5)] == [name, "40071d", "No", name, "symbolic"]

        run_app(scenario)

    def test_selecting_a_state_fills_the_inspector(self):
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view = await state_at_main(pilot)
            await step_once(pilot, view)
            simgr: Any = view.presenter.current_simgr.am_obj
            view.presenter.simgrs.toggle_stash("active")
            await settle(pilot)
            tree = view.stash_tree
            node = next(n for n in tree._all_nodes() if str(n.label).startswith("<SimState"))
            tree.move_cursor(node)
            tree.focus()
            await pilot.press("enter")
            await settle(pilot)
            assert view.presenter.current_state.am_obj is simgr.active[0]
            registers = str(view.query_one("#registers", Static).render())
            assert "rip" in registers and "40071e" in registers
            memory = view.inspector
            view.query_one("#memory-address", Input).value = f"{MAIN:x}"
            await settle(pilot)
            memory.query_one("#memory-address", Input).focus()
            await pilot.press("enter")
            await settle(pilot)
            assert f"{MAIN:08x} 55 48 89 e5" in str(view.query_one("#memory", Static).render())
            # the selected block in the path tree
            assert view.presenter.path_tree.selected is simgr.active[0].history

        run_app(scenario)

    def test_stash_menu_copies_and_pastes(self):
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view = await state_at_main(pilot)
            tree = view.stash_tree
            tree.focus()
            first = next(tree._all_nodes())
            tree.move_cursor(first)
            await pilot.press("shift+f10")
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup)
            texts = [getattr(item, "text", "") for item in app.screen.menu.items()]
            assert texts == ["Copy states", "Cut states", "Delete stash"]
            await pilot.press("enter")
            await settle(pilot)
            stashed = next(n for n in tree._all_nodes() if str(n.label).startswith("stashed"))
            tree.move_cursor(stashed)
            await pilot.press("shift+f10")
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup)
            texts = [getattr(item, "text", "") for item in app.screen.menu.items()]
            assert "Paste state" in texts and "Move states to here" in texts
            await pilot.press(*["down"] * texts.index("Paste state"), "enter")
            await settle(pilot)
            assert "stashed (1)" in tree_labels(view)

        run_app(scenario)

    def test_avoid_and_find_from_the_disassembly(self):
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view = await state_at_main(pilot)
            disasm: Any = app.view_widget("disassembly")
            disasm.presenter.avoid_addr_in_exec(0x400734)
            disasm.presenter.find_addr_in_exec(0x40073E)
            await settle(pilot)
            assert view.presenter.simgrs.avoid_addrs == [0x400734]
            assert view.presenter.simgrs.find_addrs == [0x40073E]
            marks = disasm.presenter.marks_at(0x400734)
            assert any(mark.text == "avoid" for mark in marks)
            assert str(view.avoids.address_tree.root.children[0].label) == "[x] 0x400734"

        run_app(scenario)


class TestNewStateScreen(unittest.TestCase):
    def test_form(self):
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            open_new_state(app.workspace, app.workspace.main_instance, MAIN)
            await wait_for(pilot, lambda: isinstance(app.screen, NewStateScreen))
            screen = app.screen
            assert isinstance(screen, NewStateScreen)
            ok = screen.query_one("#ok", Button)
            assert not ok.disabled
            screen.query_one("#address", Input).value = "zz"
            await settle(pilot)
            assert ok.disabled
            screen.query_one("#address", Input).value = "main"
            await settle(pilot)
            assert not ok.disabled
            # the args and environment are an entry state's
            assert not screen.query_one("#args-row").display
            screen.query_one("#template", Select).value = "entry"
            await settle(pilot)
            assert screen.query_one("#args-row").display and not screen.query_one("#base-row").display
            # a mode resets the options to its own; the filter narrows the tree
            screen.query_one("#mode", Select).value = "fastpath"
            await settle(pilot)
            assert screen.spec.options == angr.sim_options.modes["fastpath"]
            screen.query_one("#filter", Input).value = "ZERO_FILL"
            await settle(pilot)
            leaves = [label for node, label in screen._option_nodes]
            assert leaves and all("ZERO_FILL" in label for label in leaves)
            screen.toggle_option("ZERO_FILL_UNCONSTRAINED_MEMORY")
            assert "ZERO_FILL_UNCONSTRAINED_MEMORY" in screen.spec.options
            # the environment's table
            screen.query_one("#env", Button).press()
            await wait_for(pilot, lambda: isinstance(app.screen, PairsScreen))
            pairs = app.screen
            pairs.query_one("#add", Button).press()
            await settle(pilot)
            inputs = list(pairs.query(Input))
            assert [i.value for i in inputs] == ["change me", ""]
            inputs[0].value = "HOME"
            inputs[1].value = "/tmp"
            pairs.query_one("#ok", Button).press()
            await settle(pilot)
            assert screen.spec.env == [("HOME", "/tmp")]
            assert str(screen.query_one("#env", Button).label) == "1 Items"
            ok.press()
            await settle(pilot)
            # an entry state starts at the entry point, whatever the address says
            states = list(app.workspace.main_instance.states)
            assert len(states) == 1 and states[0].addr == app.workspace.main_instance.project.entry
            assert gui_data(states[0]).is_base and states[0].mode == "fastpath"

        run_app(scenario)

    def test_cancel_makes_nothing(self):
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            open_new_state(app.workspace, app.workspace.main_instance, MAIN, create_simgr=True)
            await wait_for(pilot, lambda: isinstance(app.screen, NewStateScreen))
            await pilot.press("escape")
            await settle(pilot)
            assert not list(app.workspace.main_instance.states)
            assert app.view_widget("symexec") is None

        run_app(scenario)


#
# Snapshots (pytest-textual-snapshot)
#


async def _stepped_for_snapshot(pilot: Pilot) -> None:
    await settle(pilot)
    app: Any = pilot.app
    await app.open_binary(FAUXWARE, function="main")
    await settle(pilot)
    view = await state_at_main(pilot)
    await step_once(pilot, view)
    view.presenter.simgrs.toggle_stash("active")
    await settle(pilot)


def test_snapshot_symexec(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=True)

    async def run_before(pilot: Pilot) -> None:
        # a fixed name: the new state screen picks a random one
        original = namegen.NameGenerator.random_name
        namegen.NameGenerator.random_name = staticmethod(lambda: "snapshot state")  # type: ignore[method-assign]
        try:
            await _stepped_for_snapshot(pilot)
        finally:
            namegen.NameGenerator.random_name = original  # type: ignore[method-assign]

    assert snap_compare(app, terminal_size=SIZE, run_before=run_before)


if __name__ == "__main__":
    unittest.main()
