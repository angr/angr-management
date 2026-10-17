"""
The proximity view, without a toolkit and in the terminal, on fauxware's main: the blocks' text as the Qt view shows
it (screenshots/qt-baseline/proximity.txt), the call order, expanding and collapsing a call, and Enter on a block.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from typing import TYPE_CHECKING, Any

from angr.analyses.proximity_graph import CallProxiNode, FunctionProxiNode

from angrmanagement.present.proximity import ProximityPresenter, argument_text, proximity_line
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.views.graphs import ProximityTuiView

if TYPE_CHECKING:
    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
SIZE = (200, 60)
#: The blocks of main's proximity graph in Qt (screenshots/qt-baseline/proximity.png), top to bottom.
QT_BLOCKS = [
    "Function main",
    'puts("Username: ")',
    "read(0, _, 8)",
    "read(0, _, 1)",
    'puts("Password: ")',
    "read(0, _, 8)",
    "read(0, _, 1)",
    "authenticate(_, _)",
    "rejected()",
    "accepted()",
]


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def open_proximity(pilot: Pilot) -> ProximityTuiView:
    app: Any = pilot.app
    await pilot.pause()
    await app.open_binary(FAUXWARE, function="main")
    await settle(pilot)
    await app.run_action("show_view('disassembly')")
    await settle(pilot)
    await pilot.press("ctrl+b")
    for _ in range(200):
        view = app.view_widget("proximity")
        if view is not None and view.presenter.graph.picture.boxes:
            break
        await pilot.pause()
    await settle(pilot)
    view = app.view_widget("proximity")
    assert isinstance(view, ProximityTuiView)
    return view


def block_texts(presenter: ProximityPresenter) -> list[str]:
    picture = presenter.graph.picture
    ordered = sorted(picture.layout.items(), key=lambda item: (item[1][1], item[1][0]))
    return [box.lines[0].text for box, _pos in ordered]


def run_app(scenario) -> None:
    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
        async with app.run_test(size=SIZE) as pilot:
            view = await open_proximity(pilot)
            await scenario(app, pilot, view)

    asyncio.run(main())


class TestProximity(unittest.TestCase):
    def test_blocks_are_the_qt_blocks(self):
        async def scenario(app: AmApp, pilot: Pilot, view: ProximityTuiView) -> None:
            presenter: Any = view.presenter
            assert presenter.function is not None and presenter.function.name == "main"
            assert block_texts(presenter) == QT_BLOCKS
            canvas = str(view.graph.canvas)
            assert 'puts("Username: ")' in canvas and "▼" in canvas
            # the colours: the function red, a call's name and a string argument their own
            line = next(
                proximity_line(app.workspace.main_instance, n)
                for n in presenter.proximity_graph.nodes()
                if isinstance(n, CallProxiNode) and n.args
            )
            styles = {span.style for span in line.spans}
            assert "proximity_string_node_text_color" in styles or "proximity_integer_node_text_color" in styles

        run_app(scenario)

    def test_expand_collapse_and_enter(self):
        async def scenario(app: AmApp, pilot: Pilot, view: ProximityTuiView) -> None:
            presenter: Any = view.presenter
            graph = presenter.graph
            auth = next(
                n
                for n in presenter.proximity_graph.nodes()
                if isinstance(n, CallProxiNode)
                and proximity_line(app.workspace.main_instance, n).text.startswith("auth")
            )
            view.graph.select(auth)
            view.graph.focus()
            await pilot.press("plus")
            await settle(pilot)
            texts = block_texts(presenter)
            assert "Function authenticate" in texts and len(texts) > len(QT_BLOCKS)
            func_node = next(
                n
                for n in presenter.proximity_graph.nodes()
                if isinstance(n, FunctionProxiNode) and n.func.addr != presenter.function.addr
            )
            view.graph.select(func_node)
            await pilot.press("minus")
            await settle(pilot)
            assert block_texts(presenter) == QT_BLOCKS
            # Enter on a call shows where main makes it
            first_call: Any = next(n for n in graph.nodes() if isinstance(n, CallProxiNode))
            view.graph.select(first_call)
            await pilot.press("enter")
            await settle(pilot)
            disasm: Any = app.view_widget("disassembly")
            assert disasm.presenter.jump_history.current == next(iter(first_call.ref_at))

        run_app(scenario)

    def test_argument_text(self):
        assert argument_text(object()) == (object, "Unknown")


async def _proximity_for_snapshot(pilot: Pilot) -> None:
    view = await open_proximity(pilot)
    # raising the view hides the disassembly graph that had the focus, and where Textual moves it depends on timing
    view.focus_view()
    await settle(pilot)


def test_snapshot_proximity(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=SIZE, run_before=_proximity_for_snapshot)


if __name__ == "__main__":
    unittest.main()
