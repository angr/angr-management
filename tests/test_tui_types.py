"""
The terminal types view, driven through Textual's pilot on fauxware: adding types through the type editor with its
live parse status, the lines with member offsets, editing a member, the buttons, and a snapshot at 200x60.
"""

# pylint: disable=protected-access,missing-class-docstring,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from typing import TYPE_CHECKING, Any

from textual.widgets import Input, Label, TextArea

from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.views.types import TypeEditorScreen, TypesTuiView

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
SIZE = (200, 60)
PAIR = "struct pair { int a; long long b; };"


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def wait_for_screen(pilot: Pilot, screen_type: type, rounds: int = 100) -> Any:
    for _ in range(rounds):
        if isinstance(pilot.app.screen, screen_type):
            await pilot.pause()
            return pilot.app.screen
        await pilot.pause()
    raise AssertionError(f"no {screen_type.__name__}")


async def open_types(pilot: Pilot) -> TypesTuiView:
    app: Any = pilot.app
    await pilot.pause()
    await app.open_binary(FAUXWARE, function="main")
    await settle(pilot)
    assert await app.run_action("show_view('types')")
    await settle(pilot)
    view = app.view_widget("types")
    assert isinstance(view, TypesTuiView)
    view.types_widget.focus()
    await settle(pilot)
    return view


async def add_pair(pilot: Pilot) -> None:
    await pilot.press("a")
    screen = await wait_for_screen(pilot, TypeEditorScreen)
    screen.query_one("#answer", TextArea).text = PAIR
    await settle(pilot)
    await pilot.press("ctrl+s")
    await settle(pilot)


def run_app(scenario: Callable[[AmApp, Pilot, TypesTuiView], Awaitable[None]], tier: int = 2) -> None:
    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=tier), interactive=True)
        async with app.run_test(size=SIZE) as pilot:
            view = await open_types(pilot)
            await scenario(app, pilot, view)

    asyncio.run(main())


class TestTypes(unittest.TestCase):
    def test_add_types_with_the_editor(self):
        async def scenario(app: AmApp, pilot: Pilot, view: TypesTuiView) -> None:
            assert str(view.caption_label.render()) == "Persistent (global) variable types"
            assert view.types_widget.lines == []
            await pilot.press("a")
            screen = await wait_for_screen(pilot, TypeEditorScreen)
            area = screen.query_one("#answer", TextArea)
            area.text = "struct pair { int a;"
            await settle(pilot)
            status = str(screen.query_one("#status", Label).render())
            assert status.startswith("Invalid:") and screen.query_one("#ok").disabled
            area.text = PAIR
            await settle(pilot)
            assert str(screen.query_one("#status", Label).render()) == "Valid: struct pair"
            await pilot.press("ctrl+s")
            await settle(pilot)
            assert not isinstance(app.screen, TypeEditorScreen)
            texts = [text for _t, _r, text in view.types_widget.lines]
            assert texts[0] == "00000010  typedef struct pair {"
            assert texts[1].startswith("00000000  ") and texts[1].endswith("int a;")
            assert texts[2].startswith("00000008  ") and texts[2].endswith("long long b;")
            kb = app.workspace.main_instance.kb
            assert {"pair", "struct pair"} <= set(kb.types.iter_own_keys())

        run_app(scenario)

    def test_enter_edits_a_member(self):
        async def scenario(app: AmApp, pilot: Pilot, view: TypesTuiView) -> None:
            await add_pair(pilot)
            await pilot.press("down", "down", "enter")
            screen = await wait_for_screen(pilot, TypeEditorScreen)
            answer = screen.query_one("#answer", Input)
            assert answer.value == "long long b"
            answer.value = "short c;"
            await settle(pilot)
            await pilot.press("enter")
            await settle(pilot)
            pair: Any = app.workspace.main_instance.kb.types["pair"]
            assert list(pair.type.fields) == ["a", "c"]
            assert view.types_widget.lines[2][2].endswith("short c;")

        run_app(scenario)

    def test_escape_cancels_and_the_buttons(self):
        async def scenario(app: AmApp, pilot: Pilot, view: TypesTuiView) -> None:
            await pilot.click("#add-types")
            screen = await wait_for_screen(pilot, TypeEditorScreen)
            screen.query_one("#answer", TextArea).text = PAIR
            await pilot.press("escape")
            await settle(pilot)
            assert view.types_widget.lines == []
            main = app.workspace.main_instance.kb.functions["main"]
            view.presenter.function = main
            await settle(pilot)
            assert str(view.caption_label.render()) == f"Temporary (local) variable types for function {main.addr:#x}"
            await pilot.click("#persistent-types")
            await settle(pilot)
            assert view.presenter.function.am_none

        run_app(scenario)


#
# Snapshots (pytest-textual-snapshot)
#


async def _open_types_for_snapshot(pilot: Pilot) -> None:
    await open_types(pilot)
    await add_pair(pilot)


def test_snapshot_types(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=SIZE, run_before=_open_types_for_snapshot)


if __name__ == "__main__":
    unittest.main()
