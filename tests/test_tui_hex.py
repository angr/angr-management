"""
The terminal hex view, driven through Textual's pilot on fauxware: the rows, the cursor keys and the selection, typing
a patch, the ASCII column, G, find, the context menu and the header's menus, the mouse, and a snapshot at 200x60.
"""

# pylint: disable=protected-access,missing-class-docstring,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from typing import TYPE_CHECKING, Any

from textual import events

from angrmanagement.present.hexdump import HexDataSource, PatchHighlightRegion
from angrmanagement.present.menus import Menu, walk_entries
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.screens import PromptScreen
from angrmanagement.tui.views.hex import HexLayout, HexTuiView, HexWidget
from angrmanagement.tui.widgets.menubar import MenuPopup

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
SIZE = (200, 60)
#: fauxware's lowest address, where the hex view starts
BASE = 0x400000


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def open_hex(pilot: Pilot) -> HexTuiView:
    app: Any = pilot.app
    await pilot.pause()
    await app.open_binary(FAUXWARE, function="main")
    await settle(pilot)
    assert await app.run_action("show_view('hex')")
    await settle(pilot)
    view = app.view_widget("hex")
    assert isinstance(view, HexTuiView)
    view.hex.focus()
    await settle(pilot)
    return view


def run_app(scenario: Callable[[AmApp, Pilot, HexTuiView], Awaitable[None]], tier: int = 2) -> None:
    """Open fauxware in an interactive headless app, show the hex view, and run ``scenario(app, pilot, view)``."""

    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=tier), interactive=True)
        async with app.run_test(size=SIZE) as pilot:
            view = await open_hex(pilot)
            await scenario(app, pilot, view)

    asyncio.run(main())


def row_text(view: HexTuiView, row: int) -> str:
    strip = view.hex.row_strip(row, view.hex.size.width - 1)
    return "".join(segment.text for segment in strip).rstrip()


def cell_style(view: HexTuiView, row: int, x: int) -> Any:
    strip = view.hex.row_strip(row, view.hex.size.width - 1)
    return list(strip.crop(x, x + 1))[0].style


def menu_texts(menu: Menu) -> list[str]:
    return [entry.text for _path, entry in walk_entries(menu)]


class TestRows(unittest.TestCase):
    def test_rows_as_the_qt_view_lays_them_out(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            # the Qt view's first two rows (screenshots/qt-baseline/hex.txt), spaced as Qt spaces them
            assert row_text(view, 0) == (
                " 00400000    7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00     .ELF............"
            )
            assert row_text(view, 1).startswith(" 00400010    02 00 3e 00 01 00 00 00  80 05 40 00")
            assert "Address: 00400000" in str(view.header.render())
            assert "Loader ▾" in str(view.header.render()) and "Options ▾" in str(view.header.render())
            # one row per line, and the one Qt shows in part below them
            assert view.presenter.grid.display_num_rows == view.hex.size.height + 1
            layout = HexLayout()
            assert (layout.bytes_x, layout.byte_columns[8], layout.ascii_x) == (13, 38, 66)

        run_app(scenario)

    def test_regions_tint_the_bytes(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            main = app.workspace.main_instance.kb.functions["main"]
            view.presenter.jump_to(main.addr)
            await settle(pilot)
            grid = view.presenter.grid
            row, col = grid.addr_to_row_col(main.addr)
            layout = view.hex.layout_cells
            tinted = cell_style(view, row, layout.byte_columns[col])
            view.presenter.set_smart_highlighting_enabled(False)
            await settle(pilot)
            plain = cell_style(view, row, layout.byte_columns[col])
            assert tinted.bgcolor != plain.bgcolor

        run_app(scenario)


class TestKeys(unittest.TestCase):
    def test_arrows_and_shift_select(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            grid = view.presenter.grid
            await pilot.press("right", "right", "down")
            await settle(pilot)
            assert grid.cursor == BASE + 0x12
            await pilot.press("shift+right", "shift+right")
            await settle(pilot)
            assert grid.get_selection() == (BASE + 0x12, BASE + 0x14)
            assert "Address: [00400012, 00400014], 3 bytes selected" in str(view.header.render())
            await pilot.press("end")
            await settle(pilot)
            assert grid.cursor == BASE + 0x1F and grid.get_selection() is None
            await pilot.press("pagedown")
            await settle(pilot)
            assert grid.cursor == BASE + 0x1F + 16 * view.hex.size.height

        run_app(scenario)

    def test_typing_patches_and_ctrl_space_switches_column(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            grid = view.presenter.grid
            project = app.workspace.main_instance.project.am_obj
            await pilot.press("down", "9", "0")
            await settle(pilot)
            assert grid.read(BASE + 0x10) == 0x90 and grid.cursor == BASE + 0x11
            assert [bytes(p.new_bytes) for p in project.kb.patches.values()] == [b"\x90"]
            assert any(isinstance(r, PatchHighlightRegion) for r in grid.get_highlight_regions_at_addr(BASE + 0x10))
            await pilot.press("ctrl+space")
            await settle(pilot)
            assert grid.ascii_column_active
            # in the ASCII column G is a character, not the jump
            await pilot.press("g")
            await settle(pilot)
            assert grid.read(BASE + 0x11) == ord("g") and not isinstance(app.screen, PromptScreen)
            assert row_text(view, 1).endswith(".g>.......@.....")

        run_app(scenario)

    def test_g_jumps_to_a_function(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            await pilot.press("g")
            await settle(pilot)
            assert isinstance(app.screen, PromptScreen)
            await pilot.press(*"main", "enter")
            await settle(pilot)
            main = app.workspace.main_instance.kb.functions["main"]
            assert view.presenter.grid.cursor == main.addr
            assert f"Address: {main.addr:08x}" in str(view.header.render())

        run_app(scenario)

    def test_find(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            await pilot.press("ctrl+f")
            await settle(pilot)
            assert view.find_widget.display
            await pilot.press(*"4c 46")
            await settle(pilot)
            assert view.presenter.grid.cursor == BASE + 2
            assert view.find_widget.status_label.render().plain.startswith("1 of ")
            await pilot.press("escape")
            await settle(pilot)
            assert not view.find_widget.display and app.focused is view.hex

        run_app(scenario)

    def test_shift_f10_opens_the_context_menu(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            await pilot.press("shift+right", "shift+right")
            await pilot.press("shift+f10")
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup)
            texts = menu_texts(app.screen.menu)
            assert texts[0] == "Copy 3 bytes"
            # the disassembly view is the other view to synchronize with
            assert "Break on Execute" in texts and texts[-1] == "Disassembly"
            await pilot.press("enter")
            await settle(pilot)
            assert view.presenter._clipboard == bytearray(b"\x7fEL")

        run_app(scenario)


class TestMouse(unittest.TestCase):
    def test_click_drag_and_right_click(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            grid = view.presenter.grid
            layout = view.hex.layout_cells
            await pilot.click(view.hex, offset=(layout.byte_columns[4], 2))
            await settle(pilot)
            assert grid.cursor == BASE + 0x24 and not grid.ascii_column_active
            await pilot.click(view.hex, offset=(layout.ascii_x + 6, 2), shift=True)
            await settle(pilot)
            assert grid.get_selection() == (BASE + 0x24, BASE + 0x26) and grid.ascii_column_active
            await pilot.click(view.hex, offset=(layout.byte_columns[0], 3), button=3)
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup)
            assert grid.cursor == BASE + 0x30 and grid.get_selection() is None

        run_app(scenario)

    def test_wheel_and_scroll_bar(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            grid = view.presenter.grid
            # the pilot has no wheel; its own helper posts the event where a wheel turn would
            await pilot._post_mouse_events([events.MouseScrollDown], view.hex, offset=(10, 5))
            await settle(pilot)
            assert grid.display_start_addr == BASE + 0x30
            await pilot.click(view.hex, offset=(view.hex.size.width - 1, view.hex.size.height - 1))
            await settle(pilot)
            assert grid.display_start_addr > BASE + 0x1000

        run_app(scenario)


class TestHeader(unittest.TestCase):
    def test_data_source_and_options_menus(self):
        async def scenario(app: AmApp, pilot: Pilot, view: HexTuiView) -> None:
            text = str(view.header.render())
            await pilot.click(view.header, offset=(text.index("Loader") + 1, 0))
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup)
            assert menu_texts(app.screen.menu) == ["Loader", "Debugger"]
            await pilot.press("down", "enter")
            await settle(pilot)
            presenter = view.presenter
            assert presenter.data_source == HexDataSource.Debugger
            # no debugger: every byte is unknown, and the rows shown stay where they were
            assert row_text(view, 0).startswith(" 00400000    ?? ?? ??")
            assert "Debugger ▾" in str(view.header.render())
            text = str(view.header.render())
            await pilot.click(view.header, offset=(text.index("Options") + 1, 0))
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup)
            assert menu_texts(app.screen.menu) == ["Smart highlighting"]
            await pilot.press("enter")
            await settle(pilot)
            assert not presenter.smart_highlighting_enabled

        run_app(scenario)


#
# Snapshots (pytest-textual-snapshot)
#


async def _open_hex_for_snapshot(pilot: Pilot) -> None:
    HexWidget.cursor_blink = False
    await open_hex(pilot)


def test_snapshot_hex(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    try:
        assert snap_compare(app, terminal_size=SIZE, run_before=_open_hex_for_snapshot)
    finally:
        HexWidget.cursor_blink = True


if __name__ == "__main__":
    unittest.main()
