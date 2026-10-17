"""
The terminal disassembly view, driven through Textual's pilot on fauxware: the graph and the linear listing of main,
G and the jump history, the level menu, the context menu, find, operand clicks, marks, plugins, and snapshots of both
modes at 200x60.
"""

# pylint: disable=protected-access,missing-class-docstring,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from typing import TYPE_CHECKING, Any

from angrmanagement.config.color import Color
from angrmanagement.plugins import BasePlugin
from angrmanagement.present.marks import Mark
from angrmanagement.present.menus import Menu, walk_entries
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.screens import PromptScreen
from angrmanagement.tui.views.disassembly import DisassemblyTuiView
from angrmanagement.tui.widgets.menubar import MenuPopup

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
SIZE = (200, 60)
# an instruction of authenticate, which the tests never show in the graph
AUTH_INSN = 0x400668


def run_app(scenario: Callable[[AmApp, Pilot, Any], Awaitable[None]], tier: int = 2) -> None:
    """Open fauxware in an interactive headless app, show main's disassembly, and run ``scenario(app, pilot, view)``."""

    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=tier), interactive=True)
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await app.open_binary(FAUXWARE, function="main")
            await settle(pilot)
            view = app.view_widget("disassembly")
            assert isinstance(view, DisassemblyTuiView)
            await settle_graph(pilot, view.graph_widget)
            await scenario(app, pilot, view)

    asyncio.run(main())


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def settle_graph(pilot: Pilot, widget: Any, rounds: int = 100) -> None:
    """
    Pause until the graph has scrolled to the view its control asked for, then once more so that is painted. How many
    pauses that takes depends on the machine's load, so a fixed number is not enough.
    """
    for _ in range(rounds):
        if not widget.scroll_pending:
            break
        await pilot.pause()
    assert not widget.scroll_pending, "the graph never scrolled to the view its control asked for"
    await pilot.pause()


def canvas_text(view: Any) -> str:
    canvas = view.graph_widget.canvas
    return str(canvas) if canvas is not None else ""


def linear_text(view: Any) -> list[str]:
    return [line.text for _node, line in view.linear_viewer.lines()]


def screen_offset(view: Any, insn_addr: int, column: int = 3) -> tuple[int, int]:
    """Where, in the graph widget, the instruction's line starts (plus ``column``)."""
    widget = view.graph_widget
    x, y = view.flow_graph.position_of(insn_addr)
    sx, sy = widget.scroll_offset
    return x + widget.pad[0] - sx + column, y + widget.pad[1] - sy


def menu_texts(menu: Menu) -> list[str]:
    return [entry.text for _path, entry in walk_entries(menu)]


class TestGraph(unittest.TestCase):
    def test_main_in_graph_mode(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            presenter = view.presenter
            assert presenter.function.am_obj.name == "main"
            assert not presenter.is_linear
            text = canvas_text(view)
            assert "int main(long long a0, long long a1)" in text
            assert "0040071d  push    rbp" in text
            assert '00400734  mov     edi, 0x400915 "Username: "' in text
            # four blocks and their edges
            assert len(view.flow_graph.doc.blocks) == 4
            assert "▼" in text
            header = str(view.header.render())
            assert "main (40071d)" in header and "Graph Disassembly" in header and "Machine Code" in header
            # the entry block's top sits a quarter of the way down, as in the Qt view
            widget = view.graph_widget
            top = view.flow_graph.doc.layout[view.flow_graph.doc.entry][1] + widget.pad[1] - widget.scroll_offset.y
            assert top == widget.size.height // 4

        run_app(scenario)

    def test_initial_view_waits_until_the_graph_has_a_size(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            widget = view.graph_widget
            control = view.flow_graph
            # while the graph has no size (hidden here; not laid out yet while a binary loads), it is drawn again,
            # which asks for the entry block's view, and an instruction is selected, which redraws its block
            widget.display = False
            await settle(pilot)
            assert widget.size.width == 0 and widget.size.height == 0
            control.reload()
            view.presenter.infodock.select_instruction(0x400721)
            await settle(pilot)
            widget.display = True
            await settle_graph(pilot, widget)
            doc = control.doc
            top = doc.layout[doc.entry][1] + widget.pad[1] - widget.scroll_offset.y
            assert top == widget.size.height // 4

        run_app(scenario)

    def test_scrollbars_show_a_scroll_made_while_they_were_hidden(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            widget = view.graph_widget
            assert widget.show_horizontal_scrollbar and widget.show_vertical_scrollbar
            # a scroll before the scrollbars are laid out for a new virtual size, as when a graph first shows
            widget.show_horizontal_scrollbar = widget.show_vertical_scrollbar = False
            widget.scroll_to(widget.max_scroll_x // 2, widget.max_scroll_y // 2, animate=False, force=True)
            widget.refresh(layout=True)
            await settle(pilot)
            assert widget.show_horizontal_scrollbar and widget.show_vertical_scrollbar
            assert widget.horizontal_scrollbar.position == widget.scroll_x
            assert widget.vertical_scrollbar.position == widget.scroll_y

        run_app(scenario)

    def test_g_jumps_and_escape_goes_back(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            view.graph_widget.focus()
            await settle(pilot)
            await pilot.press("g")
            await settle(pilot)
            assert isinstance(app.screen, PromptScreen)
            await pilot.press(*"authenticate", "enter")
            await settle(pilot)
            presenter = view.presenter
            assert presenter.function.am_obj.name == "authenticate"
            assert "authenticate (400664)" in str(view.header.render())
            view.graph_widget.focus()
            await pilot.press("escape")
            await settle(pilot)
            assert presenter.function.am_obj.name == "main"
            await pilot.press("alt+right")
            await settle(pilot)
            assert presenter.function.am_obj.name == "authenticate"

        run_app(scenario)

    def test_click_selects_and_right_click_opens_the_menu(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            await pilot.click(view.graph_widget, offset=screen_offset(view, 0x40071E))
            await settle(pilot)
            assert view.presenter.infodock.selected_insns == {0x40071E}
            text = canvas_text(view)
            assert "0040071e  mov     rbp, rsp" in text
            # the selected line's cells were drawn again in the selection colour (only the block that changed is)
            x, y = view.flow_graph.position_of(0x40071E)
            assert "disasm_view_node_instruction_selected_background_color" in view.graph_widget.canvas.styles[y][x]
            x2, y2 = view.flow_graph.position_of(0x400721)
            assert "selected_background" not in view.graph_widget.canvas.styles[y2][x2]
            await pilot.click(view.graph_widget, offset=screen_offset(view, 0x400721), button=3)
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup)
            texts = [getattr(item, "text", "") for item in app.screen.menu.items()]
            for expected in [
                "Toggle selection",
                "XRefs...",
                "Comment",
                "Toggle bookmark",
                "Patch...",
                "Synchronize with",
            ]:
                assert expected in texts, expected
            assert view.presenter.infodock.selected_insns == {0x400721}
            await pilot.press("escape")
            await settle(pilot)
            assert not isinstance(app.screen, MenuPopup)

        run_app(scenario)

    def test_operand_click_and_double_click(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            block = view.flow_graph.doc.blocks[view.flow_graph.doc.entry]
            row = block.rows_of(0x400728)[0]
            column = block.lines[row].text.index("rsi")
            await pilot.click(view.graph_widget, offset=screen_offset(view, 0x400728, column))
            await settle(pilot)
            infodock = view.presenter.infodock
            assert (0x400728, 1) in infodock.selected_operands
            # every rsi operand of the function is highlighted with it
            highlighted = [
                span.style
                for line in block.lines
                for span in line.spans
                if span.text == "rsi" and "disasm_view_operand_highlight_color" in span.style
            ]
            assert highlighted
            # a double click on a call target follows it
            row = block.rows_of(0x400739)[0]
            column = block.lines[row].text.index("puts")
            await pilot.click(view.graph_widget, offset=screen_offset(view, 0x400739, column), times=2)
            await settle(pilot)
            assert view.presenter.function.am_obj.name == "puts"

        run_app(scenario)

    def test_levels_from_the_header_menu(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            header = view.header
            labels = [label for label, _ in header.items()[1]]
            text = str(header.render())
            x = text.index("Machine Code")
            await pilot.click(header, offset=(x + 1, 0))
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup)
            assert menu_texts(app.screen.menu) == ["Machine Code", "Lifter IR", "AIL"]
            await pilot.press("down", "enter")
            await settle(pilot, 8)
            presenter = view.presenter
            assert presenter.disassembly_level.name == "LifterIR"
            assert "Lifter IR" in str(header.render())
            assert "IMark" in canvas_text(view) or "PUT(" in canvas_text(view)
            assert labels[-1].startswith("Options")

        run_app(scenario)

    def test_find(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            view.graph_widget.focus()
            await pilot.press("ctrl+f")
            await settle(pilot)
            assert view.find_widget.display
            await pilot.press(*"call")
            await settle(pilot)
            presenter = view.presenter
            total = len(presenter.find_matches)
            assert total > 3
            assert view.find_state.status == f"1 of {total}"
            await pilot.press("enter")
            await settle(pilot)
            assert presenter.find_index == 1
            assert view.find_state.status == f"2 of {total}"
            current = presenter.find_matches[1][0]
            await pilot.press("escape")
            await settle(pilot)
            assert not view.find_widget.display
            assert presenter.infodock.selected_insns == {current}

        run_app(scenario)

    def test_breakpoint_mark(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            await pilot.click(view.graph_widget, offset=screen_offset(view, 0x400739))
            await settle(pilot)
            await pilot.press("f2")
            await settle(pilot)
            assert view.presenter.instance.breakpoint_mgr.get_breakpoints_at(0x400739)
            assert "break 00400739  call    puts" in canvas_text(view)
            # Enter on the selected instruction runs its mark: removing the breakpoint
            view.graph_widget.focus()
            await pilot.press("enter")
            await settle(pilot)
            assert not view.presenter.instance.breakpoint_mgr.get_breakpoints_at(0x400739)

        run_app(scenario)

    def test_levels_of_detail_keys(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            view.graph_widget.focus()
            await pilot.press("ctrl+minus", "ctrl+minus")
            await settle(pilot)
            assert view.flow_graph.detail == 2
            assert "0040071d" not in canvas_text(view)
            # the lowest level shows only the headers, on the zoomed-out background, as the zoomed-out Qt graph does
            doc = view.flow_graph.doc
            x, y = doc.layout[doc.entry]
            assert "disasm_view_node_background_color" in view.graph_widget.canvas.styles[y + 1][x + 1]
            await pilot.press("ctrl+minus")
            await settle(pilot)
            assert view.flow_graph.detail == 3
            doc = view.flow_graph.doc
            x, y = doc.layout[doc.entry]
            assert "disasm_view_node_zoomed_out_background_color" in view.graph_widget.canvas.styles[y + 1][x + 1]
            await pilot.press("ctrl+0")
            await settle(pilot)
            assert view.flow_graph.detail == 0
            assert "0040071d" in canvas_text(view)

        run_app(scenario)


class TestLinear(unittest.TestCase):
    def test_space_toggles_the_linear_listing(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            view.graph_widget.focus()
            await pilot.press("space")
            await settle(pilot)
            presenter = view.presenter
            assert presenter.is_linear
            assert view.linear_widget.display and not view.graph_widget.display
            lines = linear_text(view)
            assert any(line.split() == ["0040073e", "loc_0x40073e:"] for line in lines)
            assert any(line.split() == ["0040071d", "push", "rbp"] for line in lines)
            assert "Linear Disassembly" in str(view.header.render())
            first = view.linear_viewer.offset
            await pilot.press("pagedown")
            await settle(pilot)
            assert view.linear_viewer.offset != first or view.linear_viewer.start_line != 0
            await pilot.press("space")
            await settle(pilot)
            assert not presenter.is_linear

        run_app(scenario)

    def test_breakpoint_in_the_listing(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            view.presenter.display_linear_viewer()
            await settle(pilot)
            view.presenter.infodock.select_instruction(0x40071E)
            view.linear_widget.focus()
            await pilot.press("f2")
            await settle(pilot)
            assert view.presenter.instance.breakpoint_mgr.get_breakpoints_at(0x40071E)
            assert any(text.startswith("break 0040071e") for text in linear_text(view))

        run_app(scenario)

    def test_click_in_the_listing(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            view.presenter.display_linear_viewer()
            await settle(pilot)
            rows = [line.text for _node, line in view.linear_viewer.lines()]
            row = next(i for i, text in enumerate(rows) if text.startswith("0040071e"))
            await pilot.click(view.linear_widget, offset=(view.linear_widget.LEFT_MARGIN + 2, row))
            await settle(pilot)
            assert view.presenter.infodock.selected_insns == {0x40071E}

        run_app(scenario)


class TestViews(unittest.TestCase):
    def test_new_graph_view_and_linear_view_from_the_menu(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            view.presenter.jump_to(0x400739)
            await settle(pilot)
            await pilot.press("ctrl+n")
            await settle(pilot, 6)
            views = app.workspace.view_manager.views_by_category["disassembly"]
            assert len(views) == 2
            second = views[1]
            assert second.caption == "Disassembly-2"
            assert second.presenter.function.am_obj.name == "main"
            assert second.presenter.infodock.selected_insns == {0x400739}
            # not synchronized yet: a jump in the first view leaves the second alone
            kb: Any = app.workspace.main_instance.kb
            accepted = kb.functions["accepted"]
            view.presenter.jump_to(accepted.addr)
            await settle(pilot)
            assert second.presenter.function.am_obj.name == "main"
            # the second view's "Synchronize with" lists the first; checking it makes the cursors follow each other
            sync_menu = second.presenter.synchronize_with_menu()
            entry = next(e for e in sync_menu.items() if getattr(e, "text", "") == "Disassembly")
            entry.trigger()
            assert second.presenter.sync_state is view.presenter.sync_state
            auth = kb.functions["authenticate"]
            view.presenter.jump_to(auth.addr)
            await settle(pilot)
            assert second.presenter.function.am_obj is auth
            app.workspace.show_linear_disassembly_view()
            await settle(pilot)
            shown: Any = app.workspace.view_manager.current_view_in_category("disassembly")
            assert shown.presenter.is_linear

        run_app(scenario)


class NeutralPlugin(BasePlugin):
    """Only the neutral hooks: a colour and a mark on the instruction at 0x400721."""

    def insn_style(self, addr, selected, view):
        return Color(0xAB, 0xCD, 0xEF) if addr == 0x400721 else None

    def decorate_insn(self, addr, view):
        return [Mark("hot", "disasm.mark", "after")] if addr == 0x400721 else []

    def block_style(self, addr):
        return Color(0x12, 0x34, 0x56) if addr == 0x40071D else None

    def build_context_menu_insn(self, item):
        return [("Plugin entry", lambda: None)] if item is not None and item.addr in (0x400721, AUTH_INSN) else []

    def status_bar_text(self):
        return "neutral: on"


class QtStatusPlugin(BasePlugin):
    """A Qt-era plugin with status-bar widgets: building them in a terminal process, which has no QApplication, would
    abort it, so the terminal frontend must never call the hook."""

    widget_calls = 0

    def status_bar_permanent_widgets(self):
        type(self).widget_calls += 1

    def status_bar_text(self):
        return "qt status: on"


class TestPlugins(unittest.TestCase):
    def test_neutral_hooks_show_in_the_terminal(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            plugins = app.workspace.plugins
            plugins.active_plugins["neutral"] = NeutralPlugin(app.workspace)  # type: ignore[arg-type]
            try:
                view.presenter.reload()
                await settle(pilot)
                assert "00400721  sub     rsp, 0x40 hot" in canvas_text(view)
                doc = view.flow_graph.doc
                block = doc.blocks[doc.entry]
                line = block.lines[block.rows_of(0x400721)[0]]
                assert all("bg:#abcdef" in span.style for span in line.spans)
                x, y = doc.layout[doc.entry]
                assert "bg:#123456" in view.graph_widget.canvas.styles[y + 1][x + 1]
                app.status_bar.refresh_plugin_texts()
                assert app.status_bar.plugin_text == "neutral: on"
            finally:
                plugins.active_plugins.pop("neutral", None)

        run_app(scenario)

    def test_activating_a_plugin_with_qt_status_widgets(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            plugins = app.workspace.plugins
            QtStatusPlugin.widget_calls = 0
            plugins.activate_plugin("qtstatus", QtStatusPlugin)
            try:
                assert isinstance(plugins.get_plugin_instance(QtStatusPlugin), QtStatusPlugin)
                assert QtStatusPlugin.widget_calls == 0
                app.status_bar.refresh_plugin_texts()
                assert app.status_bar.plugin_text == "qt status: on"
            finally:
                plugins.deactivate_plugin(QtStatusPlugin)
            assert plugins.get_plugin_instance(QtStatusPlugin) is None
            assert QtStatusPlugin.widget_calls == 0

        run_app(scenario)

    def test_plugin_insn_entries_in_both_context_menus(self):
        async def scenario(app: AmApp, pilot: Pilot, view: Any) -> None:
            plugins = app.workspace.plugins
            plugins.active_plugins["neutral"] = NeutralPlugin(app.workspace)  # type: ignore[arg-type]
            try:
                view.presenter.reload()
                await settle(pilot)
                # a right click on the instruction
                await pilot.click(view.graph_widget, offset=screen_offset(view, 0x400721), button=3)
                await settle(pilot)
                assert isinstance(app.screen, MenuPopup)
                assert "Plugin entry" in menu_texts(app.screen.menu)
                await pilot.press("escape")
                await settle(pilot)
                # the keyboard menu of the selected instruction (Shift+F10) asks the plugins for the same entries
                view.graph_widget.focus()
                await pilot.press("shift+f10")
                await settle(pilot)
                assert isinstance(app.screen, MenuPopup)
                assert "Plugin entry" in menu_texts(app.screen.menu)
                await pilot.press("escape")
                await settle(pilot)
                # and so does the linear listing's
                view.display_linear_viewer()
                await settle(pilot)
                menu = view.presenter.context_menu()
                assert menu is not None and "Plugin entry" in menu_texts(menu)
                # an instruction of another function, still selected after the listing has scrolled its block away
                linear = view.linear_viewer
                linear.navigate_to_addr(AUTH_INSN)
                view.infodock.select_instruction(AUTH_INSN, unique=True, use_animation=False)
                await settle(pilot)
                assert linear.insn_node(AUTH_INSN) is not None
                menu = view.presenter.context_menu()
                assert menu is not None and "Plugin entry" in menu_texts(menu)
                linear.navigate_to_addr(0x400915)  # .rodata, far from authenticate
                await settle(pilot)
                assert linear.insn_node(AUTH_INSN) is None
                assert view.presenter.instruction_at(AUTH_INSN).addr == AUTH_INSN
                menu = view.presenter.context_menu()
                assert menu is not None and "Plugin entry" in menu_texts(menu)
            finally:
                plugins.active_plugins.pop("neutral", None)

        run_app(scenario)


#
# Snapshots (pytest-textual-snapshot)
#


async def _open_main(pilot: Pilot, linear: bool) -> None:
    app = pilot.app
    assert isinstance(app, AmApp)
    await app.open_binary(FAUXWARE, function="main")
    await settle(pilot)
    view = app.view_widget("disassembly")
    assert isinstance(view, DisassemblyTuiView)
    await settle_graph(pilot, view.graph_widget)
    if linear:
        view.display_linear_viewer()
        await settle(pilot, 6)
        return
    # the entry block's top a quarter of the way down, or the capture would not match the stored one
    widget = view.graph_widget
    doc = view.flow_graph.doc
    assert doc is not None
    assert doc.layout[doc.entry][1] + widget.pad[1] - widget.scroll_offset.y == widget.size.height // 4


def test_snapshot_graph(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=SIZE, run_before=lambda pilot: _open_main(pilot, False))


def test_snapshot_linear(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=SIZE, run_before=lambda pilot: _open_main(pilot, True))


if __name__ == "__main__":
    unittest.main()
