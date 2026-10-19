"""
The terminal tiers, on fauxware from angrmanagement/binaries: Help > Terminal capabilities and the AM_TUI_TIER
override; tier 0's alternative chords, bound and shown in the menus; tier 1's angr:// links (OSC 8) on addresses in
the disassembly and the pseudocode; tier 3's pictures (the minimap, the feature map, the trace map, the export
preview and picture mode) and the braille or cell drawings below it; kitty's notification (OSC 99) when a long job
ends while the terminal is not focused; and the tabs saved on exit and opened again with the next binary.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from scripted_trace import ScriptedTrace
from textual.command import CommandPalette
from tui_pilot import settle, wait_for  # pylint: disable=import-error

from angrmanagement.config import Conf
from angrmanagement.config.color import Color
from angrmanagement.logic import GlobalInfo
from angrmanagement.plugins.base_plugin import qt_frontend
from angrmanagement.present.base import container
from angrmanagement.present.keymap import KITTY_KEYBOARD_TIER, Chord, global_keymap
from angrmanagement.present.links import angr_url
from angrmanagement.present.menus import MenuEntry
from angrmanagement.tui.app import NOTIFY_AFTER_SECONDS, AmApp
from angrmanagement.tui.caps import TerminalCaps, caps_from_environment, osc99
from angrmanagement.tui.executor import TextualExecutor
from angrmanagement.tui.picture_mode import qt_available, qt_picture
from angrmanagement.tui.screens.capabilities import CapabilitiesScreen
from angrmanagement.tui.screens.image_preview import ImagePreviewScreen
from angrmanagement.tui.views import TUI_VIEW_CLASSES
from angrmanagement.tui.widgets.menubar import MenuPopup
from angrmanagement.tui.widgets.picture import image_module

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
MAIN = 0x40071D
AUTHENTICATE = 0x400664


def run_app(
    scenario: Callable[[AmApp, Pilot], Awaitable[None]], caps: TerminalCaps, binary: str | None = FAUXWARE
) -> None:
    async def main() -> None:
        app = AmApp(caps=caps, interactive=True)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            if binary is not None:
                await app.open_binary(binary)
                await settle(pilot)
            await scenario(app, pilot)

    asyncio.run(main())


def tier(number: int, **kwargs: Any) -> TerminalCaps:
    return TerminalCaps(truecolor=True, forced_tier=number, **kwargs)


def links_of(strips: list[Any]) -> set[str]:
    return {seg.style.link for strip in strips for seg in strip if seg.style is not None and seg.style.link}


class AppCase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved = (GlobalInfo._executor, GlobalInfo._ui_services, GlobalInfo.main_window, GlobalInfo.client_id)
        self.saved_layout = Conf.tui_layout

    def tearDown(self) -> None:
        Conf.tui_layout = self.saved_layout
        GlobalInfo.client_id = self.saved[3]
        assert (GlobalInfo._ui_services, GlobalInfo.main_window) == self.saved[1:3]
        assert not isinstance(GlobalInfo._executor, TextualExecutor)
        GlobalInfo._executor = self.saved[0]


class TestCapabilities(AppCase):
    def test_the_override_and_help_terminal_capabilities(self) -> None:
        env = {"KITTY_WINDOW_ID": "1", "TERM": "xterm-kitty", "AM_TUI_TIER": "0"}
        caps = caps_from_environment(env)
        # kitty is detected, and the override still wins
        assert caps.kitty and caps.kitty_keyboard and caps.tier == 0

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            help_menu = next(menu for menu in app.menus if menu.text == "Help")
            texts = [e.text for e in help_menu.items() if isinstance(e, MenuEntry)]
            assert texts == ["Documentation", "Terminal Capabilities...", "About angr-management"]
            app.screen_stack[-1].app.push_screen(CapabilitiesScreen(app.caps, env))
            await settle(pilot)
            screen = app.screen
            assert isinstance(screen, CapabilitiesScreen)
            rows = dict(screen.rows)
            assert rows["Tier"] == "0 (forced by AM_TUI_TIER=0)" and rows["TERM"] == "xterm-kitty"
            assert rows["Kitty keyboard protocol"] == "yes" and rows["Sixel graphics"] == "no"
            await pilot.press("escape")
            await settle(pilot)
            next(e for e in help_menu.items() if isinstance(e, MenuEntry) and e.text.startswith("Terminal")).trigger()
            await settle(pilot)
            assert isinstance(app.screen, CapabilitiesScreen)

        run_app(scenario, caps, binary=None)


class TestTierZero(AppCase):
    def test_the_alternative_chords_are_bound_and_shown_in_the_menus(self) -> None:
        caps = caps_from_environment({"KITTY_WINDOW_ID": "1", "AM_TUI_TIER": "0"})

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            bound = {binding.key: binding.action for _, binding in app._bindings}
            alternatives = [b for b in global_keymap().bindings if b.tier >= KITTY_KEYBOARD_TIER and b.alternative]
            assert len(alternatives) == 13
            for binding in alternatives:
                key = Chord.parse(binding.alternative or "").to_textual()
                assert bound.get(key, "").startswith(binding.action), (binding.chord, binding.alternative, key)
                if not binding.is_sequence:
                    assert Chord.parse(binding.chord).to_textual() not in bound, binding.chord
            # the File menu shows the chord bound here, not the Qt one
            popup = await app.open_menu("File")
            await settle(pilot)
            assert isinstance(popup, MenuPopup)
            rows = [str(option.prompt) for option in popup.option_list.options]
            trace_row = next(row for row in rows if row.startswith("Load a trace file"))
            assert trace_row.endswith("Alt+T") and "Ctrl+Shift+T" not in trace_row
            assert next(row for row in rows if row.startswith("Save angr database as")).endswith("Alt+S")
            await app.close_menu()
            await settle(pilot)
            await pilot.press("alt+o")  # Preferences, for Ctrl+,
            await settle(pilot)
            assert type(app.screen).__name__ == "PreferencesScreen"

        run_app(scenario, caps, binary=None)


class TestKittyKeys(AppCase):
    def test_two_shift_presses_open_the_goto_palette(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            # a terminal with the kitty keyboard protocol reports a bare Shift press
            await pilot.press("left_shift", "a")
            await settle(pilot)
            assert not isinstance(app.screen, CommandPalette)
            await pilot.press("left_shift", "right_shift")
            await settle(pilot)
            assert isinstance(app.screen, CommandPalette)

        run_app(scenario, tier(2), binary=None)


class TestLinks(AppCase):
    def test_addresses_link_to_angr_urls_from_tier_one(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            disasm: Any = app.view_widget("disassembly")
            graph = disasm.graph_widget
            await wait_for(pilot, lambda: graph.canvas is not None)
            links = links_of(graph.canvas.to_strips(None, graph.style_of))
            assert angr_url(MAIN) == "angr://?action=jumpto&addr=0x40071d" and angr_url(MAIN) in links
            # the window's client id names the target, once connected to the daemon
            GlobalInfo.client_id = "c0ffee"
            assert angr_url(MAIN) in links_of(graph.canvas.to_strips(None, graph.style_of))
            assert angr_url(MAIN).endswith("&target_id=c0ffee")
            GlobalInfo.client_id = None
            # the pseudocode: the call to authenticate
            app.workspace.decompile_current_function()
            await app.wait_for_jobs()
            code: Any = None

            def decompiled() -> bool:
                nonlocal code
                code = app.view_widget("pseudocode")
                return code is not None and code.presenter.doc is not None

            await wait_for(pilot, decompiled)
            rows = [code.code.text_strip(row) for row in range(len(code.presenter.doc.lines))]
            assert angr_url(AUTHENTICATE) in links_of(rows)

        run_app(scenario, tier(1))

    def test_no_links_at_tier_zero(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            disasm: Any = app.view_widget("disassembly")
            graph = disasm.graph_widget
            await wait_for(pilot, lambda: graph.canvas is not None)
            assert not links_of(graph.canvas.to_strips(None, graph.style_of))

        run_app(scenario, tier(0))


@contextlib.contextmanager
def without_textual_image() -> Iterator[None]:
    """Make ``import textual_image.widget`` fail, as it does where the tui extra is not installed."""
    name = "textual_image.widget"
    saved = sys.modules.get(name)
    sys.modules[name] = None  # type: ignore[assignment]
    try:
        yield
    finally:
        if saved is None:
            del sys.modules[name]
        else:
            sys.modules[name] = saved


class TestPictures(AppCase):
    def test_tier_three_mounts_image_widgets(self) -> None:
        module = image_module()
        if module is None:
            self.skipTest("textual-image (the tui extra) is not installed")
        image_class = module.Image

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            # the feature map
            feature_picture = app.feature_map.picture
            assert feature_picture is not None and isinstance(feature_picture, image_class)
            assert feature_picture.is_mounted
            picture = app.feature_map.picture_image()
            assert picture.size == (app.feature_map.size.width * 8, 16)
            # the minimap, over the graph's top left corner
            disasm: Any = app.view_widget("disassembly")
            minimap = disasm.minimap_picture
            assert minimap is not None and isinstance(minimap.image, image_class)
            await wait_for(pilot, lambda: minimap.display)
            graph = disasm.graph_widget.region
            assert (minimap.region.x, minimap.region.y) == (graph.x + 2, graph.y + 1)
            assert app.screen.get_widget_at(minimap.region.x + 1, minimap.region.y + 1)[0] in (minimap, minimap.image)
            # no braille under it
            row = "".join(seg.text for seg in disasm.graph_widget.render_line(1))
            assert not any(0x2800 <= ord(char) <= 0x28FF for char in row)
            disasm.presenter.toggle_show_minimap(False)
            await wait_for(pilot, lambda: not minimap.display)
            # the trace map
            assert await app.run_action("show_view('tracemap')")
            await settle(pilot)
            app.workspace.main_instance.debugger_mgr.set_debugger(ScriptedTrace(app.workspace))
            await settle(pilot)
            tracemap: Any = app.view_widget("tracemap")
            assert isinstance(tracemap.map.picture, image_class)
            # the image export preview, then picture mode
            disasm.save_image()
            await wait_for(pilot, lambda: isinstance(app.screen, ImagePreviewScreen))
            assert isinstance(app.screen.query_one("#preview"), image_class)
            await pilot.press("escape")
            await settle(pilot)
            app.show_graph_picture()
            await wait_for(pilot, lambda: isinstance(app.screen, ImagePreviewScreen))
            preview: Any = app.screen.query_one("#preview")
            screen: Any = app.screen
            assert screen.large and isinstance(preview, image_class)
            if qt_available():
                strips = disasm.image_strips()
                # drawn by Qt: a font's pixels a cell, not the cell drawing's three
                drawn = qt_picture(strips, Color(0, 0, 0))
                assert drawn is not None and preview.image.size == drawn.size
                assert preview.image.size[0] > 3 * max(strip.cell_length for strip in strips)
                # picture mode's offscreen QApplication does not make the plugins open Qt dialogs in the terminal
                assert not qt_frontend()

        run_app(scenario, tier(3))

    def test_below_tier_three_the_text_drawings_stay(self) -> None:
        # the image widgets, when textual-image is installed, so a test can look for them
        module = image_module()
        image_class: Any = module.Image if module is not None else type(None)

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            assert app.feature_map.picture is None and not app.feature_map.query(image_class)
            disasm: Any = app.view_widget("disassembly")
            assert disasm.minimap_picture is None
            await wait_for(pilot, lambda: disasm.graph_widget.canvas is not None)
            await settle(pilot)
            row = "".join(seg.text for seg in disasm.graph_widget.render_line(1))
            assert any(0x2800 <= ord(char) <= 0x28FF for char in row), row
            assert await app.run_action("show_view('tracemap')")
            await settle(pilot)
            tracemap: Any = app.view_widget("tracemap")
            assert tracemap.map.picture is None
            disasm.save_image()
            await wait_for(pilot, lambda: isinstance(app.screen, ImagePreviewScreen))
            preview = app.screen.query_one("#preview")
            assert not isinstance(preview, image_class)
            assert any(0x2800 <= ord(char) <= 0x28FF for char in str(preview.render()))

        with self.subTest("tier 2"):
            run_app(scenario, tier(2))
        with self.subTest("tier 3 without textual-image"), without_textual_image():
            assert image_module() is None
            run_app(scenario, tier(3))


class TestNotification(AppCase):
    def test_a_long_job_tells_the_desktop_when_the_terminal_is_not_focused(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            written: list[str] = []
            app.write_escape = written.append  # type: ignore[method-assign]

            def run_job(seconds: float, focused: bool, failed: bool = False) -> None:
                job: Any = SimpleNamespace(name="Decompiling")
                app._on_job_starting(job)
                app._job_started[id(job)] -= seconds
                app.app_focus = focused
                app._on_job_finished(job, failed=failed)

            run_job(NOTIFY_AFTER_SECONDS + 1, focused=False)
            assert written == [osc99("angr management", "Decompiling finished")]
            assert written[0].startswith("\x1b]99;i=am:d=0;angr management\x1b\\")
            run_job(NOTIFY_AFTER_SECONDS - 5, focused=False)
            run_job(NOTIFY_AFTER_SECONDS + 1, focused=True)
            assert len(written) == 1
            run_job(NOTIFY_AFTER_SECONDS + 1, focused=False, failed=True)
            assert written[-1] == osc99("angr management", "Decompiling failed")
            app.caps.kitty = False
            run_job(NOTIFY_AFTER_SECONDS + 1, focused=False)
            assert len(written) == 2
            app.app_focus = True
            await settle(pilot)

        run_app(scenario, tier(3, kitty=True), binary=None)

    def test_the_notification_has_no_escapes_in_its_text(self) -> None:
        assert osc99("a\x1b]b", "c\x07d") == "\x1b]99;i=am:d=0;a]b\x1b\\\x1b]99;i=am:d=1:p=body;cd\x1b\\"


class TestTabs(AppCase):
    def test_the_tabs_are_saved_on_exit_and_opened_with_the_next_binary(self) -> None:
        Conf.tui_layout = ""
        exited: list[bool] = []

        async def first(app: AmApp, pilot: Pilot) -> None:
            await app.run_action("show_view('strings')")
            await app.run_action("show_view('hex')")
            await settle(pilot)
            strings = app.view_widget("strings")
            manager = app.workspace.view_manager
            assert strings is not None and manager.area_of(strings) == "center"
            jobs = app.view_widget("jobs")
            assert jobs is not None and manager.area_of(jobs) == "bottom"
            manager.raise_view(jobs)
            await settle(pilot)
            app.exit()
            exited.append(True)

        run_app(first, tier(2))
        assert exited
        saved = json.loads(Conf.tui_layout)
        assert {"strings", "hex", "disassembly"} <= set(saved["tabs"]["center"])
        assert saved["active"]["bottom"] == "jobs" and saved["tabs"]["bottom"][0] == "console"
        assert "functions" in saved["tabs"]["left"]

        async def second(app: AmApp, pilot: Pilot) -> None:
            manager = app.workspace.view_manager
            await wait_for(pilot, lambda: None not in (app.view_widget("strings"), app.view_widget("hex")))
            strings = app.view_widget("strings")
            assert manager.area_of(strings) == "center" and manager.area_of(app.view_widget("hex")) == "center"
            # one of each, as saved
            assert [v.category for v in manager.views].count("hex") == 1
            jobs = app.view_widget("jobs")
            await wait_for(pilot, lambda: manager.area("bottom").active == manager.pane_id_of(jobs))
            await settle(pilot, 8)
            assert manager.area("bottom").active == manager.pane_id_of(jobs)

        async def third(app: AmApp, pilot: Pilot) -> None:
            # whether the restored strings view opened before the CFG or after, it lists the strings once it exists
            cfg = container(app.workspace.main_instance.cfg)
            await wait_for(pilot, lambda: not cfg.am_none, rounds=1500)
            strings: Any = app.view_widget("strings")
            await wait_for(pilot, lambda: strings is not None and strings.table_widget.row_count > 0)

        run_app(second, tier(2))
        run_app(third, tier(2))

    def test_every_view_opens_before_the_cfg_exists(self) -> None:
        # the saved tabs open as soon as a binary is loaded, which can be before CFGFast has finished: every view must
        # open on an empty CFG container, and the strings view fills in when the CFG arrives
        Conf.tui_layout = ""

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            cfg_container = container(app.workspace.main_instance.cfg)
            await wait_for(pilot, lambda: not cfg_container.am_none, rounds=1500)
            cfg = cfg_container.am_obj
            cfg_container.am_obj = None
            for category in TUI_VIEW_CLASSES:
                await app.run_action(f"show_view({category!r})")
                await settle(pilot)
                assert app.view_widget(category) is not None, category
            strings: Any = app.view_widget("strings")
            assert strings.table_widget.row_count == 0
            cfg_container.am_obj = cfg
            app.workspace.on_cfg_generated()
            await settle(pilot)
            assert strings.table_widget.row_count == strings.presenter.model.row_count > 0

        run_app(scenario, tier(2))


if __name__ == "__main__":
    unittest.main()
