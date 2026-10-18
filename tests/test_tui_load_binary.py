"""
The terminal's Load a new binary screen, on fixtures from angr/binaries: the three tabs of the Qt Load Binary dialog,
the checks it makes before it accepts, the encryption key sub-screen, and the debug symbol entries of a PE file.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from typing import TYPE_CHECKING, Any

import cle
from textual.widgets import Button, Checkbox, DataTable, Input, Select, SelectionList, TabbedContent, Tree
from tui_pilot import settle  # pylint: disable=import-error

from angrmanagement.config import Conf
from angrmanagement.data.load_options import build_load_options
from angrmanagement.logic import GlobalInfo
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.screens import MessageScreen
from angrmanagement.tui.screens.form import FormScreen
from angrmanagement.tui.screens.load_binary import LoadBinaryScreen

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
ELF_CART = os.path.join(test_location, "x86_64", "1after909.cart")
CART_KEY = b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"
PE = os.path.join(test_location, "i386", "simple_windows.exe")


def partial_loader(path: str, **main_opts: Any) -> cle.Loader:
    """A partial load, as LoadBinaryJob makes it before it asks how to load the file."""
    return cle.Loader(path, perform_relocations=False, load_debug_info=False, auto_load_libs=False, main_opts=main_opts)


def run_screen(
    screen: LoadBinaryScreen, scenario: Callable[[AmApp, Pilot, LoadBinaryScreen, list[Any]], Awaitable[None]]
) -> None:
    """Show ``screen`` in a headless app and run ``scenario``; the list gets what the screen dismisses with."""

    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=False)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            results: list[Any] = []
            app.push_screen(screen, results.append)
            for _ in range(5):
                await pilot.pause()
            await scenario(app, pilot, screen, results)

    asyncio.run(main())


class LoadScreenCase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved = (GlobalInfo._executor, GlobalInfo._ui_services, GlobalInfo.main_window, Conf.frontend_adapter)

    def tearDown(self) -> None:
        GlobalInfo._executor, GlobalInfo._ui_services, GlobalInfo.main_window, _adapter = self.saved


class TestOverview(LoadScreenCase):
    def test_preselects_what_the_qt_dialog_does_and_loads_with_it(self) -> None:
        ld = partial_loader(FAUXWARE)

        async def scenario(app: AmApp, pilot: Pilot, screen: LoadBinaryScreen, results: list[Any]) -> None:
            assert screen.query_one("#backend", Select).value == "elf"
            assert screen.query_one("#os", Select).value == "SimLinux"
            assert screen.query_one("#outer", Select).value == "<None>"
            # the encryption key is only for CaRT
            assert screen.query_one("#enckey", Button).disabled
            node = screen.query_one("#arch-tree", Tree).cursor_node
            assert node is not None and getattr(node.data, "name", None) == "AMD64"
            # the addresses the partial load found, switched off
            base = screen.query_one("#base_addr", Input)
            assert base.value == "0x400000" and base.disabled
            tabs = screen.query_one(TabbedContent)
            assert [str(getattr(tab, "label", "")) for tab in tabs.query("ContentTab")] == [
                "Overview",
                "Dependencies (1)",
            ]
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            assert len(results) == 1
            selection = results[0]
            assert (selection.backend, selection.simos_name, selection.arch.name) == ("elf", "SimLinux", "AMD64")
            assert selection.skip_libs == {"libc.so.6"} and not selection.force_load_libs
            options = build_load_options(ld, selection)
            assert options.load_options["main_opts"]["backend"] == "elf"
            assert getattr(options.simos, "__name__", None) == "SimLinux"

        run_screen(
            LoadBinaryScreen(ld, suggested_backend=type(ld.main_object), suggested_os_name=ld.main_object.os), scenario
        )

    def test_a_bad_address_is_refused_with_the_dialogs_message(self) -> None:
        ld = partial_loader(FAUXWARE)

        async def scenario(app: AmApp, pilot: Pilot, screen: LoadBinaryScreen, results: list[Any]) -> None:
            screen.query_one("#base_addr-on", Checkbox).value = True
            await settle(pilot)
            base = screen.query_one("#base_addr", Input)
            assert not base.disabled
            base.value = "not hex"
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            assert isinstance(app.screen, MessageScreen) and app.screen.title_text == "Incorrect base address"
            app.screen.dismiss(None)
            await settle(pilot)
            assert not results
            base.value = "0x500000"
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            assert results and results[0].base_addr == 0x500000

        run_screen(
            LoadBinaryScreen(ld, suggested_backend=type(ld.main_object), suggested_os_name=ld.main_object.os), scenario
        )

    def test_a_blob_starts_with_the_addresses_switched_on(self) -> None:
        ld = cle.Loader(FAUXWARE, main_opts={"backend": "blob", "arch": "x86"})

        async def scenario(app: AmApp, pilot: Pilot, screen: LoadBinaryScreen, results: list[Any]) -> None:
            for key in ("base_addr", "entry_addr", "offset"):
                box = screen.query_one(f"#{key}", Input)
                assert box.value == "0x0" and not box.disabled, key

        run_screen(LoadBinaryScreen(ld, suggested_backend=cle.Blob), scenario)

    def test_cancel_and_escape_give_nothing(self) -> None:
        ld = partial_loader(FAUXWARE)
        for how in ("escape", "button"):
            with self.subTest(how=how):

                async def scenario(app, pilot, screen, results, how=how) -> None:
                    if how == "escape":
                        await pilot.press("escape")
                    else:
                        screen.query_one("#cancel", Button).press()
                    await settle(pilot)
                    assert results == [None]

                run_screen(LoadBinaryScreen(ld), scenario)


class TestDependencies(LoadScreenCase):
    def test_a_checked_library_is_loaded(self) -> None:
        ld = partial_loader(FAUXWARE)

        async def scenario(app: AmApp, pilot: Pilot, screen: LoadBinaryScreen, results: list[Any]) -> None:
            screen.query_one(TabbedContent).active = "dependencies-tab"
            await settle(pilot)
            screen.query_one("#dependencies", SelectionList).select("libc.so.6")
            screen.query_one("#auto_load_libs", Checkbox).value = True
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            selection = results[0]
            assert selection.force_load_libs == ["libc.so.6"] and not selection.skip_libs
            assert selection.auto_load_libs

        run_screen(LoadBinaryScreen(ld, suggested_backend=type(ld.main_object)), scenario)


class TestEncryptionKey(LoadScreenCase):
    def test_cart_offers_the_key_screen_and_loads_with_the_key(self) -> None:
        ld = partial_loader(ELF_CART, arc4_key=CART_KEY)

        async def scenario(app: AmApp, pilot: Pilot, screen: LoadBinaryScreen, results: list[Any]) -> None:
            assert screen.query_one("#outer", Select).value == "cart"
            assert not screen.query_one("#enckey", Button).disabled
            # the key the partial load was given
            assert "02 f5 33" in str(screen.query_one("#enckey-label").render())
            screen.query_one("#enckey", Button).press()
            await settle(pilot)
            key_screen = app.screen
            assert isinstance(key_screen, FormScreen) and key_screen.title_text == "Set an encryption key"
            key_editor: Any = key_screen.editors["key"]
            key_editor.value = "zz"
            await settle(pilot)
            assert str(key_screen.query_one("#status").render()) == "Valid"  # ASCII is a format too
            key_editor.value = "0x00112233"
            await settle(pilot)
            assert "Key in hex: 00 11 22 33" in str(key_screen.editors["as_hex"].render())
            key_screen.query_one("#ok", Button).press()
            await settle(pilot)
            assert screen.enckey == b"\x00\x11\x22\x33"
            assert "00 11 22 33" in str(screen.query_one("#enckey-label").render())
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            options = build_load_options(ld, results[0], suggested_main_opts={"arc4_key": CART_KEY})
            assert options.load_options["main_opts"]["arc4_key"] == b"\x00\x11\x22\x33"

        run_screen(
            LoadBinaryScreen(
                ld,
                suggested_backend=type(ld.main_object),
                suggested_main_opts={"arc4_key": CART_KEY},
                suggested_original_backend=type(ld.original_main_object),
                suggested_main_filename=ld.original_main_object.unpacked_name,
            ),
            scenario,
        )


class TestDebugSymbols(LoadScreenCase):
    def test_a_pe_file_has_the_debug_symbols_tab(self) -> None:
        ld = partial_loader(PE)

        async def scenario(app: AmApp, pilot: Pilot, screen: LoadBinaryScreen, results: list[Any]) -> None:
            tabs = screen.query_one(TabbedContent)
            assert "Debug Symbols" in [str(getattr(tab, "label", "")) for tab in tabs.query("ContentTab")]
            tabs.active = "symbols"
            await settle(pilot)
            # a server entry needs its URL, as in the Qt dialog
            screen.query_one("#add-symbol-path", Button).press()
            await settle(pilot)
            form: Any = app.screen
            assert isinstance(form, FormScreen)
            form.set_value("type", "srv")
            form.query_one("#ok", Button).press()
            await settle(pilot)
            assert isinstance(app.screen, MessageScreen)
            assert app.screen.text == "Server URL is required for symbol server entries."
            app.screen.dismiss(None)
            await settle(pilot)
            screen.query_one("#add-symbol-path", Button).press()
            await settle(pilot)
            form = app.screen
            form.set_value("type", "srv")
            form.set_value("cache", "/tmp/symbols")
            form.set_value("path", "https://msdl.microsoft.com/download/symbols")
            form.query_one("#ok", Button).press()
            await settle(pilot)
            assert screen.query_one("#symbol-paths", DataTable).row_count == 1
            # without debug information the symbol options do not apply
            screen.query_one("#load_debug_info", Checkbox).value = False
            await settle(pilot)
            assert screen.query_one("#allow_download", Checkbox).disabled
            screen.query_one("#load_debug_info", Checkbox).value = True
            screen.query_one("#allow_download", Checkbox).value = False
            await settle(pilot)
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            options = build_load_options(ld, results[0])
            main_opts = options.load_options["main_opts"]
            assert main_opts["download_debug_symbols"] is False
            assert main_opts["symbol_paths"] == "srv*/tmp/symbols*https://msdl.microsoft.com/download/symbols"

        run_screen(LoadBinaryScreen(ld, suggested_backend=type(ld.main_object)), scenario)


class TestExit(LoadScreenCase):
    def test_exiting_while_the_screen_mounts_lets_it_finish(self) -> None:
        # Textual's Select looks up its children when it mounts, so tearing the screen down under it raised
        # NoMatches at exit. When during the mount the exit lands depends on the machine, hence the range of delays.
        ld = partial_loader(FAUXWARE)

        async def main(delay: float) -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=False)
            async with app.run_test(size=(160, 50)) as pilot:
                await pilot.pause()
                app.push_screen(LoadBinaryScreen(ld, suggested_backend=type(ld.main_object)))
                await asyncio.sleep(delay)
                app.exit()
                # the app's own exit, not the shutdown run_test does after the scenario
                await asyncio.wait_for(asyncio.shield(app._task), 30)
                assert app.return_code == 0

        for step in range(30):
            asyncio.run(main(step * 0.002))


class TestWhereItIsShown(LoadScreenCase):
    def test_a_binary_named_on_the_command_line_loads_with_the_defaults(self) -> None:
        # am-tui FILE, as the MCP load path, loads without asking; the File menu's Load asks (tests/test_tui_app.py)
        async def main() -> None:
            app = AmApp(binary=FAUXWARE, caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            app.workspace._suppress_analysis_options_dialog = True
            shown: list[str] = []
            async with app.run_test(size=(160, 50)) as pilot:
                for _ in range(600):
                    shown.append(type(app.screen).__name__)
                    if not app.workspace.main_instance.project.am_none:
                        break
                    await pilot.pause(0.05)
                project = app.workspace.main_instance.project
                assert not project.am_none
                assert project.loader.main_object.binary.endswith("fauxware")
                assert "LoadBinaryScreen" not in shown
                # the defaults: no libraries
                assert not project.loader.requested_names - {"libc.so.6"}
                assert [obj.binary_basename for obj in project.loader.all_elf_objects] == ["fauxware"]
                await app.wait_for_jobs()

        asyncio.run(main())


if __name__ == "__main__":
    unittest.main()
