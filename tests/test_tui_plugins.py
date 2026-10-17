"""
The bundled plugins in the terminal, on fauxware from angr/binaries: each is enabled and its menu entry, context menu
entry, view or hooks exercised, as the Qt frontend shows them.
"""

# pylint: disable=missing-class-docstring,protected-access

from __future__ import annotations

import asyncio
import json
import os
import re
import unittest
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from angr.analyses.decompiler.structured_codegen import FunctionCallNode
from textual.widgets import Button, Input

from angrmanagement.config import Conf
from angrmanagement.config.color import Color
from angrmanagement.logic import GlobalInfo
from angrmanagement.present.menus import MenuEntry, walk_entries
from angrmanagement.present.symexec import open_new_state
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.executor import TextualExecutor
from angrmanagement.tui.new_state import NewStateScreen
from angrmanagement.tui.screens import FilePickerScreen, MessageScreen
from angrmanagement.tui.screens.form import FormScreen
from angrmanagement.tui.screens.plugins import PluginsScreen
from angrmanagement.tui.widgets.menubar import MenuPopup

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
MAIN = 0x40071D
SIZE = (160, 50)


def run_app(scenario: Callable[[AmApp, Pilot], Awaitable[None]], binary: str | None = FAUXWARE) -> None:
    """Run ``scenario`` in a headless app that asks through its screens, with fauxware opened."""

    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=False)
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            if binary is not None:
                await app.open_binary(binary)
                await pilot.pause()
            app.services.interactive = True
            await scenario(app, pilot)

    asyncio.run(main())


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def wait_for(pilot: Pilot, condition: Callable[[], bool], rounds: int = 400) -> None:
    for _ in range(rounds):
        if condition():
            await settle(pilot)
            return
        await pilot.pause(0.02)
    raise AssertionError("the condition never held")


async def wait_for_screen(pilot: Pilot, kind: type[Any]) -> Any:
    await wait_for(pilot, lambda: isinstance(pilot.app.screen, kind))
    return pilot.app.screen


async def enable(app: AmApp, pilot: Pilot, shortname: str) -> Any:
    """Turn the plugin on in the Manage Plugins screen, as a user does; returns the plugin."""
    app.open_load_plugins_dialog()
    screen = await wait_for_screen(pilot, PluginsScreen)
    screen.query_one("#plugins").select(shortname)
    screen.query_one("#ok", Button).press()
    await settle(pilot)
    plugin = app.workspace.plugins.get_plugin_instance_by_name(shortname)
    assert plugin is not None, f"{shortname} did not activate"
    return plugin


async def pick_menu_entry(app: AmApp, pilot: Pilot, menu: str, caption: str) -> None:
    """Open ``menu`` in the menu bar and pick the entry ``caption``, as the keyboard does."""
    popup = await app.open_menu(menu)
    await settle(pilot)
    assert isinstance(popup, MenuPopup)
    captions = [getattr(item, "caption", None) for item in popup.items]
    assert caption in captions, captions
    item_index = next(
        i for i, item in enumerate(popup.items) if isinstance(item, MenuEntry) and item.caption == caption
    )
    options = popup.option_list
    # the option list has no separators, so its indices are not the menu's
    options.highlighted = next(
        i for i in range(options.option_count) if options.get_option_at_index(i).id == str(item_index)
    )
    popup.option_list.action_select()
    await settle(pilot)


class PluginCase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved_plugins = Conf.enabled_plugins
        self.saved = (GlobalInfo._executor, GlobalInfo._ui_services, GlobalInfo.main_window)

    def tearDown(self) -> None:
        assert (GlobalInfo._ui_services, GlobalInfo.main_window) == self.saved[1:]
        assert not isinstance(GlobalInfo._executor, TextualExecutor)
        Conf.enabled_plugins = self.saved_plugins
        GlobalInfo._executor = self.saved[0]


class TestSimplePlugins(PluginCase):
    def test_memory_checker_instruments_new_states_and_stashes_use_after_free(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            plugin = await enable(app, pilot, "memory_checker")
            instance = app.workspace.main_instance
            open_new_state(app.workspace, instance, MAIN, create_simgr=True)
            screen = await wait_for_screen(pilot, NewStateScreen)
            screen.query_one("#ok", Button).press()
            await wait_for(pilot, lambda: app.view_widget("symexec") is not None)
            symexec: Any = app.view_widget("symexec")
            await wait_for(
                pilot,
                lambda: not symexec.presenter.current_simgr.am_none and symexec.presenter.current_simgr.am_obj.active,
            )
            simgr = symexec.presenter.current_simgr.am_obj
            # the plugin's heap and memory actions on the state the new state screen made
            state = simgr.active[0]
            assert "heap" in state.plugins
            # a step calls the plugins' step callbacks, which moves use-after-free states to their stash
            symexec.query_one("#step", Button).press()
            await wait_for(pilot, lambda: [s.addr for s in simgr.active] == [MAIN + 1])
            await app.wait_for_jobs()
            assert "use_after_free" in simgr.stashes and not simgr.stashes["use_after_free"]
            assert plugin.check_use_after_free(simgr.active[0]) is False

        run_app(scenario)

    def test_dependency_viewer_marks_sinks_in_the_functions_table(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            kb = app.workspace.main_instance.kb
            # fauxware calls no sink; a function named after one stands in
            kb.functions["puts"].name = "system"
            plugin = await enable(app, pilot, "dependency_viewer")
            functions: Any = app.view_widget("functions")
            model = functions.presenter.model
            await wait_for(pilot, lambda: "Vuln Sink" in [c.name for c in model.columns])
            col = [c.name for c in model.columns].index("Vuln Sink")
            row = next(i for i, func in enumerate(model.rows) if func.name == "system")
            assert model.cell(row, col).text
            assert plugin.func_style(kb.functions["system"]) == Color(255, 255, 0)
            assert app.workspace.plugins.func_style(kb.functions["system"]) == Color(255, 255, 0)

        run_app(scenario)

    def test_source_importer_asks_for_a_source_root(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            plugin = await enable(app, pilot, "source_importer")
            await pick_menu_entry(app, pilot, "Plugins", "Import source path")
            picker = await wait_for_screen(pilot, FilePickerScreen)
            assert picker.mode == "directory"
            picker.query_one("#path", Input).value = test_location
            picker.query_one("#ok", Button).press()
            await settle(pilot)
            assert os.path.normpath(test_location) in [os.path.normpath(p) for p in plugin.source_paths]

        run_app(scenario)

    def test_varec_says_when_there_is_nothing_to_rename(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            await enable(app, pilot, "varec")
            await pick_menu_entry(app, pilot, "Plugins", "&Infer variable names")
            message = await wait_for_screen(pilot, MessageScreen)
            assert message.title_text == "Error in variable name prediction"
            assert "No pseudocode" in message.text

        run_app(scenario)

    def test_varec_renames_with_the_predictions(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            await enable(app, pilot, "varec")
            app.workspace.decompile_function(app.workspace.main_instance.kb.functions["main"])
            await app.wait_for_jobs()
            code: Any = app.view_widget("pseudocode")
            await wait_for(pilot, lambda: not code.codegen.am_none)

            class Response:
                """What the VaRec service answers: a prediction for every variable it was sent."""

                text = ""

            def post(_url, data, proxies):  # pylint:disable=unused-argument
                sent = json.loads(data)["code"][0]["raw_codes"][0]
                count = len(re.findall(r"@@(\S+)@@(\S+)@@", sent))
                predictions = [{"top-k": [{"pred_name": f"predicted_{i}", "confidence": 1.0}]} for i in range(count)]
                response = Response()
                response.text = json.dumps({"code": [{"predictions": [predictions]}]})
                return response

            with patch("angrmanagement.plugins.varec.varec.requests.post", post):
                await pick_menu_entry(app, pilot, "Plugins", "&Infer variable names")
            await settle(pilot)
            assert "predicted_0" in code.codegen.text

        run_app(scenario)


class TestStatusAndMarks(PluginCase):
    def test_coverage_starts_colours_the_covered_blocks_and_stops(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            plugin = await enable(app, pilot, "coverage_viewer")
            await pick_menu_entry(app, pilot, "Plugins", "Start Showing Coverage")
            assert plugin.running
            main = app.workspace.main_instance.kb.functions["main"]
            plugin.update_coverage_from_list(list(main.block_addrs_set))
            await settle(pilot)
            plugins = app.workspace.plugins
            assert plugins.block_style(main.addr) == plugin.light_theme_color
            assert plugins.func_style(main) is not None
            functions: Any = app.view_widget("functions")
            model = functions.presenter.model
            col = [c.name for c in model.columns].index("Fuzzing Coverage")
            row = next(i for i, func in enumerate(model.rows) if func.addr == main.addr)
            assert model.cell(row, col).text == "100%"
            await pick_menu_entry(app, pilot, "Plugins", "Stop Showing Coverage")
            assert not plugin.running
            assert plugins.block_style(main.addr) is None

        run_app(scenario)

    def test_execution_statistics_count_the_states_in_the_status_bar_and_marks(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            instance = app.workspace.main_instance
            open_new_state(app.workspace, instance, MAIN, create_simgr=True)
            screen = await wait_for_screen(pilot, NewStateScreen)
            screen.query_one("#ok", Button).press()
            await wait_for(pilot, lambda: app.view_widget("symexec") is not None)
            symexec: Any = app.view_widget("symexec")
            await wait_for(pilot, lambda: not symexec.presenter.current_simgr.am_none)
            plugin = await enable(app, pilot, "exec_stats_viewer")
            simgr = symexec.presenter.current_simgr.am_obj
            symexec.query_one("#step", Button).press()
            await wait_for(pilot, lambda: [s.addr for s in simgr.active] == [MAIN + 1])
            await app.wait_for_jobs()
            await settle(pilot)
            # the Qt label's text, in the terminal's status bar
            assert "Active states: 1" in app._plugin_status_texts()
            disasm: Any = app.view_widget("disassembly")
            marks = app.workspace.plugins.block_marks(MAIN, disasm)
            active = [m for m in marks if m.style_key == "disasm.mark.active"]
            assert [(m.text, m.addr) for m in active] == [("1", MAIN + 1)]
            assert plugin.passthrough_counts
            # the Qt annotation's menu: select the states, or move them to a stash
            active[0].action()
            popup = await wait_for_screen(pilot, MenuPopup)
            assert [getattr(item, "caption", None) for item in popup.items] == ["Select", "Move To"]

        run_app(scenario)


class TestCodePlugins(PluginCase):
    async def _main_in_pseudocode(self, app: AmApp, pilot: Pilot) -> Any:
        app.workspace.decompile_function(app.workspace.main_instance.kb.functions["main"])
        await app.wait_for_jobs()
        code: Any = app.view_widget("pseudocode")
        await wait_for(pilot, lambda: not code.codegen.am_none and code.presenter.doc is not None)
        return code

    def test_decompiler_poison_removes_a_poisoned_call(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            plugin = await enable(app, pilot, "decompiler_poison")
            code = await self._main_in_pseudocode(app, pilot)
            node = next(
                element.obj
                for _start, element in code.codegen.map_pos_to_node.items()  # type: ignore[union-attr]
                if isinstance(element.obj, FunctionCallNode) and getattr(element.obj.callee_func, "name", "") == "puts"
            )
            menu = code.presenter.context_menu(node)
            entries = {entry.text: entry for _path, entry in walk_entries(menu)}
            assert "Poison call globally" in entries
            app.workspace.raise_view(code)
            entries["Poison call globally"].action()
            puts = app.workspace.main_instance.kb.functions["puts"]
            assert plugin.knowledge.is_poisoned_global(puts.addr)
            await app.wait_for_jobs()

        run_app(scenario)

    def test_ail2asm_shows_the_assembly_in_a_text_screen(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            await enable(app, pilot, "ail2asm")
            code = await self._main_in_pseudocode(app, pilot)
            presenter = code.presenter
            for start, element in code.codegen.map_pos_to_node.items():  # type: ignore[union-attr]
                if type(element.obj).__name__ != "CVariable":
                    continue
                presenter.set_cursor(start) if hasattr(presenter, "set_cursor") else code.code.set_cursor(start)
                presenter.expr2armasm(element.obj)
                await settle(pilot)
                if isinstance(app.screen, FormScreen):
                    break
            screen = app.screen
            assert isinstance(screen, FormScreen) and screen.title_text == "Assembly code output"
            assert "The AIL block:" in screen.values["asm"]

        run_app(scenario)


if __name__ == "__main__":
    unittest.main()
