"""
The terminal's dialogs, on fauxware from angr/binaries: Run Analysis (the analyses, their descriptions and option
sheets, the language questions), the forms of the small Qt dialogs (Jump to, Rename Label, Set Comment, Edit
Breakpoint, Assemble Patch, Change hook, Function Documentation, Function), and the rest of phase 5's screens.
"""

# pylint: disable=missing-class-docstring,protected-access

from __future__ import annotations

import asyncio
import os
import unittest
from typing import TYPE_CHECKING, Any

import angr
from textual.widgets import Button, Checkbox, Input, Select, SelectionList, Static, TabbedContent

from angrmanagement.config import Conf
from angrmanagement.config.color import Color
from angrmanagement.data.analysis_options import AnalysesConfiguration
from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import (
    OverviewConfiguration,
    RustSymbolRecoveryConfiguration,
    RustTypeDBLoaderConfiguration,
)
from angrmanagement.logic import GlobalInfo
from angrmanagement.present.analysis_options import RUST_DEPENDENT_ANALYSES
from angrmanagement.present.preferences import PAGE_NAMES, color_entry_names, color_text, scheme_entry_values
from angrmanagement.tui.app import AmApp, config_file_path
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.screens import QuestionScreen
from angrmanagement.tui.screens.analysis_options import AnalysisOptionsScreen
from angrmanagement.tui.screens.preferences import PreferencesScreen

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
SIZE = (160, 50)


def run_app(scenario: Callable[[AmApp, Pilot], Awaitable[None]], binary: str | None = FAUXWARE) -> None:
    """Run ``scenario(app, pilot)`` in a headless app, with fauxware opened unless ``binary`` is None."""

    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=False)
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            if binary is not None:
                await app.open_binary(binary)
                await pilot.pause()
            await scenario(app, pilot)

    asyncio.run(main())


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def wait_for_screen(pilot: Pilot, kind: type[Any], rounds: int = 200) -> Any:
    for _ in range(rounds):
        if isinstance(pilot.app.screen, kind):
            await settle(pilot)
            return pilot.app.screen
        await pilot.pause()
    raise AssertionError(f"no {kind.__name__}")


class DialogCase(unittest.TestCase):
    def setUp(self) -> None:
        self.saved = (GlobalInfo._executor, GlobalInfo._ui_services, GlobalInfo.main_window, Conf.frontend_adapter)

    def tearDown(self) -> None:
        assert (GlobalInfo._executor, GlobalInfo._ui_services, GlobalInfo.main_window) == self.saved[:3]


class TestRunAnalysis(DialogCase):
    def test_the_list_the_description_and_the_options(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            configuration = app.workspace.analysis_manager.get_default_analyses_configuration()
            results: list[Any] = []
            app.push_screen(AnalysisOptionsScreen(configuration), results.append)
            screen = await wait_for_screen(pilot, AnalysisOptionsScreen)
            selections = screen.query_one("#analyses", SelectionList)
            # every analysis, checked as configured
            assert selections.option_count == len(configuration)
            assert set(selections.selected) == {a.name for a in configuration if a.enabled}
            # the first one's description and options
            assert screen.current is configuration[0]
            cfg = configuration.by_name("cfg")
            selections.highlighted = list(configuration).index(cfg)
            await settle(pilot)
            assert screen.current is cfg
            assert cfg.description in str(screen.query_one("#description").render())
            labels = [row.label for row in screen.rows.values()]
            assert labels == [o.display_name for o in cfg.options.values()]
            # editing an option changes it in place, as the Qt property editor does
            editor, row = next((e, r) for e, r in screen.rows.items() if r.kind == "bool")
            assert isinstance(editor, Checkbox)
            before = row.option.value
            editor.value = not before
            await settle(pilot)
            assert row.option.value is (not before)
            # a number takes only what is in its bounds
            cca = configuration.by_name("cca")
            selections.highlighted = list(configuration).index(cca)
            await settle(pilot)
            int_editor, int_row = next((e, r) for e, r in screen.rows.items() if r.kind == "int")
            assert isinstance(int_editor, Input)
            int_editor.value = "3"
            await settle(pilot)
            assert int_row.option.value == 3
            int_editor.value = str(int_row.maximum + 1)
            await settle(pilot)
            assert int_row.option.value == 3
            # turning an analysis off, then running
            selections.deselect("cfg")
            await settle(pilot)
            assert cfg.enabled is False
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            assert results == [True]

        run_app(scenario)

    def test_picking_rust_asks_to_turn_the_rust_analyses_on(self) -> None:
        instance = Instance()
        instance.project.am_obj = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        instance.project.am_obj._languages = None
        configuration = AnalysesConfiguration(
            [
                OverviewConfiguration(instance),
                RustSymbolRecoveryConfiguration(instance),
                RustTypeDBLoaderConfiguration(instance),
            ]
        )
        assert not any(configuration.by_name(name).enabled for name in RUST_DEPENDENT_ANALYSES)

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.push_screen(AnalysisOptionsScreen(configuration))
            screen = await wait_for_screen(pilot, AnalysisOptionsScreen)
            assert screen.current is configuration.by_name("overview")
            select, row = next((e, r) for e, r in screen.rows.items() if r.option.name == "languages")
            assert isinstance(select, Select)
            select.value = [value for value, _caption in row.choices].index("rust")
            question = await wait_for_screen(pilot, QuestionScreen)
            assert question.title_text == "Enable Rust-specific analyses?"
            question.query_one("#button-0", Button).press()  # Yes
            await settle(pilot)
            assert instance.project.am_obj._languages == ["rust"]
            for name in RUST_DEPENDENT_ANALYSES:
                assert configuration.by_name(name).enabled, name
            assert set(RUST_DEPENDENT_ANALYSES) <= set(screen.query_one("#analyses", SelectionList).selected)

        run_app(scenario, binary=None)

    def test_cancel_runs_nothing(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            configuration = app.workspace.analysis_manager.get_default_analyses_configuration()
            results: list[Any] = []
            app.push_screen(AnalysisOptionsScreen(configuration), results.append)
            await wait_for_screen(pilot, AnalysisOptionsScreen)
            await pilot.press("escape")
            await settle(pilot)
            assert results == [None]

        run_app(scenario)


class TestPreferences(DialogCase):
    ENTRIES = (
        "theme_name",
        "base_theme_name",
        "disasm_view_operand_color",
        "log_timestamp_format",
        "mcp_server_port",
        "llm_model",
        "llm_auto_summarize",
    )

    def setUp(self) -> None:
        super().setUp()
        self.saved_entries = {name: Conf.entry(name).value for name in self.ENTRIES}

    def tearDown(self) -> None:
        super().tearDown()
        for name, value in self.saved_entries.items():
            setattr(Conf, name, value)
        # setting an entry announces it through the executor, which the line above made if there was none
        GlobalInfo._executor = self.saved[0]

    def test_the_pages_and_saving_them(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.preferences()
            screen = await wait_for_screen(pilot, PreferencesScreen)
            tabs = screen.query_one(TabbedContent)
            assert [str(tab.label) for tab in tabs.query("ContentTab")] == list(PAGE_NAMES)
            # a sheet row for every colour entry of ENTRIES, as the Qt page has
            assert len(screen.query(".color")) == len(color_entry_names())
            # picking a scheme fills the sheet with its colours and makes it the base
            tabs.active = "theme"
            await settle(pilot)
            screen.query_one("#theme_name", Select).value = "Dark"
            await settle(pilot)
            dark = scheme_entry_values("Dark")
            box = screen.query_one("#color-disasm_view_operand_color", Input)
            assert box.value == color_text(dark["disasm_view_operand_color"])
            assert str(screen.query_one("#base_theme").render()) == "Dark"
            # a colour typed in hex, with its swatch; a bad one is marked and not kept
            box.value = "#123456"
            await settle(pilot)
            assert screen.color_values["disasm_view_operand_color"] == Color(0x12, 0x34, 0x56)
            swatch = screen.query_one("#swatch-disasm_view_operand_color", Static)
            assert swatch.styles.background.hex == "#123456"
            box.value = "#12345"
            await settle(pilot)
            assert box.has_class("-invalid")
            assert screen.color_values["disasm_view_operand_color"] == Color(0x12, 0x34, 0x56)
            # the fonts are for the Qt frontend
            assert "own font" in str(screen.query_one("#style").query(".note").last().render())
            screen.query_one("#log_format", Input).value = "%H:%M"
            screen.query_one("#llm_model", Input).value = " a-model "
            screen.query_one("#llm_auto_summarize", Checkbox).value = True
            screen.query_one("#mcp_server_port", Input).value = "70000"
            screen.query_one("#save", Button).press()
            await settle(pilot)
            assert not isinstance(app.screen, PreferencesScreen)
            assert (Conf.theme_name, Conf.base_theme_name) == ("Dark", "Dark")
            assert Conf.entry("disasm_view_operand_color").value == Color(0x12, 0x34, 0x56)
            assert Conf.log_timestamp_format == "%H:%M"
            assert (Conf.llm_model, Conf.llm_auto_summarize) == ("a-model", True)
            # out of range: the Qt spin box's highest port
            assert Conf.mcp_server_port == 65535
            # the scheme is applied, and the file written
            assert app.theme == "am-dark"
            with open(config_file_path(), encoding="utf-8") as f:
                assert "a-model" in f.read()

        run_app(scenario, binary=None)

    def test_close_keeps_nothing(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            before = Conf.mcp_server_port
            app.preferences()
            screen = await wait_for_screen(pilot, PreferencesScreen)
            screen.query_one("#mcp_server_port", Input).value = "4321"
            await pilot.press("escape")
            await settle(pilot)
            assert Conf.mcp_server_port == before

        run_app(scenario, binary=None)


if __name__ == "__main__":
    unittest.main()
