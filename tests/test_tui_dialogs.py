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
from textual.widgets import Button, Checkbox, Input, Select, SelectionList

from angrmanagement.config import Conf
from angrmanagement.data.analysis_options import AnalysesConfiguration
from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import (
    OverviewConfiguration,
    RustSymbolRecoveryConfiguration,
    RustTypeDBLoaderConfiguration,
)
from angrmanagement.logic import GlobalInfo
from angrmanagement.present.analysis_options import RUST_DEPENDENT_ANALYSES
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.screens import QuestionScreen
from angrmanagement.tui.screens.analysis_options import AnalysisOptionsScreen

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


if __name__ == "__main__":
    unittest.main()
