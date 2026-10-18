"""
The terminal frontend, driven through Textual's pilot: the app starts headless on fauxware, every view of this
frontend opens, the functions table filters and opens a function, the palettes run commands, the menus open and run
entries, the console runs code, a worker thread can ask the user, and every view can be saved as a screenshot.
"""

# pylint: disable=protected-access,missing-class-docstring,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, ClassVar
from unittest.mock import patch

import pytest
from textual.command import CommandPalette
from textual.widgets import Button

from angrmanagement.config import Conf
from angrmanagement.data.log import LogDumpHandler
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.view_manager import default_position
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps, caps_from_environment
from angrmanagement.tui.executor import Deferred, TextualExecutor
from angrmanagement.tui.screens import ChecklistScreen, MessageScreen, QuestionScreen
from angrmanagement.tui.screens.analysis_options import AnalysisOptionsScreen
from angrmanagement.tui.screens.form import FormScreen
from angrmanagement.tui.screens.load_binary import LoadBinaryScreen
from angrmanagement.tui.screenshot import shoot, show_view
from angrmanagement.tui.views import TUI_VIEW_CLASSES
from angrmanagement.tui.widgets.menubar import MenuPopup
from angrmanagement.tui.widgets.statusbar import StatusBar
from angrmanagement.tui.xrefs import XRefsScreen

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
ELF_CART = os.path.join(test_location, "x86_64", "1after909.cart")
#: the key 1after909.cart was packed with, as in tests/dialogs/test_load_binary_cart.py
CART_KEY = b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"
SIZE = (160, 50)


def run_app(scenario: Callable[[AmApp, Pilot], Awaitable[None]], tier: int = 2, binary: str | None = FAUXWARE) -> None:
    """Run ``scenario(app, pilot)`` in a headless app, with fauxware opened unless ``binary`` is None."""

    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=tier), interactive=False)
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            if binary is not None:
                await app.open_binary(binary)
                await pilot.pause()
            await scenario(app, pilot)

    asyncio.run(main())


async def settle(pilot: Pilot, rounds: int = 3) -> None:
    for _ in range(rounds):
        await pilot.pause()


class TuiTestCase(unittest.TestCase):
    """Keeps the globals the app replaces as they were."""

    def setUp(self) -> None:
        self.saved = (GlobalInfo._executor, GlobalInfo._ui_services, GlobalInfo.main_window, Conf.frontend_adapter)
        self.saved_layout = Conf.tui_layout
        self.saved_recent = list(Conf.recent_files)

    def tearDown(self) -> None:
        executor, services, main_window, adapter = self.saved
        assert GlobalInfo._executor is executor, "the app did not give the executor back"
        assert GlobalInfo._ui_services is services, "the app did not give the UI services back"
        assert GlobalInfo.main_window is main_window
        assert Conf.frontend_adapter is adapter
        Conf.tui_layout = self.saved_layout
        Conf.recent_files = self.saved_recent


class TestStartup(TuiTestCase):
    def test_starts_and_opens_every_view(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            vm = app.workspace.view_manager
            # the default views, where the Qt workspace puts them
            assert vm.area_of(vm.first_view_in_category("functions")) == "left"
            for category in ("console", "log", "jobs", "mcp_history", "comments"):
                assert vm.area_of(vm.first_view_in_category(category)) == "bottom", category
            assert app.workspace.main_instance.kb is not None
            for category in TUI_VIEW_CLASSES:
                view: Any = await show_view(pilot, category)
                assert view is not None and view.is_attached, category
                assert vm.area_of(view) == default_position(category), category
                assert vm.current_view_in_category(category) is view
                pane_id = vm.pane_id_of(view)
                assert vm.area(vm.area_of(view) or "center").active == pane_id, category

        run_app(scenario)

    def test_categories_without_a_view_do_nothing(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            # a category the terminal has no view class for, such as a plugin's own view
            app.action_show_view("a_plugins_view")
            await settle(pilot)
            assert app.view_widget("a_plugins_view") is None

        run_app(scenario, binary=None)


class TestFunctionsTable(TuiTestCase):
    def test_filter_and_open(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("functions")
            assert view is not None
            view.table_widget.focus()
            await settle(pilot)
            total = view.presenter.model.row_count
            # a printable key in the table starts filtering
            await pilot.press("a", "u", "t", "h")
            await settle(pilot)
            assert view.table.filter_box.value == "auth"
            assert view.table_widget.row_count == 1 < total
            assert "1/40 functions" in str(view.table.status_label.render())
            # Enter in the filter box opens the first function and clears the filter
            await pilot.press("enter")
            await settle(pilot)
            disasm: Any = app.view_widget("disassembly")
            assert disasm is not None and disasm.presenter.function.am_obj.name == "authenticate"
            assert view.table.filter_box.value == ""
            assert view.table_widget.row_count == total
            # Escape clears a filter typed in the table
            view.table_widget.focus()
            await pilot.press("m", "a", "i", "n")
            await settle(pilot)
            assert view.table_widget.row_count >= 1
            await pilot.press("escape")
            await settle(pilot)
            assert view.table.filter_box.value == ""

        run_app(scenario)

    def test_a_right_click_on_the_header_hides_and_shows_columns(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("functions")
            table = view.table_widget
            names = [column.name for column in view.presenter.model.columns]
            assert len(table.columns) == len(names) > 2
            # a right click on the header row opens the column menu, a check box per column
            await pilot.click(table, offset=(2, 0), button=3)
            await settle(pilot)
            popup = app.screen
            assert isinstance(popup, MenuPopup) and popup.menu.text == "Column Menu"
            assert [entry.text for entry in popup.items] == names and all(entry.checked for entry in popup.items)
            await pilot.press("escape")
            await settle(pilot)
            hidden = names.index("Binary") if "Binary" in names else 1
            table.header_menu().items()[hidden].trigger()
            await settle(pilot)
            assert len(table.columns) == len(names) - 1
            assert [str(c.label).split(" ")[0] for c in table.columns.values()] == [
                n.split(" ")[0] for i, n in enumerate(names) if i != hidden
            ]
            # the cells follow the shown columns, and the last shown column cannot be hidden
            assert len(table.get_row_at(0)) == len(names) - 1
            for idx in range(len(names)):
                table.set_column_visible(idx, False)
            await settle(pilot)
            assert len(table.columns) == 1
            menu = table.header_menu()
            assert sum(entry.checked for entry in menu.items()) == 1
            assert not next(entry for entry in menu.items() if entry.checked).enabled
            for idx in range(len(names)):
                table.set_column_visible(idx, True)
            await settle(pilot)
            assert len(table.columns) == len(names)

        run_app(scenario)

    def test_sort_on_header_click(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("functions")
            assert view is not None
            table = view.table_widget
            model = view.presenter.model
            table.post_message(
                table.HeaderSelected(table, table.ordered_columns[3].key, 3, table.ordered_columns[3].label)
            )
            await settle(pilot)
            addrs = [f.addr for f in model.rows]
            assert addrs == sorted(addrs)
            table.post_message(
                table.HeaderSelected(table, table.ordered_columns[3].key, 3, table.ordered_columns[3].label)
            )
            await settle(pilot)
            assert [f.addr for f in model.rows] == sorted(addrs, reverse=True)
            assert "▼" in str(table.ordered_columns[3].label)

        run_app(scenario)


class TestPalettes(TuiTestCase):
    def test_command_palette_runs_a_command(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            assert app.view_widget("strings") is None
            await pilot.press("ctrl+shift+p")
            await settle(pilot)
            assert isinstance(app.screen, CommandPalette)
            await pilot.press(*"View: Strings")
            await settle(pilot, 6)
            await pilot.press("enter")
            await settle(pilot, 6)
            assert app.view_widget("strings") is not None

        run_app(scenario)

    def test_tier_zero_uses_ctrl_p(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            await pilot.press("ctrl+p")
            await settle(pilot)
            assert isinstance(app.screen, CommandPalette)
            await pilot.press("escape")
            await settle(pilot)
            keys = {binding.key for _, binding in app._bindings}
            assert "ctrl+shift+p" not in keys
            assert "alt+o" in keys  # Preferences, for Ctrl+,
            assert app.chord_for("command_palette") == "Ctrl+P"

        run_app(scenario, tier=0, binary=None)

    def test_goto_palette_finds_a_function(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.action_goto_palette()
            await settle(pilot)
            await pilot.press(*"rejected")
            await settle(pilot, 6)
            await pilot.press("enter")
            await settle(pilot, 6)
            disasm: Any = app.view_widget("disassembly")
            assert disasm is not None and disasm.presenter.function.am_obj.name == "rejected"

        run_app(scenario)


class TestMenus(TuiTestCase):
    def test_every_menu_opens_with_its_entries(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            assert app.menu_names() == ["File", "View", "Analyze", "AI", "Plugins", "Help"]
            for name in app.menu_names():
                popup = await app.open_menu(name)
                await settle(pilot)
                assert app.screen is popup and isinstance(popup, MenuPopup)
                entries = [item for item in popup.items if hasattr(item, "caption")]
                assert popup.option_list.option_count >= len(entries)
                await app.close_menu()
                await settle(pilot)
                assert not isinstance(app.screen, MenuPopup)

        run_app(scenario, binary=None)

    def test_f10_arrows_and_mnemonics(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            await pilot.press("f10")
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup) and app.screen.menu.text == "File"
            # the shortcut shown is the one bound here
            assert app.shortcut_text("Ctrl+Shift+S") == "Ctrl+Shift+S"
            await pilot.press("right")
            await settle(pilot)
            assert isinstance(app.screen, MenuPopup) and app.screen.menu.text == "View"
            await pilot.press("s")  # &Strings
            await settle(pilot, 5)
            assert not isinstance(app.screen, MenuPopup)
            assert app.view_widget("strings") is not None

        run_app(scenario)

    def test_menu_shortcuts_follow_the_tier(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            await settle(pilot)
            assert app.shortcut_text("Ctrl+Shift+P") == "Ctrl+P"
            assert app.shortcut_text("Ctrl+Tab") == "Ctrl+PgDown"
            assert app.shortcut_text("Ctrl+O") == "Ctrl+O"

        run_app(scenario, tier=0, binary=None)


class TestViewKeys(TuiTestCase):
    def test_strings_x_shows_cross_references(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = await show_view(pilot, "strings")
            model = view.presenter.model
            row = next(i for i, s in enumerate(model.rows) if model.column_text(s, 3) == "Go away!")
            view.table_widget.focus()
            view.table_widget.move_cursor(row=row)
            await settle(pilot)
            await pilot.press("x")
            await settle(pilot)
            assert isinstance(app.screen, XRefsScreen)
            assert app.screen.model.row_count >= 1
            await pilot.press("escape")
            await settle(pilot)
            assert not isinstance(app.screen, XRefsScreen)

        run_app(scenario)

    def test_log_ctrl_c_copies_the_message(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = await show_view(pilot, "log")
            model = view.presenter.model
            # the global queue listener serves only the first Instance created in the process, so emit through
            # this instance's own handler, as the listener would
            handler = LogDumpHandler(app.workspace.main_instance)
            handler.emit(
                logging.LogRecord(
                    "angrmanagement.tests", logging.WARNING, __file__, 0, "a message for the log view", None, None
                )
            )
            rows: list[int] = []
            for _ in range(100):
                await pilot.pause(0.05)
                rows = [i for i, r in enumerate(model.rows) if r.content == "a message for the log view"]
                if rows:
                    break
            assert rows
            view.table_widget.focus()
            view.table_widget.move_cursor(row=rows[0])
            await settle(pilot)
            await pilot.press("ctrl+c")
            await settle(pilot)
            assert app.services.clipboard_text() == "a message for the log view"

        run_app(scenario, binary=None)

    def test_copy_mcp_url(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.copy_mcp_url()
            await settle(pilot)
            assert app.services.clipboard_text().startswith("http://")
            assert app.status_bar.status_text.startswith("Copied")

        run_app(scenario, binary=None)


async def wait_for_screen(pilot: Pilot, kind: type[Any], title: str, timeout: float = 120) -> Any:
    # loading fauxware takes seconds, and much longer on a loaded machine
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        await pilot.pause(0.05)
        screen: Any = pilot.app.screen
        if isinstance(screen, kind) and screen.title_text == title:
            return screen
        if isinstance(screen, MessageScreen):
            raise AssertionError(f"{screen.title_text}: {screen.text}")
    raise AssertionError(f"no {title!r} screen")


async def wait_for_checklist(pilot: Pilot, title: str, timeout: float = 120) -> ChecklistScreen:
    return await wait_for_screen(pilot, ChecklistScreen, title, timeout)


async def wait_for_load_screen(pilot: Pilot, timeout: float = 120) -> LoadBinaryScreen:
    return await wait_for_screen(pilot, LoadBinaryScreen, "Load a new binary", timeout)


async def press_ok(pilot: Pilot, screen: Any) -> None:
    # a click can land before the screen is laid out on a busy machine; press the button itself
    await settle(pilot)
    screen.query_one("#ok", Button).press()


class TestInteractiveLoad(TuiTestCase):
    def test_load_asks_for_options_then_analyses(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.services.interactive = True
            app.interactive = True
            app.load_file(FAUXWARE)
            # the load job waits in its thread while the options screen is up
            screen = await wait_for_load_screen(pilot)
            assert app.workspace.main_instance.project.am_none
            await press_ok(pilot, screen)
            # then the analyses are offered, as the Qt analysis options dialog is
            await press_ok(pilot, await wait_for_screen(pilot, AnalysisOptionsScreen, "Run Analysis"))
            await app.wait_for_jobs()
            await settle(pilot)
            kb = app.workspace.main_instance.kb
            assert kb is not None and "main" in {f.name for f in kb.functions.values()}
            assert app.workspace.main_instance.project.loader.main_object.binary.endswith("fauxware")

        run_app(scenario, binary=None)

    def test_cancelling_the_options_stops_the_load(self) -> None:
        # as cancelling the Qt load dialog does: no project, and no analyses offered
        for how in ("escape", "#cancel"):
            with self.subTest(how=how):

                async def scenario(app: AmApp, pilot: Pilot, how: str = how) -> None:
                    app.services.interactive = True
                    app.interactive = True
                    app.load_file(FAUXWARE)
                    screen = await wait_for_load_screen(pilot)
                    await settle(pilot)
                    if how == "escape":
                        await pilot.press("escape")
                    else:
                        screen.query_one(how, Button).press()
                    await app.wait_for_jobs()
                    await settle(pilot)
                    assert app.workspace.main_instance.project.am_none
                    assert not isinstance(app.screen, LoadBinaryScreen)

                run_app(scenario, binary=None)

    def test_cancelling_the_analyses_runs_none(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.services.interactive = True
            app.interactive = True
            started: list[str] = []
            app.workspace.job_manager.job_starting.connect(lambda job: started.append(job.name))
            app.load_file(FAUXWARE)
            await press_ok(pilot, await wait_for_load_screen(pilot))
            await wait_for_screen(pilot, AnalysisOptionsScreen, "Run Analysis")
            await settle(pilot)
            await pilot.press("escape")
            await app.wait_for_jobs()
            await settle(pilot)
            assert not app.workspace.main_instance.project.am_none
            assert len(started) == 1, started

        run_app(scenario, binary=None)

    def test_an_encrypted_binary_asks_for_its_key(self) -> None:
        # the load job asks for the key from its thread, as the Qt SetEncryptionKeyDialog does, then loads with it
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.services.interactive = True
            app.interactive = True
            errors: list[str] = []
            app.workspace.job_manager.job_exception.connect(lambda job, ex: errors.append(f"{job.name}: {ex!r}"))
            # no key from a cart configuration file of whoever runs the tests
            with patch("angrmanagement.data.jobs.loading.load_cart_config_key", return_value=None):
                app.load_file(ELF_CART)
                prompt = await wait_for_screen(pilot, FormScreen, "Set an encryption key")
            assert not errors, errors
            assert app.workspace.main_instance.project.am_none
            prompt.editors["key"].value = CART_KEY.hex()
            await press_ok(pilot, prompt)
            await press_ok(pilot, await wait_for_load_screen(pilot))
            await wait_for_screen(pilot, AnalysisOptionsScreen, "Run Analysis")
            await settle(pilot)
            await pilot.press("escape")
            await app.wait_for_jobs()
            await settle(pilot)
            assert not errors, errors
            project = app.workspace.main_instance.project
            assert not project.am_none
            assert project.loader.main_object.__class__.__name__ == "ELF"
            assert project.loader.original_main_object.__class__.__name__ == "CARTFile"

        run_app(scenario, binary=None)

    @pytest.mark.timeout(180)
    def test_exit_while_the_options_screen_is_up(self) -> None:
        # the load job waits for the screen in its thread; exiting must answer it, not wait for it
        worker: list[threading.Thread] = []

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.services.interactive = True
            app.interactive = True
            app.load_file(FAUXWARE)
            await wait_for_load_screen(pilot)
            worker.append(app.workspace.job_manager._worker_thread)
            app.exit()

        run_app(scenario, binary=None)
        assert worker and not worker[0].is_alive()


class TestJobErrors(TuiTestCase):
    def test_a_failing_job_is_reported(self) -> None:
        from angrmanagement.data.jobs.job import Job  # pylint: disable=import-outside-toplevel

        class Failing(Job):
            def run(self, ctx):
                raise RuntimeError("this job always fails")

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.workspace.job_manager.add_job(Failing("Failing job"))
            await app.wait_for_jobs()
            await settle(pilot)
            assert isinstance(app.screen, MessageScreen)
            assert "Failing job" in app.screen.title_text and "this job always fails" in app.screen.text
            assert not app.workspace.job_manager.jobs

        run_app(scenario, binary=None)


class _ExitProbe(StatusBar):
    """Delivers job signals as the app removes the bar, and records what that raised."""

    seen: ClassVar[list[str]] = []

    def on_unmount(self) -> None:
        job = SimpleNamespace(name="CFG generation")
        app: Any = self.app
        self.seen.append(f"parts left: {len(self.children)}")
        for deliver in (
            lambda: app._on_job_starting(job),
            lambda: app._on_job_progress(job, 50.0, "half"),
            lambda: app._on_job_finished(job),
            lambda: self.show_message("done"),
            self._clear_message,
        ):
            try:
                deliver()
            except Exception as ex:  # pylint: disable=broad-exception-caught
                self.seen.append(repr(ex))


class TestExit(TuiTestCase):
    def test_job_signals_while_the_app_exits(self) -> None:
        # a job signal queued before the exit can be delivered while the app removes the status bar's parts
        for how in ("exit", "teardown"):
            with self.subTest(how=how):
                _ExitProbe.seen.clear()

                async def scenario(app: AmApp, pilot: Pilot, how: str = how) -> None:
                    # with no job running, the bar shows no progress
                    assert not app.status_bar.query_one("#status-progress").display
                    app.status_bar.__class__ = _ExitProbe
                    if how == "exit":
                        app.exit()

                run_app(scenario, binary=None)
                assert _ExitProbe.seen == ["parts left: 0"], _ExitProbe.seen

    def test_job_signals_before_the_bar_is_mounted(self) -> None:
        # the parts do not exist yet, so there is nothing to update and nothing raises
        bar = StatusBar()
        bar.progress("CFG generation", 10.0)
        assert bar.status_text == "CFG generation"
        bar.progress_done()
        bar.show_message("done")
        bar._clear_message()
        assert bar.status_text == ""


class TestConsole(TuiTestCase):
    def test_runs_code_in_the_workspace_namespace(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = await show_view(pilot, "console")
            assert view is not None and view.ipython_widget_available
            view.input.focus()
            await pilot.press(*"hex(project.entry)")
            await pilot.press("enter")
            await settle(pilot)
            text = "\n".join(line.text for line in view.output.lines)
            assert hex(app.workspace.main_instance.project.entry) in text
            # history
            await pilot.press("up")
            assert view.input.value == "hex(project.entry)"

        run_app(scenario)

    def test_the_kernel_keeps_its_history_out_of_the_users_profile(self) -> None:
        # conftest gives each test process its own IPYTHONDIR; workers sharing one history.sqlite race to rename it
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = await show_view(pilot, "console")
            assert view is not None and view.ipython_widget_available
            hist_file = os.path.realpath(view.presenter.kernel_manager.kernel.shell.history_manager.hist_file)
            ipython_dir = os.path.realpath(os.environ["IPYTHONDIR"])
            assert hist_file.startswith(ipython_dir + os.sep)
            assert not hist_file.startswith(os.path.realpath(os.path.expanduser("~/.ipython")) + os.sep)

        run_app(scenario)


class TestServices(TuiTestCase):
    def test_a_worker_thread_waits_for_the_answer(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.services.interactive = True
            answers: list[str] = []
            thread = threading.Thread(
                target=lambda: answers.append(app.services.question("Q", "Go?", ["Yes", "No"], "No")), daemon=True
            )
            thread.start()
            for _ in range(50):
                await pilot.pause(0.02)
                if isinstance(app.screen, QuestionScreen):
                    break
            assert isinstance(app.screen, QuestionScreen)
            assert thread.is_alive(), "the thread did not wait"
            await pilot.click("#button-0")
            await settle(pilot)
            thread.join(5)
            assert answers == ["Yes"]

        run_app(scenario, binary=None)

    def test_exit_while_a_screen_mounts(self) -> None:
        # the app may tear a modal screen down before its children are there; focusing them must not fail
        errors: list[BaseException] = []

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.services.interactive = True
            original = app._handle_exception

            def record(error: Exception) -> None:
                errors.append(error)
                original(error)

            app._handle_exception = record  # type: ignore[method-assign]
            app.push_screen(ChecklistScreen("Load a binary", "text", [("a", True)]))
            app.exit()

        run_app(scenario, binary=None)
        assert not errors, errors

    def test_a_question_on_the_ui_thread_says_it_was_not_asked(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.services.interactive = True
            notices: list[str] = []
            app.notify = lambda message, **kwargs: notices.append(str(message))  # type: ignore[method-assign]
            assert app.services.question("Q", "Go?", ["Yes", "No"], "No") == "No"
            assert notices and "could not be shown" in notices[0]

        run_app(scenario, binary=None)

    def test_closing_the_executor_answers_a_waiting_thread(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            executor = app.executor
            never: asyncio.Future = asyncio.get_running_loop().create_future()
            answers: list[Any] = []
            thread = threading.Thread(
                target=lambda: answers.append(executor.schedule(lambda: Deferred(never, "cancelled"))), daemon=True
            )
            thread.start()
            for _ in range(50):
                await pilot.pause(0.02)
                if executor._waiting and next(iter(executor._waiting)).deferred is not None:
                    break
            executor.close()
            thread.join(5)
            assert answers == ["cancelled"]
            # later calls from a thread do not wait either
            late: list[Any] = []
            thread = threading.Thread(target=lambda: late.append(executor.schedule(lambda: 1)), daemon=True)
            thread.start()
            thread.join(5)
            assert late == [None]
            executor.attach()

        run_app(scenario, binary=None)

    def test_executor_runs_calls_on_the_loop(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            executor = GlobalInfo.executor
            assert isinstance(executor, TextualExecutor) and executor.is_ui_thread()
            seen: list[bool] = []
            result: list[int] = []

            def work() -> None:
                result.append(executor.schedule(lambda: seen.append(executor.is_ui_thread()) or 7))

            thread = threading.Thread(target=work)
            thread.start()
            for _ in range(50):
                await pilot.pause(0.02)
                if result:
                    break
            thread.join(5)
            assert seen == [True] and result == [7]

        run_app(scenario, binary=None)


class TestLayout(TuiTestCase):
    def test_bottom_area_and_resizing(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            vm = app.workspace.view_manager
            assert not vm.area("bottom").display  # hidden, as the Qt bottom docks are
            assert app.query_one("#bottom-strip").display
            await pilot.press("f12")
            await settle(pilot)
            assert vm.area("bottom").display
            width = vm.layout["left"]
            await pilot.press("ctrl+shift+right")
            await settle(pilot)
            assert vm.layout["left"] == width + 4
            assert json.loads(Conf.tui_layout)["left"] == width + 4

        run_app(scenario, binary=None)


class TestThemes(TuiTestCase):
    def test_switching_the_scheme_recolours_the_tables(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("functions")
            assert app.theme == "am-light" and not app.am_theme.is_dark
            row = next(i for i, f in enumerate(view.presenter.model.rows) if f.name == "main")
            light = view.table_widget.get_row_at(row)[1].style.color
            app.theme = "am-dark"
            await settle(pilot)
            assert app.am_theme.is_dark and app.scheme_name == "Dark"
            dark = view.table_widget.get_row_at(row)[1].style.color
            assert light != dark
            assert {name for name in app.available_themes if name.startswith("am-")} >= {
                "am-light",
                "am-dark",
                "am-dracula",
                "am-catppuccin-mocha",
                "am-custom",
            }

        run_app(scenario)


class TestScreenshots(TuiTestCase):
    def test_every_view_is_saved(self) -> None:
        with tempfile.TemporaryDirectory() as outdir:
            written = asyncio.run(shoot(outdir, FAUXWARE, size=(140, 45)))
            names = sorted(os.path.basename(path) for path in written)
            assert names == sorted(["window.svg"] + [f"{category}.svg" for category in TUI_VIEW_CLASSES])
            with open(os.path.join(outdir, "functions.svg"), encoding="utf-8") as f:
                svg = f.read()
            assert "authenticate" in svg and "Filter&#160;by&#160;name" in svg


class TestCaps(unittest.TestCase):
    def test_environment(self) -> None:
        assert caps_from_environment({"KITTY_WINDOW_ID": "1"}).tier == 3
        assert caps_from_environment({"COLORTERM": "truecolor"}).tier == 1
        assert caps_from_environment({}).tier == 0
        assert caps_from_environment({"TERM_PROGRAM": "WezTerm"}).kitty_keyboard
        assert caps_from_environment({"AM_TUI_TIER": "2"}).tier == 2

    def test_replies(self) -> None:
        from angrmanagement.tui.caps import parse_replies  # pylint: disable=import-outside-toplevel

        caps = parse_replies(TerminalCaps(), b"\x1bP>|foot(1.16)\x1b\\\x1b[?1u\x1b_Gi=31;OK\x1b\\\x1b[?62;4;22c")
        assert caps.version == "foot(1.16)" and caps.kitty_keyboard and caps.kitty_graphics and caps.sixel
        assert caps.tier == 3


if __name__ == "__main__":
    unittest.main()
