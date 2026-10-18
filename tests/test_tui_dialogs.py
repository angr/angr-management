"""
The terminal's dialogs, on fauxware from angr/binaries: Run Analysis (the analyses, their descriptions and option
sheets, the language questions), the forms of the small Qt dialogs (Jump to, Rename Label, Set Comment, Edit
Breakpoint, Assemble Patch, Change hook, Function Documentation, Function), and the rest of phase 5's screens.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import tempfile
import threading
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import angr
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    Label,
    OptionList,
    RadioButton,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TextArea,
    Tree,
)
from tui_pilot import kb_of, settle  # pylint: disable=import-error

import angrmanagement
from angrmanagement.config import Conf
from angrmanagement.config.color import Color
from angrmanagement.data.analysis_options import AnalysesConfiguration
from angrmanagement.data.breakpoint import BreakpointType
from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import (
    OverviewConfiguration,
    RustSymbolRecoveryConfiguration,
    RustTypeDBLoaderConfiguration,
)
from angrmanagement.logic import GlobalInfo
from angrmanagement.present.analysis_options import RUST_DEPENDENT_ANALYSES
from angrmanagement.present.dialogs import hook_templates
from angrmanagement.present.preferences import PAGE_NAMES, color_entry_names, color_text, scheme_entry_values
from angrmanagement.tui.app import AmApp, config_file_path
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.executor import TextualExecutor
from angrmanagement.tui.screens import FilePickerScreen, MessageScreen, PromptScreen, QuestionScreen
from angrmanagement.tui.screens.about import AboutScreen
from angrmanagement.tui.screens.analysis_options import AnalysisOptionsScreen
from angrmanagement.tui.screens.archive import ArchiveScreen
from angrmanagement.tui.screens.form import FormScreen
from angrmanagement.tui.screens.plugins import PluginsScreen
from angrmanagement.tui.screens.preferences import PreferencesScreen
from angrmanagement.tui.screens.progress import ProgressScreen
from angrmanagement.tui.screens.signature_matches import SignatureMatchesScreen
from angrmanagement.tui.screens.welcome import WelcomeScreen
from angrmanagement.tui.widgets.picture import image_module

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
SIZE = (160, 50)


def run_app(
    scenario: Callable[[AmApp, Pilot], Awaitable[None]],
    binary: str | None = FAUXWARE,
    tier: int = 2,
    interactive: bool = False,
) -> None:
    """Run ``scenario(app, pilot)`` in a headless app, with fauxware opened unless ``binary`` is None."""

    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=tier), interactive=False)
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            if binary is not None:
                await app.open_binary(binary)
                await pilot.pause()
            # ask through the screens from here on
            app.services.interactive = interactive
            await scenario(app, pilot)

    asyncio.run(main())


async def show_view(app: AmApp, pilot: Pilot, category: str) -> Any:
    app.workspace.show_view(category)
    for _ in range(50):
        view = app.view_widget(category)
        if view is not None and view.is_attached:
            return view
        await pilot.pause()
    raise AssertionError(f"no {category} view")


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
        assert (GlobalInfo._ui_services, GlobalInfo.main_window) == self.saved[1:3]
        assert not isinstance(GlobalInfo._executor, TextualExecutor), "the app did not give the executor back"
        # setting an entry outside the app announces it through an executor made for the purpose
        GlobalInfo._executor = self.saved[0]


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
            project: Any = instance.project.am_obj
            assert project._languages == ["rust"]
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
        for name, value in self.saved_entries.items():
            setattr(Conf, name, value)
        super().tearDown()

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


async def answer_form(pilot: Pilot, title: str, values: dict[str, Any], ok: bool = True) -> FormScreen:
    """Wait for the form ``title``, type ``values`` into it, and press OK (if ``ok``)."""
    screen = await wait_for_screen(pilot, FormScreen)
    assert screen.title_text == title, screen.title_text
    for key, value in values.items():
        editor = screen.editors[key]
        if isinstance(editor, (Input, TextArea, Checkbox)) and not isinstance(value, bool):
            if isinstance(editor, TextArea):
                editor.load_text(value)
            else:
                editor.value = value
        else:
            screen.set_value(key, value)
            screen._changed(editor)
    await settle(pilot)
    if ok:
        screen.query_one("#ok", Button).press()
        await settle(pilot)
    return screen


def status_of(screen: FormScreen) -> str:
    return str(screen.query_one("#status").render())


class TestForms(DialogCase):
    """The small Qt dialogs, shown as forms by the terminal's disassembly view and workspace."""

    MAIN = 0x40071D
    CALL_PUTS = 0x400739

    def test_set_comment_takes_several_lines(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("disassembly")
            view.presenter.infodock.select_instruction(self.MAIN + 1)
            view.presenter.popup_comment_dialog()
            await answer_form(pilot, "Set Comment", {"comment": "first line\nsecond line\n"})
            assert kb_of(app).comments[self.MAIN + 1] == "first line\nsecond line"

        run_app(scenario, interactive=True)

    def test_rename_label_refuses_a_name_with_a_space(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("disassembly")
            kb = kb_of(app)
            view.presenter.infodock.select_label(self.CALL_PUTS)
            view.presenter.popup_rename_label_dialog()
            screen = await answer_form(pilot, f"Rename Label at {self.CALL_PUTS:#08x}", {"name": "a b"}, ok=False)
            assert status_of(screen) == "Invalid" and screen.query_one("#ok", Button).disabled
            await answer_form(pilot, f"Rename Label at {self.CALL_PUTS:#08x}", {"name": "before_puts"})
            assert kb.labels.get(self.CALL_PUTS) == "before_puts"

        run_app(scenario, interactive=True)

    def test_assemble_patch_shows_the_bytes_and_pads(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("disassembly")
            view.presenter.infodock.select_instruction(self.CALL_PUTS)
            view.presenter.popup_patch_dialog()
            title = f"Assemble Patch at {self.CALL_PUTS:#x}"
            screen = await answer_form(pilot, title, {}, ok=False)
            # the instruction there, and its bytes
            asm_editor: Any = screen.editors["asm"]
            assert asm_editor.value == "call 0x400510"
            screen = await answer_form(pilot, title, {"asm": "nop"}, ok=False)
            assert screen.values["bytes"] == "90 90 90 90 90"
            screen = await answer_form(pilot, title, {"pad": False}, ok=False)
            assert screen.values["bytes"] == "90"
            assert status_of(screen) == "Warning: Patch is shorter than original instruction"
            screen = await answer_form(pilot, title, {"asm": "not an instruction"}, ok=False)
            assert status_of(screen).startswith("Error:") and screen.query_one("#ok", Button).disabled
            await answer_form(pilot, title, {"asm": "nop", "pad": True})
            patches = app.workspace.main_instance.project.kb.patches
            assert patches.get_patch(self.CALL_PUTS).new_bytes == b"\x90" * 5

        run_app(scenario, interactive=True)

    def test_change_hook_appends_the_preset_to_the_console(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("disassembly")
            view.presenter.popup_hook_dialog(self.MAIN)
            screen = await answer_form(pilot, "Change hook", {"preset": "assertion"}, ok=False)
            assert screen.values["code"] == hook_templates(self.MAIN)["assertion"]
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            console: Any = app.workspace.view_manager.first_view_in_category("console")
            assert console.input.value == hook_templates(self.MAIN)["assertion"]

        run_app(scenario, interactive=True)

    def test_function_documentation_of_a_call(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = app.view_widget("disassembly")
            for _ in range(50):
                if view.presenter.instruction_at(self.CALL_PUTS) is not None:
                    break
                await pilot.pause()
            view.presenter.popup_func_doc_dialog(self.CALL_PUTS)
            screen = await wait_for_screen(pilot, FormScreen)
            assert screen.title_text == "Function Documentation"
            texts = [str(widget.render()) for widget in screen.query(Static)]
            assert "Function at address 0x400510: puts" in texts
            assert any(text.startswith("Type: ") for text in texts)
            url = screen.editors["url"]
            assert "link" in str(url.render().spans[0].style)

        run_app(scenario, interactive=True)

    def test_edit_breakpoint_checks_the_address_and_size(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            view: Any = await show_view(app, pilot, "breakpoints")
            view.presenter.new_breakpoint()
            title = "Edit Breakpoint"
            screen = await answer_form(pilot, title, {"addr": "no_such_function"}, ok=False)
            assert status_of(screen) == "Invalid"
            # a function's name is an address, as in the Qt dialog's address box
            await answer_form(pilot, title, {"type": BreakpointType.Write, "addr": "main", "size": "0x8"})
            (bp,) = app.workspace.main_instance.breakpoint_mgr.breakpoints
            assert (bp.type, bp.addr, bp.size) == (BreakpointType.Write, self.MAIN, 8)

        run_app(scenario, interactive=True)

    def test_function_information_and_its_actions(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            app.workspace.show_function_info("authenticate")
            screen = await wait_for_screen(pilot, FormScreen)
            assert screen.title_text == "Function authenticate"
            labels = [f.label for f in screen.form.fields]
            assert labels[:3] == ["Name", "Address", "Binary"] and "Variadic" in labels
            assert [a.caption for a in screen.form.actions] == [
                "&Decompile",
                "Dis&assemble",
                "Show &Xrefs",
                "Show &Strings",
            ]
            screen.query_one("#action-1", Button).press()
            await settle(pilot)
            view: Any = app.view_widget("disassembly")
            assert view.presenter.function.am_obj.name == "authenticate"
            assert not isinstance(app.screen, FormScreen)

        run_app(scenario, interactive=True)


ZIP_PATH = os.path.join(test_location, "x86_64", "test_zip_archive.zip")
ENC_ZIP_PATH = os.path.join(test_location, "x86_64", "test_enc_zip_archive.zip")
ENC_ZIP_PASSWORD = "infected"


class TestSmallScreens(DialogCase):
    def test_about_draws_the_logo_as_a_picture_only_on_tier_3(self) -> None:
        for tier in (0, 2, 3):
            with self.subTest(tier=tier):

                async def scenario(app: AmApp, pilot: Pilot, tier: int = tier) -> None:
                    app.open_about_dialog()
                    screen = await wait_for_screen(pilot, AboutScreen)
                    logo = screen.query_one("#logo")
                    module = image_module()
                    if tier == 3 and module is not None:
                        assert isinstance(logo, module.Image), type(logo)
                    else:
                        assert isinstance(logo, Static) and "|___/" in str(logo.render())
                    assert angrmanagement.__version__ in str(screen.query_one("#version").render())
                    credits_label = screen.query_one("#credits", Label)
                    assert "link http://angr.io/" in str(credits_label.render().spans[0].style)
                    await pilot.press("escape")
                    await settle(pilot)
                    assert not isinstance(app.screen, AboutScreen)

                run_app(scenario, binary=None, tier=tier)

    def test_welcome_lists_the_recent_projects_and_opens_one(self) -> None:
        saved = list(Conf.recent_files)
        Conf.recent_files = [ZIP_PATH, FAUXWARE]
        try:

            async def scenario(app: AmApp, pilot: Pilot) -> None:
                opened: list[str] = []
                app.load_file = opened.append  # type: ignore[method-assign]
                app.show_welcome_dialog()
                screen = await wait_for_screen(pilot, WelcomeScreen)
                recent = screen.query_one("#recent", OptionList)
                # the most recent first
                assert [str(recent.get_option_at_index(i).prompt) for i in range(recent.option_count)] == [
                    "fauxware",
                    "test_zip_archive.zip",
                ]
                recent.highlighted = 0
                recent.action_select()
                await settle(pilot)
                assert opened == [FAUXWARE]
                # the Getting Started buttons
                about: list[bool] = []
                app.open_about_dialog = lambda: about.append(True)  # type: ignore[method-assign]
                app.show_welcome_dialog()
                screen = await wait_for_screen(pilot, WelcomeScreen)
                screen.query_one("#about", Button).press()
                await settle(pilot)
                assert about == [True]

            run_app(scenario, binary=None)
        finally:
            Conf.recent_files = saved

    def test_an_archive_entry_is_extracted_and_loaded(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            started: list[Any] = []
            app.workspace.job_manager.add_job = started.append  # type: ignore[method-assign]
            app.load_file(ENC_ZIP_PATH)
            screen = await wait_for_screen(pilot, ArchiveScreen)
            tree = screen.query_one("#members", Tree)
            assert screen.query_one("#ok", Button).disabled
            leaf = next(node for node in tree.root.children if node.data is not None)
            tree.move_cursor(leaf)
            await settle(pilot)
            assert not screen.query_one("#ok", Button).disabled
            screen.query_one("#ok", Button).press()
            # an encrypted entry: a wrong password is refused and asked again
            prompt = await wait_for_screen(pilot, PromptScreen)
            assert prompt.title_text == "Archive Password" and prompt.password
            prompt.query_one("#answer", Input).value = "wrong"
            prompt.query_one("#ok", Button).press()
            message = await wait_for_screen(pilot, MessageScreen)
            assert message.title_text == "Incorrect Password"
            message.dismiss(None)
            prompt = await wait_for_screen(pilot, PromptScreen)
            prompt.query_one("#answer", Input).value = ENC_ZIP_PASSWORD
            prompt.query_one("#ok", Button).press()
            for _ in range(100):
                if started:
                    break
                await pilot.pause()
            assert len(started) == 1
            path = started[0].fname
            assert os.path.isfile(path) and os.path.basename(path) == "fauxware"
            assert app.workspace.main_instance.binary_path == path
            assert app.workspace.main_instance.original_binary_path == ENC_ZIP_PATH

        run_app(scenario, binary=None)

    def test_manage_plugins_turns_a_plugin_on_and_off(self) -> None:
        saved = Conf.enabled_plugins

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            pm = app.workspace.plugins
            pm.discover_and_initialize_plugins()
            assert "memory_checker" not in pm.active_plugins
            app.open_load_plugins_dialog()
            screen = await wait_for_screen(pilot, PluginsScreen)
            plugins = screen.query_one("#plugins", SelectionList)
            assert plugins.option_count == len(pm.loaded_plugins)
            plugins.select("memory_checker")
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            assert pm.get_plugin_instance_by_name("memory_checker") is not None
            assert "memory_checker" in Conf.enabled_plugins
            app.open_load_plugins_dialog()
            screen = await wait_for_screen(pilot, PluginsScreen)
            assert "memory_checker" in screen.query_one("#plugins", SelectionList).selected
            screen.query_one("#plugins", SelectionList).deselect("memory_checker")
            screen.query_one("#ok", Button).press()
            await settle(pilot)
            assert pm.get_plugin_instance_by_name("memory_checker") is None

        try:
            run_app(scenario, binary=None)
        finally:
            Conf.enabled_plugins = saved

    def test_signature_matches_apply_and_keep_conflicting_names(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            kb = kb_of(app)
            main = kb.functions["main"]
            sub = next(f for f in kb.functions.values() if f.is_default_name)
            matches = {main.addr: "not_main", sub.addr: "from_the_signature"}
            applied: list[Any] = []

            class Manager:
                """Records what would be applied."""

                @staticmethod
                def apply_signatures(sigs, dry_run, ignore_addresses):
                    applied.append((sigs, dry_run, ignore_addresses))

            sig = SimpleNamespace(sig_name="a signature")
            view: Any = await show_view(app, pilot, "signatures")
            view.presenter.signature_mgr = Manager()
            view.presenter.show_matches(sig, matches)
            screen = await wait_for_screen(pilot, SignatureMatchesScreen)
            assert screen.title_text == "Signature Matches: a signature"
            # main has a name of its own: a conflict
            assert str(screen.query_one("#conflicts").render()) == "Conflict Resolution (1/2 conflicts)"
            table = screen.query_one("#matches", DataTable)
            assert [str(table.get_cell_at((row, 2))) for row in range(table.row_count)] == ["✓", ""] or [
                str(table.get_cell_at((row, 2))) for row in range(table.row_count)
            ] == ["", "✓"]
            screen.query_one("#ignore", RadioButton).value = True
            screen.query_one("#apply", Button).press()
            await settle(pilot)
            assert applied == [([sig], False, {main.addr})]

        run_app(scenario)

    def test_a_blocking_job_shows_the_progress_screen_and_cancel_interrupts_it(self) -> None:
        from angrmanagement.data.jobs.job import Job  # pylint: disable=import-outside-toplevel

        release = threading.Event()

        class Blocking(Job):
            """A blocking job that waits until it is let go or interrupted."""

            def __init__(self) -> None:
                super().__init__("A blocking job")
                self.blocking = True

            def run(self, ctx):
                ctx.set_progress(40, "halfway")
                for _ in range(400):
                    if release.wait(0.05):
                        return

        async def scenario(app: AmApp, pilot: Pilot) -> None:
            interrupted: list[bool] = []
            manager = app.workspace.job_manager
            original = manager.interrupt_current_job

            def interrupt() -> None:
                interrupted.append(True)
                release.set()
                original()

            manager.interrupt_current_job = interrupt  # type: ignore[method-assign]
            manager.add_job(Blocking())
            screen = await wait_for_screen(pilot, ProgressScreen)
            for _ in range(100):
                if "halfway" in screen.text:
                    break
                await pilot.pause(0.05)
            assert screen.text == "A blocking job: halfway"
            screen.query_one("#cancel", Button).press()
            await app.wait_for_jobs()
            await settle(pilot)
            assert interrupted == [True]
            assert not isinstance(app.screen, ProgressScreen) and app.progress_screen is None

        run_app(scenario, binary=None)


class TestDirectoryPicker(DialogCase):
    def test_a_symbolic_link_is_resolved_only_when_asked(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            real = os.path.join(root, "real")
            link = os.path.join(root, "link")
            os.mkdir(real)
            os.symlink(real, link)
            answers: list[str | None] = []

            async def scenario(app: AmApp, pilot: Pilot) -> None:
                for resolve in (False, True):
                    app.services.pick_directory_async("Directory", root, answers.append, resolve_symlinks=resolve)
                    picker = await wait_for_screen(pilot, FilePickerScreen)
                    picker.query_one("#path", Input).value = link
                    picker.query_one("#ok", Button).press()
                    for _ in range(100):
                        if not isinstance(app.screen, FilePickerScreen):
                            break
                        await pilot.pause()
                    await settle(pilot)

            run_app(scenario, binary=None, interactive=True)
            assert answers == [link, os.path.realpath(real)]


if __name__ == "__main__":
    unittest.main()
