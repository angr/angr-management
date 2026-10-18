"""
The bundled plugins in the terminal, on fauxware from angr/binaries: each is enabled and its menu entry, context menu
entry, view or hooks exercised, as the Qt frontend shows them.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import functools
import json
import os
import re
import tempfile
import unittest
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

from angr.analyses.decompiler.structured_codegen import FunctionCallNode
from headless import run_without_qt  # pylint: disable=import-error
from textual.widgets import Button, Input
from tui_pilot import kb_of, settle  # pylint: disable=import-error
from tui_pilot import wait_for as wait_until  # pylint: disable=import-error

from angrmanagement.config import Conf
from angrmanagement.config.color import Color
from angrmanagement.logic import GlobalInfo
from angrmanagement.present.menus import MenuEntry, walk_entries
from angrmanagement.present.symexec import open_new_state
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.executor import TextualExecutor
from angrmanagement.tui.new_state import NewStateScreen
from angrmanagement.tui.screens import FilePickerScreen, MessageScreen, PromptScreen
from angrmanagement.tui.screens.form import FormScreen
from angrmanagement.tui.screens.load_binary import LoadBinaryScreen
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


#: the plugins' views take longer to come up than the app's own, and are let settle once there
wait_for = functools.partial(wait_until, rounds=400, then_settle=4)


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
            kb = kb_of(app)
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
            app.workspace.decompile_function(kb_of(app).functions["main"])
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
            main = kb_of(app).functions["main"]
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
            action = active[0].action
            assert action is not None
            action()
            popup = await wait_for_screen(pilot, MenuPopup)
            assert [getattr(item, "caption", None) for item in popup.items] == ["Select", "Move To"]

        run_app(scenario)


class TestTraceViewer(PluginCase):
    def test_a_trace_opened_from_the_menu_shows_in_the_strip_the_marks_and_the_functions(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            plugin = await enable(app, pilot, "trace_viewer")
            disasm: Any = app.view_widget("disassembly")
            strip = next(w for w in disasm.plugin_widgets if type(w).__name__ == "TraceStrip")
            assert not strip.display
            kb = kb_of(app)
            main = kb.functions["main"]
            blocks = sorted(main.block_addrs_set)
            # a basic block trace of main, in the plugin's JSON form, at the binary's own base address
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "main.json")
                with open(path, "w", encoding="utf-8") as f:
                    trace = {"bb_addrs": blocks, "syscalls": [], "id": "t1", "created_at": "", "input_id": "i1"}
                    json.dump({**trace, "complete": True}, f)
                await pick_menu_entry(app, pilot, "Plugins", "Open/Add trace...")
                picker = await wait_for_screen(pilot, FilePickerScreen)
                picker.query_one("#path", Input).value = path
                picker.query_one("#ok", Button).press()
                prompt = await wait_for_screen(pilot, PromptScreen)
                assert prompt.title_text == "Input Trace Base Address"
                prompt.query_one("#answer", Input).value = "0x400000"
                prompt.query_one("#ok", Button).press()
                await wait_for(pilot, lambda: not plugin.trace.am_none)
            assert plugin.trace.count == len(blocks)
            # the strip beside the graph, the marks on the instructions, and the coverage of the function
            await wait_for(pilot, lambda: strip.display)
            assert "Trace t1" in str(strip.render_line(0).text)
            # as in Qt, the block colours and the marks are the heat map's: H switches it on
            assert not app.workspace.plugins.decorate_insn(main.addr, disasm)
            strip.action_heatmap()
            await settle(pilot)
            marks = app.workspace.plugins.decorate_insn(main.addr, disasm)
            assert [m.text for m in marks if m.style_key == "disasm.mark.trace"] == ["1×"]
            assert app.workspace.plugins.block_style(main.addr) is not None
            assert app.workspace.plugins.func_style(main) is not None
            functions: Any = app.view_widget("functions")
            model = functions.presenter.model
            col = [c.name for c in model.columns].index("Coverage")
            row = next(i for i, func in enumerate(model.rows) if func.addr == main.addr)
            assert model.cell(row, col).text.endswith("%")
            # a click on the strip goes to that point of the trace
            strip.go_to(len(blocks) - 1)
            await settle(pilot)
            assert disasm.infodock.selected_insns == set(
                app.workspace.main_instance.project.factory.block(blocks[-1]).instruction_addrs
            )
            await pick_menu_entry(app, pilot, "Plugins", "Clear trace")
            assert plugin.trace.am_none

        run_app(scenario)


#: small and dynamically linked, so its analyses take seconds (the static langdetect_gcc_dwarf takes minutes)
DWARF = os.path.join(test_location, "x86_64", "langdetect_gcc_dwarf_dyn")
#: what the debug information's source file held, which is not on this machine (it names where the binary was built)
HELLO_SOURCE = (
    "\n".join(f"/* line {i} */" for i in range(1, 6)) + '\nint main() { puts("hello"); // greet\n  return 0;\n}\n'
)


class TestSourceViewer(PluginCase):
    def test_the_source_tabs_markers_and_comment(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            plugin = await enable(app, pilot, "source_viewer")
            view: Any = plugin.source_viewer
            await wait_for(pilot, lambda: bool(view.files))
            # the file is not here; the view reads it again with the text it held
            view.presenter.read_source = lambda _path: HELLO_SOURCE
            view.load_from_project()
            await settle(pilot)
            assert view in app.workspace.view_manager.views
            presenter = view.presenter
            assert presenter.source_map.file_list == {"/workspace/angr/hello_gcc.c"}
            widget = view.files["/workspace/angr/hello_gcc.c"]
            valid = presenter.source_map.valid_lines(widget.filename)
            assert 6 in valid
            # the marker menu on a line with code, as the Qt marker panel's
            app.workspace.show_view("symexec")
            await settle(pilot)
            widget.cursor_line = 6
            widget.action_marker_menu()
            popup = await wait_for_screen(pilot, MenuPopup)
            assert [getattr(item, "text", None) for item in popup.items][:2] == ["Add Find", "Add Avoid"]
            entry = popup.items[0]
            popup.close_all()
            entry.trigger()
            await settle(pilot)
            assert presenter.markers == {(widget.filename, 6): "find"}
            symexec: Any = app.view_widget("symexec")
            addrs = presenter.source_map.line_to_addr[(widget.filename, 6)]
            assert set(addrs) <= set(symexec.presenter.simgrs.find_addrs)
            app.workspace.raise_view(view)
            await wait_for(pilot, lambda: widget.size.width > 0)
            widget.scroll_to(y=0, animate=False)
            await settle(pilot)
            assert " F " in str(widget.render_line(5).text)
            # / edits the line's comment
            widget.action_comment()
            prompt = await wait_for_screen(pilot, PromptScreen)
            assert prompt.default == " greet"
            prompt.query_one("#answer", Input).value = " say hello"
            prompt.query_one("#ok", Button).press()
            await settle(pilot)
            assert widget.lines[5].endswith("// say hello")

        run_app(scenario, binary=DWARF)


BINDIFF_A = os.path.join(test_location, "x86_64", "bindiff_a")
BINDIFF_B = os.path.join(test_location, "x86_64", "bindiff_b")


class TestPreciseDiffing(PluginCase):
    def test_settings_load_a_revised_binary_and_the_two_diff_views(self) -> None:
        async def scenario(app: AmApp, pilot: Pilot) -> None:
            plugin = await enable(app, pilot, "precise_diff")
            # the settings dialog, as a form
            await pick_menu_entry(app, pilot, "Plugins", "Precise Diffing settings...")
            form = await wait_for_screen(pilot, FormScreen)
            assert form.title_text == "Precise Diff Settings"
            assert form.values["chg_color"] == "0xfff4ecc2"
            form.editors["ignore_globals"].value = False
            form.query_one("#ok", Button).press()
            await settle(pilot)
            assert plugin.ignore_globals is False
            # the revised binary: picked, then loaded through the load screen, as in Qt
            await pick_menu_entry(app, pilot, "Plugins", "Load binary for Precise Diffing...")
            picker = await wait_for_screen(pilot, FilePickerScreen)
            picker.query_one("#path", Input).value = BINDIFF_B
            picker.query_one("#ok", Button).press()
            load = await wait_for_screen(pilot, LoadBinaryScreen)
            load.query_one("#ok", Button).press()
            await wait_until(pilot, lambda: plugin.current_revised_code is not None, rounds=3000, then_settle=4)
            await app.wait_for_jobs()
            await settle(pilot)
            vm = app.workspace.view_manager
            assert vm.first_view_in_category("diff") is plugin.current_revised_view
            assert vm.first_view_in_category("pseudocode_diff") is plugin.current_revised_code
            assert plugin.current_revised_view.instance is plugin.diff_instance
            # the revised view shows the original's function, coloured by the diff
            original: Any = vm.first_view_in_category("disassembly")
            revised: Any = plugin.current_revised_view
            assert revised.current_function.am_obj.name == original.current_function.am_obj.name
            # the functions that differ are coloured in the functions table
            assert plugin._differing_funcs
            differing = sorted(plugin._differing_funcs, key=lambda f: f.addr)[0]
            assert app.workspace.plugins.func_style(differing) == plugin.chg_color
            # showing one in the original view shows its revision beside it, coloured by the diff
            original.display_function(differing)
            await wait_for(pilot, lambda: revised.current_function.am_obj.name == differing.name)
            func = revised.current_function.am_obj
            addrs = [a for b in func.blocks for a in b.instruction_addrs]
            styles = {app.workspace.plugins.insn_style(a, False, revised) for a in addrs}
            assert styles - {None}, "no instruction is coloured as changed, added or deleted"
            # the original view is not coloured
            assert app.workspace.plugins.insn_style(differing.addr, False, original) is None
            # the two pseudocode views: the lines that differ are highlighted, added in the revision, deleted in the
            # original, as the Qt plugin formats them
            app.workspace.decompile_function(differing)
            await app.wait_for_jobs()
            revised.decompile_current_function()
            await app.wait_for_jobs()
            code: Any = vm.first_view_in_category("pseudocode")
            diff_code: Any = plugin.current_revised_code
            await wait_until(
                pilot, lambda: not diff_code.codegen.am_none and not code.codegen.am_none, rounds=3000, then_settle=4
            )
            plugin.color_pseudocode_diff()
            highlights = code.extra_highlights + diff_code.extra_highlights
            assert {style for _start, _end, style in highlights} <= {"diff.added", "diff.deleted"}
            assert highlights, "the two decompilations are the same"

        run_app(scenario, binary=BINDIFF_A)


class TestCodePlugins(PluginCase):
    async def _main_in_pseudocode(self, app: AmApp, pilot: Pilot) -> Any:
        app.workspace.decompile_function(kb_of(app).functions["main"])
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
                if isinstance(element.obj, FunctionCallNode)
                and getattr(getattr(element.obj, "callee_func", None), "name", "") == "puts"
            )
            menu = code.presenter.context_menu(node)
            entries = {entry.text: entry for _path, entry in walk_entries(menu)}
            assert "Poison call globally" in entries
            app.workspace.raise_view(code)
            entries["Poison call globally"].action()
            puts = kb_of(app).functions["puts"]
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
                if hasattr(presenter, "set_cursor"):
                    presenter.set_cursor(start)
                else:
                    code.code.set_cursor(start)
                presenter.expr2armasm(element.obj)
                await settle(pilot)
                if isinstance(app.screen, FormScreen):
                    break
            screen = app.screen
            assert isinstance(screen, FormScreen) and screen.title_text == "Assembly code output"
            assert "The AIL block:" in screen.values["asm"]

        run_app(scenario)


#: Plugins that are Qt-only by nature: angr_binsync is the BinSync project's own Qt plugin, which it ships itself.
QT_ONLY_PLUGINS = {"binsync"}

WITHOUT_QT_SCRIPT = """
import asyncio
import os

import angrmanagement.plugins as plugins_pkg
from angrmanagement.plugins import load_plugin_description, load_plugins_from_file
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps

# every bundled plugin's entry point, loaded as the plugin manager loads it
root = os.path.dirname(plugins_pkg.__file__)
failed = {}
for sub in sorted(os.listdir(root)):
    for desc in load_plugin_description(os.path.join(root, sub)):
        entry = os.path.join(os.path.dirname(desc.plugin_file_path), desc.entrypoints[0])
        errors = [repr(cls) for cls in load_plugins_from_file(entry) if isinstance(cls, Exception)]
        if errors:
            failed[desc.shortname] = errors


async def main():
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=False)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        app.workspace.plugins.activate_plugin_by_name("source_viewer")
        await pilot.pause()
        plugin = app.workspace.plugins.get_plugin_instance_by_name("source_viewer")
        return None if plugin is None else type(plugin.source_viewer).__name__


RESULT = {"failed": failed, "source_viewer": asyncio.run(main())}
"""


class TestWithoutQt(unittest.TestCase):
    def test_the_bundled_plugins_load_and_the_source_viewer_activates_without_pyside6(self) -> None:
        outcome = run_without_qt(WITHOUT_QT_SCRIPT)
        result = outcome["result"]
        assert outcome["qt_modules_loaded"] == []
        assert set(result["failed"]) == QT_ONLY_PLUGINS, result["failed"]
        assert result["source_viewer"] == "SourceTuiView"


if __name__ == "__main__":
    unittest.main()
