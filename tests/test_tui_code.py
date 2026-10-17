"""
The terminal pseudocode view, driven through Textual's pilot on fauxware: main's decompilation and its lines, the keys
that rename, retype and comment, flavors, the context menu, find, hover, following a call, the side panels, and a
snapshot at 200x60.
"""

# pylint: disable=protected-access,missing-class-docstring,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import re
import unittest
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, PropertyMock, patch

from angr.analyses.decompiler.structured_codegen import ConstantNode, FunctionCallNode, VariableNode
from textual.widgets import Button

from angrmanagement.plugins import BasePlugin
from angrmanagement.present.code_highlight import kind_style
from angrmanagement.present.menus import Menu, walk_entries
from angrmanagement.present.xrefs import XRefMode
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.code_screens import CommentScreen, RenameScreen, RetypeScreen
from angrmanagement.tui.screens import PromptScreen
from angrmanagement.tui.screens.form import FormScreen
from angrmanagement.tui.views.code import CodeTuiView, OptionsScreen
from angrmanagement.tui.widgets.menubar import MenuPopup
from angrmanagement.tui.xrefs import XRefsScreen

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
SIZE = (200, 60)


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def open_main(pilot: Pilot) -> CodeTuiView:
    """Load fauxware, show main in the disassembly, and press Tab there: the pseudocode view shows main."""
    app = pilot.app
    assert isinstance(app, AmApp)
    await app.open_binary(FAUXWARE, function="main")
    await settle(pilot)
    disasm: Any = app.view_widget("disassembly")
    disasm.graph_widget.focus()
    await settle(pilot)
    await pilot.press("tab")
    await wait_for_code(pilot)
    view = app.view_widget("pseudocode")
    assert isinstance(view, CodeTuiView)
    return view


async def wait_for_code(pilot: Pilot, rounds: int = 200) -> None:
    """Pause until the jobs are done and the pseudocode view shows a decompilation."""
    app = pilot.app
    assert isinstance(app, AmApp)
    await app.wait_for_jobs()
    for _ in range(rounds):
        view = app.view_widget("pseudocode")
        if isinstance(view, CodeTuiView) and view.presenter.doc is not None and app.workspace.job_manager.jobs == []:
            break
        await pilot.pause()
    await settle(pilot)


async def wait_for_screen(pilot: Pilot, screen_class: type, shown: bool = True, rounds: int = 200) -> None:
    """Pause until the app's screen is (or, with ``shown`` False, is no longer) a ``screen_class``."""
    for _ in range(rounds):
        if isinstance(pilot.app.screen, screen_class) == shown:
            break
        await pilot.pause()
    await settle(pilot)


def run_app(scenario: Callable[[AmApp, Pilot, CodeTuiView], Awaitable[None]], tier: int = 2) -> None:
    """Open fauxware's main in the pseudocode view of an interactive headless app and run ``scenario``."""

    async def main() -> None:
        app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=tier), interactive=True)
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            view = await open_main(pilot)
            await scenario(app, pilot, view)

    asyncio.run(main())


def element(view: CodeTuiView, text: str, kind: type, nth: int = 0):
    codegen = view.presenter.codegen
    found = [
        elem
        for _pos, elem in sorted(codegen.map_pos_to_node.items())
        if isinstance(elem.obj, kind) and codegen.text[elem.start : elem.start + elem.length] == text
    ]
    return found[nth]


def offset_of(view: CodeTuiView, pos: int) -> tuple[int, int]:
    """Where, in the text widget, the character at text position ``pos`` is drawn."""
    code = view.code
    doc = view.presenter.doc
    assert doc is not None
    row, col = doc.row_column(pos)
    sx, sy = code.scroll_offset
    return code.number_width + col - sx, row - sy


def menu_texts(menu: Menu) -> list[str]:
    return [entry.text for _path, entry in walk_entries(menu)]


def text_of(view: CodeTuiView) -> str:
    return view.presenter.codegen.text


class TestShow(unittest.TestCase):
    def test_the_focus_asked_for_before_the_view_is_mounted_is_given_on_mount(self):
        # the first decompilation asks for the focus before the view is mounted; Tab then hides the disassembly, and
        # on a loaded machine nothing was left with the focus
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=SIZE) as pilot:
                await pilot.pause()
                # something else has the focus, as the disassembly has when Tab is pressed there
                other = app.screen.focus_chain[0]
                other.focus()
                await settle(pilot)
                assert app.focused is other
                view = CodeTuiView(app.workspace, "center", app.workspace.main_instance)
                view.focus_text()
                assert not view.is_mounted
                await app.screen.mount(view)
                await settle(pilot)
                assert app.focused is view.code

        asyncio.run(main())

    def test_main_pseudocode(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            presenter: Any = view.presenter
            assert presenter.function.am_obj.name == "main"
            assert text_of(view).startswith("int main(")
            # every line the widget draws is the line of the text
            assert view.line_texts() == text_of(view).split("\n")
            header = str(view.header.render())
            assert "main (40071d)" in header and "pseudocode ▾" in header and "Decompilation Options" in header
            # the text has the focus, and the cursor is on the first node: its mentions are highlighted
            assert app.focused is view.code
            assert presenter.chunks
            # the line numbers are drawn beside the text
            strip = view.code.render_line(0)
            assert strip.text.startswith(" 1 int main(")

        run_app(scenario)

    def test_styles_of_the_text(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            doc = view.presenter.doc
            assert doc is not None
            row = next(i for i, line in enumerate(doc.lines) if "puts(" in line.text)
            spans = {span.text: span.style for span in doc.lines[row].spans}
            assert spans["puts"] == kind_style("library_function")
            assert spans['"Username: "'] == kind_style("quotation")

        run_app(scenario)


class TestEdits(unittest.TestCase):
    def test_rename_a_variable_with_n(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            elem = element(view, "v5", VariableNode)
            view.code.set_cursor(elem.start)
            await settle(pilot)
            await pilot.press("n")
            await wait_for_screen(pilot, RenameScreen)
            assert isinstance(app.screen, RenameScreen)
            await pilot.press(*"username", "enter")
            await settle(pilot)
            assert "username" in text_of(view) and not re.search(r"\bv5\b", text_of(view))
            assert view.line_texts() == text_of(view).split("\n")
            # the cursor stayed on the renamed variable
            assert view.presenter.current_node.am_obj is not None
            assert view.presenter.current_node.am_obj.unified_variable.name == "username"

        run_app(scenario)

    def test_an_invalid_name_cannot_be_confirmed(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.code.set_cursor(element(view, "v5", VariableNode).start)
            await settle(pilot)
            await pilot.press("n")
            await wait_for_screen(pilot, RenameScreen)
            assert isinstance(app.screen, RenameScreen)
            await pilot.press("space", "enter")
            await settle(pilot)
            screen = app.screen
            assert isinstance(screen, RenameScreen)
            assert screen.query_one("#ok").disabled
            await pilot.press("escape")
            await settle(pilot)
            assert "v5" in text_of(view)

        run_app(scenario)

    def test_retype_a_variable_with_y(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.code.set_cursor(element(view, "v5", VariableNode).start)
            await pilot.press("y")
            await wait_for_screen(pilot, RetypeScreen)
            screen = app.screen
            assert isinstance(screen, RetypeScreen)
            # the box completes the known type names
            assert "char" in screen.type_names
            await pilot.press(*"long long", "enter")
            await wait_for_code(pilot)
            assert re.search(r"long long v5;", text_of(view)), text_of(view)

        run_app(scenario)

    def test_comments(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            doc = view.presenter.doc
            assert doc is not None
            row = next(i for i, line in enumerate(doc.lines) if 'puts("Password: ")' in line.text)
            view.code.set_cursor(doc.position(row, 6))
            await pilot.press("semicolon")
            await wait_for_screen(pilot, PromptScreen)
            assert isinstance(app.screen, PromptScreen)
            await pilot.press(*"ask for it", "enter")
            await settle(pilot)
            kb: Any = app.workspace.main_instance.kb
            addr = view.presenter.closest_insaddr(None)
            assert kb.comments[addr] == "ask for it"
            assert "ask for it" in text_of(view).split("\n")[row]
            # Shift+; edits it in the multi-line editor; Ctrl+S confirms where Ctrl+Enter is not reported
            await pilot.press("colon")
            await wait_for_screen(pilot, CommentScreen)
            assert isinstance(app.screen, CommentScreen)
            # the old comment is selected, so typing replaces it
            await pilot.press(*"first", "enter", *"second", "ctrl+s")
            await settle(pilot)
            assert kb.comments[addr] == "first\nsecond"

        run_app(scenario)

    def test_constant_toggle_with_h(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.code.set_cursor(element(view, "8", ConstantNode).start)
            await pilot.press("h")
            await settle(pilot)
            assert "0x8" in text_of(view)
            # H on a variable does nothing: its menu has no Toggle hex
            view.code.set_cursor(element(view, "v3", VariableNode).start)
            before = text_of(view)
            await pilot.press("h")
            await settle(pilot)
            assert text_of(view) == before

        run_app(scenario)


class TestNavigation(unittest.TestCase):
    def test_flavors(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            presenter: Any = view.presenter
            presenter.select_flavor("rust")
            await wait_for_code(pilot)
            assert presenter.flavor == "rust" and "\nfn main(" in text_of(view)
            doc = presenter.doc
            assert doc is not None
            row = next(i for i, line in enumerate(doc.lines) if line.text.startswith("fn main("))
            # the Rust keywords
            assert doc.lines[row].spans[0].text == "fn" and doc.lines[row].spans[0].style == kind_style("keyword")
            assert "rust ▾" in str(view.header.render())
            assert view.line_texts() == text_of(view).split("\n")
            view.code.focus()
            await pilot.press("space")
            await settle(pilot)
            assert presenter.flavor == "pseudocode" and text_of(view).startswith("int main(")
            await pilot.press("space")
            await settle(pilot)
            assert presenter.flavor == "rust"
            # F opens the flavor menu
            await pilot.press("f")
            await wait_for_screen(pilot, MenuPopup)
            assert isinstance(app.screen, MenuPopup)
            # every flavor the decompiler has, as the Qt flavor selector lists them
            assert menu_texts(app.screen.menu) == presenter.available_flavors
            assert {"pseudocode", "rust"} <= set(presenter.available_flavors)
            await pilot.press("escape")

        run_app(scenario)

    def test_enter_on_a_call_shows_the_callee_and_escape_comes_back(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.code.set_cursor(element(view, "authenticate", FunctionCallNode).start)
            await pilot.press("enter")
            await wait_for_code(pilot)
            presenter: Any = view.presenter
            assert presenter.function.am_obj.name == "authenticate"
            assert "unsigned int authenticate(" in text_of(view)
            assert "authenticate (400664)" in str(view.header.render())
            view.code.focus()
            await pilot.press("escape")
            await wait_for_code(pilot)
            assert presenter.function.am_obj.name == "main"

        run_app(scenario)

    def test_another_function_starts_at_its_top(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            # a terminal too short for main, so that the view scrolls
            async with app.run_test(size=(120, 16)) as pilot:
                await pilot.pause()
                view = await open_main(pilot)
                view.code.focus()
                await pilot.press("ctrl+end")
                await settle(pilot)
                assert view.code.scroll_offset.y > 0
                view.code.set_cursor(element(view, "authenticate", FunctionCallNode).start)
                await pilot.press("enter")
                await wait_for_code(pilot)
                func: Any = view.presenter.function.am_obj
                assert func.name == "authenticate"
                assert view.code.scroll_offset.y == 0 and view.code.cursor == 0

        asyncio.run(main())

    def test_tab_goes_back_to_the_disassembly(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.code.set_cursor(element(view, "authenticate", FunctionCallNode).start)
            await settle(pilot)
            await pilot.press("tab")
            await settle(pilot)
            disasm: Any = app.view_widget("disassembly")
            assert disasm.infodock.selected_insns == {view.presenter.addr.am_obj}

        run_app(scenario)

    def test_g_jumps_to_a_function(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.code.focus()
            await pilot.press("g")
            await wait_for_screen(pilot, FormScreen)
            assert isinstance(app.screen, FormScreen)
            await pilot.press(*"authenticate", "enter")
            await wait_for_code(pilot)
            func: Any = view.presenter.function.am_obj
            assert func.name == "authenticate"

        run_app(scenario)

    def test_f5_in_the_disassembly_decompiles(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=SIZE) as pilot:
                await pilot.pause()
                await app.open_binary(FAUXWARE, function="authenticate")
                await settle(pilot)
                disasm: Any = app.view_widget("disassembly")
                disasm.graph_widget.focus()
                await pilot.press("f5")
                await wait_for_code(pilot)
                view = app.view_widget("pseudocode")
                assert isinstance(view, CodeTuiView)
                func: Any = view.presenter.function.am_obj
                assert func.name == "authenticate"
                assert "unsigned int authenticate(" in text_of(view)

        asyncio.run(main())

    def test_x_shows_the_cross_references(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            # of a variable
            view.code.set_cursor(element(view, "v5", VariableNode).start)
            await pilot.press("x")
            await settle(pilot)
            screen: Any = app.screen
            assert isinstance(screen, XRefsScreen)
            assert screen.model.mode == XRefMode.Variable and screen.model.row_count > 0
            await pilot.press("escape")
            await settle(pilot)
            # of a function, at a call to it
            view.code.set_cursor(element(view, "authenticate", FunctionCallNode).start)
            await pilot.press("x")
            await settle(pilot)
            screen = app.screen
            assert isinstance(screen, XRefsScreen)
            assert screen.model.mode == XRefMode.Address and screen.model.row_count > 0

        run_app(scenario)

    def test_double_click_and_hover(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            elem = element(view, "authenticate", FunctionCallNode)
            offset = offset_of(view, elem.start + 1)
            await pilot.hover(view.code, offset=offset)
            await settle(pilot)
            tooltip = str(view.code.tooltip)
            assert "authenticate(" in tooltip and "@ <rdi>" in tooltip
            await pilot.double_click(view.code, offset=offset)
            await wait_for_code(pilot)
            func: Any = view.presenter.function.am_obj
            assert func.name == "authenticate"

        run_app(scenario)


class TestMenusAndFind(unittest.TestCase):
    def test_right_click_on_a_variable_opens_its_menu(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            elem = element(view, "v5", VariableNode)
            await pilot.click(view.code, offset=offset_of(view, elem.start), button=3)
            await wait_for_screen(pilot, MenuPopup)
            assert isinstance(app.screen, MenuPopup)
            texts = menu_texts(app.screen.menu)
            for expected in ["Rename...", "Specify a new type", "Xrefs...", "Comment...", "AI: Refine All"]:
                assert expected in texts, expected
            assert view.presenter.selected_node is elem.obj
            await pilot.press("escape")
            await settle(pilot)
            # Shift+F10 opens the same menu from the keyboard
            view.code.focus()
            await pilot.press("shift+f10")
            await wait_for_screen(pilot, MenuPopup)
            assert isinstance(app.screen, MenuPopup)
            assert menu_texts(app.screen.menu) == texts

        run_app(scenario)

    def test_find(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            await pilot.press("ctrl+f")
            await settle(pilot)
            assert view.find_widget.display
            await pilot.press(*"read")
            await settle(pilot)
            matches = view.presenter.find_matches
            assert len(matches) == text_of(view).count("read") > 1
            assert view.code.selection_range() == matches[0]
            await pilot.press("enter")
            await settle(pilot)
            assert view.code.selection_range() == matches[1]
            assert view.find_state.status == f"2 of {len(matches)}"
            await pilot.press("escape")
            await settle(pilot)
            assert not view.find_widget.display and not view.presenter.find_matches
            assert app.focused is view.code

        run_app(scenario)

    def test_shift_arrows_select_and_ctrl_c_copies(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.code.set_cursor(0)
            await settle(pilot)
            assert app.focused is view.code
            await pilot.press("shift+right", "shift+right", "shift+right")
            await settle(pilot)
            assert view.code.selection_range() == (0, 3) and view.code.selected_text() == "int"
            view.presenter.copy()
            assert app.services.clipboard_text() == "int"

        run_app(scenario)


class TestSidePanels(unittest.TestCase):
    def test_options_pane(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.toggle_panel("options")
            await settle(pilot)
            assert view.side_panel.display and view.side_panel.active == "options"
            assert "▾ Decompilation Options" in str(view.header.render())
            sheet = view.presenter.options
            tree = view.side_panel.options.options_tree
            groups = [str(node.label) for node in tree.root.children]
            assert groups[-2:] == ["Optimization Passes", "Peephole Optimizations"]
            first = tree.root.children[0].children[0]
            item = first.data
            before = sheet.values[item]
            view.side_panel.options.edit(first, item)
            assert sheet.values[item] != before
            # Apply decompiles again with the new value
            view.side_panel.options.query_one("#apply-options", Button).press()
            await wait_for_code(pilot)
            assert not sheet.dirty
            # O hides the panel again
            view.code.focus()
            await pilot.press("o")
            await settle(pilot)
            assert not view.side_panel.display

        run_app(scenario)

    def test_a_narrow_view_shows_the_options_in_a_modal_screen(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=(100, 40)) as pilot:
                await pilot.pause()
                view = await open_main(pilot)
                # the header has no room for its Decompilation Options toggle here; O opens the options
                assert "Decompilation Options" not in str(view.header.render())[: view.header.size.width]
                view.code.focus()
                await pilot.press("o")
                await wait_for_screen(pilot, OptionsScreen)
                assert isinstance(app.screen, OptionsScreen) and not view.side_panel.display
                sheet = view.presenter.options
                widget = app.screen.sheet_widget
                first = widget.options_tree.root.children[0].children[0]
                before = sheet.values[first.data]
                widget.edit(first, first.data)
                assert sheet.values[first.data] != before
                widget.query_one("#apply-options", Button).press()
                await wait_for_code(pilot)
                assert not sheet.dirty
                # O closes the modal as it hides the side panel; so does Escape
                await pilot.press("o")
                await wait_for_screen(pilot, OptionsScreen, shown=False)
                assert not isinstance(app.screen, OptionsScreen)
                await pilot.press("o")
                await wait_for_screen(pilot, OptionsScreen)
                assert isinstance(app.screen, OptionsScreen)
                await pilot.press("escape")
                await wait_for_screen(pilot, OptionsScreen, shown=False)
                assert not isinstance(app.screen, OptionsScreen)

        asyncio.run(main())

    def test_patterns_and_summary_panes(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            view.toggle_panel("patterns")
            await settle(pilot)
            assert view.side_panel.active == "patterns"
            kb: Any = app.workspace.main_instance.kb
            assert view.side_panel.patterns.model.row_count == len(list(kb.patterns))
            view.toggle_panel("summary")
            await settle(pilot)
            assert view.side_panel.active == "summary"
            assert "No summary available" in str(view.side_panel.summary.render())

        run_app(scenario)

    def test_pattern_highlight_bands_a_line(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            presenter: Any = view.presenter
            doc = presenter.doc
            assert doc is not None
            row = next(i for i, line in enumerate(doc.lines) if 'puts("Username: ")' in line.text)
            addr = presenter.src_to_inst(doc.position(row, 6))
            presenter.highlight_pattern(presenter.function.am_obj.addr, [frozenset({addr})])
            await settle(pilot)
            assert row in presenter.pattern_highlight_rows()
            # the banded line is drawn on another background than the line under it
            assert row + 1 not in presenter.pattern_highlight_rows()
            banded = list(view.code.text_strip(row))[0].style
            plain = list(view.code.text_strip(row + 1))[0].style
            assert banded is not None and plain is not None and banded.bgcolor != plain.bgcolor
            # Escape clears it first, and only then goes back
            view.code.focus()
            await pilot.press("escape")
            await settle(pilot)
            assert not presenter.has_pattern_highlight and presenter.function.am_obj.name == "main"

        run_app(scenario)


class TestWorkspaceUses(unittest.TestCase):
    def test_ai_refine_runs_on_the_function_shown(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            project: Any = app.workspace.main_instance.project.am_obj
            with (
                patch.object(type(project), "llm_client", new_callable=PropertyMock, return_value=MagicMock()),
                patch("angrmanagement.logic.workspace.LLMRefineJob") as job_class,
                patch.object(app.workspace.job_manager, "add_job") as add_job,
            ):
                # the AI entries of the context menu run the AI menu's commands
                menu = view.presenter.context_menu(node=None)
                assert menu is not None
                entry = next(e for _p, e in walk_entries(menu) if e.text == "AI: Suggest Variable Names")
                entry.trigger()
            job_class.assert_called_once()
            assert job_class.call_args.args[1] is view.presenter.function.am_obj
            assert job_class.call_args.kwargs["mode"] == "variable_names"
            add_job.assert_called_once()

        run_app(scenario)

    def test_a_plugin_that_wants_the_qt_editor_is_still_activated(self):
        class QtEditorPlugin(BasePlugin):
            """Instruments a pseudocode view through the Qt view's editor, which the terminal view has not got."""

            def __init__(self, workspace) -> None:
                super().__init__(workspace)
                self.instrumented: list[Any] = []

            def instrument_code_view(self, cview: Any) -> None:
                self.instrumented.append(cview)
                cview._textedit.document()

        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            plugins: Any = app.workspace.plugins
            with (
                patch.object(app.workspace, "log") as log,
                patch.object(plugins, "_register_url_actions") as url_actions,
                self.assertLogs("angrmanagement.plugins.plugin_manager", level="INFO") as logged,
            ):
                plugins.activate_plugin("qt_editor", QtEditorPlugin)
            plugin = plugins.get_plugin_instance(QtEditorPlugin)
            assert plugin is not None and plugin.instrumented == [view]
            # the rest of the activation ran, and the error is logged as for a view opened after the plugin
            url_actions.assert_called_once()
            assert [record.getMessage() for record in logged.records] == ["Activated plugin QtEditorPlugin"]
            assert any("instrument_code_view" in str(call.args[0]) for call in log.call_args_list)
            plugins.deactivate_plugin(plugin)

        run_app(scenario)

    def test_a_bookmark_bands_its_line(self):
        async def scenario(app: AmApp, pilot: Pilot, view: CodeTuiView) -> None:
            presenter: Any = view.presenter
            doc = presenter.doc
            row = next(i for i, line in enumerate(doc.lines) if 'puts("Password: ")' in line.text)
            addr = presenter.src_to_inst(doc.position(row, 6))
            plain = list(view.code.text_strip(row))[0].style
            app.workspace.main_instance.annotations.toggle_bookmark(addr)
            await settle(pilot)
            banded = list(view.code.text_strip(row))[0].style
            assert plain is not None and banded is not None and plain.bgcolor != banded.bgcolor

        run_app(scenario)


#
# Snapshots (pytest-textual-snapshot)
#


async def _open_main_for_snapshot(pilot: Pilot) -> None:
    view = await open_main(pilot)
    view.code.set_cursor(0)
    await settle(pilot)


def test_snapshot_pseudocode(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=SIZE, run_before=_open_main_for_snapshot)


if __name__ == "__main__":
    unittest.main()
