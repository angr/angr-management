"""
The pattern view, without a toolkit and in the terminal, on 1after909's doit: the pattern lifted from its first error
exit (`puts("String is empty."); fflush(stdout); return 0xffffffff;`), as a graph that collapses and expands, its
property sheet and what setting a property does, saving it to the project and the library's toggling, export and
import, searching, failed leaves, discovery, and the terminal view's widgets.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import re
import tempfile
import unittest
from typing import TYPE_CHECKING, Any

import angr
from angr.analyses.decompiler.known_patterns import PConst
from angr.analyses.decompiler.known_patterns.generator import PatternGenerator
from textual.widgets import Input

from angrmanagement.data.jobs.pattern_search import current_decompilation
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.present.menus import walk_entries
from angrmanagement.present.patterns import (
    FAILED_BORDER_STYLE,
    PatternPresenter,
    match_cells,
    node_label,
)
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.views.pattern import PatternTuiView

if TYPE_CHECKING:
    from textual.pilot import Pilot

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
BINARY = os.path.join(test_location, "x86_64", "1after909")
#: doit's first error exit, as the pseudocode shows it
ERROR_EXIT = r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n'
SIZE = (200, 60)


def captions(menu) -> list[str]:
    return [entry.text for _path, entry in walk_entries(menu)]


def labels(presenter: PatternPresenter) -> list[str]:
    return [node_label(box.node.node) for box in presenter.graph.picture.boxes]


class TestPresenter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(BINARY, auto_load_libs=False)
        cls.cfg = cls.project.analyses.CFGFast(normalize=True)

    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance
        self.instance.project.am_obj = self.project
        self.instance.project.am_event()
        self.instance.cfg.am_obj = self.cfg.model
        self.func = self.project.kb.functions["doit"]
        self.presenter = PatternPresenter(self.workspace, self.instance)
        # in the view manager, so the workspace tells it when the project's patterns change
        self.workspace.add_view(self.presenter)
        dec = current_decompilation(self.instance, self.func)
        m = re.search(ERROR_EXIT, dec.codegen.text)
        assert m is not None
        self.pattern = PatternGenerator(dec.codegen, dec.ail_graph).generate_pattern(
            m.start(), m.end(), "PatternErrorsOut"
        )

    def tearDown(self):
        self.workspace.job_manager.quit()
        for name in [p.name for p in self.project.kb.patterns]:
            self.project.kb.patterns.remove(name)

    def test_graph_collapses_and_expands(self):
        presenter = self.presenter
        assert not presenter.graph.picture.boxes and presenter.status == "no pattern loaded"
        presenter.load_pattern(self.pattern, origin_func=self.func.addr)
        assert presenter.status == "editing patternerrorsout: 3 statements"
        # the three statements, each with its expression tree under it, as the Qt view shows them
        assert labels(presenter) == [
            "Call puts",
            "Call puts",
            "Expression (any) [_s1]",
            "Call fflush",
            "Call fflush",
            "Load 8 bytes",
            "Const &stdout",
            "Return",
            "Const 0xffffffff",
        ]
        leaves = [path for path, _ in presenter.editor.leaves()]  # type: ignore[union-attr]
        assert [presenter.nodes_by_path[p].kind for p in leaves] == ["required"] * 3
        assert [line.text for line in presenter._box(presenter.nodes_by_path[leaves[0]]).lines] == [
            "Call puts",
            "required",
        ]
        assert captions(presenter.context_menu(None)) == ["Expand all", "Collapse all"]
        presenter.collapse_all()
        assert labels(presenter) == ["Call puts", "Call fflush", "Return"]
        assert presenter._box(presenter.nodes_by_path[leaves[0]]).lines[1].text == "required, collapsed"
        presenter.activate(presenter.nodes_by_path[leaves[1]])
        assert labels(presenter) == [
            "Call puts",
            "Call fflush",
            "Call fflush",
            "Load 8 bytes",
            "Const &stdout",
            "Return",
        ]
        assert presenter.selected_path == leaves[1]
        assert presenter.graph.selected is presenter.nodes_by_path[leaves[1]]
        presenter.expand_all()
        assert len(presenter.graph.picture.boxes) == 9

    def test_properties(self):
        presenter = self.presenter
        presenter.load_pattern(self.pattern, origin_func=self.func.addr)
        groups = presenter.property_groups()
        assert [g.name for g in groups] == ["Pattern"]
        assert [(s.label, s.value) for s in groups[0].items] == [
            ("Name", "patternerrorsout"),
            ("Call name", "PatternErrorsOut"),
            ("Display name", "PatternErrorsOut"),
            ("Return type", ""),
            ("Min similarity", 0.8),
            ("Enabled", False),
            ("Require structural match", True),
        ]
        editor = presenter.editor
        assert editor is not None
        # the return's constant: pinned, then loosened
        const_path = next(p for p, ref in presenter.nodes_by_path.items() if node_label(ref.node) == "Const 0xffffffff")
        presenter.select_ref(presenter.nodes_by_path[const_path])
        node_group = presenter.property_groups()[1]
        assert [s.label for s in node_group.items] == [
            "Wildcard",
            "Value (blank = any)",
            "Symbol (blank = none)",
            "Bits (0 = any)",
        ]
        assert node_group.items[1].value == "0xffffffff"
        presenter.set_property(("const_value", const_path), "0x10")
        node = editor.node_at(const_path)
        assert isinstance(node, PConst) and node.value == 0x10
        presenter.set_property(("const_value", const_path), "zz")
        assert presenter.status.startswith("not applied: ")
        presenter.set_property(("call_name", None), "ErrorsOut")
        assert editor.pattern.call_name == "ErrorsOut"
        # a statement made optional
        leaf = editor.leaves()[0][0]
        presenter.select_node(leaf)
        mode = presenter.property_groups()[1].items[0]
        assert (mode.kind, mode.value, mode.choices) == ("combo", "required", ["required", "optional", "wildcard"])
        presenter.set_property(("leaf_mode", leaf), "optional")
        ref = presenter.nodes_by_path[leaf]
        assert ref.kind == "optional" and presenter._box(ref).style == "pattern.optional"
        presenter.undo()
        assert presenter.nodes_by_path[leaf].kind == "required"
        # the editing buttons
        assert presenter.loosen_constants() >= 1 and presenter.status.startswith("loosened ")

    def test_save_and_the_library(self):
        presenter = self.presenter
        presenter.load_pattern(self.pattern, origin_func=self.func.addr)
        assert presenter.library.row_count == 0
        stored = presenter.save()
        assert stored is not None and presenter.status == "saved patternerrorsout to the project (disabled)"
        assert presenter.library.row_count == 1
        assert [presenter.library.cell(0, c).text for c in (0, 1, 3, 4)] == [
            "patternerrorsout",
            "PatternErrorsOut",
            "80%",
            f"{self.func.addr:#x}",
        ]
        # the Enabled check box turns it on
        assert presenter.library.cell(0, 2).checked is False
        presenter.library.set_checked(0, 2, True)
        assert self.project.kb.patterns.get("patternerrorsout").enabled
        assert presenter.status == "patternerrorsout is on; it applies the next time a function is decompiled"
        assert presenter.library.cell(0, 2).checked is True
        # export, delete, import
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "p.json")
            presenter.export_stored(self.project.kb.patterns.get("patternerrorsout"), path)
            presenter.delete_stored(self.project.kb.patterns.get("patternerrorsout"))
            assert presenter.library.row_count == 0 and presenter.status == "deleted patternerrorsout"
            imported = presenter.import_stored(path)
        assert imported.name == "patternerrorsout" and presenter.library.row_count == 1
        # Enter on a row edits it
        presenter.load_pattern(self.pattern, origin_func=None)
        presenter.library.activate(0)
        assert presenter.origin_func == self.func.addr

    def test_search_and_failed_leaves(self):
        presenter = self.presenter
        presenter.load_pattern(self.pattern, origin_func=self.func.addr)
        presenter.search_current_function()
        self.workspace.job_manager.join_all_jobs()
        assert presenter.matches and presenter.matches_model.row_count == len(presenter.matches)
        best = presenter.matches[0]
        assert best.func_addr == self.func.addr and best.verified
        assert presenter.matches_model.cell(0, 0).text == "doit"
        assert presenter.matches_model.cell(0, 4).text == "yes"
        assert match_cells(best)[2] == f"{best.similarity:.0%}"
        verified = sum(r.verified for r in presenter.matches)
        assert presenter.status == f"{len(presenter.matches)} occurrence(s), {verified} verified"
        # a failed leaf is framed red
        best.failed_leaves = [0]
        presenter.show_match(0)
        first = presenter.nodes_by_path[presenter.editor.leaves()[0][0]]  # type: ignore[union-attr]
        assert presenter.is_failed(first) and presenter._box(first).border_style == FAILED_BORDER_STYLE
        box = next(b for b in presenter.graph.picture.boxes if b.node is first)
        assert box.border_style == FAILED_BORDER_STYLE
        presenter.show_match(-1)
        assert not presenter.is_failed(first)
        # loading another pattern empties the table
        presenter.load_pattern(self.pattern)
        assert presenter.matches_model.row_count == 0

    def test_discovery(self):
        presenter = self.presenter
        shown: list[str] = []

        class View:
            def show_tab(self, name):
                shown.append(name)

        presenter.view = View()
        # three statements, as the Qt view's discovery test asks for
        presenter.min_size = 3
        presenter.discover(self.func)
        self.workspace.job_manager.join_all_jobs()
        assert shown == ["discover"]
        assert presenter.families and presenter.discovered_func == self.func.addr
        assert presenter.families_model.row_count == len(presenter.families)
        assert presenter.discover_status.startswith(f"{len(presenter.families)} famil")
        # the Found column is counted in the background
        lifted = next(i for i, f in enumerate(presenter.families) if f.pattern is not None)
        family = presenter.families[lifted]
        assert family.found is not None
        row = presenter.families_model.index_of(lifted)
        assert row is not None and presenter.families_model.cell(row, 4).text.startswith(f"{family.found} (")
        menu = presenter.families_menu([lifted])
        assert captions(menu) == [
            "Highlight patterns in pseudocode",
            "Highlight patterns in disassembly",
            "Edit pattern...",
        ]
        assert presenter.load_family(lifted)
        assert shown[-1] == "pattern" and presenter.editor is not None
        assert presenter.origin_func == self.func.addr


#
# The terminal
#


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def open_pattern(pilot: Pilot) -> PatternTuiView:
    """Decompile doit, select its first error exit and make it the pattern PatternErrorsOut, as Qt's tests do."""
    app: Any = pilot.app
    await settle(pilot)
    await app.open_binary(BINARY, function="doit")
    await settle(pilot)
    app.workspace.decompile_function(app.workspace.main_instance.kb.functions["doit"])
    await app.wait_for_jobs()
    for _ in range(200):
        code = app.view_widget("pseudocode")
        if code is not None and code.presenter.doc is not None and not app.workspace.job_manager.jobs:
            break
        await pilot.pause()
    await settle(pilot)
    code = app.view_widget("pseudocode")
    m = re.search(ERROR_EXIT, code.presenter.codegen.text)
    assert m is not None
    code.code.select_range(m.start(), m.end())
    view = code.presenter.create_pattern("PatternErrorsOut")
    await settle(pilot, 8)
    assert isinstance(view, PatternTuiView) and app.view_widget("pattern") is view
    return view


class TestTerminal(unittest.TestCase):
    def test_view(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=SIZE) as pilot:
                view = await open_pattern(pilot)
                presenter = view.presenter
                assert len(presenter.graph.picture.boxes) == 9
                assert view.graph.canvas is not None and "Call fflush" in str(view.graph.canvas)
                assert "editing patternerrorsout: 3 statements" in str(view.status.render())
                # C and E in the graph collapse and expand everything
                view.graph.focus()
                await pilot.press("c")
                await settle(pilot)
                assert len(presenter.graph.picture.boxes) == 3
                await pilot.press("e")
                await settle(pilot)
                assert len(presenter.graph.picture.boxes) == 9
                # the property sheet: Enter in Call name applies it
                editor = next(w for w, spec in view.properties.specs.items() if spec.label == "Call name")
                editor.focus()
                editor.value = "ErrorsOut"  # type: ignore[attr-defined]
                await pilot.press("enter")
                await settle(pilot)
                assert presenter.editor is not None and presenter.editor.pattern.call_name == "ErrorsOut"
                # the focus stays on the row
                focused = app.focused
                assert focused in view.properties.specs and view.properties.specs[focused].label == "Call name"
                # Save to project fills the library
                await pilot.click("#save")
                await settle(pilot)
                assert view.library.row_count == 1
                assert presenter.status == "saved patternerrorsout to the project (disabled)"
                # Discover runs on the function in the pseudocode view, with three statements as Qt's test asks for
                await pilot.click("#--content-tab-discover-tab")
                await settle(pilot)
                assert view.tabs.active == "discover-tab"
                view.query_one("#min-size", Input).value = "3"
                await settle(pilot)
                assert presenter.min_size == 3
                await pilot.click("#discover")
                await app.wait_for_jobs()
                for _ in range(100):
                    if presenter.families and not app.workspace.job_manager.jobs:
                        break
                    await pilot.pause()
                await settle(pilot)
                assert view.tabs.active == "discover-tab"
                assert view.families.row_count == len(presenter.families) > 0
                assert str(view.discover_status.render()).startswith(f"{len(presenter.families)} famil")

        asyncio.run(main())


async def _pattern_for_snapshot(pilot: Pilot) -> None:
    view = await open_pattern(pilot)
    leaf = view.presenter.editor.leaves()[1][0]  # type: ignore[union-attr]
    view.presenter.select_node(leaf)
    await settle(pilot)
    # the graph is wider than the view; where centering it lands depends on when the scroll bars came
    view.graph.scroll_to(0, 0, animate=False)
    await settle(pilot)


def test_snapshot_pattern(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=SIZE, run_before=_pattern_for_snapshot)


if __name__ == "__main__":
    unittest.main()
