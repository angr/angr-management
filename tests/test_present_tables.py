"""
The table models of angrmanagement.present, on fauxware, without a window: columns, filtering, sorting, activation
and context menus.
"""

# pylint: disable=no-self-use,protected-access,missing-class-docstring

from __future__ import annotations

import dataclasses
import logging
import os
import unittest
from datetime import datetime
from typing import Any
from unittest.mock import patch

import angr
from angr.knowledge_plugins.patches import Patch

from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.data.jobs.job import Job, JobState
from angrmanagement.data.log import LogRecord
from angrmanagement.data.search import SearchKind, SearchResult
from angrmanagement.data.signatures import PrecomputedSignature
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.logic.ui_services import HeadlessServices
from angrmanagement.present.bookmarks import BookmarksPresenter
from angrmanagement.present.breakpoints import BreakpointsPresenter, parse_breakpoint
from angrmanagement.present.comments import CommentsPresenter
from angrmanagement.present.functions import FunctionsPresenter
from angrmanagement.present.jobs import JobsPresenter, progress_bar
from angrmanagement.present.log import LogPresenter, record_line
from angrmanagement.present.mcp_history import MCPHistoryPresenter
from angrmanagement.present.menus import walk_entries
from angrmanagement.present.patches import PatchesPresenter
from angrmanagement.present.registers import RegistersTableModel
from angrmanagement.present.search import SearchPresenter, SearchResultsModel
from angrmanagement.present.signatures import SignaturesPresenter
from angrmanagement.present.stack import STACK_ROWS, StackTableModel
from angrmanagement.present.strings import StringsPresenter
from angrmanagement.present.traces import TracesPresenter
from angrmanagement.present.xrefs import XRefMode, XRefsModel

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


def captions(menu: Any) -> list[str]:
    return [entry.text for _, entry in walk_entries(menu)] if menu is not None else []


def menu_entry(menu: Any, text: str) -> Any:
    return next(e for _, e in walk_entries(menu) if e.text == text)


def set_services(services: Any) -> None:
    GlobalInfo.ui_services = services  # pyright: ignore[reportAttributeAccessIssue]


class AnsweringServices(HeadlessServices):
    """Headless services that give fixed answers."""

    def __init__(self, answers: dict[str, object]) -> None:
        super().__init__()
        self.answers = answers

    def question(self, title: str, text: str, buttons: Any, default: str) -> str:
        return str(self.answers.get("question", default))

    def prompt_text(self, title: str, label: str, default: str = "") -> str | None:
        answer = self.answers.get("prompt")
        return None if answer is None else str(answer)

    def ask_form_async(self, form: Any, callback: Any) -> None:
        """Fill the form with ``answers["form"]``; OK only if the form's check accepts it."""
        answer: Any = self.answers.get("form")
        values = None if answer is None else {**form.initial_values(), **answer}
        callback(values if values is not None and form.checked(values).ok else None)


class FauxwareTestCase(unittest.TestCase):
    """A headless workspace with fauxware loaded and its CFG built once."""

    project: angr.Project
    cfg: angr.analyses.CFGFast

    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.cfg = cls.project.analyses.CFGFast(normalize=True, data_references=True, cross_references=True)

    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance
        self.instance.project.am_obj = self.project
        self.instance.project.am_event()
        self.instance.cfg.am_obj = self.cfg.model
        self.instance.cfg.am_event()
        self.saved_services = GlobalInfo._ui_services
        # never the Qt services an earlier test in this process installed: their dialogs would wait for a click
        set_services(HeadlessServices())

    def tearDown(self):
        set_services(self.saved_services)
        self.workspace.job_manager.quit()

    def answer(self, **answers):
        set_services(AnsweringServices(answers))


class TestFunctionTable(FauxwareTestCase):
    def setUp(self):
        super().setUp()
        self.selected = []
        self.presenter = FunctionsPresenter(self.workspace, self.instance)
        self.presenter.subscribe_func_select(self._on_select)
        self.presenter.reload()
        self.model: Any = self.presenter.model

    def _on_select(self, func) -> None:
        self.selected.append(func)

    def test_columns_are_the_qt_headers(self):
        assert [c.name for c in self.model.columns] == [
            "Inline?",
            "Name",
            "Tags",
            "Address",
            "Binary",
            "Size",
            "Blocks",
            "Complexity",
        ]

    def test_alignment_functions_are_hidden_until_asked(self):
        total = len(self.project.kb.functions)
        assert self.model.total_count == total
        alignment = sum(1 for f in self.project.kb.functions.values() if f.is_alignment)
        assert alignment > 0
        assert self.model.row_count == total - alignment
        assert self.presenter.count_text() == f"{total - alignment}/{total} functions"
        self.presenter.toggle_show_alignment_functions()
        assert self.model.row_count == total
        assert self.presenter.count_text() == f"{total} functions"

    def test_filter_and_activate(self):
        self.presenter.filter("auth")
        assert [self.model.column_text(f, self.model.NAME_COL) for f in self.model.rows] == ["authenticate"]
        self.presenter.jump_to_result()
        assert [f.name for f in self.selected] == ["authenticate"]
        self.presenter.filter("4007")
        assert {f.name for f in self.model.rows} == {"__libc_csu_init"} | {
            f.name for f in self.project.kb.functions.values() if "4007" in f"{f.addr:x}" and not f.is_alignment
        }

    def test_sort_by_address_descending(self):
        self.model.sort(self.model.ADDRESS_COL, descending=True)
        addrs = [f.addr for f in self.model.rows]
        assert addrs == sorted(addrs, reverse=True)

    def test_colours(self):
        by_name = {(self.model.column_text(f, 1), f.addr): f for f in self.model.rows}
        puts_plt = next(f for (name, addr), f in by_name.items() if name == "puts" and addr < 0x700000)
        puts_extern = next(f for (name, addr), f in by_name.items() if name == "puts" and addr >= 0x700000)
        main = next(f for (name, _), f in by_name.items() if name == "main")
        assert self.model.style_key(puts_plt, 1).startswith("function_table_plt_color")
        assert self.model.style_key(puts_extern, 1).startswith("function_table_simprocedure_color")
        assert self.model.style_key(main, 1).startswith("function_table_color")

    def test_inline_check_box_stores_the_function(self):
        row = next(i for i, f in enumerate(self.model.rows) if f.name == "authenticate")
        assert self.model.set_checked(row, self.model.INLINE_COL, True)
        func = self.project.kb.functions["authenticate"]
        # the decompiler looks the callee's Function up in this set
        assert func in self.instance.functions_to_inline
        assert self.model.cell(row, self.model.INLINE_COL).checked
        self.model.set_checked(row, self.model.INLINE_COL, False)
        assert func not in self.instance.functions_to_inline

    def test_context_menu(self):
        row = next(i for i, f in enumerate(self.model.rows) if f.name == "main")
        assert captions(self.model.context_menu([row])) == ["Show Function Info", "Edit Function Comment..."]

    def test_function_comment_from_the_menu(self):
        self.answer(prompt="the entry point")
        row = next(i for i, f in enumerate(self.model.rows) if f.name == "main")
        menu = self.model.context_menu([row])
        menu_entry(menu, "Edit Function Comment...").trigger()
        assert self.project.kb.comments[self.project.kb.functions["main"].addr] == "the entry point"


class TestStringsTable(FauxwareTestCase):
    def setUp(self):
        super().setUp()
        self.presenter = StringsPresenter(self.workspace, self.instance)
        self.presenter.reload()
        self.model: Any = self.presenter.model

    def texts(self) -> list[str]:
        return [self.model.column_text(s, self.model.STRING_COL) for s in self.model.rows]

    def test_lists_the_strings(self):
        assert "Welcome to the admin console, trusted user!" in self.texts()
        assert [c.name for c in self.model.columns] == ["Address", "Size (Bytes)", "Length", "String"]

    def test_wildcard_and_regex_filters(self):
        self.presenter.set_filter("*admin*")
        assert self.texts() == ["Welcome to the admin console, trusted user!"]
        self.presenter.set_filter("go AWAY*")
        assert self.texts() == ["Go away!"]
        assert self.presenter.set_filter("^(User|Pass)", regex=True)
        assert sorted(self.texts()) == ["Password: ", "Username: "]
        # an invalid expression leaves the filter alone
        assert not self.presenter.set_filter("(", regex=True)
        assert sorted(self.texts()) == ["Password: ", "Username: "]

    def test_narrow_to_a_function(self):
        self.presenter.select_function(self.project.kb.functions["main"])
        assert "Username: " in self.texts()
        assert "Welcome to the admin console, trusted user!" not in self.texts()

    def test_xrefs_to_a_string(self):
        string = next(s for s in self.model.rows if self.model.column_text(s, 3) == "Go away!")
        jumps = []
        xrefs: Any = XRefsModel(
            self.instance,
            addr=string.addr,
            xrefs_manager=self.project.kb.xrefs,
            dst_addr=string.addr,
            on_jump=jumps.append,
        )
        assert xrefs.mode == XRefMode.Address
        assert xrefs.title == f"XRefs to address {string.addr:#x}"
        assert xrefs.row_count >= 1
        assert [c.name for c in xrefs.columns] == ["Direction", "Type", "PC", "Text"]
        assert "rejected" in xrefs.column_text(xrefs.rows[0], 2)
        xrefs.activate(0)
        assert jumps == [xrefs.rows[0].ins_addr]


class TestSearchResults(FauxwareTestCase):
    def test_model(self):
        model = SearchResultsModel()
        model.set_results(
            [SearchResult(0x2000, "insn", "mov", "", 0x2000, "beta"), SearchResult(0x1000, "ascii", "hi", "", None)]
        )
        model.sort(model.ADDRESS_COL)
        assert [r.addr for r in model.results] == [0x1000, 0x2000]
        model.filter("beta")
        assert [r.addr for r in model.results] == [0x2000]

    def test_presenter_builds_validates_and_runs(self):
        presenter = SearchPresenter(self.workspace, self.instance)
        statuses = []
        presenter.status_changed.connect(statuses.append)
        assert presenter.scopes[0].name == "Entire address space"
        query = presenter.build_query(kind=SearchKind.STRING, text="admin")
        presenter.start_search(query)
        self.workspace.job_manager.join_all_jobs()
        assert presenter.results and statuses[-1] == f"{len(presenter.results)} results"
        menu = presenter.results_model.context_menu([0])
        assert captions(menu) == [
            "Copy address",
            "Copy match",
            "Copy row",
            "Jump in disassembly",
            "Jump in pseudocode",
            "Jump in hex view",
        ]
        menu_entry(menu, "Copy address").trigger()
        assert GlobalInfo.ui_services.clipboard_text() == f"{presenter.results[0].addr:#x}"
        presenter.close()


class TestComments(FauxwareTestCase):
    def test_lists_filters_and_edits(self):
        presenter = CommentsPresenter(self.workspace, self.instance)
        main = self.project.kb.functions["main"]
        self.workspace.set_comment(main.addr + 1, "first line\nsecond")
        self.workspace.set_comment(main.addr + 4, "another")
        model: Any = presenter.model
        assert model.row_count == 2
        row = next(i for i, c in enumerate(model.rows) if c.addr == main.addr + 1)
        assert model.cell(row, model.COMMENT_COL).text == "first line ..."
        assert model.cell(row, model.ADDRESS_COL).tooltip == "first line\nsecond"
        assert model.cell(row, model.FUNCTION_COL).text == "main"
        model.filter("anot")
        assert [c.text for c in model.rows] == ["another"]
        assert presenter.count_text() == "1 of 2 comments"
        model.filter("")
        self.answer(prompt="edited")
        menu = model.context_menu([row])
        assert captions(menu)[:2] == ["Edit comment...", "Copy text"]
        menu_entry(menu, "Edit comment...").trigger()
        assert self.project.kb.comments[main.addr + 1] == "edited"
        presenter.close()


class TestBookmarks(FauxwareTestCase):
    def test_label_edit_and_delete(self):
        presenter = BookmarksPresenter(self.workspace, self.instance)
        main = self.project.kb.functions["main"]
        self.instance.annotations.toggle_bookmark(main.addr)
        model: Any = presenter.model
        assert model.row_count == 1
        assert model.cell(0, model.FUNCTION_COL).text == "main"
        assert model.columns[model.LABEL_COL].editable
        assert model.set_text(0, model.LABEL_COL, "start here")
        assert self.instance.annotations.get_bookmark(main.addr).label == "start here"
        self.answer(prompt="renamed")
        presenter.rename(model.row(0))
        assert self.instance.annotations.get_bookmark(main.addr).label == "renamed"
        assert captions(presenter.bookmarks_menu(model.objects([0]))) == ["Go to", "Rename label", "Delete"]
        presenter.delete(model.objects([0]))
        assert model.row_count == 0
        presenter.close()


class TestPatches(FauxwareTestCase):
    def test_list_comment_and_revert(self):
        presenter = PatchesPresenter(self.workspace, self.instance)
        main = self.project.kb.functions["main"]
        patch_mgr = self.project.kb.patches
        patch_mgr.add_patch_obj(Patch(main.addr, b"\x90\x90"))
        # no CFG regeneration in this test: the patch event goes straight to the presenter
        with patch.object(self.workspace, "_on_patch_event"):
            self.instance.patches.am_event(added=set())
        model: Any = presenter.model
        assert model.row_count == 1
        assert model.cell(0, model.NEW_BYTES_COL).text == "9090"
        assert model.cell(0, model.SIZE_COL).text == "2 bytes"
        assert model.set_text(0, model.COMMENT_COL, "nop it")
        assert patch_mgr.get_patch(main.addr).comment == "nop it"
        # the headless default answer is Cancel: nothing is reverted
        presenter.revert(model.patches([0]))
        assert patch_mgr.get_patch(main.addr) is not None
        self.answer(question="Yes")
        with patch.object(self.workspace, "_on_patch_event"):
            presenter.revert(model.patches([0]))
        assert patch_mgr.get_patch(main.addr) is None
        presenter.close()


class TestLog(FauxwareTestCase):
    def test_records_and_copy(self):
        presenter = LogPresenter(self.workspace, self.instance)
        before = presenter.model.row_count
        self.instance.log.append(LogRecord(logging.WARNING, 0, "src", "careful"))
        self.instance.log.am_event(log_record=self.instance.log[-1])
        model: Any = presenter.model
        assert model.row_count == before + 1
        row = model.row_count - 1
        assert model.cell(row, model.COL_ICON).style_key == "log.warning"
        presenter.copy_selected_messages([row])
        assert GlobalInfo.ui_services.clipboard_text() == "careful"
        presenter.copy_selected([row])
        assert GlobalInfo.ui_services.clipboard_text() == record_line(model.row(row))
        assert record_line(model.row(row)).startswith("WARNING | ")
        assert "C&lear log" in [e.caption for _, e in walk_entries(model.context_menu([row]))]
        presenter.clear_log()
        assert model.row_count == 0
        presenter.close()


class TestBreakpoints(FauxwareTestCase):
    def test_table_menu_and_prompt(self):
        presenter = BreakpointsPresenter(self.workspace, self.instance)
        model: Any = presenter.model
        self.instance.breakpoint_mgr.add_breakpoint(Breakpoint(BreakpointType.Write, 0x601040, 4, "x"))
        assert model.row_count == 1
        assert [model.cell(0, c).text for c in range(4)] == ["Write", "0x601040", "0x4", "x"]
        assert captions(model.context_menu([0])) == ["Edit breakpoint", "Remove breakpoint", "New breakpoint"]
        # the Edit Breakpoint form, which refuses a size of 0 as the Qt dialog does
        self.answer(form={"type": BreakpointType.Read, "addr": "0x601050", "size": "0"})
        presenter.new_breakpoint()
        assert model.row_count == 1
        self.answer(form={"type": BreakpointType.Read, "addr": "0x601050", "size": "8"})
        presenter.new_breakpoint()
        assert model.row_count == 2
        added = model.row(1)
        assert (added.type, added.addr, added.size) == (BreakpointType.Read, 0x601050, 8)
        assert parse_breakpoint("400100") == (BreakpointType.Execute, 0x400100, 1)
        assert parse_breakpoint("nope") is None
        presenter.remove_breakpoints(model.objects([0, 1]))
        assert model.row_count == 0
        presenter.close()


class TestTraces(FauxwareTestCase):
    def test_current_trace_and_menu(self):
        class FakeTrace:
            def __init__(self, source):
                self.source = source

        presenter = TracesPresenter(self.workspace, self.instance)
        one: Any = FakeTrace("one")
        two: Any = FakeTrace("two")
        for trace in (one, two):
            self.instance.traces.append(trace)
        self.instance.traces.am_event()
        self.workspace.set_current_trace(one)
        model: Any = presenter.model
        assert [model.cell(r, 0).text for r in range(2)] == ["one (Current)", "two"]
        # the menu used to crash on a missing attribute
        assert captions(model.context_menu([1])) == ["Use as current trace", "Remove trace"]
        assert captions(model.context_menu([0])) == ["Remove trace"]
        presenter.remove_traces([two])
        assert model.row_count == 1
        presenter.close()


class TestSignatures(FauxwareTestCase):
    def test_matches_column_and_menu(self):
        presenter = SignaturesPresenter(self.workspace, self.instance)
        mgr = self.instance.signature_mgr
        mgr.add_precomputed_signature("Bindif", "/x/other.o", {self.project.kb.functions["main"].addr: "main"})
        model: Any = presenter.model
        row = next(i for i, s in enumerate(model.rows) if isinstance(s, PrecomputedSignature))
        assert model.cell(row, model.COL_TYPE).text == "Bindif"
        assert model.cell(row, model.COL_NAME).text == "other"
        assert captions(presenter.signatures_menu([])) == ["Load signature files..."]
        # files picked headless: none, so nothing is loaded
        before = model.row_count
        presenter.load_signatures()
        assert model.row_count == before
        presenter.close()


class TestRegistersAndStack(FauxwareTestCase):
    def test_state_tables(self):
        state = self.project.factory.entry_state()
        registers: Any = RegistersTableModel()
        registers.update_state(state)
        names = [registers.cell(r, 0).text for r in range(registers.row_count)]
        assert "rax" in names and "rsp" in names
        rax = names.index("rax")
        state2 = state.copy()
        state2.regs.rax = 0x1234
        registers.update_state(state2)
        assert registers.cell(rax, 1).style_key == "table.changed"
        stack: Any = StackTableModel()
        stack.set_state(state)
        assert stack.row_count == STACK_ROWS
        assert stack.cell(1, 0).text == "8"
        stack.set_state(None)
        assert stack.row_count == 0


class TestJobs(FauxwareTestCase):
    def test_rows_follow_the_job_manager(self):
        presenter = JobsPresenter(self.workspace, self.instance)

        class Quick(Job):
            def run(self, ctx):
                ctx.set_progress(50)

        job = Quick("Quick job", on_finish=None)
        self.workspace.job_manager.add_job(job)
        self.workspace.job_manager.join_all_jobs()
        model: Any = presenter.model
        assert model.row_count == 1
        assert model.cell(0, model.COL_NAME).text == "Quick job"
        assert model.cell(0, model.COL_STATUS).text.endswith("Finished")
        assert model.cell(0, model.COL_STATUS).style_key == "job.finished"
        assert job.state == JobState.FINISHED
        # nothing to cancel on a finished job
        assert model.context_menu([0]) is None
        assert progress_bar(50, 10) == "█" * 5 + "░" * 5 + "  50%"
        presenter.close()


class TestMCPHistory(FauxwareTestCase):
    @dataclasses.dataclass
    class Record:
        tool: str
        status: str
        duration_ms: float
        error: str | None = None
        timestamp: datetime = dataclasses.field(default_factory=datetime.now)
        arguments_summary: str = "addr=4196125"

    def test_mirrors_the_capped_history(self):
        presenter = MCPHistoryPresenter(self.workspace, self.instance)
        model: Any = presenter.model
        history: Any = self.workspace.mcp_history
        for idx in range(3):
            record = self.Record(f"tool{idx}", "ok" if idx else "error", 12.3, error="boom" if not idx else None)
            history.am_obj.append(record)
            history.am_event(added=record)
        assert model.row_count == 3
        assert model.cell(0, model.COL_STATUS).style_key == "table.error"
        assert model.cell(0, model.COL_STATUS).tooltip == "boom"
        assert model.cell(1, model.COL_DURATION).text == "12"
        # the container drops its oldest record; the table follows
        history.am_obj.pop(0)
        record = self.Record("tool3", "ok", 1)
        history.am_obj.append(record)
        history.am_event(added=record)
        assert [model.cell(r, model.COL_TOOL).text for r in range(model.row_count)] == ["tool1", "tool2", "tool3"]
        presenter.clear()
        assert model.row_count == 0
        presenter.close()


if __name__ == "__main__":
    unittest.main()
