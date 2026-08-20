from __future__ import annotations

import os
import unittest

import angr
from common import AngrManagementTestCase, test_location
from PySide6.QtCore import QItemSelectionModel

from angrmanagement.data.indirect_jumps import IndirectJumpResolutionResult
from angrmanagement.data.jobs import IndirectJumpResolutionConfiguration, IndirectJumpResolutionJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.logic.jobmanager import JobCancelled
from angrmanagement.ui.views import IndirectJumpsView
from angrmanagement.ui.views.indirect_jumps_view import TARGET_ROLE

BINARY = os.path.join(test_location, "x86_64", "fpijr_global_table")
# a callback registered at run time: nothing but the whole-binary analysis resolves it, and its provenance runs
# across three functions
CALLBACK_BINARY = os.path.join(test_location, "x86_64", "fpijr_global_callback")


class TestIndirectJumpResolutionJob(AngrManagementTestCase):
    """Tests for the whole-binary indirect jump resolution job."""

    def _open_and_analyze(self) -> None:
        self.main.workspace.main_instance.project.am_obj = angr.Project(BINARY, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()

    def test_configuration_is_offered_and_off_by_default(self):
        self.main.workspace.main_instance.project.am_obj = angr.Project(BINARY, auto_load_libs=False)
        conf = self.main.workspace.analysis_manager.get_default_analyses_configuration()
        analysis = conf["indirect_jumps"]

        assert isinstance(analysis, IndirectJumpResolutionConfiguration)
        assert analysis.description
        # it decompiles the whole binary, so it must not run unless it is asked for
        assert not analysis.enabled
        assert set(analysis.to_dict()) == {"track_provenance", "max_iterations"}

    def test_job_resolves_and_publishes_results(self):
        self._open_and_analyze()
        instance = self.main.workspace.main_instance

        job = IndirectJumpResolutionJob(
            instance, on_finish=self.main.workspace.analysis_manager._on_indirect_jumps_resolved
        )
        self.main.workspace.job_manager.add_job(job)
        self.main.workspace.job_manager.join_all_jobs()

        assert job.state == JobState.FINISHED
        result = job.result
        assert isinstance(result, IndirectJumpResolutionResult)

        # the indirect call in dispatch() goes through a global table of four handlers
        dispatch = instance.kb.functions["dispatch"]
        expected = {instance.kb.functions[name].addr for name in ("f0", "f1", "f2", "f3")}
        sites_in_dispatch = [site for site, (func_addr, _) in result.sites.items() if func_addr == dispatch.addr]
        assert sites_in_dispatch
        resolved = set()
        for site in sites_in_dispatch:
            resolved |= result.resolutions.get(site, set())
        assert resolved == expected

        # every resolved site is mapped onto its block, which is how kb.indirect_jumps names the same site
        for site in result.resolutions:
            block_addr = result.block_addrs.get(site)
            assert block_addr is not None
            assert result.targets_of_block(block_addr) >= result.resolutions[site]
            assert site in result.sites_in_block(block_addr)

        # and the run reached the knowledge base
        for site, targets in result.resolutions.items():
            block_addr = result.block_addrs[site]
            assert targets <= set(instance.kb.indirect_jumps.resolved.get(block_addr, ()))

        assert result.summary
        assert not result.aborted

        # the results are published on the instance for views to pick up
        assert instance.indirect_jump_resolution.am_obj is result

    def test_job_records_provenance(self):
        self._open_and_analyze()
        instance = self.main.workspace.main_instance

        job = IndirectJumpResolutionJob(instance)
        self.main.workspace.job_manager.add_job(job)
        self.main.workspace.job_manager.join_all_jobs()
        result = job.result

        site, targets = next(iter(result.resolutions.items()))
        target = next(iter(targets))
        chain = result.provenance_of(site, target)
        assert chain
        # the chain ends where the pointer was consumed, and every step says something
        assert all(step.text for step in chain)
        assert "indirect target" in chain[-1].text
        assert any(step.addr is not None for step in chain)

        # a pair that was never resolved has no chain, and asking for one is not an error
        assert result.provenance_of(site, 0xDEAD) == []

    def test_provenance_can_be_switched_off(self):
        self._open_and_analyze()
        instance = self.main.workspace.main_instance

        job = IndirectJumpResolutionJob(instance, track_provenance=False)
        self.main.workspace.job_manager.add_job(job)
        self.main.workspace.job_manager.join_all_jobs()

        assert job.result.resolutions
        assert not job.result.provenance

    def test_cancellation_aborts_instead_of_unwinding(self):
        # cancelling must ask the analysis to stop, not let JobCancelled tear it down: the interprocedural phases
        # still have to run over what was collected so the partial results survive
        class FakeContext:
            def set_progress(self, percentage, text=""):  # pylint:disable=unused-argument
                raise JobCancelled

        class FakeAnalysis:
            def __init__(self):
                self.aborted = False

            def abort(self):
                self.aborted = True

        analysis = FakeAnalysis()
        IndirectJumpResolutionJob._progress_callback(FakeContext(), 12.0, "Analyzing", analysis)
        assert analysis.aborted

        # with no analysis to abort there is nothing to do but let the cancellation through
        with self.assertRaises(JobCancelled):
            IndirectJumpResolutionJob._progress_callback(FakeContext(), 12.0, "Analyzing", None)


class TestIndirectJumpsView(AngrManagementTestCase):
    """Tests for the indirect jumps view."""

    def setUp(self):
        super().setUp()
        self.main.workspace.main_instance.project.am_obj = angr.Project(BINARY, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()
        self.main.workspace.show_view("indirect_jumps", IndirectJumpsView)
        self.view: IndirectJumpsView = self.main.workspace.view_manager.first_view_in_category("indirect_jumps")

    @property
    def instance(self):
        return self.main.workspace.main_instance

    def _rows(self) -> list[list[str]]:
        model = self.view._tree.model()
        return [[model.item(row, col).text() for col in range(model.columnCount())] for row in range(model.rowCount())]

    def _row_for(self, address: str) -> list[str]:
        for row in self._rows():
            if row[IndirectJumpsView.COL_ADDRESS] == address:
                return row
        raise AssertionError(f"no row for {address} in {self._rows()}")

    def test_lists_sites_from_the_knowledge_base(self):
        indirect_jumps = self.instance.kb.indirect_jumps
        # one row per site the knowledge base knows about, resolved or not
        assert len(self._rows()) == len(set(indirect_jumps) | set(indirect_jumps.unresolved))
        assert len(self._rows()) > 1

        # the jump table in dispatch() is resolved, and its four targets hang off it as child rows
        dispatch = self.instance.kb.functions["dispatch"]
        site = next(s for s in self.view._sites if s.func_addr == dispatch.addr)
        row = self._row_for(f"{site.address:#x}")
        assert row[IndirectJumpsView.COL_FUNCTION] == "dispatch"
        assert row[IndirectJumpsView.COL_KIND] == "Jump table"
        assert row[IndirectJumpsView.COL_STATUS] == "Resolved"
        assert row[IndirectJumpsView.COL_TARGETS] == "4"
        assert row[IndirectJumpsView.COL_SOURCE] == "CFG"

        model = self.view._tree.model()
        item = next(
            model.item(r, 0) for r in range(model.rowCount()) if model.item(r, 0).text() == f"{site.address:#x}"
        )
        target_names = {item.child(i, IndirectJumpsView.COL_FUNCTION).text() for i in range(item.rowCount())}
        assert target_names == {"f0", "f1", "f2", "f3"}

        # an indirect call nothing resolved is listed as such
        unresolved = [r for r in self._rows() if r[IndirectJumpsView.COL_STATUS] == "Unresolved"]
        assert unresolved
        assert all(r[IndirectJumpsView.COL_TARGETS] == "" for r in unresolved)
        assert any(r[IndirectJumpsView.COL_KIND] == "Call" for r in unresolved)

    def test_filter_by_source_function(self):
        dispatch = self.instance.kb.functions["dispatch"]
        self.view.select_function(dispatch)
        rows = self._rows()
        assert rows
        assert {r[IndirectJumpsView.COL_FUNCTION] for r in rows} == {"dispatch"}

        # and back to everything
        self.view.select_function(None)
        assert len(self._rows()) > len(rows)

    def test_filter_by_status(self):
        all_rows = len(self._rows())

        self.view._status_filter.setCurrentIndex(self.view._status_filter.findData("resolved"))
        resolved = self._rows()
        assert resolved
        assert all(r[IndirectJumpsView.COL_STATUS] == "Resolved" for r in resolved)

        self.view._status_filter.setCurrentIndex(self.view._status_filter.findData("unresolved"))
        unresolved = self._rows()
        assert unresolved
        assert all(r[IndirectJumpsView.COL_STATUS] == "Unresolved" for r in unresolved)

        assert len(resolved) + len(unresolved) == all_rows

    def test_text_filter_matches_addresses_and_names(self):
        self.view._filter_string.setText("dispatch")
        assert {r[IndirectJumpsView.COL_FUNCTION] for r in self._rows()} == {"dispatch"}

        # a target name matches the site it belongs to
        self.view._filter_string.setText("f3")
        assert {r[IndirectJumpsView.COL_FUNCTION] for r in self._rows()} == {"dispatch"}

        self.view._filter_string.setText("no such thing")
        assert self._rows() == []

        self.view._filter_string.setText("")
        assert self._rows()

    def test_shows_results_of_the_analysis(self):
        before = self.view._status_label.text()
        assert "Run the indirect jump analysis" in before

        self.main.workspace.analysis_manager.resolve_indirect_jumps()
        self.main.workspace.job_manager.join_all_jobs()

        # the view picks the results up on its own, through the instance container
        assert self.instance.indirect_jump_resolution.am_obj is not None
        assert "Last analysis run:" in self.view._status_label.text()
        assert any(site.analysis_sites for site in self.view._sites)


class TestIndirectJumpsViewSync(AngrManagementTestCase):
    """Tests for following another view's function from the indirect jumps view."""

    def setUp(self):
        super().setUp()
        self.main.workspace.main_instance.project.am_obj = angr.Project(BINARY, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()
        self.main.workspace.show_view("indirect_jumps", IndirectJumpsView)
        self.view: IndirectJumpsView = self.main.workspace.view_manager.first_view_in_category("indirect_jumps")

    @property
    def instance(self):
        return self.main.workspace.main_instance

    def _functions_shown(self) -> set[str]:
        model = self.view._tree.model()
        return {model.item(row, IndirectJumpsView.COL_FUNCTION).text() for row in range(model.rowCount())}

    def test_sync_is_off_by_default_and_offers_the_open_views(self):
        assert self.view.synced_view is None

        self.view._populate_sync_combo()
        offered = [self.view._sync_combo.itemText(i) for i in range(self.view._sync_combo.count())]
        assert offered[0] == "None"
        # both the disassembly and the pseudocode views show one function at a time, so both can be followed
        assert "Disassembly" in offered
        assert "Pseudocode" in offered
        # and the view never offers to follow itself
        assert self.view.caption not in offered

    def test_following_a_view_selects_its_function(self):
        disassembly = self.main.workspace.view_manager.first_view_in_category("disassembly")
        dispatch = self.instance.kb.functions["dispatch"]
        disassembly.function = dispatch

        self.view.sync_with_view(disassembly)
        assert self.view.synced_view is disassembly
        # following it adopts whatever function it is already on
        assert self._functions_shown() == {"dispatch"}

        # and it keeps up as that view moves
        main_func = self.instance.kb.functions["main"]
        disassembly.function = main_func
        assert self.view._selected_function is main_func

        # unfollowing leaves the last selection in place but stops tracking
        self.view.sync_with_view(None)
        assert self.view.synced_view is None
        disassembly.function = dispatch
        assert self.view._selected_function is main_func

    def test_following_the_pseudocode_view(self):
        code_view = self.main.workspace.view_manager.first_view_in_category("pseudocode")
        assert code_view is not None

        self.view.sync_with_view(code_view)
        code_view.function = self.instance.kb.functions["dispatch"]
        assert self._functions_shown() == {"dispatch"}

    def test_closing_the_followed_view_stops_the_sync(self):
        disassembly = self.main.workspace.view_manager.first_view_in_category("disassembly")
        self.view.sync_with_view(disassembly)

        self.main.workspace.view_manager.remove_view(disassembly)
        self.view._populate_sync_combo()
        assert self.view.synced_view is None


class TestIndirectJumpsViewProvenance(AngrManagementTestCase):
    """Tests for querying why a target was resolved."""

    def setUp(self):
        super().setUp()
        self.main.workspace.main_instance.project.am_obj = angr.Project(CALLBACK_BINARY, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()
        self.main.workspace.show_view("indirect_jumps", IndirectJumpsView)
        self.view: IndirectJumpsView = self.main.workspace.view_manager.first_view_in_category("indirect_jumps")

    @property
    def instance(self):
        return self.main.workspace.main_instance

    def _dispatch_site(self):
        dispatch = self.instance.kb.functions["dispatch"]
        return next(s for s in self.view._sites if s.func_addr == dispatch.addr)

    def _run_analysis(self) -> None:
        self.main.workspace.analysis_manager.resolve_indirect_jumps()
        self.main.workspace.job_manager.join_all_jobs()

    def test_nothing_to_show_before_the_analysis_has_run(self):
        assert "Select a resolved target" in self.view._provenance_label.text()

        # control-flow recovery never even records the tail call in dispatch(), so the site is not listed yet
        dispatch = self.instance.kb.functions["dispatch"]
        assert not [s for s in self.view._sites if s.func_addr == dispatch.addr]

        site = self.view._sites[0]
        self.view.show_provenance(site, self.instance.kb.functions["h1"].addr)
        assert "Run the indirect jump analysis" in self.view._provenance_label.text()

    def test_the_analysis_adds_sites_the_cfg_never_recorded(self):
        dispatch = self.instance.kb.functions["dispatch"]
        self._run_analysis()
        site = self._dispatch_site()
        assert site.func_addr == dispatch.addr
        assert site.analysis_targets

    def test_shows_the_chain_that_carried_the_pointer(self):
        self._run_analysis()
        site = self._dispatch_site()
        h1 = self.instance.kb.functions["h1"].addr
        assert h1 in site.targets

        chain = self.view.provenance_of(site, h1)
        # the pointer is taken as a constant in main, passed to register_cb, stored into a global by it, and read
        # back at the indirect jump: every one of those steps has to be there
        assert len(chain) >= 4
        assert "constant" in chain[0].text
        assert any("argument" in step.text for step in chain)
        assert any("stored to" in step.text for step in chain)
        assert "indirect target" in chain[-1].text
        # and each step points at the instruction it happened at, so it can be jumped to
        assert all(step.addr is not None for step in chain)

        self.view.show_provenance(site, h1)
        assert f"{site.address:#x}" in self.view._provenance_label.text()
        assert self.view._provenance_tree.topLevelItemCount() == len(chain)
        first = self.view._provenance_tree.topLevelItem(0)
        assert first.text(1) == chain[0].text
        assert first.text(2) == f"{chain[0].addr:#x}"

    def test_selecting_a_target_row_shows_its_provenance(self):
        self._run_analysis()
        site = self._dispatch_site()

        model = self.view._tree.model()
        row = next(r for r in range(model.rowCount()) if model.item(r, 0).text() == f"{site.address:#x}")
        parent = model.index(row, 0)
        child = model.index(0, 0, parent)
        target = child.data(TARGET_ROLE)
        assert target is not None

        self.view._tree.selectionModel().select(
            child, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows
        )
        assert f"{target:#x}" in self.view._provenance_label.text()
        assert self.view._provenance_tree.topLevelItemCount() == len(self.view.provenance_of(site, target))

    def test_targets_are_attributed_to_whoever_found_them(self):
        self._run_analysis()
        site = self._dispatch_site()
        # this site is invisible to control-flow recovery, so the analysis alone gets the credit even though the
        # analysis published its findings into the same place the view reads
        assert site.analysis_targets
        assert not site.cfg_targets
        for target in site.targets:
            assert site.source_of(target) == "Indirect jump analysis"

    def test_attribution_survives_a_second_run(self):
        self._run_analysis()
        self._run_analysis()

        site = self._dispatch_site()
        # the second run must not hand the first run's findings over to control-flow recovery, which is what reading
        # back the knowledge base naively would do
        assert site.analysis_targets
        assert not site.cfg_targets

    def test_provenance_recording_can_be_switched_off(self):
        self.main.workspace.analysis_manager.resolve_indirect_jumps(track_provenance=False)
        self.main.workspace.job_manager.join_all_jobs()

        site = self._dispatch_site()
        target = next(iter(site.targets))
        assert self.view.provenance_of(site, target) == []
        self.view.show_provenance(site, target)
        assert "did not record provenance" in self.view._provenance_label.text()


if __name__ == "__main__":
    unittest.main()
