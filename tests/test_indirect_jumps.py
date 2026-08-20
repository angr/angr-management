from __future__ import annotations

import os
import unittest

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.data.indirect_jumps import IndirectJumpResolutionResult
from angrmanagement.data.jobs import IndirectJumpResolutionConfiguration, IndirectJumpResolutionJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.logic.jobmanager import JobCancelled
from angrmanagement.ui.views import IndirectJumpsView

BINARY = os.path.join(test_location, "x86_64", "fpijr_global_table")


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


if __name__ == "__main__":
    unittest.main()
