from __future__ import annotations

import os
import unittest

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.data.indirect_jumps import IndirectJumpResolutionResult
from angrmanagement.data.jobs import IndirectJumpResolutionConfiguration, IndirectJumpResolutionJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.logic.jobmanager import JobCancelled

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


if __name__ == "__main__":
    unittest.main()
