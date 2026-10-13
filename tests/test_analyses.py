from __future__ import annotations

import os
import unittest
from typing import TYPE_CHECKING
from unittest.mock import patch

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.data.jobs import (
    APIDeobfuscationJob,
    CallingConventionRecoveryJob,
    CFGGenerationJob,
    CodeTaggingJob,
    FlirtSignatureRecognitionJob,
    GoGlobalsRecoveryJob,
    PrototypeFindingJob,
    RustSymbolRecoveryJob,
    RustTypeDBLoaderJob,
    StringDeobfuscationJob,
    VariableRecoveryJob,
)
from angrmanagement.data.jobs.job import JobState
from angrmanagement.logic.analysis_manager import AnalysisManager

if TYPE_CHECKING:
    from angrmanagement.data.analysis_options import AnalysesConfiguration
    from angrmanagement.data.jobs import Job


class TestAnalysisManager(AngrManagementTestCase):
    """Smoke test analysis configuration."""

    def common(self, analysis_config_callback, binpath: str = "x86_64/true"):
        # Patch _schedule_job to inspect job kind and success
        _schedule_job = self.main.workspace.analysis_manager._schedule_job
        with patch.object(AnalysisManager, "_schedule_job", wraps=_schedule_job) as mocked:
            jobs = []

            def _schedule_job_wrapper(job: Job):
                nonlocal jobs
                jobs.append(job)
                return _schedule_job(job)

            mocked.side_effect = _schedule_job_wrapper

            self.main.workspace.main_instance.project.am_obj = angr.Project(
                os.path.join(test_location, binpath), auto_load_libs=False
            )
            conf = self.main.workspace.analysis_manager.get_default_analyses_configuration()
            analysis_config_callback(conf)
            self.main.workspace.main_instance.analysis_configuration = conf
            self.main.workspace.main_instance.project.am_event()
            self.main.workspace.job_manager.join_all_jobs()
            return jobs

    def test_all_analyses_on(self):
        def config_analysis(conf: AnalysesConfiguration):
            for analysis in conf.analyses:
                analysis.enabled = True

        jobs = self.common(config_analysis)
        assert all(j.state == JobState.FINISHED for j in jobs)
        assert [type(j) for j in jobs] == [
            CFGGenerationJob,
            FlirtSignatureRecognitionJob,
            PrototypeFindingJob,
            APIDeobfuscationJob,
            StringDeobfuscationJob,
            CodeTaggingJob,
            CallingConventionRecoveryJob,
            RustSymbolRecoveryJob,
            RustTypeDBLoaderJob,
            GoGlobalsRecoveryJob,
            VariableRecoveryJob,
        ]

    def test_go_globals_recovery_on_go_binary(self):
        """The Go job is on by default only for Go binaries and fills kb.go_globals in the background."""
        progress = []
        self.main.workspace.job_manager.job_progressed.connect(
            lambda job, pct, _text: progress.append(pct) if isinstance(job, GoGlobalsRecoveryJob) else None
        )

        def config_analysis(conf: AnalysesConfiguration):
            assert conf["go_globals_recovery"].enabled is True
            assert conf["rust_symbol_recovery"].enabled is False
            for analysis in conf.analyses:
                analysis.enabled = analysis.name in ("cfg", "go_globals_recovery")

        jobs = self.common(config_analysis, "x86_64/go/go1.27.1/basics_stripped")
        assert [type(j) for j in jobs] == [CFGGenerationJob, GoGlobalsRecoveryJob]
        assert all(j.state == JobState.FINISHED for j in jobs)
        assert progress and progress[-1] == 100.0 and progress == sorted(progress)
        go_globals = self.main.workspace.main_instance.project.kb.go_globals
        assert go_globals.loaded
        assert "runtime.writeBarrier" in {v.name for v in go_globals.variables.values()}

    def test_go_globals_recovery_off_by_default_on_c_binary(self):
        conf = None

        def config_analysis(c: AnalysesConfiguration):
            nonlocal conf
            conf = c
            for analysis in c.analyses:
                analysis.enabled = False

        self.common(config_analysis)
        assert conf["go_globals_recovery"].enabled is False

    def test_all_analyses_off(self):
        def config_analysis(conf: AnalysesConfiguration):
            for analysis in conf.analyses:
                analysis.enabled = False

        jobs = self.common(config_analysis)
        assert len(jobs) == 0
        assert self.main.workspace.main_instance.project.kb.cfgs.get_most_accurate() is None


if __name__ == "__main__":
    unittest.main()
