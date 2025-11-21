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
    PrototypeFindingJob,
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

    def common(self, analysis_config_callback):
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
                os.path.join(test_location, "x86_64", "true"), auto_load_libs=False
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
            VariableRecoveryJob,
        ]

    def test_all_analyses_off(self):
        def config_analysis(conf: AnalysesConfiguration):
            for analysis in conf.analyses:
                analysis.enabled = False

        jobs = self.common(config_analysis)
        assert len(jobs) == 0
        assert self.main.workspace.main_instance.project.kb.cfgs.get_most_accurate() is None


if __name__ == "__main__":
    unittest.main()
