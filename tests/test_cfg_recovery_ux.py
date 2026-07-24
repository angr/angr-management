# pylint:disable=missing-class-docstring,wrong-import-order,protected-access
from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace

import angr
from common import AngrManagementTestCase, test_location
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QMessageBox

from angrmanagement.data.jobs import CFGGenerationJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.ui.views import DisassemblyView


def assert_no_overlap(cfb) -> None:
    """
    Assert that no two objects in the blanket overlap.
    """
    prev_key, prev_end = None, None
    for key, obj in cfb._blanket.items():
        size = obj.size if isinstance(getattr(obj, "size", None), int) else None
        if prev_end is not None:
            assert key >= prev_end, f"object at {key:#x} overlaps the object at {prev_key:#x} (ends at {prev_end:#x})"
        prev_key, prev_end = key, key + max(size or 1, 1)


class CfgRecoveryUxTestCase(AngrManagementTestCase):
    """
    Base class: loads fauxware without triggering the automatic analysis, so that tests fully control CFG generation.
    """

    binary = os.path.join(test_location, "x86_64", "fauxware")

    def setUp(self):
        super().setUp()
        # suppress the automatic analysis that project.am_event() would trigger
        self.main.workspace.run_analysis = lambda *args, **kwargs: None
        proj = angr.Project(self.binary, auto_load_libs=False)
        self.main.workspace.main_instance.project.am_obj = proj
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()

    def run_cfg_job(self, cancel_on_first_progress: bool = False, cfg_args: dict | None = None) -> CFGGenerationJob:
        """
        Run a CFG generation job through the analysis manager plumbing, optionally simulating a user cancellation at
        the first progress notification from CFGFast.
        """
        workspace = self.main.workspace
        am = workspace.analysis_manager
        job = CFGGenerationJob(
            workspace.main_instance,
            on_finish=am._on_cfg_generated,
            on_cfb_available=am._on_cfg_recovery_started,
            **(cfg_args or {}),
        )

        if cancel_on_first_progress:
            orig_cb = job._progress_callback

            def cancelling_cb(ctx, percentage, text=None, cfg=None):
                if cfg is not None and job.state == JobState.RUNNING:
                    workspace.job_manager.cancel_job(job)
                orig_cb(ctx, percentage, text=text, cfg=cfg)

            job._progress_callback = cancelling_cb

        workspace.job_manager.add_job(job)
        workspace.job_manager.join_all_jobs()
        return job

    @staticmethod
    def full_reference_functions() -> set[int]:
        proj = angr.Project(CfgRecoveryUxTestCase.binary, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        return set(proj.kb.functions)


class TestGracefulCancel(CfgRecoveryUxTestCase):
    def test_cancel_produces_finalized_partial_cfg(self):
        workspace = self.main.workspace
        job = self.run_cfg_job(cancel_on_first_progress=True)

        assert job.state == JobState.CANCELLED
        # the partial results were published despite the cancellation
        assert not workspace.main_instance.cfg.am_none
        assert not workspace.main_instance.cfb.am_none
        assert len(workspace.main_instance.cfg.graph) > 0
        # the unprocessed frontier and the resume state were captured for resuming
        assert len(workspace.main_instance.cfg_resume_frontier) > 0
        assert workspace.main_instance.cfg_resume_state is not None
        assert len(workspace.main_instance.cfg_resume_state.jobs) > 0
        # the recovery was truncated: some functions of the full run are missing
        assert self.full_reference_functions() - set(workspace.main_instance.kb.functions)


class TestResume(CfgRecoveryUxTestCase):
    def test_resume_from_address(self):
        workspace = self.main.workspace
        self.run_cfg_job(cancel_on_first_progress=True)

        missing = sorted(self.full_reference_functions() - set(workspace.main_instance.kb.functions))
        assert missing
        seed = missing[0]

        assert workspace.can_resume_cfg_recovery(seed)
        workspace.resume_cfg_recovery(seed)
        workspace.job_manager.join_all_jobs()

        assert seed in workspace.main_instance.kb.functions

    def test_full_resume_converges(self):
        workspace = self.main.workspace
        self.run_cfg_job(cancel_on_first_progress=True)

        assert workspace.can_resume_cfg_recovery()
        workspace.resume_cfg_recovery_full()
        workspace.job_manager.join_all_jobs()

        # resuming with the captured resume state reproduces the exact function set of an uninterrupted run
        assert set(workspace.main_instance.kb.functions) == self.full_reference_functions()

    def test_full_resume_after_strict_resume_converges(self):
        # a strict resume-from-address job must not clobber the captured resume state; a full resume afterwards
        # still converges to the uninterrupted function set
        workspace = self.main.workspace
        self.run_cfg_job(cancel_on_first_progress=True)
        state = workspace.main_instance.cfg_resume_state
        assert state is not None

        missing = sorted(self.full_reference_functions() - set(workspace.main_instance.kb.functions))
        assert missing
        workspace.resume_cfg_recovery(missing[0])
        workspace.job_manager.join_all_jobs()

        # the strict resume completed but the captured resume state is preserved
        assert workspace.main_instance.cfg_resume_state is state

        workspace.resume_cfg_recovery_full()
        workspace.job_manager.join_all_jobs()
        assert set(workspace.main_instance.kb.functions) == self.full_reference_functions()
        # the full resume consumed the state
        assert workspace.main_instance.cfg_resume_state is None

    def test_can_resume_enablement(self):
        workspace = self.main.workspace

        # no CFG yet: resume is not possible
        assert not workspace.can_resume_cfg_recovery()

        self.run_cfg_job()
        assert not workspace.main_instance.cfg.am_none

        # a complete CFG exists and no job is running: full resume is possible
        assert workspace.can_resume_cfg_recovery()
        # an address that is already part of the CFG cannot be used as a resume point
        entry = workspace.main_instance.project.entry
        assert workspace.main_instance.cfg.get_any_node(entry) is not None
        assert not workspace.can_resume_cfg_recovery(entry)
        # an unmapped address cannot be used as a resume point
        assert not workspace.can_resume_cfg_recovery(0x100)


class TestEntryPointAtRecoveryStart(CfgRecoveryUxTestCase):
    def test_on_cfg_recovery_started_shows_entry_in_linear_view(self):
        workspace = self.main.workspace
        proj = workspace.main_instance.project.am_obj
        cfb = proj.analyses.CFB(exclude_region_types={"kernel", "tls"})

        assert not workspace._first_cfg_generation_callback_completed
        workspace.on_cfg_recovery_started(cfb)

        assert not workspace.main_instance.cfb.am_none
        disasm_view = workspace.view_manager.first_view_in_category("disassembly")
        assert disasm_view is not None
        # the linear viewer is displayed and the entry point is the current location
        assert disasm_view._current_view is disasm_view._linear_viewer
        assert disasm_view.jump_history.current == proj.entry
        # the programmatic navigation was not recorded as a user navigation
        assert not workspace._user_navigated_during_cfg


class TestLiveViewportUpdates(CfgRecoveryUxTestCase):
    def test_objects_added_in_viewport_triggers_refresh(self):
        workspace = self.main.workspace
        self.run_cfg_job()

        disasm_view = workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        entry = workspace.main_instance.project.entry
        disasm_view.jump_to(entry)
        QTest.qWait(100)

        addr_range = disasm_view._linear_viewer.visible_addr_range()
        assert addr_range is not None
        assert addr_range[0] <= entry < addr_range[1]

        refreshes = []
        disasm_view._linear_viewer.refresh_objects = lambda: refreshes.append(True)

        # an object within the viewport triggers a refresh
        disasm_view._last_objects_added_refresh = 0.0
        disasm_view._on_cfb_event(objects_added=[(entry, SimpleNamespace(size=4))])
        QTest.qWait(200)
        assert refreshes

        # an object far outside the viewport does not
        refreshes.clear()
        disasm_view._last_objects_added_refresh = 0.0
        disasm_view._on_cfb_event(objects_added=[(addr_range[1] + 0x10000, SimpleNamespace(size=4))])
        QTest.qWait(200)
        assert not refreshes

        # an object without a size must not crash the intersection check
        disasm_view._refresh_linear_viewer_on_objects_added([(entry, SimpleNamespace(size=None))])


class TestBlanketNonOverlap(CfgRecoveryUxTestCase):
    def test_blanket_nonoverlapping_after_completed_recovery(self):
        workspace = self.main.workspace
        self.run_cfg_job()
        assert not workspace.main_instance.cfb.am_none
        assert_no_overlap(workspace.main_instance.cfb)

    def test_blanket_nonoverlapping_after_cancelled_recovery(self):
        workspace = self.main.workspace
        self.run_cfg_job(cancel_on_first_progress=True)
        assert not workspace.main_instance.cfb.am_none
        assert_no_overlap(workspace.main_instance.cfb)


class TestAskBeforeNavigating(CfgRecoveryUxTestCase):
    def test_no_prompt_without_user_navigation(self):
        workspace = self.main.workspace
        questions = []
        orig_question = QMessageBox.question
        QMessageBox.question = lambda *args, **kwargs: questions.append(args) or QMessageBox.StandardButton.Yes
        try:
            self.run_cfg_job()
        finally:
            QMessageBox.question = orig_question

        # no prompt: the view navigated to main and switched to the graph view
        assert not questions
        disasm_view = workspace.view_manager.first_view_in_category("disassembly")
        assert disasm_view is not None
        assert disasm_view._current_view is disasm_view._flow_graph
        main_func = workspace.main_instance.kb.functions.function(name="main")
        assert main_func is not None
        assert disasm_view.jump_history.current == main_func.addr

    def test_prompt_after_user_navigation_can_decline(self):
        workspace = self.main.workspace

        # pretend the user navigated during the job by forcing the flag through the completion path
        questions = []
        orig_question = QMessageBox.question
        QMessageBox.question = lambda *args, **kwargs: questions.append(args) or QMessageBox.StandardButton.No

        orig_started = workspace.on_cfg_recovery_started

        def started_and_navigate(cfb):
            orig_started(cfb)
            workspace._user_navigated_during_cfg = True

        workspace.on_cfg_recovery_started = started_and_navigate
        try:
            self.run_cfg_job()
        finally:
            QMessageBox.question = orig_question
            workspace.on_cfg_recovery_started = orig_started

        # the user was asked and declined: the view stays in the linear viewer
        assert questions
        disasm_view = workspace.view_manager.first_view_in_category("disassembly")
        assert disasm_view is not None
        assert disasm_view._current_view is disasm_view._linear_viewer


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
