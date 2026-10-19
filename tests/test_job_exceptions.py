"""
Test cases for how the workspace reports job exceptions.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import threading
import unittest
from typing import TYPE_CHECKING

from common import AngrManagementTestCase, join_all_jobs  # pylint: disable=import-error
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from angrmanagement.data.jobs.job import InstanceJob
from angrmanagement.logic.jobmanager import JobCancelled

if TYPE_CHECKING:
    from angrmanagement.logic.jobmanager import JobContext


class FailingJob(InstanceJob):
    """A job that always raises."""

    def __init__(self, instance) -> None:
        super().__init__("Failing", instance)

    def run(self, ctx: JobContext) -> None:
        raise RuntimeError("this job always fails")


class CancelledJob(InstanceJob):
    """A job that reports itself as cancelled."""

    def __init__(self, instance) -> None:
        super().__init__("Cancelled", instance)

    def run(self, ctx: JobContext) -> None:
        raise JobCancelled


class SucceedingJob(InstanceJob):
    """A job that records that it ran."""

    def __init__(self, instance, ran: list) -> None:
        super().__init__("Succeeding", instance)
        self.ran = ran

    def run(self, ctx: JobContext) -> None:
        self.ran.append(self.name)


class FinishRaisingJob(InstanceJob):
    """A job that runs, then raises in its finish handler on the GUI thread."""

    def __init__(self, instance) -> None:
        super().__init__("FinishRaising", instance)

    def run(self, ctx: JobContext) -> None:
        pass

    def finish(self) -> None:
        raise RuntimeError("this finish handler always fails")


#: How long BlockedJob waits for its test to release it. A test always releases the job when it is done, so this only
#: ends a job whose test never does, before pytest-timeout (900 s in CI) kills the process. It used to be 30 s, and a
#: stop of 35 s (SIGSTOP on the xdist workers, which is what a stall of the macOS runner looks like to them; tests in
#: flight there have run up to 60 s over their usual time) let the job time out and finish while its test still
#: needed it running.
BLOCKED_JOB_WAIT = 600

#: How long a test waits for BlockedJob to start: the same two minutes conftest.py gives a pilot's wait, which covers
#: those stalls, so a job that never starts fails the test in two minutes rather than ten.
BLOCKED_JOB_START_WAIT = 120


class BlockedJob(InstanceJob):
    """A job that runs until it is released."""

    def __init__(self, instance, release: threading.Event) -> None:
        super().__init__("Blocked", instance)
        self.started = threading.Event()
        self.release = release

    def run(self, ctx: JobContext) -> None:
        self.started.set()
        self.release.wait(BLOCKED_JOB_WAIT)


class TestJobExceptionReporting(AngrManagementTestCase):
    """Test that a failed job is reported to the user without stalling the job queue."""

    def setUp(self) -> None:
        super().setUp()
        # other tests may have left message boxes behind
        self._close_message_boxes()

    def tearDown(self) -> None:
        self._close_message_boxes()
        super().tearDown()

    @staticmethod
    def _message_boxes() -> list[QMessageBox]:
        return [w for w in QApplication.topLevelWidgets() if isinstance(w, QMessageBox) and w.isVisible()]

    def _close_message_boxes(self) -> None:
        for box in self._message_boxes():
            box.close()

    def _run(self, *jobs) -> None:
        for job in jobs:
            self.main.workspace.job_manager.add_job(job)
        # fails with every thread's stack instead of hanging until pytest-timeout kills the worker
        join_all_jobs(self.main.workspace.job_manager)

    def test_failed_job_shows_a_message_box(self) -> None:
        self._run(FailingJob(self.main.workspace.main_instance))

        boxes = self._message_boxes()
        assert len(boxes) == 1
        # not windowTitle(): QMessageBox.setWindowTitle is a no-op on macOS, so the job name has to
        # be readable from the body text on every platform
        assert "Failing" in boxes[0].text()
        assert "this job always fails" in boxes[0].text()

    def test_the_message_box_is_not_modal(self) -> None:
        # a modal box would block whoever pumps events on macOS; QtServices.notify says why
        self._run(FailingJob(self.main.workspace.main_instance))

        boxes = self._message_boxes()
        assert len(boxes) == 1
        assert boxes[0].windowModality() == Qt.WindowModality.NonModal
        assert QApplication.activeModalWidget() is None

    def test_cancelled_job_is_not_reported(self) -> None:
        self._run(CancelledJob(self.main.workspace.main_instance))

        assert self._message_boxes() == []

    def test_the_queue_keeps_moving_after_a_failure(self) -> None:
        # the message box must not be modal, or everything waiting on the job queue stalls behind it
        ran = []
        self._run(
            FailingJob(self.main.workspace.main_instance),
            SucceedingJob(self.main.workspace.main_instance, ran),
        )

        assert ran == ["Succeeding"]

    def test_a_raising_finish_handler_still_ends_the_job(self) -> None:
        # the frontend clears its progress display on job_finished, so it must be sent even when finish() raises
        job_manager = self.main.workspace.job_manager
        finished = []
        job_manager.job_finished.connect(finished.append)
        try:
            job = FinishRaisingJob(self.main.workspace.main_instance)
            with self.assertLogs("angrmanagement.logic.signal", level="ERROR"):
                self._run(job)
        finally:
            job_manager.job_finished.disconnect(finished.append)

        assert finished == [job]
        assert job not in job_manager.jobs

    def test_a_join_that_does_not_end_fails_with_every_thread_stack(self) -> None:
        job_manager = self.main.workspace.job_manager
        release = threading.Event()
        job = BlockedJob(self.main.workspace.main_instance, release)
        job_manager.add_job(job)
        try:
            assert job.started.wait(BLOCKED_JOB_START_WAIT)
            with self.assertRaises(AssertionError) as caught:
                join_all_jobs(job_manager, timeout=0.5)
        finally:
            release.set()
        join_all_jobs(job_manager)

        message = str(caught.exception)
        assert "('Blocked', 'RUNNING')" in message
        assert "'angr management job worker'" in message
        assert "self.release.wait(BLOCKED_JOB_WAIT)" in message


if __name__ == "__main__":
    unittest.main(argv=[__file__])
