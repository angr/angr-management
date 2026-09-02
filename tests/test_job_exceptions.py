"""
Test cases for how the workspace reports job exceptions.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from common import AngrManagementTestCase  # pylint: disable=import-error
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
        self.main.workspace.job_manager.join_all_jobs()

    def test_failed_job_shows_a_message_box(self) -> None:
        self._run(FailingJob(self.main.workspace.main_instance))

        boxes = self._message_boxes()
        assert len(boxes) == 1
        # not windowTitle(): QMessageBox.setWindowTitle is a no-op on macOS, so the job name has to
        # be readable from the body text on every platform
        assert "Failing" in boxes[0].text()
        assert "this job always fails" in boxes[0].text()

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


if __name__ == "__main__":
    unittest.main(argv=[__file__])
