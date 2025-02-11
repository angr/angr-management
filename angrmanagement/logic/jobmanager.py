from __future__ import annotations

import logging
import sys
import time
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import QApplication

from angrmanagement.data.jobs.job import Job, JobState

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.ui.workspace import Workspace


log = logging.getLogger(__name__)


class JobCancelled(BaseException):
    """Raised when a job is cancelled."""


class JobContext:
    """Passed to each job to allow it to report progress."""

    _job: Job
    _job_worker: Worker
    _last_reported_timestamp: float
    _last_reported_percentage: float
    _last_text: str

    def __init__(self, worker: Worker, job: Job):
        self._job_worker = worker
        self._job = job
        self._last_reported_timestamp = 0.0
        self._last_reported_percentage = 0.0
        self._last_text = ""

    def set_progress(self, percentage: float, text: str = "") -> None:
        if self._job.state == JobState.CANCELLED:
            raise JobCancelled

        self._job.progress_percentage = percentage

        percentage_delta = percentage - self._last_reported_percentage
        time_delta = time.time() - self._last_reported_timestamp

        if (percentage_delta > 0.02 or self._last_text != text) and time_delta >= 0.1:
            self._last_reported_percentage = percentage
            self._last_reported_timestamp = time.time()
            self._job_worker.job_progressed.emit(self._job, percentage, text)


class Worker(QObject):
    """Executes jobs."""

    job_starting = Signal(Job)
    job_progressed = Signal(Job, float, str)
    job_exception = Signal(Job, BaseException)
    job_finished = Signal(Job)

    def __init__(self, job_manager: JobManager):
        super().__init__()
        self.job_manager = job_manager

    @Slot(Job)
    def execute_job(self, job: Job) -> None:
        if job.state != JobState.PENDING:
            return

        self.job_starting.emit(job)

        try:
            job.state = JobState.RUNNING
            job.start_at = time.time()
            log.info('Job "%s" started', job.name)
            ctx = JobContext(self, job)
            ctx.set_progress(0.0)
            job.start(ctx)
            duration = time.time() - job.start_at
            log.info('Job "%s" completed after %.2f seconds', job.name, duration)

            if job.state == JobState.RUNNING:
                job.state = JobState.FINISHED
                ctx.set_progress(100.0)
            self.job_finished.emit(job)

        except JobCancelled as e:
            log.exception("Job successfully cancelled")
            self.job_exception.emit(job, e)

        except Exception as e:  # pylint: disable=broad-except
            log.exception('Exception while running job "%s":', job.name)
            job.state = JobState.FAILED
            self.job_exception.emit(job, e)


class JobManager(QObject):
    """Manages job execution in a worker thread."""

    workspace: Workspace
    jobs: list[Job]
    job_worker_exception_callback: Callable[[Job, BaseException], None] | None

    job_added = Signal(Job)
    job_starting = Signal(Job)
    job_progressed = Signal(Job, float, str)
    job_exception = Signal(Job, BaseException)
    job_finished = Signal(Job)

    _worker_thread: QThread
    _worker: Worker

    def __init__(self, workspace: Workspace):
        super().__init__()

        self.workspace = workspace
        self.jobs = []
        self._current_job: Job | None = None
        self.job_worker_exception_callback = None

        self._worker_thread = QThread()
        self._worker = Worker(self)
        self._worker.moveToThread(self._worker_thread)
        self._worker.job_starting.connect(self._on_job_starting)
        self._worker.job_progressed.connect(self._on_job_progress)
        self._worker.job_exception.connect(self._on_job_exception)
        self._worker.job_finished.connect(self._on_job_finished)
        self.job_added.connect(self._worker.execute_job)
        self._worker_thread.start()

    def quit(self):
        self._worker_thread.quit()
        self._worker_thread.wait()

    def add_job(self, job: Job) -> None:
        self.jobs.append(job)
        self.job_added.emit(job)

    @staticmethod
    def cancel_job(job: Job) -> None:
        """
        Cancel a job.
        """
        job.state = JobState.CANCELLED

    def interrupt_current_job(self) -> None:
        """Notify the current running job that the user requested an interrupt. The job may ignore it."""
        if self._current_job:
            self._current_job.state = JobState.CANCELLED

    def join_all_jobs(self, wait_period: float = 2.0) -> None:
        """
        Wait until self.jobs is empty for at least `wait_period` seconds.

        This is because one job may add another job upon completion. We cannot simply wait until self.jobs becomes
        empty.
        """
        last_has_job = time.time()
        while time.time() - last_has_job <= wait_period:
            while self.jobs:
                QApplication.processEvents()
                last_has_job = time.time()
                time.sleep(0.05)

    def _on_job_starting(self, job):
        self._current_job = job
        self.job_starting.emit(job)

    def _on_job_progress(self, job: Job, percentage: float, text: str = "") -> None:
        self.job_progressed.emit(job, percentage, text)

    def _on_job_exception(self, job, e):
        if self.job_worker_exception_callback is not None:
            self.job_worker_exception_callback(job, e)

        if job in self.jobs:
            self.jobs.remove(job)

        # Store exception for console debugging
        sys.last_traceback = e.__traceback__
        sys.last_value = e
        sys.last_type = type(e)
        sys.last_exc = e

        self._current_job = None
        self.job_exception.emit(job, e)

    def _on_job_finished(self, job):
        job.finish()  # Job finished handler (GUI thread only)

        if job in self.jobs:
            self.jobs.remove(job)

        self._current_job = None
        self.job_finished.emit(job)
