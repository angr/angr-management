from __future__ import annotations

import logging
import queue
import sys
import threading
import time
from typing import TYPE_CHECKING

from angrmanagement.data.jobs.job import Job, JobState

from . import GlobalInfo
from .signal import Signal

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

    def set_progress(self, percentage: float, text: str = "", ignore_cancel: bool = False) -> None:
        if self._job.state == JobState.CANCELLED and not ignore_cancel:
            raise JobCancelled

        self._job.progress_percentage = percentage

        percentage_delta = percentage - self._last_reported_percentage
        time_delta = time.time() - self._last_reported_timestamp

        if (percentage_delta > 0.02 or self._last_text != text) and time_delta >= 0.1 or percentage_delta >= 1.0:
            self._last_reported_percentage = percentage
            self._last_reported_timestamp = time.time()
            self._job_worker.job_progressed.emit(self._job, percentage, text)


class Worker:
    """Executes jobs. Its signals are emitted on the worker thread and delivered on the UI thread."""

    def __init__(self, job_manager: JobManager):
        self.job_manager = job_manager
        self.job_starting = Signal(Job, name="job_starting")
        self.job_progressed = Signal(Job, float, str, name="job_progressed")
        self.job_exception = Signal(Job, BaseException, name="job_exception")
        self.job_finished = Signal(Job, name="job_finished")

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


class JobManager:
    """
    Manages job execution in a worker thread.

    Jobs run one at a time, in the order they were added, on a daemon thread. The signals and ``Job.finish`` are
    delivered on the UI thread through ``GlobalInfo.executor``.
    """

    workspace: Workspace
    jobs: list[Job]
    job_worker_exception_callback: Callable[[Job, BaseException], None] | None

    _worker_thread: threading.Thread
    _worker: Worker

    def __init__(self, workspace: Workspace):
        self.workspace = workspace
        self.jobs = []
        self._current_job: Job | None = None
        self.job_worker_exception_callback = None

        self.job_added = Signal(Job, name="job_added")
        self.job_starting = Signal(Job, name="job_starting")
        self.job_progressed = Signal(Job, float, str, name="job_progressed")
        self.job_exception = Signal(Job, BaseException, name="job_exception")
        self.job_finished = Signal(Job, name="job_finished")

        # the thread creating the job manager is the UI thread; fix the default executor's owner before the worker
        # thread can be the first to ask for it
        _ = GlobalInfo.executor

        self._queue: queue.SimpleQueue[Job | None] = queue.SimpleQueue()
        self._stopping = False
        self._worker = Worker(self)
        self._worker.job_starting.connect(self._on_job_starting)
        self._worker.job_progressed.connect(self._on_job_progress)
        self._worker.job_exception.connect(self._on_job_exception)
        self._worker.job_finished.connect(self._on_job_finished)
        self._worker_thread = threading.Thread(target=self._run_worker, name="angr management job worker", daemon=True)
        self._worker_thread.start()

    def _run_worker(self) -> None:
        while True:
            job = self._queue.get()
            if job is None or self._stopping:
                return
            self._worker.execute_job(job)

    def quit(self):
        """Stop the worker thread once the running job, if any, returns. Jobs still waiting do not run."""
        self._stopping = True
        self._queue.put(None)
        if self._worker_thread is not threading.current_thread():
            self._worker_thread.join()

    def add_job(self, job: Job) -> None:
        self.jobs.append(job)
        # announce the job before the worker can start it, so job_added reaches listeners before job_starting
        self.job_added.emit(job)
        self._queue.put(job)

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

    def join_all_jobs(self, wait_period: float = 0.05) -> None:
        """
        Wait until self.jobs has stayed empty for `wait_period` seconds.

        One job may add another upon completion, so an empty list alone does not mean done; the UI executor
        keeps being pumped meanwhile so such follow-up jobs get queued. The exit checks the list at that
        instant, not only the clock: a worker holding the GIL can delay this thread past any deadline.

        Call it on the UI thread: it is what runs the jobs' finish handlers in a headless process.
        """
        last_has_job = time.monotonic()
        executor = GlobalInfo.executor
        while True:
            executor.process_pending()
            now = time.monotonic()
            if self.jobs:
                last_has_job = now
            elif now - last_has_job > wait_period:
                return
            time.sleep(0.001)

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
