from __future__ import annotations

import ctypes
import itertools
import logging
import sys
import time
from queue import Queue
from threading import Thread
from typing import TYPE_CHECKING

from angrmanagement.data.jobs.job import JobState
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule, gui_thread_schedule_async

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.jobs.job import Job
    from angrmanagement.ui.workspace import Workspace


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class JobContext:
    """JobContext is a context object that is passed to each job to allow it to
    report progress and other information back to the JobManager.
    """

    _job_manager: JobManager
    _job: Job

    def __init__(self, job_manager: JobManager, job: Job):
        self._job_manager = job_manager
        self._job = job

    def set_progress(self, percentage: float, text: str | None = None) -> None:
        self._job_manager.callback_job_set_progress(self._job, percentage, text)


class Worker(Thread):
    """Worker is a thread that runs jobs in the background."""

    job_manager: JobManager
    id_: int

    current_job: Job | None

    def __init__(self, job_manager: JobManager, id_: int):
        super().__init__(name=f"angr-management Worker Thread {id_}", daemon=True)
        self.job_manager = job_manager
        self.id_ = id_
        self.current_job = None

    def run(self) -> None:
        while True:
            # Add a small delay when the queue is empty to avoid busy waiting
            if self.job_manager.jobs_queue.empty():
                gui_thread_schedule(GlobalInfo.main_window.status_bar.progress_done, args=())
                time.sleep(0.1)
                continue

            # Show progress dialog if any job is blocking and the main window is visible
            if any(job.blocking for job in self.job_manager.jobs) and GlobalInfo.main_window.isVisible():
                gui_thread_schedule(GlobalInfo.main_window.status_bar._progress_dialog.show, args=())

            # Get the next job from the queue
            self.current_job = self.job_manager.jobs_queue.get()

            # If the job is cancelled, skip it
            if self.current_job.state == JobState.CANCELLED:
                self.job_manager.jobs.remove(self.current_job)
                self.current_job = None
                continue

            # Indicate that the job is running in the status bar
            gui_thread_schedule_async(GlobalInfo.main_window.status_bar.progress, args=("Working...", 0.0, True))
            self.job_manager.callback_worker_new_job(self.current_job)
            log.info('Job "%s" started', self.current_job.name)

            # Set up the job context
            ctx = JobContext(self.job_manager, self.current_job)
            ctx.set_progress(0)
            self.current_job.state = JobState.RUNNING
            self.current_job.start_at = time.time()

            # Run the job
            try:
                result = self.current_job.run(ctx)

            except KeyboardInterrupt:
                # Handle cancellation

                self.current_job.state = JobState.CANCELLED
                log.info('Job "%s" cancelled', self.current_job.name)

            except Exception as e:  # pylint: disable=broad-except
                # Handle exceptions

                sys.last_traceback = e.__traceback__

                self.current_job.state = JobState.FAILED
                log.exception('Exception while running job "%s":', self.current_job.name)
                if self.job_manager.job_worker_exception_callback is not None:
                    self.job_manager.job_worker_exception_callback(self.current_job, e)

            else:
                # Handle successful completion

                duration = time.time() - self.current_job.start_at
                if self.current_job.state != JobState.CANCELLED:
                    self.job_manager.callback_job_complete(self.current_job)
                log.info('Job "%s" completed after %.2f seconds', self.current_job.name, duration)
                self.current_job.state = JobState.FINISHED
                gui_thread_schedule_async(self.current_job.finish, args=(result,))

            finally:
                self.job_manager.jobs.remove(self.current_job)
                self.current_job = None

    def keyboard_interrupt(self) -> None:
        """Called from the GUI thread when the user presses Ctrl+C or presses a cancel button"""
        # lol. lmao even.
        if self.ident is not None:
            res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_long(self.ident), ctypes.py_object(KeyboardInterrupt)
            )
            if res != 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(self.ident), 0)
                log.error("Failed to interrupt thread")


class JobManager:
    """JobManager is responsible for managing jobs and running them in a separate thread."""

    workspace: Workspace

    jobs: list[Job]
    jobs_queue: Queue[Job]
    worker_thread: Worker | None

    job_worker_exception_callback: Callable[[Job, BaseException], None] | None
    _job_id_counter: itertools.count

    _gui_last_updated_at: float
    _last_text: str | None

    def __init__(self, workspace: Workspace):
        self.workspace = workspace

        self.jobs = []
        self.jobs_queue = Queue()
        self.worker_thread = None
        self.job_worker_exception_callback = None
        self._job_id_counter = itertools.count()
        self._gui_last_updated_at = 0.0
        self._last_text = None

    def add_job(self, job: Job) -> None:
        self.jobs.append(job)
        if self.workspace.view_manager.first_view_in_category("jobs") is not None:
            self.callback_job_added(job)
        self.jobs_queue.put(job)

        if self.worker_thread is None or not self.worker_thread.is_alive():
            self._start_worker()

    def cancel_job(self, job: Job) -> bool:
        """Cancel a job. Returns True if the job was cancelled, False if it was
        not found or already completed.
        """
        if job.state not in (JobState.PENDING, JobState.RUNNING):
            return False
        if job in self.jobs:
            self.jobs.remove(job)
            job.state = JobState.CANCELLED
            if self.worker_thread is not None and self.worker_thread.current_job == job:
                self.worker_thread.keyboard_interrupt()

            return True
        return False

    def interrupt_current_job(self) -> None:
        """Notify the current running job that the user requested an interrupt. The job may ignore it."""
        # Due to thread scheduling, current_job reference *must* first be saved on the stack. Accessing self.current_job
        # multiple times will lead to a race condition.
        if self.worker_thread is not None:
            current_job = self.worker_thread.current_job
            if current_job:
                self.worker_thread.keyboard_interrupt()

    def join_all_jobs(self, wait_period: float = 2.0) -> None:
        """
        Wait until self.jobs is empty for at least `wait_period` seconds.

        This is because one job may add another job upon completion. We cannot simply wait until self.jobs becomes
        empty.
        """

        last_has_job = time.time()
        while time.time() - last_has_job <= wait_period:
            while self.jobs:
                last_has_job = time.time()
                time.sleep(0.05)

    def _start_worker(self) -> None:
        self.worker_thread = Worker(self, next(self._job_id_counter))
        self.worker_thread.start()

    # Job callbacks

    def callback_job_set_progress(self, job: Job, percentage: float, text: str | None) -> None:
        delta = percentage - job.progress_percentage

        if (delta > 0.02 or self._last_text != text) and time.time() - self._gui_last_updated_at >= 0.1:
            self._gui_last_updated_at = time.time()
            job.progress_percentage = percentage
            status_text = f"{job.name}: {text}" if text else job.name
            gui_thread_schedule_async(GlobalInfo.main_window.status_bar.progress, args=(status_text, percentage))

            # Dynamically update jobs view progress with instance
            if self.workspace.view_manager.first_view_in_category("jobs") is not None:
                self.callback_worker_progress(job)

    def callback_job_added(self, job: Job) -> None:
        """
        This callback adds jobs dynamically to the jobsView
        upon addition of a new job
        """
        if self.workspace.view_manager.first_view_in_category("jobs") is not None:
            jobs_view = self.workspace.view_manager.first_view_in_category("jobs")
            gui_thread_schedule_async(jobs_view.qjobs.add_new_job, args=[job])

    def callback_worker_progress(self, job: Job) -> None:
        """
        This callback modifies the jobsView table to
        change the progress of a job visually
        """
        if self.workspace.view_manager.first_view_in_category("jobs") is not None:
            jobs_view = self.workspace.view_manager.first_view_in_category("jobs")
            gui_thread_schedule_async(jobs_view.qjobs.change_job_progress, args=[job])

    def callback_worker_new_job(self, job: Job) -> None:
        """
        This callback changes the jobsView table to have the table modified
        with modifying the job status as running
        """
        if self.workspace.view_manager.first_view_in_category("jobs") is not None:
            jobs_view = self.workspace.view_manager.first_view_in_category("jobs")
            gui_thread_schedule_async(jobs_view.qjobs.change_job_running, args=(job,))

    def callback_job_complete(self, job: Job):
        """
        This callback changes the jobsView table to have the table modified
        with the job complete
        """
        if self.workspace.view_manager.first_view_in_category("jobs") is not None:
            jobs_view = self.workspace.view_manager.first_view_in_category("jobs")
            gui_thread_schedule_async(jobs_view.qjobs.change_job_finish, args=[job])
