from __future__ import annotations

import logging
import sys
import time
from queue import Queue
from typing import TYPE_CHECKING

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule, gui_thread_schedule_async
from angrmanagement.utils.daemon_thread import start_daemon_thread

if TYPE_CHECKING:
    from collections.abc import Callable
    from threading import Thread

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.jobs.job import Job

log = logging.getLogger(__name__)


class JobManager:
    """JobManager is responsible for managing jobs and running them in a separate thread."""

    instance: Instance

    jobs: list[Job]
    _jobs_queue: Queue[Job]
    current_job: Job | None
    worker_thread: Thread

    job_worker_exception_callback: Callable[[Job, BaseException], None] | None

    def __init__(self, instance: Instance):
        self.instance = instance

        self.jobs = []
        self._jobs_queue = Queue()
        self.current_job = None
        self.worker_thread = None
        self.job_worker_exception_callback = None

        self._start_worker()

    def add_job(self, job: Job) -> None:
        self.jobs.append(job)
        self._jobs_queue.put(job)

    def interrupt_current_job(self) -> None:
        """Notify the current running job that the user requested an interrupt. The job may ignore it."""
        # Due to thread scheduling, current_job reference *must* first be saved on the stack. Accessing self.current_job
        # multiple times will lead to a race condition.
        current_job = self.current_job
        if current_job:
            current_job.keyboard_interrupt()

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
        self.worker_thread = start_daemon_thread(self._worker, "angr-management Worker Thread")

    def _worker(self) -> None:
        while True:
            if self._jobs_queue.empty():
                callback_worker_progress_empty()

            if any(job.blocking for job in self.jobs):
                callback_worker_blocking_job()

            job = self._jobs_queue.get()
            callback_worker_new_job()

            if any(job.blocking for job in self.jobs):
                callback_worker_blocking_job_2()

            try:
                self.current_job = job
                result = job.run(self.instance)
                self.current_job = None
            except (Exception, KeyboardInterrupt) as e:  # pylint: disable=broad-except
                sys.last_traceback = e.__traceback__
                self.current_job = None
                log.exception('Exception while running job "%s":', job.name)
                if self.job_worker_exception_callback is not None:
                    self.job_worker_exception_callback(job, e)
            else:
                callback_job_complete(self.instance, job, result)

    # pylint:disable=no-self-use
    def _set_status(self, status_text) -> None:
        GlobalInfo.main_window.status = status_text


def callback_worker_progress_empty() -> None:
    gui_thread_schedule(GlobalInfo.main_window.progress_done, args=())


def callback_worker_blocking_job() -> None:
    if GlobalInfo.main_window is not None and GlobalInfo.main_window.workspace:
        gui_thread_schedule(GlobalInfo.main_window._progress_dialog.hide, args=())


def callback_worker_new_job() -> None:
    gui_thread_schedule_async(GlobalInfo.main_window.progress, args=("Working...", 0.0, True))


def callback_worker_blocking_job_2() -> None:
    if GlobalInfo.main_window.isVisible():
        gui_thread_schedule(GlobalInfo.main_window._progress_dialog.show, args=())


def callback_job_complete(instance: Instance, job: Job, result) -> None:
    gui_thread_schedule_async(job.finish, args=(instance, result))
