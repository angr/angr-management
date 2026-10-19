"""The jobs view without a toolkit: every job the job manager saw, its state and progress, and cancelling it."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from angrmanagement.data.jobs import CFGGenerationJob
from angrmanagement.data.jobs.job import JobState

from .base import InstancePresenter
from .keymap import Binding, Keymap
from .menus import Menu, MenuEntry
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.jobs.job import Job

_STATE_DISPLAY = {
    JobState.PENDING: ("○ Pending", "job.pending"),
    JobState.RUNNING: ("◔ Running", "job.running"),
    JobState.FINISHED: ("✔ Finished", "job.finished"),
    JobState.CANCELLED: ("✖ Cancelled", "job.cancelled"),
}


def cancel_job(workspace, job: Job) -> None:
    """Cancel ``job``, as the Cancel button does."""
    if isinstance(job, CFGGenerationJob):
        # a cancelled CFG job still publishes its partial results; treat the cancellation like a manual
        # navigation so that the completion handler asks before navigating away
        workspace.note_user_navigation()
    workspace.job_manager.cancel_job(job)


def progress_bar(percentage: float, width: int = 20) -> str:
    """A text progress bar such as ``"█████░░░░░  50%"``."""
    filled = max(0, min(width, round(width * percentage / 100)))
    return "█" * filled + "░" * (width - filled) + f" {int(percentage):3d}%"


class JobsTableModel(ListTableModel["Job"]):
    """The jobs added to a job manager, in order, and their state and progress."""

    COL_STATUS = 0
    COL_NAME = 1
    COL_PROGRESS = 2

    COLUMNS: ClassVar[list[Column]] = [Column("Status", 12), Column("Name", 32), Column("Progress", stretch=True)]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, presenter: JobsPresenter | None = None) -> None:
        super().__init__()
        self.presenter = presenter

    def column_text(self, obj: Job, col: int) -> str:
        if col == self.COL_STATUS:
            return _STATE_DISPLAY.get(obj.state, (str(obj.state), None))[0]
        if col == self.COL_NAME:
            return obj.name
        if col == self.COL_PROGRESS:
            return progress_bar(obj.progress_percentage)
        return ""

    def column_value(self, obj: Job, col: int):
        if col == self.COL_PROGRESS:
            return obj.progress_percentage
        return self.column_text(obj, col)

    def style_key(self, obj: Job, col: int) -> str | None:
        return _STATE_DISPLAY.get(obj.state, ("", None))[1] if col == self.COL_STATUS else None

    def job_changed(self, job: Job) -> None:
        idx = self.index_of(job)
        if idx is not None:
            self.rows_changed(idx, idx)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.jobs_menu(self.objects(rows))


class JobsPresenter(InstancePresenter):
    """The jobs view: it follows the job manager's signals."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "bottom") -> None:
        super().__init__(workspace, "jobs", instance, default_docking_position)
        self.base_caption = "Jobs"
        self.model = JobsTableModel(self)
        job_manager = workspace.job_manager
        job_manager.job_added.connect(self._on_job_added)
        job_manager.job_progressed.connect(self._on_job_progressed)
        job_manager.job_starting.connect(self.model.job_changed)
        job_manager.job_exception.connect(self._on_job_exception)
        job_manager.job_finished.connect(self.model.job_changed)

    def close(self) -> None:
        job_manager = self.workspace.job_manager
        job_manager.job_added.disconnect(self._on_job_added)
        job_manager.job_progressed.disconnect(self._on_job_progressed)
        job_manager.job_starting.disconnect(self.model.job_changed)
        job_manager.job_exception.disconnect(self._on_job_exception)
        job_manager.job_finished.disconnect(self.model.job_changed)

    @property
    def keymap(self) -> Keymap:
        return Keymap("jobs", [Binding("Del", "cancel_job", "Cancel the job")])

    def cancel(self, job: Job) -> None:
        if job.state in (JobState.PENDING, JobState.RUNNING):
            cancel_job(self.workspace, job)

    def jobs_menu(self, jobs: Sequence[Job]) -> Menu | None:
        jobs = [job for job in jobs if job.state in (JobState.PENDING, JobState.RUNNING)]
        if not jobs:
            return None
        menu = Menu("")
        menu.add(MenuEntry("Cancel" + ("" if len(jobs) == 1 else f" ({len(jobs)})"), lambda: self._cancel_all(jobs)))
        return menu

    def _cancel_all(self, jobs: Sequence[Job]) -> None:
        for job in jobs:
            self.cancel(job)

    def _on_job_added(self, job: Job) -> None:
        self.model.append_rows([job])

    def _on_job_progressed(self, job: Job, *_args) -> None:
        self.model.job_changed(job)

    def _on_job_exception(self, job: Job, *_args) -> None:
        self.model.job_changed(job)
