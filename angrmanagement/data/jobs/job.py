from __future__ import annotations

import datetime
import logging
import time
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from angrmanagement.logic import GlobalInfo

if TYPE_CHECKING:
    from collections.abc import Callable

    from IPython.extensions.autoreload import ModuleReloader

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _module_reloader() -> ModuleReloader:
    try:
        from IPython.extensions.autoreload import ModuleReloader  # pylint:disable=import-outside-toplevel

        m = ModuleReloader()
        m.enabled = True
        m.check_all = True
        m.check()
    except ImportError:
        m = None

    return m


class JobState(Enum):
    """
    The state of a job.
    """

    PENDING = 0
    RUNNING = 1
    FINISHED = 2
    CANCELLED = 3
    FAILED = 4


class Job:
    """
    The base class of all Jobs in angr management.
    """

    name: str
    progress_percentage: float
    last_text: str | None
    start_at: float
    blocking: bool
    state: JobState = JobState.PENDING
    _on_finish: Callable[[Any], None] | None

    def __init__(self, name: str, on_finish: Callable[[Any], None] | None = None, blocking: bool = False) -> None:
        self.name = name
        self.progress_percentage = 0.0
        self.last_text = None
        self.start_at = 0.0
        self.blocking = blocking
        self.cancelled = False

        # callbacks
        self._on_finish = on_finish

        if GlobalInfo.autoreload:
            m = _module_reloader()
            if m is not None:
                prestate = dict(m.modules_mtimes)
                m.check()
                poststate = dict(m.modules_mtimes)
                if prestate != poststate:
                    log.warning("Auto-reload found changed modules")

    @property
    def time_elapsed(self) -> str:
        return str(datetime.timedelta(seconds=int(time.time() - self.start_at)))

    def run(self, ctx: JobContext):
        """Run the job. This method is called in a worker thread."""
        raise NotImplementedError

    def finish(self, result: Any) -> None:
        """Runs after the job has finished in the GUI thread."""
        if self._on_finish is not None:
            self._on_finish(result)


class InstanceJob(Job):
    """
    A job that operates on an instance.
    """

    instance: Instance

    def __init__(
        self, name: str, instance: Instance, on_finish: Callable[[Any], None] | None = None, blocking: bool = False
    ):
        super().__init__(name, on_finish, blocking)
        self.instance = instance
