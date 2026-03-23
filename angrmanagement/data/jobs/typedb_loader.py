from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(__name__)


class TypeDBLoaderJob(InstanceJob):
    """
    Job for loading type database information.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("TypeDB Loading", instance, on_finish=on_finish)

    def run(self, ctx: JobContext) -> None:
        ctx.set_progress(0, text="Loading TypeDB...")
        _l.info("Running TypeDBLoader...")
        self.instance.project.analyses.TypeDBLoader()
        ctx.set_progress(100, text="TypeDB Loading complete")

    def __repr__(self) -> str:
        return "Loading TypeDB"
