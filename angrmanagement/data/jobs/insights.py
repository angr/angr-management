from __future__ import annotations

from typing import TYPE_CHECKING

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class InsightsJob(InstanceJob):
    """
    Use some magic to gain insights on the current binary.
    """

    def __init__(self, instance: Instance, on_finish=None):
        super().__init__("Insights collection", instance, on_finish=on_finish)

        self._last_progress_callback_triggered = None

    def run(self, ctx: JobContext):
        self.instance.project.analyses.Insights(cfg=self.instance.cfg.am_obj)
        return self.instance.kb.insights.insights

    def __repr__(self):
        return "<Insights Collection Job>"
