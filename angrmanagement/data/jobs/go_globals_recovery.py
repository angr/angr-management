from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angrmanagement.data.analysis_options import AnalysisConfiguration

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(__name__)


class GoGlobalsRecoveryConfiguration(AnalysisConfiguration):
    """
    Configuration for Go Globals Recovery.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "go_globals_recovery"
        self.display_name = "Go Globals Recovery"
        self.description = (
            "Recover Go runtime globals and package-level variables without data symbols. Enabled by default "
            "for Go binaries."
        )
        self.enabled = not self.instance.project.am_none and self.instance.project.is_go_binary


class GoGlobalsRecoveryJob(InstanceJob):
    """
    Job for recovering Go globals in the background, ahead of the first decompilation.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("Go Globals Recovery", instance, on_finish=on_finish)

    def run(self, ctx: JobContext) -> None:
        if self.instance.project.kb.go_globals.loaded:
            _l.info("Go globals are already loaded, skipping GoGlobalsRecovery.")
            return
        _l.info("Running GoGlobalsRecovery...")
        self.instance.project.analyses.GoGlobalsRecovery(low_priority=True, progress_callback=ctx.set_progress)

    def __repr__(self) -> str:
        return "Recovering Go globals"
