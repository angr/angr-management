from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angrmanagement.data.analysis_options import AnalysisConfiguration

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(__name__)


class RustTypeDBLoaderConfiguration(AnalysisConfiguration):
    """
    Configuration for the Rust TypeDB Loader.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "rust_typedb_loader"
        self.display_name = "Rust TypeDB Loader"
        self.description = (
            "Load Rust prototype and type information from the Rust type database. Enabled by default "
            "for Rust binaries."
        )
        self.enabled = not self.instance.project.am_none and self.instance.project.is_rust_binary


class RustTypeDBLoaderJob(InstanceJob):
    """
    Job for loading Rust type database information.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("Rust TypeDB Loading", instance, on_finish=on_finish)

    def run(self, ctx: JobContext) -> None:
        ctx.set_progress(0, text="Loading Rust TypeDB...")
        _l.info("Running Rust TypeDBLoader...")
        self.instance.project.analyses.TypeDBLoader()
        ctx.set_progress(100, text="Rust TypeDB Loading complete")

    def __repr__(self) -> str:
        return "Loading Rust TypeDB"
