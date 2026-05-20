from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angrmanagement.data.analysis_options import AnalysisConfiguration
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule_async

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(__name__)


class RustSymbolRecoveryConfiguration(AnalysisConfiguration):
    """
    Configuration for Rust Symbol Recovery.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "rust_symbol_recovery"
        self.display_name = "Rust Symbol Recovery"
        self.description = "Recover Rust symbols from stripped Rust binaries. Enabled by default for Rust binaries."
        self.enabled = not self.instance.project.am_none and self.instance.project.is_rust_binary


class RustSymbolRecoveryJob(InstanceJob):
    """
    Job for recovering Rust symbols from stripped binaries.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("Rust Symbol Recovery", instance, on_finish=on_finish)

    def _is_stripped(self) -> bool:
        """Check if the binary appears to be stripped (has no or very few symbols)."""
        proj = self.instance.project
        main_obj = proj.loader.main_object
        if hasattr(main_obj, "symbols"):
            func_symbols = [s for s in main_obj.symbols if s.is_function and not s.is_import]
            return len(func_symbols) == 0
        return True

    def run(self, ctx: JobContext) -> None:
        if not self._is_stripped():
            _l.info("Binary is not stripped, skipping RustSymbolRecovery.")
            return

        ctx.set_progress(0, text="Recovering Rust symbols...")
        _l.info("Binary is stripped, running RustSymbolRecovery...")
        self.instance.project.analyses.RustSymbolRecovery()
        ctx.set_progress(100, text="Rust Symbol Recovery complete")

        # Trigger functions view refresh
        gui_thread_schedule_async(self._refresh_functions_view)

    @staticmethod
    def _refresh_functions_view() -> None:
        workspace = GlobalInfo.main_window.workspace
        view = workspace.view_manager.first_view_in_category("functions")
        if view is not None:
            view.reload()

    def __repr__(self) -> str:
        return "Recovering Rust symbols"
