from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import angr

from angrmanagement.data.analysis_options import (
    AnalysisConfiguration,
    BoolAnalysisOption,
    IntAnalysisOption,
    extract_first_paragraph_from_docstring,
)
from angrmanagement.data.indirect_jumps import IndirectJumpResolutionResult
from angrmanagement.logic.jobmanager import JobCancelled

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(__name__)


class IndirectJumpResolutionConfiguration(AnalysisConfiguration):
    """
    Configuration for whole-binary indirect jump and call resolution.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "indirect_jumps"
        self.display_name = "Resolve Indirect Jumps and Calls Across the Binary"
        doc = angr.analyses.FullProgramIndirectJumpResolution.__doc__
        self.description = extract_first_paragraph_from_docstring(doc) if doc else ""
        # off by default: this decompiles every function in the binary, so it costs about as much as decompiling the
        # whole program
        self.enabled = False
        self.options = {
            o.name: o
            for o in [
                BoolAnalysisOption(
                    "track_provenance",
                    "Record why each target was resolved",
                    True,
                    tooltip="Keep the chain of copies, stores, loads and argument passes that carried each code "
                    "pointer to its indirect jump, so it can be inspected afterwards.",
                ),
                IntAnalysisOption(
                    "max_iterations",
                    "Maximum interprocedural propagation rounds",
                    default=8,
                    tooltip="Cap on how many rounds the interprocedural pointer-shape propagation runs before "
                    "giving up on reaching a fixed point.",
                    minimum=1,
                    maximum=64,
                ),
            ]
        }


class IndirectJumpResolutionJob(InstanceJob):
    """
    Resolve indirect jumps and calls across the whole binary.

    The analysis writes what it resolves into ``kb.indirect_jumps``; the job additionally hands back a snapshot of
    the run (see :class:`IndirectJumpResolutionResult`) so the GUI can show provenance afterwards without keeping
    the analysis itself resident.

    Cancelling this job asks the analysis to stop rather than tearing it down: the interprocedural phases still run
    over whatever was collected, so a cancelled run yields partial - but real - results.
    """

    def __init__(
        self,
        instance: Instance,
        on_finish=None,
        track_provenance: bool = True,
        max_iterations: int = 8,
        functions=None,
    ) -> None:
        super().__init__("Indirect jump resolution", instance, on_finish=on_finish)
        self.track_provenance = track_provenance
        self.max_iterations = max_iterations
        self.functions = functions

    def run(self, ctx: JobContext) -> IndirectJumpResolutionResult | None:
        if self.instance.project.am_none:
            return None
        cfg_model = None if self.instance.cfg.am_none else self.instance.cfg.am_obj
        if cfg_model is None:
            _l.warning("Cannot resolve indirect jumps before a control-flow graph has been recovered.")
            return None

        analysis = self.instance.project.analyses.FullProgramIndirectJumpResolution(
            functions=self.functions,
            low_priority=True,
            track_provenance=self.track_provenance,
            max_iterations=self.max_iterations,
            progress_callback=lambda percentage, text=None, **kwargs: self._progress_callback(
                ctx, percentage, text, kwargs.get("analysis")
            ),
        )
        return IndirectJumpResolutionResult.from_analysis(analysis, cfg_model)

    @staticmethod
    def _progress_callback(ctx: JobContext, percentage: float, text: str | None, analysis) -> None:
        """
        Forward progress to the job, and turn a cancellation into an abort request.

        Letting JobCancelled propagate out of the analysis would throw away everything the run had collected. Asking
        the analysis to abort instead lets it finish the cheap phases over the facts it already has and return a
        partial result.
        """
        try:
            ctx.set_progress(percentage, text or "")
        except JobCancelled:
            if analysis is None:
                raise
            analysis.abort()

    def __repr__(self) -> str:
        return "<Indirect Jump Resolution Job>"
