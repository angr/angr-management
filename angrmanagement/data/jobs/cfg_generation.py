from __future__ import annotations

import functools
import logging
import time
from enum import Enum
from typing import TYPE_CHECKING

import angr

from angrmanagement.data.analysis_options import (
    AnalysisConfiguration,
    BoolAnalysisOption,
    ChoiceAnalysisOption,
    StringAnalysisOption,
    extract_first_paragraph_from_docstring,
)
from angrmanagement.logic.threads import gui_thread_schedule_async

from .job import InstanceJob, JobState

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(name=__name__)

# the minimum interval (in seconds) between two consecutive GUI refreshes during CFG recovery
MIN_REFRESH_INTERVAL = 0.1
# the minimum amount of time (in seconds) between two consecutive batches of CFB object-added events
MIN_CFB_EVENT_INTERVAL = 0.1


class CFGForceScanMode(Enum):
    """
    CFG scanning mode options.
    """

    Disabled = 0
    SmartScan = 1
    CompleteScan = 2


class CFGAnalysisConfiguration(AnalysisConfiguration):
    """
    Configuration for CFGFast analysis.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "cfg"
        self.display_name = "Control-Flow Graph Recovery"
        doc = angr.analyses.cfg.CFGFast.__doc__
        self.description = extract_first_paragraph_from_docstring(doc) if doc else ""
        self.enabled = True
        self.options = {
            o.name: o
            for o in [
                BoolAnalysisOption("resolve_indirect_jumps", "Resolve indirect jumps", True),
                BoolAnalysisOption("data_references", "Collect cross-references and guess data types", True),
                BoolAnalysisOption("cross_references", "Perform deep analysis on cross-references (slow)"),
                BoolAnalysisOption("skip_unmapped_addrs", "Skip unmapped addresses", True),
                BoolAnalysisOption("exclude_sparse_regions", "Exclude Sparse Regions", True),
                BoolAnalysisOption(
                    "explicit_analysis_starts", "Exclude non-explicit functions for analysis (incomplete)", False
                ),
                ChoiceAnalysisOption(
                    "scanning_mode",
                    "Scan to maximize identified code blocks",
                    {
                        CFGForceScanMode.Disabled: "Disabled",
                        CFGForceScanMode.SmartScan: "Smart Scan",
                        CFGForceScanMode.CompleteScan: "Complete Scan",
                    },
                    CFGForceScanMode.SmartScan,
                ),
                ChoiceAnalysisOption(
                    "function_prologues",
                    "Scan for function prologues",
                    {
                        None: "Auto",
                        True: "Enabled",
                        False: "Disabled",
                    },
                    None,
                ),
                StringAnalysisOption(
                    "regions",
                    "Regions for analysis",
                    tooltip="Specify ranges of regions for which to recover CFG. Example: 0x400000-0x401000. You may "
                    "specify multiple address ranges for analysis.",
                ),
                StringAnalysisOption(
                    "function_starts",
                    "Start at function addresses",
                    tooltip="Specify function addresses to start recursive descent of CFG generation to speed up "
                    "analysis. Example: 0x400000,0x401000",
                ),
            ]
        }

    def to_dict(self) -> dict:
        cfg_options = super().to_dict()

        # update function start locations
        if "function_starts" in cfg_options:
            function_starts = []
            for func_start_str in cfg_options["function_starts"].split(","):
                func_start_str = func_start_str.strip(" ")
                if not func_start_str:
                    continue

                try:
                    func_addr = int(func_start_str, 16)
                except ValueError as e:
                    _l.error("Invalid analysis start: %s", func_start_str)
                    raise ValueError("Invalid function start string") from e

                function_starts.append(func_addr)

            if function_starts:
                if "explicit_analysis_starts" in cfg_options:
                    cfg_options["elf_eh_frame"] = False
                    cfg_options["symbols"] = False
                    cfg_options["start_at_entry"] = False

                cfg_options["function_starts"] = function_starts

        # discard "explicit_analysis_starts" even if function_starts is not set
        if "explicit_analysis_starts" in cfg_options:
            del cfg_options["explicit_analysis_starts"]

        # update options for region specification
        if "regions" in cfg_options:
            regions = []
            for region_str in cfg_options["regions"].split(","):
                region_str = region_str.strip(" ")
                if not region_str:
                    continue
                if "-" not in region_str or region_str.count("-") != 1:
                    _l.error("Invalid analysis region: %s", region_str)
                    raise ValueError("Invalid analysis region")
                min_addr, max_addr = region_str.split("-")
                try:
                    min_addr = int(min_addr, 16)
                    max_addr = int(max_addr, 16)
                except ValueError as e:
                    _l.error("Invalid analysis region: %s", region_str)
                    raise ValueError("Invalid analysis region bound") from e
                regions.append((min_addr, max_addr))
            if regions:
                cfg_options["regions"] = regions

        scanning_mode = cfg_options.pop("scanning_mode", None)
        if scanning_mode is not None:
            cfg_options["force_smart_scan"] = scanning_mode == CFGForceScanMode.SmartScan
            cfg_options["force_complete_scan"] = scanning_mode == CFGForceScanMode.CompleteScan

        return cfg_options


class CFGGenerationJob(InstanceJob):
    """
    Job for generating the Control Flow Graph.
    """

    DEFAULT_CFG_ARGS = {
        "normalize": True,  # this is what people naturally expect
    }

    def __init__(self, instance: Instance, on_finish=None, on_cfb_available=None, **kwargs) -> None:
        super().__init__("CFG generation", instance, on_finish=on_finish)

        # called on the GUI thread with the temporary CFBlanket as soon as it exists, so that the UI can start
        # displaying the binary before CFG recovery finishes
        self._on_cfb_available = on_cfb_available

        # TODO: sanitize arguments

        # make a copy
        cfg_args = dict(kwargs)
        for key, val in self.DEFAULT_CFG_ARGS.items():
            if key not in cfg_args:
                cfg_args[key] = val

        self.cfg_args = cfg_args
        self._cfb = None
        self._last_refresh: float = 0.0
        self._pending_cfb_objs: list[tuple[int, object]] = []
        self._last_cfb_event: float = 0.0
        self._abort_requested: bool = False

    def run(self, ctx: JobContext):
        exclude_region_types = {"kernel", "tls"}
        # create a temporary CFB for displaying partially analyzed binary during CFG recovery
        temp_cfb = self.instance.project.analyses.CFB(
            exclude_region_types=exclude_region_types, on_object_added=self._on_cfb_object_added
        )
        self._cfb = temp_cfb

        if self._on_cfb_available is not None:
            gui_thread_schedule_async(self._on_cfb_available, args=(temp_cfb,))

        cfg = self.instance.project.analyses.CFG(
            progress_callback=functools.partial(self._progress_callback, ctx),
            low_priority=True,
            cfb=temp_cfb,
            **self.cfg_args,
        )
        # if the job was cancelled, the CFG recovery was gracefully aborted and returned a finalized partial model;
        # remember the state it did not get to process so that the user may resume the recovery later
        aborted_state = getattr(cfg, "resume_state", None)
        if aborted_state is not None:
            self.instance.cfg_resume_state = aborted_state
            self.instance.cfg_resume_frontier = set(getattr(cfg, "unprocessed_job_addrs", None) or set())
        elif "resume_state" in self.cfg_args or "model" not in self.cfg_args:
            # a full recovery (initial, or one that consumed the captured resume state) completed: there is nothing
            # left to resume
            self.instance.cfg_resume_state = None
            self.instance.cfg_resume_frontier = set()
        # otherwise: an incremental job (resume-from-address, define/undefine code) completed; a previously captured
        # resume state still describes the remaining unprocessed work of the cancelled recovery - keep it
        self._flush_cfb_objects()
        self._cfb = None
        # Build the real one
        cfb = self.instance.project.analyses.CFB(kb=cfg.kb, exclude_region_types=exclude_region_types)

        return cfg.model, cfb

    def __repr__(self) -> str:
        return "Generating CFG"

    #
    # Private methods
    #

    def _progress_callback(self, ctx: JobContext, percentage, text: str | None = None, cfg=None) -> None:
        if self.state == JobState.CANCELLED:
            # gracefully abort the CFG recovery instead of raising JobCancelled: the analysis finalizes the partially
            # recovered model, run() returns normally, and the partial result gets published
            if cfg is not None and not self._abort_requested:
                self._abort_requested = True
                cfg.abort()
            ctx.set_progress(percentage, "Cancelling: finalizing the partial CFG...", ignore_cancel=True)
            return

        ctx.set_progress(percentage, text)

        if cfg is not None and time.monotonic() - self._last_refresh >= MIN_REFRESH_INTERVAL:
            self._last_refresh = time.monotonic()
            # Peek into the CFG
            gui_thread_schedule_async(
                self._refresh,
                args=(
                    cfg.model,
                    self._cfb,
                ),
            )

    def _refresh(self, cfg_model, cfb) -> None:
        # do not signal events. that will happen on a timer to not overwhelm the renderer
        # instance will exist because _run must be used first
        self.instance.cfg = cfg_model
        self.instance.cfb = cfb

    def _on_cfb_object_added(self, addr: int, obj) -> None:
        self._pending_cfb_objs.append((addr, obj))
        if time.monotonic() - self._last_cfb_event >= MIN_CFB_EVENT_INTERVAL:
            self._flush_cfb_objects()

    def _flush_cfb_objects(self) -> None:
        self._last_cfb_event = time.monotonic()
        if self._pending_cfb_objs:
            objs = self._pending_cfb_objs
            self._pending_cfb_objs = []
            self.instance.cfb.am_event(objects_added=objs)
