from __future__ import annotations

import functools
import logging
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

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(name=__name__)


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

    def __init__(self, instance: Instance, on_finish=None, **kwargs) -> None:
        super().__init__("CFG generation", instance, on_finish=on_finish)

        # TODO: sanitize arguments

        # make a copy
        cfg_args = dict(kwargs)
        for key, val in self.DEFAULT_CFG_ARGS.items():
            if key not in cfg_args:
                cfg_args[key] = val

        self.cfg_args = cfg_args
        self._cfb = None

    def run(self, ctx: JobContext):
        exclude_region_types = {"kernel", "tls"}
        # create a temporary CFB for displaying partially analyzed binary during CFG recovery
        temp_cfb = self.instance.project.analyses.CFB(
            exclude_region_types=exclude_region_types, on_object_added=self._on_cfb_object_added
        )
        self._cfb = temp_cfb

        cfg = self.instance.project.analyses.CFG(
            progress_callback=functools.partial(self._progress_callback, ctx),
            low_priority=True,
            cfb=temp_cfb,
            **self.cfg_args,
        )
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
        ctx.set_progress(percentage, text)

        if cfg is not None:
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
        self.instance.cfb.am_event(object_added=(addr, obj))
