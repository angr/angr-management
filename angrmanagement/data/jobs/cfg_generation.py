from __future__ import annotations

import functools
import logging
from typing import TYPE_CHECKING

from angrmanagement.data.analysis_options import CFGForceScanMode
from angrmanagement.logic.threads import gui_thread_schedule_async

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(name=__name__)


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

        scanning_mode = self.cfg_args.pop("scanning_mode", None)
        if scanning_mode is not None:
            self.cfg_args["force_smart_scan"] = scanning_mode == CFGForceScanMode.SmartScan
            self.cfg_args["force_complete_scan"] = scanning_mode == CFGForceScanMode.CompleteScan

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
                    cfg,
                    self._cfb,
                ),
            )

    def _refresh(self, cfg, cfb) -> None:
        # do not signal events. that will happen on a timer to not overwhelm the renderer
        # instance will exist because _run must be used first
        self.instance.cfg = cfg
        self.instance.cfb = cfb

    def _on_cfb_object_added(self, addr: int, obj) -> None:
        self.instance.cfb.am_event(object_added=(addr, obj))
