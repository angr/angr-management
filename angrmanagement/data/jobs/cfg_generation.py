import logging
import time

from angrmanagement.data.analysis_options import CFGForceScanMode
from angrmanagement.logic.threads import gui_thread_schedule_async

from .job import Job

_l = logging.getLogger(name=__name__)


class CFGGenerationJob(Job):
    DEFAULT_CFG_ARGS = {
        "normalize": True,  # this is what people naturally expect
    }

    def __init__(self, on_finish=None, **kwargs):
        super().__init__(name="CFG generation", on_finish=on_finish)

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
        self._last_progress_callback_triggered = None

    def _run(self, inst):
        self.instance = inst
        exclude_region_types = {"kernel", "tls"}
        # create a temporary CFB for displaying partially analyzed binary during CFG recovery
        temp_cfb = inst.project.analyses.CFB(exclude_region_types=exclude_region_types)
        self._cfb = temp_cfb
        cfg = inst.project.analyses.CFG(
            progress_callback=self._progress_callback,
            low_priority=True,
            cfb=temp_cfb,
            use_patches=True,
            **self.cfg_args,
        )
        self._cfb = None
        # Build the real one
        cfb = inst.project.analyses.CFB(kb=cfg.kb, exclude_region_types=exclude_region_types)

        return cfg, cfb

    def finish(self, inst, result):
        try:
            cfg, cfb = result
            inst.cfb = cfb
            inst.cfg = cfg.model
            inst.cfb.am_event()
            inst.cfg.am_event()
            super().finish(inst, result)
        except Exception:
            _l.error("Exception occurred in CFGGenerationJob.finish().", exc_info=True)

    def __repr__(self):
        return "Generating CFG"

    #
    # Private methods
    #

    def _progress_callback(self, percentage, text=None, cfg=None):
        t = time.time()
        if self._last_progress_callback_triggered is not None and t - self._last_progress_callback_triggered < 0.2:
            return
        self._last_progress_callback_triggered = t

        text = "%.02f%%" % percentage

        super()._progress_callback(percentage, text=text)

        if cfg is not None:
            # Peek into the CFG
            gui_thread_schedule_async(
                self._refresh,
                args=(
                    cfg,
                    self._cfb,
                ),
            )

    def _refresh(self, cfg, cfb):
        # do not signal events. that will happen on a timer to not overwhelm the renderer
        # instance will exist because _run must be used first
        self.instance.cfg = cfg
        self.instance.cfb = cfb
