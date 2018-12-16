
import logging

from .job import Job

_l = logging.getLogger(name=__name__)


class CFGGenerationJob(Job):

    DEFAULT_CFG_ARGS = {
        'normalize': True,  # this is what people naturally expect
        'resolve_indirect_jumps': True,
    }

    def __init__(self, on_finish=None, **kwargs):
        super(CFGGenerationJob, self).__init__(name='CFG generation', on_finish=on_finish)

        # TODO: sanitize arguments

        # make a copy
        cfg_args = dict(kwargs)
        for key, val in self.DEFAULT_CFG_ARGS.items():
            if key not in cfg_args:
                cfg_args[key] = val

        self.cfg_args = cfg_args

    def run(self, inst):
        cfg = inst.project.analyses.CFG(progress_callback=self._progress_callback,
                                        **self.cfg_args
                                        )
        cfb = inst.project.analyses.CFB(cfg=cfg)

        return cfg, cfb

    def finish(self, inst, result):
        try:
            cfg, cfb = result
            inst.cfb = cfb
            inst.cfg = cfg
            super(CFGGenerationJob, self).finish(inst, result)
        except Exception:
            _l.error("Exception occurred in CFGGenerationJob.finish().", exc_info=True)

    def __repr__(self):
        return "Generating CFG"
