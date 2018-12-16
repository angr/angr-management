
from .job import Job


class CodeTaggingJob(Job):

    def __init__(self, on_finish=None):
        super(CodeTaggingJob, self).__init__(name="Code tagging", on_finish=on_finish)

    def run(self, inst):
        for func in inst.cfg.functions.values():
            ct = inst.project.analyses.CodeTagging(func)
            func.tags = tuple(ct.tags)

    def finish(self, inst, result):
        super(CodeTaggingJob, self).finish(inst, result)

    def __repr__(self):
        return "Tagging Code"