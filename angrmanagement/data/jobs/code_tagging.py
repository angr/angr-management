
from .job import Job


class CodeTaggingJob(Job):

    def __init__(self, on_finish=None):
        super(CodeTaggingJob, self).__init__(name="Code tagging", on_finish=on_finish)

    def _run(self, inst):

        func_count = len(inst.kb.functions)
        for i, func in enumerate(inst.kb.functions.values()):
            ct = inst.project.analyses.CodeTagging(func)
            func.tags = tuple(ct.tags)

            percentage = i / func_count * 100
            text = "%.02f%%" % percentage

            super()._progress_callback(percentage, text=text)

    def finish(self, inst, result):
        super(CodeTaggingJob, self).finish(inst, result)

    def __repr__(self):
        return "CodeTaggingJob"
