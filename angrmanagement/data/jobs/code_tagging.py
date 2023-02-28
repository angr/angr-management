from .job import Job


class CodeTaggingJob(Job):
    """
    Job for tagging functions.
    """

    def __init__(self, on_finish=None):
        super().__init__(name="Code tagging", on_finish=on_finish)

    def _run(self, inst):
        func_count = len(inst.kb.functions)
        for i, func in enumerate(inst.kb.functions.values()):
            if func.alignment:
                continue
            ct = inst.project.analyses.CodeTagging(func)
            func.tags = tuple(ct.tags)

            percentage = i / func_count * 100
            super()._progress_callback(percentage)

    def __repr__(self):
        return "CodeTaggingJob"
