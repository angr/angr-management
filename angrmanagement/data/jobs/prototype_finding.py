from __future__ import annotations

from .job import Job


class PrototypeFindingJob(Job):
    def __init__(self, on_finish=None) -> None:
        super().__init__(name="Function prototype finding", on_finish=on_finish)

    def _run(self, inst) -> None:
        func_count = len(inst.kb.functions)
        for i, func in enumerate(inst.kb.functions.values()):
            if func.is_simprocedure or func.is_plt:
                func.find_declaration()

            percentage = i / func_count * 100
            super()._progress_callback(percentage)

    def finish(self, inst, result) -> None:
        super().finish(inst, result)

    def __repr__(self) -> str:
        return "PrototypeFindingJob"
