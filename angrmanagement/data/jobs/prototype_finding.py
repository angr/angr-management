from __future__ import annotations

from typing import TYPE_CHECKING

from .job import Job

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class PrototypeFindingJob(Job):
    def __init__(self, on_finish=None) -> None:
        super().__init__(name="Function prototype finding", on_finish=on_finish)

    def _run(self, ctx: JobContext, inst: Instance) -> None:
        func_count = len(inst.kb.functions)
        for i, func in enumerate(inst.kb.functions.values()):
            if func.is_simprocedure or func.is_plt:
                func.find_declaration()

            percentage = i / func_count * 100
            ctx.set_progress(percentage)

    def finish(self, inst, result) -> None:
        super().finish(inst, result)

    def __repr__(self) -> str:
        return "PrototypeFindingJob"
