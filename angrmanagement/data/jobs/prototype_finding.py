from __future__ import annotations

from typing import TYPE_CHECKING

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class PrototypeFindingJob(InstanceJob):
    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("Function prototype finding", instance, on_finish=on_finish)

    def run(self, ctx: JobContext) -> None:
        func_count = len(self.instance.kb.functions)
        for i, func in enumerate(self.instance.kb.functions.values()):
            if func.is_simprocedure or func.is_plt:
                func.find_declaration()

            percentage = i / func_count * 100
            ctx.set_progress(percentage)

    def __repr__(self) -> str:
        return "PrototypeFindingJob"
