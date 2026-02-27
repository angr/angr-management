from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .job import InstanceJob

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions.function import Function

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

log = logging.getLogger(__name__)


class LLMPreloadCalleesJob(InstanceJob):
    """
    Job that auto-decompiles and LLM-refines callees of a given function.
    This pre-loads refined decompilations for functions called by the target,
    so that when the user navigates into them the results are already available.
    """

    def __init__(self, instance: Instance, function: Function, on_finish=None) -> None:
        super().__init__("LLM Preload Callees", instance, on_finish=on_finish)
        self.function = function

    def run(self, ctx: JobContext) -> None:
        project = self.instance.project.am_obj
        if project is None:
            return

        llm_client = project.llm_client
        if llm_client is None:
            return

        kb = self.instance.kb
        callgraph = kb.functions.callgraph

        if self.function.addr not in callgraph:
            return

        # get callees
        callee_addrs = list(callgraph.successors(self.function.addr))

        if not callee_addrs:
            return

        # filter out simprocedures and PLT stubs
        callees = []
        for addr in callee_addrs:
            if addr not in kb.functions:
                continue
            func = kb.functions[addr]
            if func.is_simprocedure or func.is_plt:
                continue
            callees.append(func)

        if not callees:
            return

        total = len(callees)
        for i, callee in enumerate(callees):
            if self.cancelled:
                return

            pct = int((i / total) * 100)
            ctx.set_progress(pct, f"Refining callee {callee.name} ({i + 1}/{total})")

            # decompile if not already cached
            dec_cache = kb.decompilations.get((callee.addr, "pseudocode"))
            if dec_cache is None or dec_cache.codegen is None:
                try:
                    decompiler = project.analyses.Decompiler(
                        callee,
                        flavor="pseudocode",
                        variable_kb=self.instance.pseudocode_variable_kb,
                    )
                    kb.decompilations[(callee.addr, "pseudocode")] = decompiler.cache
                    dec_cache = decompiler.cache
                except Exception:  # pylint: disable=broad-except
                    log.debug("Failed to decompile callee %s", callee.name, exc_info=True)
                    continue

            if dec_cache is None or dec_cache.codegen is None:
                continue

            # run LLM refinement
            dec = project.analyses.Decompiler(
                callee,
                variable_kb=self.instance.pseudocode_variable_kb,
                decompile=False,
            )
            dec.codegen = dec_cache.codegen
            changed = dec.llm_refine()
            if changed:
                dec_cache.codegen = dec.codegen

        ctx.set_progress(100, "Done")
