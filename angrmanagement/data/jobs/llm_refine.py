from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .job import InstanceJob

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions.function import Function

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

log = logging.getLogger(__name__)


class LLMRefineJob(InstanceJob):
    """
    Job that runs LLM-based refinement on a decompiled function.
    Supports different modes: suggest variable names, function name, variable types, or all.
    """

    SUGGEST_VARIABLE_NAMES = "variable_names"
    SUGGEST_FUNCTION_NAME = "function_name"
    SUGGEST_VARIABLE_TYPES = "variable_types"
    SUMMARIZE = "summarize"
    REFINE_ALL = "all"

    def __init__(
        self,
        instance: Instance,
        function: Function,
        mode: str = "all",
        on_finish=None,
        blocking: bool = False,
    ) -> None:
        super().__init__("LLM Refine", instance, on_finish=on_finish, blocking=blocking)
        self.function = function
        self.mode = mode

    def run(self, ctx: JobContext) -> None:
        project = self.instance.project.am_obj
        if project is None:
            log.warning("LLMRefineJob: no project available")
            return

        llm_client = project.llm_client
        if llm_client is None:
            log.warning("LLMRefineJob: no LLM client configured")
            return

        # get cached decompilation
        key = self.function.addr, "pseudocode"
        if key not in self.instance.kb.decompilations:
            log.warning("LLMRefineJob: no cached decompilation for %s", self.function.name)
            return
        dec_cache = self.instance.kb.decompilations[key]
        if dec_cache is None or dec_cache.codegen is None:
            log.warning("LLMRefineJob: no cached decompilation for %s", self.function.name)
            return

        ctx.set_progress(0, "Setting up decompiler")

        # create a Decompiler instance without decompiling, then attach existing codegen
        dec = project.analyses.Decompiler(
            self.function,
            variable_kb=self.instance.pseudocode_variable_kb,
            decompile=False,
        )
        dec.codegen = dec_cache.codegen
        dec.cache = dec_cache

        changed = False
        if self.mode in (self.REFINE_ALL, self.SUGGEST_VARIABLE_NAMES):
            ctx.set_progress(10, "Suggesting variable names...")
            changed |= dec.llm_suggest_variable_names(llm_client=llm_client)

        if self.mode in (self.REFINE_ALL, self.SUGGEST_FUNCTION_NAME):
            ctx.set_progress(40, "Suggesting function name...")
            changed |= dec.llm_suggest_function_name(llm_client=llm_client)

        if self.mode in (self.REFINE_ALL, self.SUGGEST_VARIABLE_TYPES):
            ctx.set_progress(70, "Suggesting variable types...")
            changed |= dec.llm_suggest_variable_types(llm_client=llm_client)

        if changed:
            ctx.set_progress(90, "Regenerating text...")
            dec.codegen.regenerate_text()
            dec_cache.codegen = dec.codegen

        if self.mode in (self.REFINE_ALL, self.SUMMARIZE):
            ctx.set_progress(95, "Summarizing function...")
            dec.llm_summarize_function(llm_client=llm_client)

        ctx.set_progress(100, "Done")
