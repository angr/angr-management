from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.errors import AngrAIError
from PySide6.QtWidgets import QMessageBox

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule_async

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
        flavor: str = "pseudocode",
        on_finish=None,
        blocking: bool = False,
    ) -> None:
        super().__init__("LLM Refine", instance, on_finish=on_finish, blocking=blocking)
        self.function = function
        self.mode = mode
        self.flavor = flavor

    def _show_error_msgbox(self, message: str) -> None:
        msgbox = QMessageBox(GlobalInfo.main_window)
        msgbox.setWindowTitle("LLM Refinement Error")
        msgbox.setText(message)
        msgbox.setIcon(QMessageBox.Icon.Critical)
        msgbox.setStandardButtons(QMessageBox.StandardButton.Ok)
        msgbox.exec_()

    def run(self, ctx: JobContext) -> None:
        project = self.instance.project.am_obj
        if project is None:
            log.warning("LLMRefineJob: no project available")
            gui_thread_schedule_async(self._show_error_msgbox, ("No project is available.",))
            return

        llm_client = project.llm_client
        if llm_client is None:
            log.warning("LLMRefineJob: no LLM client configured")
            gui_thread_schedule_async(
                self._show_error_msgbox,
                ("No LLM client is configured. Please configure an LLM client first in Preferences -> LLM.",),
            )
            return

        # get cached decompilation
        key = self.function.addr, self.flavor
        if key not in self.instance.kb.decompilations:
            log.warning("LLMRefineJob: no cached decompilation for %s", self.function.name)
            gui_thread_schedule_async(
                self._show_error_msgbox,
                (
                    f"No cached decompilation found for this function and decompilation flavor {self.flavor}. "
                    f"Please decompile the function first before running LLM refinement.",
                ),
            )
            return
        dec_cache = self.instance.kb.decompilations[key]
        if dec_cache is None or dec_cache.codegen is None:
            log.warning("LLMRefineJob: no cached decompilation for %s", self.function.name)
            gui_thread_schedule_async(
                self._show_error_msgbox,
                (
                    f"No cached decompilation found for this function and decompilation flavor {self.flavor}. "
                    f"Please decompile the function first before running LLM refinement.",
                ),
            )
            return

        ctx.set_progress(0, "Preparing LLM refinement...")

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
            try:
                changed |= dec.llm_suggest_variable_names(llm_client=llm_client, raise_exc=True)
            except AngrAIError as ex:
                log.error("LLM refinement error during variable name suggestion: %s", ex)
                gui_thread_schedule_async(
                    self._show_error_msgbox,
                    (f"An error occurred during LLM refinement for variable name suggestion: {ex}",),
                )
                return

        if self.mode in (self.REFINE_ALL, self.SUGGEST_FUNCTION_NAME):
            ctx.set_progress(40, "Suggesting function name...")
            try:
                changed |= dec.llm_suggest_function_name(llm_client=llm_client, raise_exc=True)
            except AngrAIError as ex:
                log.error("LLM refinement error during function name suggestion: %s", ex)
                gui_thread_schedule_async(
                    self._show_error_msgbox,
                    (f"An error occurred during LLM refinement for function name suggestion: {ex}",),
                )
                return

        if self.mode in (self.REFINE_ALL, self.SUGGEST_VARIABLE_TYPES):
            ctx.set_progress(70, "Suggesting variable types...")
            try:
                changed |= dec.llm_suggest_variable_types(llm_client=llm_client, raise_exc=True)
            except AngrAIError as ex:
                log.error("LLM refinement error during variable type suggestion: %s", ex)
                gui_thread_schedule_async(
                    self._show_error_msgbox,
                    (f"An error occurred during LLM refinement for variable type suggestion: {ex}",),
                )
                return

        if changed:
            ctx.set_progress(90, "Regenerating text...")
            dec.codegen.regenerate_text()
            dec_cache.codegen = dec.codegen

        if self.mode in (self.REFINE_ALL, self.SUMMARIZE):
            ctx.set_progress(95, "Summarizing function...")
            try:
                dec.llm_summarize_function(llm_client=llm_client)
            except AngrAIError as ex:
                log.error("LLM refinement error during function summarization: %s", ex)
                gui_thread_schedule_async(
                    self._show_error_msgbox,
                    (f"An error occurred during LLM refinement for function summarization: {ex}",),
                )
                return

        ctx.set_progress(100, "Done")
