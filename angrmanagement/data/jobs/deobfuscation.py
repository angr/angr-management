from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.deobfuscator import APIObfuscationFinder, StringObfuscationFinder

from angrmanagement.data.analysis_options import AnalysisConfiguration

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class APIDeobfuscationConfiguration(AnalysisConfiguration):
    """
    Configuration for API deobfuscation.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "api_deobfuscation"
        self.display_name = "Deobfuscate API usage"
        self.description = "Search for 'obfuscated' API use and attempt to deobfuscate it."
        self.enabled = False


class StringDeobfuscationConfiguration(AnalysisConfiguration):
    """
    Configuration for String deobfuscation.
    """

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "string_deobfuscation"
        self.display_name = "Deobfuscate Strings"
        self.description = "Search for 'obfuscated' strings and attempt to deobfuscate them."
        self.enabled = False


class APIDeobfuscationJob(InstanceJob):
    """
    Job for deobfuscating API usage.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("API Deobfuscation", instance, on_finish=on_finish)

    def run(self, ctx: JobContext) -> None:
        self.instance.project.analyses[APIObfuscationFinder].prep(progress_callback=ctx.set_progress)(
            variable_kb=self.instance.pseudocode_variable_kb
        )

    def __repr__(self) -> str:
        return "APIDeobfuscationJob"


class StringDeobfuscationJob(InstanceJob):
    """
    Job for deobfuscating strings.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("String Deobfuscation", instance, on_finish=on_finish)

    def run(self, ctx: JobContext) -> None:
        self.instance.project.analyses[StringObfuscationFinder].prep(progress_callback=ctx.set_progress)()

    def __repr__(self) -> str:
        return "StringDeobfuscationJob"
