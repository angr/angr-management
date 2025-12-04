from __future__ import annotations

from angrmanagement.data.analysis_options import AnalysesConfiguration
from angrmanagement.data.jobs import (
    APIDeobfuscationConfiguration,
    APIDeobfuscationJob,
    CallingConventionRecoveryConfiguration,
    CallingConventionRecoveryJob,
    CFGAnalysisConfiguration,
    CFGGenerationJob,
    CodeTaggingConfiguration,
    CodeTaggingJob,
    FlirtAnalysisConfiguration,
    FlirtSignatureRecognitionJob,
    Job,
    PrototypeFindingJob,
    StringDeobfuscationConfiguration,
    StringDeobfuscationJob,
    VariableRecoveryConfiguration,
    VariableRecoveryJob,
)


class AnalysisManager:
    """
    Manager of analyses.
    """

    def __init__(self, workspace):
        self.workspace = workspace

    def get_default_analyses_configuration(self) -> AnalysesConfiguration:
        return AnalysesConfiguration(
            [
                a(self.workspace.main_instance)
                for a in [
                    CFGAnalysisConfiguration,
                    APIDeobfuscationConfiguration,
                    StringDeobfuscationConfiguration,
                    FlirtAnalysisConfiguration,
                    CodeTaggingConfiguration,
                    CallingConventionRecoveryConfiguration,
                    VariableRecoveryConfiguration,
                ]
            ]
        )

    def _schedule_job(self, job: Job):
        self.workspace.job_manager.add_job(job)

    def run_analysis(self) -> None:
        instance = self.workspace.main_instance
        conf = instance.analysis_configuration

        if conf["cfg"].enabled:
            job = CFGGenerationJob(instance, on_finish=self.workspace.on_cfg_generated, **conf["cfg"].to_dict())
            self._schedule_job(job)

        if conf["flirt"].enabled:
            self._schedule_job(FlirtSignatureRecognitionJob(instance))
            self._schedule_job(PrototypeFindingJob(instance))

        if conf["api_deobfuscation"].enabled:
            self._schedule_job(APIDeobfuscationJob(instance))

        if conf["string_deobfuscation"].enabled:
            self._schedule_job(StringDeobfuscationJob(instance))

        if conf["code_tagging"].enabled:
            self._schedule_job(
                CodeTaggingJob(
                    instance,
                    on_finish=self.workspace.on_function_tagged,
                )
            )

        if conf["cca"].enabled:
            job = CallingConventionRecoveryJob(
                instance, **conf["cca"].to_dict(), on_cc_recovered=self.workspace.on_cc_recovered
            )

            # prioritize the current function in display
            disassembly_view = self.workspace.view_manager.first_view_in_category("disassembly")
            if disassembly_view is not None and not disassembly_view.function.am_none:
                job.prioritize_function(disassembly_view.function.addr)

            self._schedule_job(job)

        if conf["varec"].enabled:
            job = VariableRecoveryJob(
                instance, **conf["varec"].to_dict(), on_variable_recovered=self.workspace.on_variable_recovered
            )

            # prioritize the current function in display
            disassembly_view = self.workspace.view_manager.first_view_in_category("disassembly")
            if disassembly_view is not None and not disassembly_view.function.am_none:
                job.prioritize_function(disassembly_view.function.addr)

            self._schedule_job(job)

    def generate_cfg(self, cfg_args=None) -> None:
        job = CFGGenerationJob(
            self.workspace.main_instance, on_finish=self.workspace.on_cfg_generated, **(cfg_args or {})
        )
        self._schedule_job(job)
