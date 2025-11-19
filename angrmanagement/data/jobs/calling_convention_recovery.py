from __future__ import annotations

import multiprocessing
import platform
from typing import TYPE_CHECKING

from angr.misc.testing import is_testing

from angrmanagement.data.analysis_options import AnalysisConfiguration, BoolAnalysisOption, IntAnalysisOption
from angrmanagement.logic.threads import gui_thread_schedule_async

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class CallingConventionRecoveryConfiguration(AnalysisConfiguration):
    """
    Configuration for CCCA.
    """

    MAX_BINARY_SIZE = 5_120_000

    def __init__(self, instance: Instance) -> None:
        super().__init__(instance)
        self.name = "cca"
        self.display_name = "Recover Prototypes on All Functions"
        self.description = "Perform a full-project calling-convention and prototype recovery analysis. "
        self.enabled = self.get_main_obj_size() <= self.MAX_BINARY_SIZE
        self.options = {
            o.name: o
            for o in [
                IntAnalysisOption(
                    "workers",
                    "Number of parallel workers",
                    tooltip="0 to disable parallel analysis. Default to the number of available cores "
                    "minus one in the local system. Automatically default to 0 for small binaries "
                    "on all platforms, and small- to medium-sized binaries on Windows and MacOS "
                    "(to avoid the cost of spawning new angr-management processes).",
                    default=self.get_default_workers(),
                    minimum=0,
                ),
                BoolAnalysisOption(
                    "skip_signature_matched_functions",
                    "Skip variable recovery for signature-matched functions",
                    True,
                ),
                BoolAnalysisOption(
                    "analyze_callsites",
                    "Analyze callsites of each function to improve prototype recovery",
                    False,
                ),
            ]
        }

    def get_default_workers(self) -> int:
        if is_testing:
            return 0

        main_obj_size = self.get_main_obj_size()

        default_workers = max(multiprocessing.cpu_count() - 1, 1)
        if default_workers == 1:
            return 0

        if platform.system() in {"Windows", "Darwin"}:
            if main_obj_size <= self.MAX_BINARY_SIZE:
                return 0
            return default_workers

        return default_workers


class CallingConventionRecoveryJob(InstanceJob):
    """
    Recover calling conventions for functions without recovering variables.
    """

    def __init__(
        self,
        instance: Instance,
        on_finish=None,
        on_cc_recovered=None,
        workers: int | None = None,
        func_addr: int | None = None,
        auto_start: bool = False,
        **kwargs,
    ) -> None:
        super().__init__("Calling Convention Recovery", instance, on_finish=on_finish)

        self.cc_recovery_args = kwargs
        self.on_cc_recovered = on_cc_recovered
        self.workers = workers
        self.ccc = None
        self.started = False
        self.auto_start = auto_start
        self.func_addr = func_addr
        self.func_addrs_to_prioritize = set() if func_addr is None else {func_addr}

    def prioritize_function(self, func_addr: int) -> None:
        """
        Prioritize the specified function and its callee functions.

        :param func_addr:   Address of the function to prioritize.
        """
        if not self.started:
            # hasn't started - cache all requests
            self.func_addrs_to_prioritize.add(func_addr)
            return

        if self.instance is None:
            return
        if self.ccc is None:
            return

        # find its callee functions
        callees = set(self.instance.kb.functions.callgraph.successors(func_addr))
        self.ccc.prioritize_functions({func_addr} | callees)

    def run(self, ctx: JobContext) -> None:
        self.started = True

        cc_callback = self._cc_callback if self.on_cc_recovered is not None else None

        # update addrs to prioritize with their callees
        func_addrs_to_prioritize = set()
        if self.func_addrs_to_prioritize:
            for func_addr in self.func_addrs_to_prioritize:
                if func_addr in self.instance.kb.functions:
                    callees = set(self.instance.kb.functions.callgraph.successors(func_addr))
                    func_addrs_to_prioritize |= {func_addr} | callees

        self.ccc = self.instance.project.analyses.CompleteCallingConventions(
            recover_variables=False,
            low_priority=True,
            cfg=self.instance.cfg.am_obj,
            progress_callback=ctx.set_progress,
            cc_callback=cc_callback,
            max_function_blocks=2000,
            max_function_size=16384,
            workers=0 if self.workers is None else self.workers,
            prioritize_func_addrs=func_addrs_to_prioritize,
            skip_other_funcs=self.func_addr is not None,
            auto_start=self.auto_start,
            **self.cc_recovery_args,
        )
        self.ccc.work()

        self.ccc = None

    def _cc_callback(self, func_addr: int) -> None:
        gui_thread_schedule_async(self.on_cc_recovered, args=(func_addr,))

    def __repr__(self) -> str:
        return "<Calling Convention Recovery Job>"
