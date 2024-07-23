from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.logic.threads import gui_thread_schedule_async

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class VariableRecoveryJob(InstanceJob):
    """
    Identify variables and recover calling convention for a specific, or all function if no function is specified.
    """

    def __init__(
        self,
        instance: Instance,
        on_finish=None,
        on_variable_recovered=None,
        workers: int | None = None,
        func_addr: int | None = None,
        auto_start: bool = False,
        **kwargs,
    ) -> None:
        super().__init__("Variable Recovery", instance, on_finish=on_finish)

        self.variable_recovery_args = kwargs
        self.on_variable_recovered = on_variable_recovered
        self.workers = workers
        self.ccc = None
        self.started = False
        self.auto_start = auto_start
        self.func_addr = func_addr
        self.func_addrs_to_prioritize = set() if func_addr is None else {func_addr}

        self._last_progress_callback_triggered = None

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

        cc_callback = self._cc_callback if self.on_variable_recovered is not None else None

        # update addrs to prioritize with their callees
        func_addrs_to_prioritize = set()
        if self.func_addrs_to_prioritize:
            for func_addr in self.func_addrs_to_prioritize:
                if func_addr in self.instance.kb.functions:
                    callees = set(self.instance.kb.functions.callgraph.successors(func_addr))
                    func_addrs_to_prioritize |= {func_addr} | callees

        self.ccc = self.instance.project.analyses.CompleteCallingConventions(
            recover_variables=True,
            low_priority=True,
            cfg=self.instance.cfg.am_obj,
            progress_callback=ctx.set_progress,
            cc_callback=cc_callback,
            analyze_callsites=True,
            max_function_blocks=300,
            max_function_size=4096,
            workers=0 if self.workers is None else self.workers,
            prioritize_func_addrs=func_addrs_to_prioritize,
            skip_other_funcs=self.func_addr is not None,
            auto_start=self.auto_start,
            **self.variable_recovery_args,
        )
        self.ccc.work()

        self.ccc = None

    def _cc_callback(self, func_addr: int) -> None:
        gui_thread_schedule_async(self.on_variable_recovered, args=(func_addr,))

    def __repr__(self) -> str:
        return "<Variable Recovery Job>"
