import time
from typing import TYPE_CHECKING, Optional

from angrmanagement.logic.threads import gui_thread_schedule_async

from .job import Job

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class VariableRecoveryJob(Job):
    """
    Identify variables and recover calling convention for a specific, or all function if no function is specified.
    """

    def __init__(
        self,
        on_finish=None,
        on_variable_recovered=None,
        workers: Optional[int] = None,
        func_addr: Optional[int] = None,
        auto_start=False,
        **kwargs,
    ):
        super().__init__(name="Variable Recovery", on_finish=on_finish)

        self.variable_recovery_args = kwargs
        self.on_variable_recovered = on_variable_recovered
        self.workers = workers
        self.ccc = None
        self.instance: Optional[Instance] = None
        self.started = False
        self.auto_start = auto_start
        self.func_addr = func_addr
        self.func_addrs_to_prioritize = set() if func_addr is None else {func_addr}

        self._last_progress_callback_triggered = None

    def prioritize_function(self, func_addr: int):
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

    def _run(self, inst: "Instance"):
        self.instance = inst
        self.started = True

        cc_callback = self._cc_callback if self.on_variable_recovered is not None else None

        # update addrs to prioritize with their callees
        func_addrs_to_prioritize = set()
        if self.func_addrs_to_prioritize:
            for func_addr in self.func_addrs_to_prioritize:
                if func_addr in self.instance.kb.functions:
                    callees = set(self.instance.kb.functions.callgraph.successors(func_addr))
                    func_addrs_to_prioritize |= {func_addr} | callees

        self.ccc = inst.project.analyses.CompleteCallingConventions(
            recover_variables=True,
            low_priority=True,
            cfg=inst.cfg.am_obj,
            progress_callback=self._progress_callback,
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

    def _cc_callback(self, func_addr: int):
        gui_thread_schedule_async(self.on_variable_recovered, args=(func_addr,))

    def _progress_callback(self, percentage, text=None):
        t = time.time()
        if self._last_progress_callback_triggered is not None and t - self._last_progress_callback_triggered < 0.2:
            return
        self._last_progress_callback_triggered = t

        super()._progress_callback(percentage, text=text)

    def finish(self, inst, result):
        self.ccc = None  # essentially disabling self.prioritize_function()
        super().finish(inst, result)

    def __repr__(self):
        return "<Variable Recovery Job>"
