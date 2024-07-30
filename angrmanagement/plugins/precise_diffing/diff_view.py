from __future__ import annotations

from angrmanagement.data.jobs import DecompileFunctionJob, VariableRecoveryJob
from angrmanagement.ui.views.code_view import CodeView
from angrmanagement.ui.views.disassembly_view import DisassemblyView


class DiffDisassemblyView(DisassemblyView):
    """
    A Disassembly View for a binary being Diffed. Should never try to synchronize normally since
    it will almost certainly have different addresses
    """

    def on_synchronized_cursor_address_changed(self) -> None:
        assert not self._processing_synchronized_cursor_update
        self._processing_synchronized_cursor_update = True
        try:
            if self.sync_state.cursor_address is not None:
                self.instance.recompilation_plugin.syncronize_with_original_disassembly_view()
        finally:
            self._processing_synchronized_cursor_update = False

    def set_synchronized_cursor_address(self, address: int | None) -> None:
        pass

    def decompile_current_function(self) -> None:
        if self.function.am_obj is not None:
            try:
                curr_ins = next(iter(self.infodock.selected_insns))
            except StopIteration:
                curr_ins = None

            view = self.workspace._get_or_create_view("pseudocode_diff", DiffCodeView)

            view.function.am_obj = self.function.am_obj
            view.function.am_event(focus=True, focus_addr=curr_ins)


class DiffCodeView(CodeView):
    """
    A view for Psuedocode of a function being Diffed.
    """

    def __init__(self, workspace, category, diff_instance, after_ready):
        super().__init__(workspace, category, diff_instance)
        self.after_ready = after_ready

    def _on_codegen_changes(self, already_regenerated: bool = False, event: str | None = None, **kwargs) -> None:
        super()._on_codegen_changes(already_regenerated, event, **kwargs)
        self.after_ready()

    def _on_new_function(self, *args, **kwargs) -> None:
        super()._on_new_function(*args, **kwargs)
        self.after_ready()

    def decompile(
        self,
        clear_prototype: bool = True,
        focus: bool = False,
        focus_addr=None,
        flavor: str = "pseudocode",
        reset_cache: bool = False,
        regen_clinic: bool = True,
    ) -> None:
        if self._function.am_none:
            return

        if clear_prototype:
            # clear the existing function prototype
            self._function.prototype = None
            self._function.ran_cca = False

        if reset_cache:
            self.instance.kb.structured_code.discard((self._function.addr, flavor))
            variables = self.instance.pseudocode_variable_kb.variables
            if variables.has_function_manager(self._function.addr):
                del variables[self._function.addr]

        def decomp_ready(*args, **kwargs) -> None:  # pylint:disable=unused-argument
            # this code is _partially_ duplicated from _on_new_function. be careful!
            available = self.instance.kb.structured_code.available_flavors(self._function.addr)
            self._update_available_views(available)
            if available:
                chosen_flavor = flavor if flavor in available else available[0]
                self.codegen.am_obj = self.instance.kb.structured_code[(self._function.addr, chosen_flavor)].codegen
                self.codegen.am_event(already_regenerated=True)
                self._focus_core(focus, focus_addr)
                if focus_addr is not None:
                    self.jump_history.record_address(focus_addr)
                else:
                    self.jump_history.record_address(self._function.am_obj.addr)
                self.after_ready()

        def decomp(*_) -> None:
            job = DecompileFunctionJob(
                self.instance,
                self._function.am_obj,
                cfg=self.instance.cfg,
                options=self._options.option_and_values,
                optimization_passes=self._options.selected_passes,
                peephole_optimizations=self._options.selected_peephole_opts,
                vars_must_struct=self.vars_must_struct,
                on_finish=decomp_ready,
                blocking=True,
                regen_clinic=regen_clinic,
            )
            self.workspace.job_manager.add_job(job)

        if self._function.ran_cca is False:
            # run calling convention analysis for this function
            if self.instance._analysis_configuration:
                options = self.instance._analysis_configuration["varec"].to_dict()
            else:
                options = {}
            options["workers"] = 0
            varrec_job = VariableRecoveryJob(self.instance, **options, on_finish=decomp, func_addr=self._function.addr)
            self.workspace.job_manager.add_job(varrec_job)
        else:
            decomp()
