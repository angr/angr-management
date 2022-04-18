import os
import logging
from typing import Optional

from binsync.common.controller import BinSyncController, init_checker, make_ro_state, make_state_with_func
from binsync.data import StackOffsetType, FunctionHeader
import binsync

from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
import angr
from ...ui.views import CodeView


l = logging.getLogger(__name__)


class AngrBinSyncController(BinSyncController):
    """
    The class used for all pushing/pulling and merging based actions with BinSync data.
    This class is resposible for handling callbacks that are done by changes from the local user
    and responsible for running a thread to get new changes from other users.
    """

    def __init__(self, workspace):
        super().__init__()
        self._workspace = workspace
        self._instance = workspace.instance

    def binary_hash(self) -> str:
        return self._instance.project.loader.main_object.md5.hex()

    def active_context(self):
        curr_view = self._workspace.view_manager.current_tab
        if not curr_view:
            return None

        try:
            func = curr_view.function
        except NotImplementedError:
            return None

        if func is None or func.am_obj is None:
            return None

        return binsync.data.Function(
            func.addr, 0, header=FunctionHeader(func.name, func.addr)
        )

    def binary_path(self) -> Optional[str]:
        try:
            return self._instance.project.loader.main_object.binary
        # pylint: disable=broad-except
        except Exception:
            return None

    def get_func_size(self, func_addr) -> int:
        try:
            func = self._instance.kb.functions[func_addr]
            return func.size
        except KeyError:
            return 0

    #
    # Display Fillers
    #

    def fill_struct(self, struct_name, user=None, state=None):
        pass

    @init_checker
    @make_ro_state
    def fill_function(self, func_addr, user=None, state=None):
        func = self._instance.kb.functions[func_addr]

        # re-decompile a function if needed
        decompilation = self.decompile_function(func)

        sync_func: binsync.data.Function = self.pull_function(func.addr, user=user)
        if sync_func is None:
            # the function does not exist for that user's state
            return False

        sync_func = self.generate_func_for_sync_level(sync_func)

        #
        # Function Header
        #

        if sync_func.header:
            if sync_func.name and sync_func.name != func.name:
                func.name = sync_func.name
                decompilation.cfunc.name = sync_func.name
                decompilation.cfunc.demangled_name = sync_func.name

            if sync_func.header.args:
                for i, arg in sync_func.header.args.items():
                    if i >= len(decompilation.cfunc.arg_list):
                        break

                    decompilation.cfunc.arg_list[i].variable.name = arg.name

        #
        # Comments
        #

        for addr, cmt in self.pull_func_comments(func_addr).items():
            if not cmt or not cmt.comment:
                continue

            if cmt.decompiled:
                try:
                    pos = decompilation.map_addr_to_pos.get_nearest_pos(addr)
                    corrected_addr = decompilation.map_pos_to_addr.get_node(pos).tags['ins_addr']
                # pylint: disable=broad-except
                except Exception:
                    break

                decompilation.stmt_comments[corrected_addr] = cmt.comment
            else:
                self._instance.kb.comments[cmt.addr] = cmt.comment

        # ==== Stack Vars ==== #
        sync_vars = self.pull_stack_variables(func.addr, user=user)
        for offset, sync_var in sync_vars.items():
            code_var = AngrBinSyncController.find_stack_var_in_codegen(decompilation, offset)
            if code_var:
                code_var.name = sync_var.name
                code_var.renamed = True

        decompilation.regenerate_text()
        self.decompile_function(func, refresh_gui=True)
        return True

    #
    #   Pushers
    #

    @init_checker
    @make_state_with_func
    # pylint: disable=arguments-differ
    def push_function_header(self, addr, new_name, ret_type=None, args=None, user=None, state=None):
        func_header = FunctionHeader(new_name, addr, ret_type=ret_type, args=args)
        return state.set_function_header(func_header)

    @init_checker
    @make_state_with_func
    # pylint: disable=arguments-differ
    def push_stack_variable(self, func_addr, offset, name, type_, size_, user=None, state=None):
        sync_var = binsync.data.StackVariable(offset, StackOffsetType.ANGR, name, type_, size_, func_addr)
        return state.set_stack_variable(sync_var, offset, func_addr)

    @init_checker
    @make_state_with_func
    # pylint: disable=unused-argument,arguments-differ
    def push_comment(self, addr, cmt, decompiled, func_addr=None, user=None, state=None):
        sync_cmt = binsync.data.Comment(addr, cmt, decompiled=decompiled)
        return state.set_comment(sync_cmt)

    #
    #   Utils
    #

    def decompile_function(self, func, refresh_gui=False):
        # check for known decompilation
        available = self._instance.kb.structured_code.available_flavors(func.addr)
        should_decompile = False
        if 'pseudocode' not in available:
            should_decompile = True
        else:
            cached = self._instance.kb.structured_code[(func.addr, 'pseudocode')]
            if isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = True

        if should_decompile:
            # recover direct pseudocode
            self._instance.project.analyses.Decompiler(func, flavor='pseudocode')

            # attempt to get source code if its available
            source_root = None
            if self._instance.original_binary_path:
                source_root = os.path.dirname(self._instance.original_binary_path)
            self._instance.project.analyses.ImportSourceCode(func, flavor='source', source_root=source_root)

        # grab newly cached pseudocode
        decomp = self._instance.kb.structured_code[(func.addr, 'pseudocode')].codegen
        if refresh_gui:
            # refresh all views
            self._workspace.reload()

            # re-decompile current view to cause a refresh
            current_tab = self._workspace.view_manager.current_tab
            if isinstance(current_tab, CodeView) and current_tab.function == func:
                self._workspace.decompile_current_function()

        return decomp

    @staticmethod
    def find_stack_var_in_codegen(decompilation, stack_offset: int) -> Optional[angr.sim_variable.SimStackVariable]:
        for var in decompilation.cfunc.variable_manager._unified_variables:
            if hasattr(var, "offset") and var.offset == stack_offset:
                return var

        return None

    @staticmethod
    def stack_var_type_str(decompilation, stack_var: angr.sim_variable.SimStackVariable):
        try:
            var_type = decompilation.cfunc.variable_manager.get_variable_type(stack_var)
        # pylint: disable=broad-except
        except Exception:
            return None

        return var_type.c_repr()

    @staticmethod
    def get_func_args(decompilation):
        arg_info = {
            i: (arg.variable, decompilation.cfunc.functy.args[i].c_repr())
            for i, arg in enumerate(decompilation.cfunc.arg_list)
        }
        return arg_info

    @staticmethod
    def func_insn_addrs(func: angr.knowledge_plugins.Function):
        insn_addrs = set()
        for block in func.blocks:
            insn_addrs.update(block.instruction_addrs)

        return insn_addrs

    def get_func_addr_from_addr(self, addr):
        try:
            func_addr = self._workspace.instance.kb.cfgs.get_most_accurate()\
                .get_any_node(addr, anyaddr=True)\
                .function_address
        except AttributeError:
            func_addr = None

        return func_addr
