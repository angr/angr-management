"""Bridges angr's decompilation edit hooks to angr management's plugin notifications."""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.decompiler.edits import NullEditHooks

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.sim_type import SimType, SimTypeFunction
    from angr.sim_variable import SimVariable

    from angrmanagement.ui.workspace import Workspace


class WorkspaceEditHooks(NullEditHooks):
    """
    Forwards each edit notification to the workspace's plugins.

    The edits layer fires these before it mutates anything, while the old value is still readable
    from the knowledge base, which is what the GUI's own edit dialogs do.
    """

    def __init__(self, workspace: Workspace):
        self._workspace = workspace

    def before_function_renamed(self, func: Function, old_name: str, new_name: str) -> None:
        self._workspace.plugins.handle_function_renamed(func, old_name, new_name)

    def before_stack_var_renamed(self, func: Function, offset: int, old_name: str, new_name: str) -> None:
        self._workspace.plugins.handle_stack_var_renamed(func, offset, old_name, new_name)

    def before_func_arg_renamed(self, func: Function, arg_index: int, old_name: str, new_name: str) -> None:
        self._workspace.plugins.handle_func_arg_renamed(func, arg_index, old_name, new_name)

    def before_global_var_renamed(self, addr: int, old_name: str, new_name: str) -> None:
        self._workspace.plugins.handle_global_var_renamed(addr, old_name, new_name)

    def before_stack_var_retyped(
        self, func: Function, offset: int, old_type: SimType | None, new_type: SimType
    ) -> None:
        self._workspace.plugins.handle_stack_var_retyped(func, offset, old_type, new_type)

    def before_func_arg_retyped(
        self, func: Function, arg_index: int, old_type: SimType | None, new_type: SimType
    ) -> None:
        self._workspace.plugins.handle_func_arg_retyped(func, arg_index, old_type, new_type)

    def before_global_var_retyped(self, addr: int, old_type: SimType | None, new_type: SimType) -> None:
        self._workspace.plugins.handle_global_var_retyped(addr, old_type, new_type)

    def before_other_var_retyped(self, var: SimVariable, old_type: SimType | None, new_type: SimType) -> None:
        self._workspace.plugins.handle_other_var_retyped(var, old_type, new_type)

    def before_function_retyped(
        self, func: Function, old_proto: SimTypeFunction | None, new_proto: SimTypeFunction
    ) -> None:
        self._workspace.plugins.handle_function_retyped(func, old_proto, new_proto)

    def before_comment_changed(self, addr: int, old: str, new: str, created: bool, decomp: bool) -> None:
        self._workspace.plugins.handle_comment_changed(addr, old, new, created, decomp)
