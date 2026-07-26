"""MCP tools that modify the loaded binary's knowledge base and refresh the GUI live.

Every mutation runs on the GUI thread (via gui_thread_schedule) and follows the same code
paths as the corresponding GUI actions, including plugin hook dispatch and view refreshes,
so the user sees the changes immediately.
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import parse_signature, parse_type
from fastmcp.exceptions import ToolError

from angrmanagement.logic.threads import gui_thread_schedule

from .tools import (
    PSEUDOCODE_FLAVOR,
    _submit_background_decompilation,
    find_function,
    parse_address,
    require_project,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins.functions import Function
    from fastmcp import FastMCP

    from angrmanagement.ui.views.code_view import CodeView
    from angrmanagement.ui.workspace import Workspace

GUI_TIMEOUT = 60

_VALID_NAME_RE = re.compile(r"^\S+$")


def _run_on_gui(func: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run a mutation on the GUI thread, propagating ToolErrors and guarding against timeouts."""
    result = gui_thread_schedule(func, timeout=GUI_TIMEOUT)
    if result is None:
        raise ToolError("The GUI thread did not respond in time; angr management may be busy running an analysis.")
    return result


def _validate_name(new_name: str) -> None:
    if not new_name or _VALID_NAME_RE.match(new_name) is None:
        raise ToolError(f"Invalid name {new_name!r}: names must be non-empty and contain no whitespace.")


def _code_view_showing(workspace: Workspace, func_addr: int) -> CodeView | None:
    """Return the pseudocode view if it is currently showing the given function. GUI thread only."""
    view = workspace.view_manager.first_view_in_category("pseudocode")
    if view is not None and not view.function.am_none and view.function.am_obj.addr == func_addr:
        return view
    return None


def _cached_decompilation(workspace: Workspace, func_addr: int):
    kb = workspace.main_instance.kb
    key = (func_addr, PSEUDOCODE_FLAVOR)
    return kb.decompilations.get(key, None)


def _require_cached_decompilation(workspace: Workspace, func: Function):
    cache = _cached_decompilation(workspace, func.addr)
    if cache is None or cache.codegen is None:
        raise ToolError(
            f"Function {func.name} has not been decompiled yet. Call decompile_function first "
            "(use focus=False to avoid disturbing the user)."
        )
    return cache


def _find_variable_node(codegen, variable_name: str) -> CVariable | None:
    """Find a CVariable node in a codegen by its current display name."""
    if codegen.map_pos_to_node is None:
        return None
    global_node = None
    for _, item in codegen.map_pos_to_node.items():
        obj = getattr(item, "obj", None)
        if not isinstance(obj, CVariable):
            continue
        if obj.unified_variable is not None:
            if obj.unified_variable.name == variable_name:
                return obj
        elif obj.variable is not None and not obj.variable.region and obj.variable.name == variable_name:
            global_node = obj
    return global_node


def _refresh_pseudocode(workspace: Workspace, func_addr: int, codegen) -> None:
    """Re-render the pseudocode view if it shows the function; otherwise refresh the cached text."""
    view = _code_view_showing(workspace, func_addr)
    if view is not None:
        view.codegen.am_event()
    elif codegen is not None and codegen.text is not None:
        codegen.regenerate_text()


def _wait_for_decompilation(workspace: Workspace, func: Function, timeout_seconds: int) -> str:
    kb = workspace.main_instance.kb
    key = (func.addr, PSEUDOCODE_FLAVOR)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if key in kb.decompilations:
            cache = kb.decompilations[key]
            if cache.codegen is not None and cache.codegen.text:
                return cache.codegen.text
        time.sleep(0.2)
    raise ToolError(
        f"Re-decompilation of {func.name} did not complete within {timeout_seconds} seconds. "
        "Call get_decompilation to fetch the result later."
    )


def register_edit_tools(server: FastMCP, workspace: Workspace) -> None:
    """Register tools that modify the knowledge base with live GUI refresh."""

    # pylint:disable=unused-variable

    @server.tool()
    def rename_function(
        new_name: str,
        address: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """
        Rename a function in the loaded binary. The functions list, disassembly, and pseudocode
        views in angr management update immediately.

        Specify the function by address (hex string) or by its current name.
        """
        _validate_name(new_name)
        func = find_function(workspace, address=address, name=name)

        def apply() -> dict[str, Any]:
            kb = workspace.main_instance.kb
            old_name = func.name
            kb.functions.get_by_addr(func.addr).name = new_name

            cache = _cached_decompilation(workspace, func.addr)
            if cache is not None and cache.codegen is not None and cache.codegen.cfunc is not None:
                cache.codegen.cfunc.name = new_name
                cache.codegen.cfunc.demangled_name = new_name

            workspace.plugins.handle_function_renamed(func, old_name, new_name)

            # re-render whatever the pseudocode view currently shows: both the renamed function
            # and call sites in other functions pick up the new name on regeneration
            view = workspace.view_manager.first_view_in_category("pseudocode")
            if view is not None and not view.codegen.am_none:
                view.codegen.am_event()
            if cache is not None and cache.codegen is not None and _code_view_showing(workspace, func.addr) is None:
                cache.codegen.regenerate_text()

            workspace.on_function_updated()
            workspace.refresh(["disassembly"])
            return {"old_name": old_name}

        result = _run_on_gui(apply)
        return {"function_address": hex(func.addr), "old_name": result["old_name"], "new_name": new_name}

    @server.tool()
    def rename_variable(
        variable_name: str,
        new_name: str,
        address: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """
        Rename a variable in a function's decompilation. The pseudocode view updates immediately.

        The function must have been decompiled already (call decompile_function first). Specify
        the function by address or name, and the variable by its current name as it appears in
        the pseudocode (e.g., "v4" or "a0").
        """
        _validate_name(new_name)
        func = find_function(workspace, address=address, name=name)
        cache = _require_cached_decompilation(workspace, func)
        codegen = cache.codegen

        def apply() -> dict[str, Any]:
            node = _find_variable_node(codegen, variable_name)
            if node is None:
                raise ToolError(
                    f"No variable named {variable_name!r} in the decompilation of {func.name}. "
                    "Check get_decompilation for the current variable names."
                )

            if node.unified_variable is not None:
                unified = node.unified_variable
                if getattr(node.variable, "offset", None) is not None:
                    workspace.plugins.handle_stack_var_renamed(func, node.variable.offset, variable_name, new_name)
                elif unified.is_function_argument:
                    workspace.plugins.handle_func_arg_renamed(func, 0, variable_name, new_name)
                    cfunc = codegen.cfunc
                    if cfunc is not None and cfunc.functy.arg_names:
                        arg_names = list(cfunc.functy.arg_names)
                        for idx, arg in enumerate(cfunc.arg_list):
                            if arg is node and idx < len(arg_names):
                                arg_names[idx] = new_name
                                break
                        cfunc.functy.arg_names = tuple(arg_names)
                unified.name = new_name
                unified.renamed = True
                kind = "argument" if unified.is_function_argument else "local"
            else:
                workspace.plugins.handle_global_var_renamed(node.variable.addr, variable_name, new_name)
                workspace.main_instance.kb.labels[node.variable.addr] = new_name
                node.variable.name = new_name
                node.variable.renamed = True
                kind = "global"

            _refresh_pseudocode(workspace, func.addr, codegen)
            return {"kind": kind}

        result = _run_on_gui(apply)
        return {
            "function_address": hex(func.addr),
            "function_name": func.name,
            "variable_kind": result["kind"],
            "old_name": variable_name,
            "new_name": new_name,
        }

    @server.tool()
    def set_variable_type(
        variable_name: str,
        c_type: str,
        address: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """
        Change the type of a variable in a function's decompilation. The pseudocode view
        updates immediately with re-flowed types.

        The function must have been decompiled already. c_type is a C type declaration such as
        "unsigned int", "char *", or "struct my_struct *".
        """
        proj = require_project(workspace)
        func = find_function(workspace, address=address, name=name)
        cache = _require_cached_decompilation(workspace, func)
        codegen = cache.codegen

        try:
            new_type = parse_type(c_type).with_arch(proj.arch)
        except Exception as e:  # pylint:disable=broad-exception-caught
            raise ToolError(f"Could not parse C type {c_type!r}: {e}") from e

        def apply() -> dict[str, Any]:
            node = _find_variable_node(codegen, variable_name)
            if node is None:
                raise ToolError(
                    f"No variable named {variable_name!r} in the decompilation of {func.name}. "
                    "Check get_decompilation for the current variable names."
                )

            kb = workspace.main_instance.kb
            dec_variables = kb.dec_variables

            if node.unified_variable is not None and node.unified_variable.is_function_argument:
                raise ToolError(
                    f"{variable_name!r} is a function argument; change it by updating the whole "
                    "prototype with set_function_prototype."
                )

            if node.unified_variable is not None:
                dec_variables[func.addr].set_variable_type(node.variable, new_type, all_unified=True, mark_manual=True)
            else:
                dec_variables["global"].set_variable_type(node.variable, new_type, all_unified=False, mark_manual=True)

            # re-flow variable types through the cached decompilation, like the GUI does
            dec = proj.analyses.Decompiler(func, decompile=False, use_cache=True)
            new_codegen = dec.reflow_variable_types(cache)
            cache.codegen = new_codegen

            view = _code_view_showing(workspace, func.addr)
            if view is not None:
                view.codegen.am_obj = new_codegen
                view.codegen.am_event(already_regenerated=True)

            return {"code": new_codegen.text}

        result = _run_on_gui(apply)
        return {
            "function_address": hex(func.addr),
            "function_name": func.name,
            "variable": variable_name,
            "new_type": c_type,
            "code": result["code"],
        }

    @server.tool()
    def set_function_prototype(
        prototype: str,
        address: str | None = None,
        name: str | None = None,
        timeout_seconds: int = 300,
    ) -> dict[str, Any]:
        """
        Set the prototype (signature) of a function and re-decompile it. The pseudocode view
        updates once re-decompilation finishes.

        prototype is a full C signature, e.g. "int authenticate(char *username, char *password)".
        The function name inside the prototype is ignored; use rename_function to rename.
        """
        proj = require_project(workspace)
        func = find_function(workspace, address=address, name=name)

        try:
            new_proto = parse_signature(prototype).with_arch(proj.arch)
        except Exception as e:  # pylint:disable=broad-exception-caught
            raise ToolError(f"Could not parse C prototype {prototype!r}: {e}") from e

        def apply() -> dict[str, Any]:
            func.prototype = new_proto
            func.prototype_source = PrototypeSource.USER
            func.ran_cca = True

            view = _code_view_showing(workspace, func.addr)
            if view is not None:
                # the pseudocode view is showing this function: let it drive re-decompilation,
                # re-deriving variables so the new prototype's argument names take effect
                view.decompile(reset_cache=True)
                return {"mode": "view"}

            kb = workspace.main_instance.kb
            kb.decompilations.discard((func.addr, PSEUDOCODE_FLAVOR))
            dec_variables = kb.dec_variables
            if dec_variables.has_function_manager(func.addr):
                del dec_variables[func.addr]
            return {"mode": "background"}

        result = _run_on_gui(apply)
        if result["mode"] == "background":
            _submit_background_decompilation(workspace, func)

        code = _wait_for_decompilation(workspace, func, timeout_seconds)
        return {
            "function_address": hex(func.addr),
            "function_name": func.name,
            "prototype": prototype,
            "code": code,
        }

    @server.tool()
    def set_comment(address: str, comment: str) -> dict[str, Any]:
        """
        Set a comment at an address, or clear it by passing an empty string. The comment shows
        up in the disassembly view and, if the containing function is decompiled, next to the
        corresponding statement in the pseudocode view.

        Args:
            address: The address to comment (hex string, e.g., "0x401000")
            comment: The comment text; an empty string removes the comment
        """
        require_project(workspace)
        addr = parse_address(address)

        def apply() -> dict[str, Any]:
            workspace.set_comment(addr, comment)

            # also attach it to the decompilation of the containing function, if cached
            kb = workspace.main_instance.kb
            func = kb.functions.floor_func(addr)
            in_pseudocode = False
            if func is not None:
                cache = _cached_decompilation(workspace, func.addr)
                if cache is not None and cache.codegen is not None:
                    # The function-entry address is rendered as a header comment sourced from
                    # kb.comments (already set above), so only mirror non-entry addresses into
                    # the per-statement comment map to avoid a duplicate.
                    if addr == func.addr:
                        in_pseudocode = True
                    else:
                        cdict = cache.codegen.stmt_comments
                        old = cdict.get(addr, "")
                        if comment:
                            workspace.plugins.handle_comment_changed(addr, old, comment, addr not in cdict, True)
                            cdict[addr] = comment
                            in_pseudocode = True
                        elif addr in cdict:
                            workspace.plugins.handle_comment_changed(addr, old, "", False, True)
                            del cdict[addr]
                    _refresh_pseudocode(workspace, func.addr, cache.codegen)
            return {"in_pseudocode": in_pseudocode}

        result = _run_on_gui(apply)
        return {
            "address": hex(addr),
            "comment": comment,
            "shown_in_pseudocode": result["in_pseudocode"],
        }
