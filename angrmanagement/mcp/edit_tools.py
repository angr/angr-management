"""MCP tools that modify the loaded binary's knowledge base and refresh the GUI live.

The knowledge-base mutations themselves live in angr's decompilation edit layer
(:mod:`angr.analyses.decompiler.edits`), which the headless MCP server uses too. What stays here is
the GUI half: marshalling onto the GUI thread, firing plugin notifications through
:class:`WorkspaceEditHooks`, and refreshing the views.

Everything runs on the GUI thread via gui_thread_schedule, and each mutation resolves its target
*inside* that closure: kb.decompilations spills to LMDB, so a cache resolved outside can be evicted
and reloaded as a different object before the closure runs.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler.edits import (
    DecompilationEditError,
    require_cache,
    restore_user_edits,
)
from angr.analyses.decompiler.edits import (
    rename_function as core_rename_function,
)
from angr.analyses.decompiler.edits import (
    rename_variable as core_rename_variable,
)
from angr.analyses.decompiler.edits import (
    set_comment as core_set_comment,
)
from angr.analyses.decompiler.edits import (
    set_function_prototype as core_set_function_prototype,
)
from angr.analyses.decompiler.edits import (
    set_variable_type as core_set_variable_type,
)
from fastmcp.exceptions import ToolError

from angrmanagement.logic.threads import gui_thread_schedule

from .edit_hooks import WorkspaceEditHooks
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


def _run_on_gui(func: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run a mutation on the GUI thread, propagating ToolErrors and guarding against timeouts."""
    result = gui_thread_schedule(func, timeout=GUI_TIMEOUT)
    if result is None:
        raise ToolError("The GUI thread did not respond in time; angr management may be busy running an analysis.")
    return result


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


def _as_tool_error(func: Callable[[], dict[str, Any]]) -> Callable[[], dict[str, Any]]:
    """Surface the edit layer's messages, which fastmcp would otherwise mask."""

    def wrapper() -> dict[str, Any]:
        try:
            return func()
        except DecompilationEditError as e:
            raise ToolError(str(e)) from e

    return wrapper


def register_edit_tools(server: FastMCP, workspace: Workspace) -> None:
    """Register tools that modify the knowledge base with live GUI refresh."""

    # pylint:disable=unused-variable

    def hooks() -> WorkspaceEditHooks:
        return WorkspaceEditHooks(workspace)

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
        proj = require_project(workspace)
        func = find_function(workspace, address=address, name=name)

        @_as_tool_error
        def apply() -> dict[str, Any]:
            result = core_rename_function(
                proj,
                func,
                new_name,
                kb=workspace.main_instance.kb,
                hooks=hooks(),
                rerender=False,
            )

            # re-render whatever the pseudocode view currently shows: both the renamed function
            # and call sites in other functions pick up the new name on regeneration
            view = workspace.view_manager.first_view_in_category("pseudocode")
            if view is not None and not view.codegen.am_none:
                view.codegen.am_event()
            cache = _cached_decompilation(workspace, func.addr)
            if cache is not None and cache.codegen is not None and _code_view_showing(workspace, func.addr) is None:
                cache.codegen.regenerate_text()

            workspace.on_function_updated()
            workspace.refresh(["disassembly"])
            return {"old_name": result.old}

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
        proj = require_project(workspace)
        func = find_function(workspace, address=address, name=name)

        @_as_tool_error
        def apply() -> dict[str, Any]:
            result = core_rename_variable(
                proj,
                func,
                variable_name,
                new_name,
                kb=workspace.main_instance.kb,
                hooks=hooks(),
                rerender=False,
            )
            cache = _cached_decompilation(workspace, func.addr)
            _refresh_pseudocode(workspace, func.addr, cache.codegen if cache is not None else None)
            if result.refresh.disassembly_dirty:
                workspace.refresh(["disassembly"])
            return {"kind": result.detail.get("storage"), "is_argument": result.detail.get("is_argument")}

        result = _run_on_gui(apply)
        return {
            "function_address": hex(func.addr),
            "function_name": func.name,
            "variable_kind": "argument" if result["is_argument"] else result["kind"],
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
        "unsigned int", "char *", or "struct my_struct *". Retyping a function argument rewrites
        the function's prototype and re-decompiles it.
        """
        proj = require_project(workspace)
        func = find_function(workspace, address=address, name=name)

        @_as_tool_error
        def apply() -> dict[str, Any]:
            result = core_set_variable_type(
                proj,
                func,
                variable_name,
                c_type,
                kb=workspace.main_instance.kb,
                hooks=hooks(),
            )

            if func.addr in result.refresh.redecompile:
                # an argument retype changed the prototype: the function has to be rebuilt
                view = _code_view_showing(workspace, func.addr)
                if view is not None:
                    view.decompile(reset_cache=True)
                    return {"mode": "view", "code": None}
                return {"mode": "background", "code": None}

            cache = require_cache(workspace.main_instance.kb, func.addr, PSEUDOCODE_FLAVOR)
            view = _code_view_showing(workspace, func.addr)
            if view is not None:
                view.codegen.am_obj = cache.codegen
                view.codegen.am_event(already_regenerated=True)
            return {"mode": "reflow", "code": cache.codegen.text}

        outcome = _run_on_gui(apply)
        if outcome["mode"] == "background":
            _submit_background_decompilation(workspace, func)
        code = outcome["code"] if outcome["code"] is not None else _wait_for_decompilation(workspace, func, 300)

        return {
            "function_address": hex(func.addr),
            "function_name": func.name,
            "variable": variable_name,
            "new_type": c_type,
            "code": code,
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
        Variable renames and manual types set earlier are restored after the re-decompilation.
        """
        proj = require_project(workspace)
        func = find_function(workspace, address=address, name=name)

        @_as_tool_error
        def apply() -> dict[str, Any]:
            result = core_set_function_prototype(
                proj,
                func,
                prototype,
                kb=workspace.main_instance.kb,
                hooks=hooks(),
            )

            view = _code_view_showing(workspace, func.addr)
            if view is not None:
                # the pseudocode view is showing this function: let it drive re-decompilation,
                # re-deriving variables so the new prototype's argument names take effect
                view.decompile(reset_cache=True)
                return {"mode": "view", "user_edits": result.detail.get("user_edits") or {}}
            return {"mode": "background", "user_edits": result.detail.get("user_edits") or {}}

        outcome = _run_on_gui(apply)
        if outcome["mode"] == "background":
            _submit_background_decompilation(workspace, func)

        code = _wait_for_decompilation(workspace, func, timeout_seconds)

        # dropping the variable manager is what makes the new argument names take effect, but it
        # also discards earlier renames and manual types; put them back now that variables exist
        if outcome["user_edits"]:

            def restore() -> dict[str, Any]:
                kb = workspace.main_instance.kb
                restored, _ = restore_user_edits(kb, func.addr, outcome["user_edits"])
                if restored:
                    cache = _cached_decompilation(workspace, func.addr)
                    _refresh_pseudocode(workspace, func.addr, cache.codegen if cache is not None else None)
                    return {"code": cache.codegen.text if cache is not None and cache.codegen else None}
                return {"code": None}

            restored = _run_on_gui(restore)
            if restored["code"]:
                code = restored["code"]

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
        proj = require_project(workspace)
        addr = parse_address(address)

        @_as_tool_error
        def apply() -> dict[str, Any]:
            result = core_set_comment(
                proj,
                addr,
                comment,
                kb=workspace.main_instance.kb,
                hooks=hooks(),
                rerender=False,
            )

            if result.func_addr is not None:
                cache = _cached_decompilation(workspace, result.func_addr)
                _refresh_pseudocode(workspace, result.func_addr, cache.codegen if cache is not None else None)

            # the disassembly redraw that Workspace.set_comment used to do; the knowledge-base
            # write and its notification already happened in the edit layer
            workspace.refresh(["disassembly"])
            return {"in_pseudocode": result.detail["shown_in_pseudocode"]}

        result = _run_on_gui(apply)
        return {
            "address": hex(addr),
            "comment": comment,
            "shown_in_pseudocode": result["in_pseudocode"],
        }
