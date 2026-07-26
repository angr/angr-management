"""MCP tools that operate on the binary loaded in the live angr management instance.

Read-only tools access the knowledge base directly from the MCP server thread; anything that
touches views or fires GUI events must be marshalled through gui_thread_schedule[_async].
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import angr
import networkx as nx
from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.mcp.serializers import (
    serialize_basic_block,
    serialize_cfg_stats,
    serialize_function,
    serialize_function_summary,
    serialize_symbol,
    serialize_xref,
)
from fastmcp.exceptions import ToolError

from angrmanagement.data.jobs import DecompileFunctionJob, VariableRecoveryJob
from angrmanagement.logic.threads import gui_thread_schedule, gui_thread_schedule_async

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from fastmcp import FastMCP

    from angrmanagement.ui.workspace import Workspace

PSEUDOCODE_FLAVOR = "pseudocode"


def parse_address(address: str | int) -> int:
    """Parse an address given as an int or a hex/decimal string."""
    if isinstance(address, int):
        return address
    try:
        return int(address, 0)
    except (ValueError, TypeError) as e:
        raise ToolError(f'Invalid address {address!r}. Pass a hex string such as "0x401000".') from e


def require_project(workspace: Workspace) -> angr.Project:
    """Return the loaded angr project, or raise a ToolError if no binary is open."""
    instance = workspace.main_instance
    if instance.project.am_none:
        raise ToolError("No binary is loaded in angr management. Ask the user to open a binary first.")
    return instance.project.am_obj


def require_cfg(workspace: Workspace) -> angr.Project:
    """Return the loaded project, ensuring its CFG has been recovered."""
    proj = require_project(workspace)
    if workspace.main_instance.cfg.am_none:
        raise ToolError(
            "The control-flow graph has not been recovered yet. The initial analysis may still be "
            "running in angr management; try again shortly."
        )
    return proj


def find_function(workspace: Workspace, address: str | int | None = None, name: str | None = None) -> Function:
    """Find a function by address (any address inside the function works) or by name."""
    proj = require_cfg(workspace)
    functions = proj.kb.functions

    if address is None and name is None:
        raise ToolError("Specify either 'address' or 'name'.")

    if address is not None:
        addr = parse_address(address)
        func = functions.get(addr)
        if func is None:
            # accept any address inside a function
            func = functions.floor_func(addr)
            if func is not None and (addr < func.addr or addr >= func.addr + max(func.size, 1)):
                func = None
        if func is None:
            raise ToolError(f"No function found at address {hex(addr)}.")
        return func

    func = next((f for f in functions.values() if f.name == name), None)
    if func is None:
        raise ToolError(f"No function named {name!r}. Use list_functions to see available functions.")
    return func


def register_read_tools(server: FastMCP, workspace: Workspace) -> None:
    """Register read-only tools bound to the live workspace on the given server."""

    # pylint:disable=unused-variable

    @server.tool()
    def get_project_info() -> dict[str, Any]:
        """
        Get information about the binary currently loaded in angr management.

        Returns architecture, entry point, and analysis state. Call this first to understand
        what is being analyzed.
        """
        proj = require_project(workspace)
        instance = workspace.main_instance
        result: dict[str, Any] = {
            "binary_path": proj.filename,
            "arch": proj.arch.name,
            "bits": proj.arch.bits,
            "endianness": "little" if proj.arch.memory_endness == "Iend_LE" else "big",
            "entry_point": hex(proj.entry),
            "os": proj.loader.main_object.os,
            "cfg_built": not instance.cfg.am_none,
        }
        if not instance.cfg.am_none:
            result["cfg"] = serialize_cfg_stats(instance.cfg.am_obj)
            result["function_count"] = len(proj.kb.functions)
        return result

    @server.tool()
    def list_functions(
        filter_plt: bool | None = None,
        filter_syscall: bool | None = None,
        name_pattern: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """
        List functions discovered in the loaded binary.

        Args:
            filter_plt: If True, only show PLT stubs; if False, exclude them
            filter_syscall: If True, only show syscalls; if False, exclude them
            name_pattern: Filter functions by name substring or regular expression (case-insensitive)
            limit: Maximum number of functions to return (default: 100)
            offset: Number of functions to skip (for pagination)
        """
        proj = require_cfg(workspace)

        pattern = None
        if name_pattern:
            try:
                pattern = re.compile(name_pattern, re.IGNORECASE)
            except re.error as e:
                raise ToolError(f"Invalid name_pattern regex: {e}") from e

        functions = []
        for func in proj.kb.functions.values():
            if filter_plt is not None and func.is_plt != filter_plt:
                continue
            if filter_syscall is not None and func.is_syscall != filter_syscall:
                continue
            if pattern is not None and pattern.search(func.name) is None:
                continue
            functions.append(serialize_function_summary(func))

        functions.sort(key=lambda f: int(f["address"], 16))
        total = len(functions)
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "functions": functions[offset : offset + limit],
        }

    @server.tool()
    def get_function_info(
        address: str | None = None,
        name: str | None = None,
        include_blocks: bool = False,
    ) -> dict[str, Any]:
        """
        Get detailed information about a function in the loaded binary.

        Specify either address (hex string like "0x401000"; any address inside the function
        works) or function name.
        """
        func = find_function(workspace, address=address, name=name)
        return serialize_function(func, include_blocks=include_blocks)

    @server.tool()
    def get_disassembly(
        address: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """
        Get the disassembly of a function in the loaded binary, one entry per basic block.

        Specify either address (hex string) or function name.
        """
        func = find_function(workspace, address=address, name=name)
        blocks = [serialize_basic_block(block, include_disasm=True) for block in func.blocks]
        return {
            "function_address": hex(func.addr),
            "function_name": func.name,
            "block_count": len(blocks),
            "blocks": blocks,
        }

    @server.tool()
    def get_decompilation(
        address: str | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        """
        Get the cached decompilation (C-like pseudocode) of a function, exactly as currently
        shown in the angr management pseudocode view.

        Only returns already-decompiled output. If the function has not been decompiled yet,
        call decompile_function instead, which runs the decompiler and can display the result
        in the GUI.
        """
        func = find_function(workspace, address=address, name=name)
        kb = workspace.main_instance.kb
        key = (func.addr, PSEUDOCODE_FLAVOR)
        if key not in kb.decompilations:
            raise ToolError(
                f"Function {func.name} has not been decompiled yet. Call decompile_function to decompile it."
            )
        cache = kb.decompilations[key]
        if cache.codegen is None or cache.codegen.text is None:
            raise ToolError(f"The cached decompilation of {func.name} is empty. Call decompile_function to re-run.")
        return {
            "function_address": hex(func.addr),
            "function_name": func.name,
            "code": cache.codegen.text,
        }

    @server.tool()
    def get_xrefs(address: str, direction: str = "to") -> dict[str, Any]:
        """
        Get cross-references to or from an address in the loaded binary.

        Args:
            address: The address to query (hex string, e.g., "0x401000")
            direction: "to" for references TO this address, "from" for references FROM this address
        """
        proj = require_cfg(workspace)
        addr = parse_address(address)
        xref_manager = proj.kb.xrefs

        if direction == "to":
            xrefs = list(xref_manager.xrefs_by_dst.get(addr, set()))
        elif direction == "from":
            xrefs = list(xref_manager.xrefs_by_ins_addr.get(addr, set()))
        else:
            raise ToolError(f"Invalid direction: {direction}. Use 'to' or 'from'.")

        return {
            "address": hex(addr),
            "direction": direction,
            "count": len(xrefs),
            "xrefs": [serialize_xref(x) for x in xrefs],
        }

    @server.tool()
    def get_strings(min_length: int = 4, limit: int = 100) -> dict[str, Any]:
        """
        Extract strings from the loaded binary.

        Args:
            min_length: Minimum string length to include (default: 4)
            limit: Maximum number of strings to return (default: 100)
        """
        proj = require_cfg(workspace)
        cfg = workspace.main_instance.cfg.am_obj

        strings = []
        for md in cfg.memory_data.values():
            if md.sort not in (MemoryDataSort.String, MemoryDataSort.UnicodeString):
                continue

            if md.content is None:
                try:
                    md.fill_content(proj.loader)
                except KeyError:
                    continue

            if md.content and len(md.content) >= min_length:
                content = md.content.decode("utf-8", errors="replace").rstrip("\x00")
                if len(content) >= min_length:
                    strings.append(
                        {
                            "address": hex(md.addr),
                            "content": content,
                            "size": md.size,
                            "type": "unicode" if md.sort == MemoryDataSort.UnicodeString else "ascii",
                        }
                    )

            if len(strings) >= limit:
                break

        return {"count": len(strings), "strings": strings}

    @server.tool()
    def get_imports() -> dict[str, Any]:
        """List symbols the loaded binary imports from external libraries."""
        proj = require_project(workspace)
        main_obj = proj.loader.main_object

        imports = []
        for import_name, reloc in getattr(main_obj, "imports", {}).items():
            import_info: dict[str, Any] = {
                "name": import_name,
                "resolved": reloc.resolved,
            }
            if reloc.symbol:
                import_info["address"] = hex(reloc.symbol.rebased_addr) if reloc.symbol.rebased_addr else None
            if getattr(reloc, "resolvewith", None):
                import_info["library"] = reloc.resolvewith
            imports.append(import_info)

        return {"count": len(imports), "imports": imports}

    @server.tool()
    def get_exports() -> dict[str, Any]:
        """List symbols the loaded binary exports."""
        proj = require_project(workspace)
        main_obj = proj.loader.main_object

        exports = [serialize_symbol(sym) for sym in getattr(main_obj, "symbols", []) if sym.is_export]
        return {"count": len(exports), "exports": exports}

    @server.tool()
    def get_callgraph(
        root_address: str | None = None,
        max_depth: int | None = None,
    ) -> dict[str, Any]:
        """
        Get the function call graph of the loaded binary.

        Args:
            root_address: Optional starting function address; only its callees are returned
            max_depth: Maximum call depth from the root (None for unlimited)
        """
        proj = require_cfg(workspace)
        func_manager = proj.kb.functions
        cg = func_manager.callgraph

        if root_address:
            root_addr = find_function(workspace, address=root_address).addr
            if root_addr not in cg:
                raise ToolError(f"Function at {hex(root_addr)} is not in the call graph.")

            if max_depth:
                nodes: set[int] = set()
                current_level = {root_addr}
                for _ in range(max_depth + 1):
                    nodes.update(current_level)
                    next_level: set[int] = set()
                    for node in current_level:
                        if node in cg:
                            next_level.update(cg.successors(node))
                    current_level = next_level - nodes
                cg = cg.subgraph(nodes)
            else:
                descendants = nx.descendants(cg, root_addr)
                descendants.add(root_addr)
                cg = cg.subgraph(descendants)

        nodes_out = []
        for addr in cg.nodes():
            func = func_manager.get(addr)
            if func is not None:
                nodes_out.append({"address": hex(addr), "name": func.name, "is_plt": func.is_plt})

        edges_out = [{"from": hex(src), "to": hex(dst)} for src, dst in cg.edges()]

        return {
            "node_count": len(nodes_out),
            "edge_count": len(edges_out),
            "nodes": nodes_out,
            "edges": edges_out,
        }


def _submit_background_decompilation(workspace: Workspace, func: Function) -> None:
    """Queue a decompilation of the given function without touching any views."""
    instance = workspace.main_instance

    def submit_decomp(*_args, **_kwargs) -> None:
        job = DecompileFunctionJob(instance, func, cfg=instance.cfg, flavor=PSEUDOCODE_FLAVOR)
        workspace.job_manager.add_job(job)

    if func.ran_cca is False and (func.prototype is None or func.is_prototype_guessed is True):
        # run calling convention analysis for this function first, like the pseudocode view does
        options = instance.analysis_configuration["varec"].to_dict() if instance.analysis_configuration else {}
        options["workers"] = 0
        varrec_job = VariableRecoveryJob(instance, **options, on_finish=submit_decomp, func_addr=func.addr)
        workspace.job_manager.add_job(varrec_job)
    else:
        submit_decomp()


def register_project_tools(server: FastMCP, workspace: Workspace) -> None:
    """Register tools that load or unload the binary shown in angr management."""

    # pylint:disable=unused-variable

    @server.tool()
    def load_binary(
        binary_path: str,
        auto_load_libs: bool = False,
        wait_for_analysis: bool = True,
        timeout_seconds: int = 600,
        show_analysis_options: bool = False,
    ) -> dict[str, Any]:
        """
        Load a binary into angr management so it is analyzed and displayed in the GUI, in front
        of the user.

        Use this when no binary is loaded yet: the file opens in angr management exactly as if the
        user had opened it, and subsequent tools operate on it. If a binary is already loaded, this
        fails; call close_project first to switch to a different one.

        Initial analysis (including CFG recovery) runs with the default analysis settings so the
        load proceeds without user interaction. With wait_for_analysis=True this call blocks until
        the CFG is ready or timeout_seconds elapses.

        Args:
            binary_path: Absolute path to the binary file to load
            auto_load_libs: Whether to also load shared libraries (default: False)
            wait_for_analysis: Wait until the CFG has been recovered before returning (default: True)
            timeout_seconds: Maximum time to wait for analysis (default: 600)
            show_analysis_options: If True, pop the analysis-options dialog in the GUI for the user
                to choose settings (the load then waits for them); default False uses the default
                analysis settings without prompting
        """
        if not workspace.main_instance.project.am_none:
            raise ToolError(
                "A binary is already loaded in angr management. Call close_project first to unload it "
                "before loading a different one."
            )

        path = Path(binary_path)
        if not path.exists() or not path.is_file():
            raise ToolError(f"No such file: {binary_path}. Provide an absolute path to a binary on disk.")
        resolved = str(path.resolve())

        # Create the project off the GUI thread so loading a large binary does not freeze the UI.
        try:
            project = angr.Project(resolved, auto_load_libs=auto_load_libs)
        except Exception as e:  # pylint:disable=broad-exception-caught
            raise ToolError(f"angr failed to load {binary_path}: {e}") from e

        def install() -> bool:
            instance = workspace.main_instance
            instance._reset_containers()
            instance.binary_path = resolved
            instance.original_binary_path = resolved
            # By default, skip the analysis-options dialog and use the default settings so the load
            # does not block waiting for the user to choose.
            workspace._suppress_analysis_options_dialog = not show_analysis_options
            # Assigning the project and firing the event runs the same initialization as File -> Open,
            # which kicks off the initial analyses (CFG recovery and friends).
            instance.project.am_obj = project
            instance.project.am_event()
            return True

        if gui_thread_schedule(install, timeout=60) is None:
            raise ToolError("The GUI thread did not respond while installing the project; it may be busy.")

        info: dict[str, Any] = {
            "binary_path": resolved,
            "arch": project.arch.name,
            "entry_point": hex(project.entry),
            "loaded": True,
        }

        if not wait_for_analysis:
            info["cfg_built"] = not workspace.main_instance.cfg.am_none
            info["note"] = "Analysis is starting; poll get_project_info until cfg_built is true."
            return info

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if not workspace.main_instance.cfg.am_none:
                info["cfg_built"] = True
                info["function_count"] = len(workspace.main_instance.kb.functions)
                return info
            time.sleep(0.25)

        info["cfg_built"] = False
        info["note"] = (
            "The binary is loaded but analysis has not finished within the timeout. In the GUI the "
            "user may still need to confirm the analysis-options dialog. Poll get_project_info later."
        )
        return info

    @server.tool()
    def close_project() -> dict[str, Any]:
        """
        Close the binary currently loaded in angr management, returning the GUI to an empty state.

        Use this when the user asks to unload the current binary or project. Does nothing if
        nothing is loaded.
        """
        if workspace.main_instance.project.am_none:
            return {"closed": False, "note": "No binary is loaded."}

        def clear() -> bool:
            # close_project() clears the paths and resets the containers, clearing the binary from
            # the GUI; the data views clear themselves in response.
            workspace.close_project()
            return True

        if gui_thread_schedule(clear, timeout=60) is None:
            raise ToolError("The GUI thread did not respond while closing the project; it may be busy.")
        return {"closed": True}

    @server.tool()
    def load_database(
        database_path: str,
        wait_for_load: bool = True,
        timeout_seconds: int = 600,
    ) -> dict[str, Any]:
        """
        Load a saved angr database (.adb) into angr management, restoring a previous analysis
        session (project, CFG, decompilations, renames, types, comments) and displaying it in the
        GUI in front of the user.

        Use this when no binary is loaded yet; if a binary is already loaded, this fails, so call
        close_project first. angr databases are produced by save_database or by the user via
        File → Save angr database.

        Args:
            database_path: Absolute path to the .adb file to load
            wait_for_load: Wait until the database has finished loading before returning (default: True)
            timeout_seconds: Maximum time to wait for the load (default: 600)
        """
        if not workspace.main_instance.project.am_none:
            raise ToolError(
                "A binary is already loaded in angr management. Call close_project first to unload it "
                "before loading a database."
            )

        path = Path(database_path)
        if not path.exists() or not path.is_file():
            raise ToolError(f"No such file: {database_path}. Provide an absolute path to an .adb file on disk.")
        resolved = str(path.resolve())

        def start() -> bool:
            workspace.load_database(resolved)
            return True

        if gui_thread_schedule(start, timeout=60) is None:
            raise ToolError("The GUI thread did not respond while starting the database load; it may be busy.")

        info: dict[str, Any] = {"database_path": resolved}
        if not wait_for_load:
            info["loaded"] = not workspace.main_instance.project.am_none
            info["note"] = "The database is loading; poll get_project_info until cfg_built is true."
            return info

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            instance = workspace.main_instance
            if not instance.project.am_none and not instance.cfg.am_none:
                proj = instance.project.am_obj
                return {
                    "database_path": resolved,
                    "loaded": True,
                    "binary_path": proj.filename,
                    "arch": proj.arch.name,
                    "entry_point": hex(proj.entry),
                    "function_count": len(instance.kb.functions),
                }
            time.sleep(0.25)

        if workspace.main_instance.project.am_none:
            raise ToolError(
                f"Failed to load the angr database within {timeout_seconds} seconds. It may be incompatible "
                "or corrupt; check angr management for an error dialog."
            )
        info["loaded"] = True
        info["note"] = "The database loaded but analysis is still finalizing; poll get_project_info."
        return info

    @server.tool()
    def save_database(database_path: str, overwrite: bool = False) -> dict[str, Any]:
        """
        Save the current angr management project to an angr database (.adb), persisting the whole
        analysis session (CFG, decompilations, and any renames, types, and comments) so it can be
        restored later with load_database.

        Args:
            database_path: Absolute path to write the .adb file to
            overwrite: If False (the default), refuse to overwrite an existing file; pass True to replace it
        """
        require_project(workspace)

        path = Path(database_path)
        if path.exists():
            if not path.is_file():
                raise ToolError(f"{database_path} exists and is not a regular file.")
            if not overwrite:
                raise ToolError(f"{database_path} already exists. Pass overwrite=true to replace it.")
        elif not path.parent.exists():
            raise ToolError(f"The directory {path.parent} does not exist.")
        resolved = str(path.resolve())

        def do_save() -> bool:
            return workspace.save_database(resolved)

        result = gui_thread_schedule(do_save, timeout=300)
        if result is None:
            raise ToolError("The GUI thread did not respond while saving the database; it may be busy.")
        if result is False:
            raise ToolError("No project is loaded, so there is nothing to save.")
        return {"saved": True, "database_path": resolved}


def register_view_tools(server: FastMCP, workspace: Workspace) -> None:
    """Register tools that run analyses through the GUI job system and control what the user sees."""

    # pylint:disable=unused-variable

    @server.tool()
    def decompile_function(
        address: str | None = None,
        name: str | None = None,
        focus: bool = True,
        timeout_seconds: int = 300,
    ) -> dict[str, Any]:
        """
        Decompile a function using the same pipeline and options as the angr management GUI,
        and return the C-like pseudocode.

        With focus=True (the default) the pseudocode view is opened on this function so the
        user immediately sees the result. Use focus=False to decompile in the background
        without changing what the user is looking at. Results are cached in the GUI session.

        Specify either address (hex string; any address inside the function works) or name.
        """
        func = find_function(workspace, address=address, name=name)
        kb = workspace.main_instance.kb
        key = (func.addr, PSEUDOCODE_FLAVOR)

        if focus:
            gui_thread_schedule_async(workspace.decompile_function, (func,))
        elif key not in kb.decompilations:
            _submit_background_decompilation(workspace, func)

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if key in kb.decompilations:
                cache = kb.decompilations[key]
                if cache.codegen is not None and cache.codegen.text:
                    return {
                        "function_address": hex(func.addr),
                        "function_name": func.name,
                        "shown_to_user": focus,
                        "code": cache.codegen.text,
                    }
            time.sleep(0.2)

        raise ToolError(
            f"Decompilation of {func.name} did not complete within {timeout_seconds} seconds. "
            "It may still be running; call get_decompilation to fetch the result later."
        )

    @server.tool()
    def jump_to(address: str) -> dict[str, Any]:
        """
        Navigate the angr management disassembly view to the given address, in front of the user.

        Args:
            address: The address to jump to (hex string, e.g., "0x401000")
        """
        require_project(workspace)
        addr = parse_address(address)
        gui_thread_schedule_async(workspace.jump_to, (addr,))
        return {"jumped_to": hex(addr)}

    @server.tool()
    def get_view_state() -> dict[str, Any]:
        """
        Get what the user is currently looking at in angr management: the focused view and the
        functions shown in the disassembly and pseudocode views.

        Call this to gain context before answering questions such as "what does this function do?".
        """
        require_project(workspace)

        def collect() -> dict[str, Any]:
            view_manager = workspace.view_manager
            current = view_manager.current_tab
            state: dict[str, Any] = {"current_view": current.category if current is not None else None}

            disasm_view = view_manager.current_view_in_category("disassembly") or view_manager.first_view_in_category(
                "disassembly"
            )
            if disasm_view is not None and not disasm_view.current_function.am_none:
                func = disasm_view.current_function.am_obj
                state["disassembly_view_function"] = {"address": hex(func.addr), "name": func.name}

            code_view = view_manager.current_view_in_category("pseudocode") or view_manager.first_view_in_category(
                "pseudocode"
            )
            if code_view is not None and not code_view.function.am_none:
                func = code_view.function.am_obj
                state["pseudocode_view_function"] = {"address": hex(func.addr), "name": func.name}

            return state

        result = gui_thread_schedule(collect, timeout=10)
        if result is None:
            raise ToolError("Timed out reading the GUI state; the GUI thread may be busy.")
        return result
