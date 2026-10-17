"""MCP access to the same live runtime session shown in the GUI."""

from __future__ import annotations

from os.path import realpath
from typing import TYPE_CHECKING, Literal

from fastmcp.exceptions import ToolError

from angrmanagement.logic.debugger.gdb import RuntimeErrorBase
from angrmanagement.logic.debugger.variable_binding import (
    VariableBindingError,
    describe_variable,
    instruction_at,
    list_variable_bindings,
    selection_at,
    verify_module_identity,
)
from angrmanagement.logic.threads import gui_thread_schedule, gui_thread_schedule_async

from .tools import find_function, parse_address, require_project

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from angrmanagement.ui.workspace import Workspace


def register_runtime_tools(server: FastMCP, workspace: Workspace) -> None:
    """Register live-process control, inspection, rules and decompiler bindings."""
    # pylint:disable=unused-variable
    runtime = workspace.runtime

    def call(method, *args, **kwargs):
        try:
            return method(*args, **kwargs)
        except (RuntimeErrorBase, VariableBindingError, ValueError, OSError) as ex:
            raise ToolError(str(ex)) from ex

    def cached_function(address):
        project = require_project(workspace)
        function = find_function(workspace, address=address)
        cache = project.kb.decompilations.get((function.addr, "pseudocode"))
        if cache is None or cache.codegen is None:
            raise ToolError("Decompile this function first with decompile_function.")
        return function, cache.codegen

    @server.tool()
    def runtime_configure(gdb_path: str = "gdb") -> dict:
        """Choose the GDB executable while disconnected. Close the session before changing it."""
        call(runtime.configure_gdb, gdb_path)
        return runtime.snapshot()

    @server.tool()
    def runtime_status(refresh: bool = False) -> dict:
        """Get live process state, capabilities, threads, frames, modules, rules and bounded event history.

        Refresh reads stopped-target state. Running-target values are the last stopped snapshot.
        """
        return call(runtime.snapshot, refresh=refresh)

    @server.tool()
    def runtime_launch(
        executable: str | None = None,
        args: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stop_at_entry: bool = True,
    ) -> dict:
        """Launch an executable under GDB, defaulting to the analyzed binary.

        GDB does not disable ASLR. Stops at the first instruction by default.
        Local launch requires POSIX PTY support.
        """
        binary = executable or require_project(workspace).filename
        call(runtime.launch, binary, args=args, cwd=cwd, env=env, stop_at_entry=stop_at_entry)
        gui_thread_schedule_async(workspace.show_runtime_view)
        return runtime.snapshot()

    @server.tool()
    def runtime_attach(pid: int, executable: str | None = None) -> dict:
        """Attach GDB to a local PID. Detach resumes the process; stop terminates it."""
        call(runtime.attach, pid, executable=executable)
        gui_thread_schedule_async(workspace.show_runtime_view)
        return runtime.snapshot()

    @server.tool()
    def runtime_connect_remote(endpoint: str, executable: str | None = None) -> dict:
        """Connect to gdbserver. Automatic address relocation is unavailable for remote targets."""
        call(runtime.connect_remote, endpoint, executable=executable)
        gui_thread_schedule_async(workspace.show_runtime_view)
        return runtime.snapshot()

    @server.tool()
    def runtime_control(
        action: Literal[
            "continue",
            "interrupt",
            "step",
            "next",
            "step_source",
            "next_source",
            "finish",
            "detach",
            "stop",
            "close",
            "wait",
        ],
        timeout: float = 10.0,
    ) -> dict:
        """Control execution. step/next operate on machine instructions; wait waits for a stop.

        Interrupt before inspecting or editing a running target. Stop kills the inferior.
        """
        methods = {
            "continue": runtime.continue_execution,
            "interrupt": runtime.interrupt,
            "step": runtime.step_instruction,
            "next": runtime.next_instruction,
            "step_source": runtime.step_source,
            "next_source": runtime.next_source,
            "finish": runtime.finish,
            "detach": runtime.detach,
            "stop": runtime.stop,
            "close": runtime.close,
        }
        if action == "wait":
            if not 0 < timeout <= 60:
                raise ToolError("timeout must be between 0 and 60 seconds.")
            return call(runtime.wait_for_stop, timeout=timeout)
        call(methods[action])
        return runtime.snapshot()

    @server.tool()
    def runtime_select(thread_id: str | None = None, frame: int | None = None) -> dict:
        """Select a stopped thread and/or stack frame, then refresh its registers and stack."""

        def select():
            if thread_id is not None:
                runtime.select_thread(thread_id)
            if frame is not None:
                runtime.select_frame(frame)
            return runtime.refresh()

        return call(runtime.checked, select, runtime.snapshot()["generation"])

    @server.tool()
    def runtime_evaluate(expression: str) -> dict:
        """Evaluate a GDB expression in the selected stopped frame. GDB expressions may have side effects."""
        return {"expression": expression, "value": call(runtime.evaluate, expression)}

    @server.tool()
    def runtime_memory(address: str, size: int = 64, data_hex: str | None = None) -> dict:
        """Read live memory, or write hex bytes and read them back. Addresses are runtime addresses."""
        addr = parse_address(address)
        if not 1 <= size <= 65536:
            raise ToolError("size must be between 1 and 65536 bytes.")
        data = None
        if data_hex is not None:
            data = call(bytes.fromhex, data_hex)
            if not 1 <= len(data) <= 65536:
                raise ToolError("Write between 1 and 65536 bytes.")
            size = len(data)

        def access():
            if data is not None:
                runtime.write_memory(addr, data)
            return {"address": hex(addr), "size": size, "data_hex": runtime.read_memory(addr, size).hex()}

        return call(runtime.checked, access, runtime.snapshot()["generation"])

    @server.tool()
    def runtime_write_register(name: str, value: str) -> dict:
        """Set a register in the selected stopped frame and refresh the runtime snapshot."""
        call(runtime.write_register, name, value)
        return call(runtime.refresh)

    @server.tool()
    def runtime_map_address(
        address: str,
        direction: Literal["to_runtime", "to_static"] = "to_runtime",
        module: str | None = None,
        static_base: str | None = None,
    ) -> dict:
        """Translate between angr and process addresses using the loaded module's ELF mappings."""
        loader = require_project(workspace).loader
        obj = loader.main_object
        if module is not None:
            loaded = next((row for row in runtime.snapshot()["modules"] if row["id"] == module), None)
            path = loaded["path"] if loaded else module
            obj = next(
                (item for item in loader.all_objects if item.binary and realpath(item.binary) == realpath(path)), None
            )
        if static_base is None:
            if obj is None:
                raise ToolError("Specify static_base for a module that is not loaded in the analysis.")
            base = obj.mapped_base
        else:
            base = parse_address(static_base)
        if obj is not None:
            call(verify_module_identity, runtime, obj.binary, getattr(obj, "build_id", None))
        method = runtime.static_to_runtime if direction == "to_runtime" else runtime.runtime_to_static
        mapped = call(method, parse_address(address), base, module or loader.main_object.binary)
        return {"address": hex(mapped), "direction": direction}

    @server.tool()
    def runtime_breakpoint(
        action: Literal["add", "remove", "enable", "disable"],
        location: str = "",
        number: str = "",
        kind: Literal["execute", "write", "read", "access"] = "execute",
        condition: str | None = None,
        temporary: bool = False,
    ) -> dict:
        """Manage GDB breakpoints/watchpoints. Use *0xADDRESS for an execution address or a GDB lvalue for a watch."""
        if action == "add":
            return call(runtime.add_breakpoint, location, kind=kind, condition=condition, temporary=temporary)
        if not number:
            raise ToolError("Specify a breakpoint number.")
        if action == "remove":
            call(runtime.remove_breakpoint, number)
        else:
            call(runtime.enable_breakpoint, number, enabled=action == "enable")
        return runtime.snapshot()

    @server.tool()
    def runtime_add_rule(
        label: str,
        expression: str,
        mode: Literal["monitor", "clamp", "custom"] = "monitor",
        value: str | None = None,
        trigger: str | None = None,
        commands: list[str] | None = None,
        enabled: bool = True,
        preview: bool = False,
    ) -> dict:
        """Create or preview an auto-continuing monitor, clamp, or custom GDB hook.

        With no trigger, watches writes to expression. A trigger is an execution breakpoint location.
        Local/register expressions should use an instruction-scoped trigger. Rules expire on reconnect.
        Custom commands execute in GDB and can change the process or debugger.
        Custom rules with explicit resume commands must run alone at their trigger.
        """
        if preview:
            return {"commands": call(runtime.preview_rule, expression, mode=mode, value=value, commands=commands)}
        return call(
            runtime.add_rule,
            label,
            expression,
            mode=mode,
            value=value,
            trigger=trigger,
            commands=commands,
            enabled=enabled,
        )

    @server.tool()
    def runtime_update_rule(
        rule_id: str,
        enabled: bool | None = None,
        value: str | None = None,
        commands: list[str] | None = None,
        remove: bool = False,
    ) -> dict:
        """Enable, disable, retune or remove a runtime rule."""
        if remove:
            call(runtime.remove_rule, rule_id)
        else:
            call(runtime.update_rule, rule_id, enabled=enabled, value=value, commands=commands)
        return runtime.snapshot()

    @server.tool()
    def runtime_send_input(text: str) -> dict:
        """Send text to a locally launched program's terminal. Include a newline when submitting a line."""
        call(runtime.send_input, text)
        return runtime.snapshot()

    @server.tool()
    def runtime_console(command: str) -> dict:
        """Execute a GDB command or multiline script, including user-defined hooks. May modify the inferior."""
        return {"output": call(runtime.execute_console, command)}

    @server.tool()
    def runtime_list_variables(function_address: str) -> dict:
        """List selectable decompiler variables and why some need a manual runtime expression."""

        def collect():
            function, codegen = cached_function(function_address)
            return {"variables": list_variable_bindings(require_project(workspace), function, codegen)}

        result = gui_thread_schedule(collect, timeout=10)
        if result is None:
            raise ToolError("The GUI did not respond while reading decompiler variables.")
        return result

    @server.tool()
    def runtime_bind_variable(
        function_address: str,
        position: int,
        mode: Literal["monitor", "clamp"] = "monitor",
        value: str | None = None,
        preview: bool = True,
    ) -> dict:
        """Resolve a selection from runtime_list_variables and preview or add its scoped runtime rule."""

        generation = runtime.snapshot()["generation"]

        def describe():
            function, codegen = cached_function(function_address)
            node = selection_at(codegen, position)
            if node is None:
                raise ToolError("No variable at this position; refresh runtime_list_variables.")
            instruction = instruction_at(codegen, position)
            return call(describe_variable, require_project(workspace), function, codegen, node, instruction)

        binding = gui_thread_schedule(describe, timeout=10)
        if binding is None:
            raise ToolError("The GUI did not respond while resolving the selected variable.")

        def apply():
            resolved = binding.resolve(runtime)
            if preview:
                return {**resolved, "commands": runtime.preview_rule(resolved["expression"], mode=mode, value=value)}
            return runtime.add_rule(
                resolved["label"], resolved["expression"], mode=mode, value=value, trigger=resolved["trigger"]
            )

        return call(runtime.checked, apply, generation)
