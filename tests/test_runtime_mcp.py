from __future__ import annotations

import os
import platform
import shutil
import unittest
from unittest.mock import MagicMock, patch

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CIndexedVariable,
    CStructField,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeInt, SimTypePointer, TypeRef, parse_types
from angr.sim_variable import SimStackVariable
from common import test_location
from PySide6.QtCore import QThread
from PySide6.QtWidgets import QMenu
from test_mcp_server import MCPTestCase, ToolError

from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.logic.threads import gui_thread_schedule
from angrmanagement.ui.documents.qcodedocument import QCodeDocument
from angrmanagement.ui.views.code_view import CodeView


@unittest.skipUnless(
    shutil.which("gdb") and platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
    "Live MCP fixtures require GDB on Linux x86-64",
)
class TestRuntimeMCP(MCPTestCase):
    """Exercise runtime tools over HTTP with the real GUI session and GDB."""

    binary = os.path.join(test_location, "x86_64", "runtime_2048", "2048.pie")

    def test_rendered_selections_use_live_storage_and_refuse_bitfields(self):
        async def scenario(client):
            async def call(tool_name, **arguments):
                return (await client.call_tool(tool_name, arguments)).data

            decomp = await call("decompile_function", name="slideArray", focus=True)
            address = decomp["function_address"]
            await call("runtime_launch", executable=self.binary, args=["test"])
            await call("runtime_breakpoint", action="add", location="slideArray", temporary=True)
            await call("runtime_control", action="continue")
            await call("runtime_control", action="wait")
            status = await call("runtime_status", refresh=True)
            pc = int(
                (await call("runtime_map_address", address=hex(status["frame"]["addr"]), direction="to_static"))[
                    "address"
                ],
                0,
            )

            async def integer(expression):
                return int(
                    (await call("runtime_evaluate", expression=f"(unsigned long long)({expression})"))["value"], 0
                )

            sp, pointer_storage, pointee = await integer("$sp"), await integer("&score"), await integer("score")
            self.assertNotEqual(pointer_storage, pointee)
            project = self.main.workspace.main_instance.project.am_obj
            assert project is not None
            cache = project.kb.decompilations[(int(address, 0), "pseudocode")]
            codegen = cache.codegen
            delta = cache.clinic._spt.offset_before(pc, project.arch.sp_offset)
            self.assertIsInstance(delta, int)
            mask = (1 << project.arch.bits) - 1

            def stack_variable(storage, size, name):
                offset = (storage - sp + delta) & mask
                if offset & (1 << (project.arch.bits - 1)):
                    offset -= mask + 1
                return SimStackVariable(offset, size, name=name)

            score_type = parse_types("struct Score { unsigned int value; };")["struct Score"].with_arch(project.arch)
            assert isinstance(score_type, SimStruct)
            bits_type = parse_types("struct Bits { unsigned int low:3; unsigned int high:5; };")[
                "struct Bits"
            ].with_arch(project.arch)
            assert isinstance(bits_type, SimStruct)

            def install_selection(kind):
                # Supply test types over DWARF-located storage; render/select through the real GUI and MCP cache.
                if kind in ("plain", "alias", "array"):
                    ty = SimTypePointer(SimTypeInt(signed=False) if kind == "array" else score_type)
                    if kind == "alias":
                        ty = TypeRef("ScorePointer", ty)
                    variable = CVariable(
                        stack_variable(pointer_storage, project.arch.bytes, "items"), variable_type=ty, codegen=codegen
                    )
                    index = CConstant(0, SimTypeInt(), codegen=codegen)
                    access = CIndexedVariable(variable, index, tags={"ins_addr": pc}, codegen=codegen)
                    if kind != "array":
                        access = CVariableField(
                            access,
                            CStructField(score_type, 0, "value", codegen=codegen),
                            tags={"ins_addr": pc},
                            codegen=codegen,
                        )
                else:
                    variable = CVariable(stack_variable(pointee, 1, "flags"), variable_type=bits_type, codegen=codegen)
                    access = CVariableField(
                        variable,
                        CStructField(bits_type, bits_type.offsets[kind], kind, codegen=codegen),
                        tags={"ins_addr": pc},
                        codegen=codegen,
                    )
                (
                    codegen.text,
                    codegen.map_pos_to_node,
                    codegen.map_pos_to_addr,
                    codegen.map_addr_to_pos,
                    codegen.map_ast_to_pos,
                ) = codegen.render_text(access)
                code_view = self.main.workspace.view_manager.first_view_in_category("pseudocode")
                assert isinstance(code_view, CodeView)
                assert code_view.textedit is not None
                assert isinstance(code_view.codegen, ObjectContainer)
                code_view.codegen.am_obj = codegen
                code_view.codegen.am_event(already_regenerated=True)
                positions = (
                    [codegen.text.index(char) for char in "[0]"] if kind == "array" else [codegen.text.rindex(".") + 1]
                )
                for position in positions:
                    cursor = code_view.textedit.textCursor()
                    cursor.setPosition(position)
                    code_view.textedit.setTextCursor(cursor)
                    menu = code_view.textedit.get_context_menu()
                    actions = menu.actions()
                    runtime_action = next(action for action in actions if action.text() == "Runtime")
                    runtime_menu = runtime_action.menu()
                    assert isinstance(runtime_menu, QMenu)
                    dialog = MagicMock()
                    with patch.object(self.main.workspace, "show_runtime_view", return_value=dialog):
                        runtime_menu.actions()[1].trigger()
                    if kind in ("low", "high"):
                        dialog.resolve_binding.assert_not_called()
                        dialog.open_binding.assert_called_once()
                        self.assertEqual(dialog.open_binding.call_args.args, ("",))
                        self.assertIn("Bitfields", dialog.open_binding.call_args.kwargs["note"])
                    else:
                        dialog.open_binding.assert_not_called()
                        dialog.resolve_binding.assert_called_once()
                    menu.deleteLater()
                if kind == "array":
                    document = code_view.textedit.document()
                    assert isinstance(document, QCodeDocument)
                    chunks = document.find_related_text_chunks(access)
                    assert chunks is not None
                    self.assertEqual(len(chunks), 2)
                return positions[-1]

            original = (
                codegen.text,
                codegen.map_pos_to_node,
                codegen.map_pos_to_addr,
                codegen.map_addr_to_pos,
                codegen.map_ast_to_pos,
            )
            before = await call("runtime_memory", address=hex(pointee), size=4)
            try:
                for kind in ("plain", "alias", "array", "low", "high"):
                    position = gui_thread_schedule(lambda k=kind: install_selection(k))
                    rows = (await call("runtime_list_variables", function_address=address))["variables"]
                    if kind in ("low", "high"):
                        self.assertTrue(rows)
                        self.assertFalse(any(row["available"] for row in rows))
                        with self.assertRaisesRegex(ToolError, "Bitfields"):
                            await call(
                                "runtime_bind_variable",
                                function_address=address,
                                position=position,
                                mode="clamp",
                                value="255",
                                preview=False,
                            )
                        self.assertFalse((await call("runtime_status"))["rules"])
                    else:
                        listed = next(row for row in rows if row["available"] and row["label"] == codegen.text)
                        binding = await call(
                            "runtime_bind_variable", function_address=address, position=listed["position"]
                        )
                        self.assertEqual(await integer(f"&({binding['expression']})"), pointee)
                        self.assertEqual(await integer(binding["expression"]), await integer("*score"))
                self.assertEqual(
                    (await call("runtime_memory", address=hex(pointee), size=4))["data_hex"], before["data_hex"]
                )
            finally:
                (
                    codegen.text,
                    codegen.map_pos_to_node,
                    codegen.map_pos_to_addr,
                    codegen.map_addr_to_pos,
                    codegen.map_ast_to_pos,
                ) = original
                await call("runtime_control", action="stop")

        self.run_client(scenario)

    def test_live_session_tools_share_gui_state(self):
        async def scenario(client):
            names = {tool.name for tool in await client.list_tools()}
            expected = {
                "runtime_status",
                "runtime_configure",
                "runtime_launch",
                "runtime_attach",
                "runtime_connect_remote",
                "runtime_control",
                "runtime_select",
                "runtime_evaluate",
                "runtime_memory",
                "runtime_write_register",
                "runtime_map_address",
                "runtime_breakpoint",
                "runtime_add_rule",
                "runtime_update_rule",
                "runtime_console",
                "runtime_send_input",
                "runtime_list_variables",
                "runtime_bind_variable",
            }
            self.assertTrue(expected <= names)

            async def call(tool_name, **arguments):
                return (await client.call_tool(tool_name, arguments)).data

            status = await call("runtime_status")
            self.assertEqual(status["state"], "disconnected")
            await call("runtime_configure", gdb_path=shutil.which("gdb"))
            await call("runtime_launch", executable=self.binary, args=["test"])
            status = await call("runtime_control", action="wait")
            self.assertEqual(status["state"], "stopped")
            status = await call("runtime_status", refresh=True)
            self.assertTrue(status["modules"])
            self.assertEqual(self.main.workspace.runtime.snapshot()["pid"], status["pid"])

            stop_point = await call("runtime_breakpoint", action="add", location="slideArray")
            await call("runtime_control", action="continue")
            await call("runtime_control", action="wait")
            status = await call("runtime_select", frame=0)
            self.assertTrue(status["frames"])
            self.assertTrue(status["registers"])
            pc = (await call("runtime_evaluate", expression="$pc"))["value"].split()[0]
            mapped = await call("runtime_map_address", address=pc, direction="to_static")
            restored = await call("runtime_map_address", address=mapped["address"])
            self.assertEqual(int(restored["address"], 0), int(pc, 0))
            register = next(row for row in status["registers"] if row["name"] == "rax")
            await call("runtime_write_register", name="rax", value=register["value"])

            score_address = (await call("runtime_evaluate", expression="score"))["value"].split()[0]
            before = await call("runtime_memory", address=score_address, size=4)
            after = await call("runtime_memory", address=score_address, data_hex=before["data_hex"])
            self.assertEqual(before["data_hex"], after["data_hex"])
            preview = await call(
                "runtime_add_rule",
                label="Score",
                expression="*score",
                mode="clamp",
                value="123",
                trigger="slideArray",
                preview=True,
            )
            self.assertTrue(any("123" in line for line in preview["commands"]))
            await call("runtime_breakpoint", action="disable", number=stop_point["number"])
            rule = await call("runtime_add_rule", label="Score", expression="*score", trigger="slideArray")
            await call("runtime_update_rule", rule_id=rule["id"], enabled=False)
            self.assertFalse(self.main.workspace.runtime.snapshot()["rules"][0]["enabled"])
            await call("runtime_update_rule", rule_id=rule["id"], enabled=True)
            await call("runtime_console", command="set $am_seen = 0")
            hook = await call(
                "runtime_add_rule",
                label="Count calls",
                expression="*score",
                mode="custom",
                trigger="slideArray",
                commands=["set $am_seen = $am_seen + 1"],
            )
            await call("runtime_breakpoint", action="disable", number=stop_point["number"])
            await call("runtime_control", action="continue")
            status = await call("runtime_control", action="wait")
            self.assertEqual(status["state"], "exited")
            rules = {row["id"]: row for row in status["rules"]}
            self.assertTrue(rules[rule["id"]]["samples"])
            self.assertTrue(rules[hook["id"]]["samples"])
            await call("runtime_control", action="close")
            self.assertEqual((await call("runtime_status"))["state"], "disconnected")

        self.run_client(scenario)

    def test_decompiler_stack_binding_matches_debug_information(self):
        submission_threads = []
        gui_thread = QThread.currentThread()
        add_job = self.main.workspace.job_manager.add_job

        def record_submission(job):
            submission_threads.append(QThread.currentThread() == gui_thread)
            return add_job(job)

        async def scenario(client):
            async def call(tool_name, **arguments):
                return (await client.call_tool(tool_name, arguments)).data

            decomp = await call("decompile_function", name="testSucceed", focus=False)
            address = decomp["function_address"]
            rows = (await call("runtime_list_variables", function_address=address))["variables"]
            candidates = [row for row in rows if row["available"] and row["kind"] == "stack"]
            self.assertTrue(candidates, "The fixture must expose decompiler stack selections")
            await call("runtime_launch", executable=self.binary, args=["test"])
            await call("runtime_breakpoint", action="add", location="testSucceed", temporary=True)
            await call("runtime_control", action="continue")
            await call("runtime_control", action="wait")
            status = await call("runtime_status", refresh=True)
            pc = status["frame"]["addr"]
            static_pc = int((await call("runtime_map_address", address=hex(pc), direction="to_static"))["address"], 0)
            project = self.main.workspace.main_instance.project.am_obj
            assert project is not None
            cache = project.kb.decompilations[(int(address, 0), "pseudocode")]
            tracker = cache.clinic._spt
            delta = tracker.offset_before(static_pc, project.arch.sp_offset)
            self.assertIsInstance(delta, int)
            sp = int((await call("runtime_evaluate", expression="(unsigned long long)$sp"))["value"], 0)
            score = int((await call("runtime_evaluate", expression="(unsigned long long)&score"))["value"], 0)
            mask = (1 << project.arch.bits) - 1
            expected_offset = (score - sp + delta) & mask
            matching = [
                row
                for row in candidates
                if row["instruction"] > static_pc
                and (row["location"] + tracker.offset_before(row["instruction"], project.arch.sp_offset)) & mask
                == expected_offset
            ]
            self.assertTrue(matching, "Recovered score storage must agree with GDB's independent DWARF location")
            position = min(matching, key=lambda row: row["instruction"])["position"]
            binding = await call("runtime_bind_variable", function_address=address, position=position)
            await call("runtime_breakpoint", action="add", location=binding["trigger"], temporary=True)
            await call("runtime_control", action="continue")
            await call("runtime_control", action="wait")
            actual_address = int(
                (await call("runtime_evaluate", expression=f"(unsigned long long)&({binding['expression']})"))["value"],
                0,
            )
            score = int((await call("runtime_evaluate", expression="(unsigned long long)&score"))["value"], 0)
            self.assertEqual(actual_address, score)
            rule = await call("runtime_bind_variable", function_address=address, position=position, preview=False)
            await call("runtime_update_rule", rule_id=rule["id"], remove=True)
            await call("runtime_control", action="stop")

        with patch.object(self.main.workspace.job_manager, "add_job", side_effect=record_submission):
            self.run_client(scenario)
        self.assertTrue(submission_threads)
        self.assertTrue(all(submission_threads), "Job notifications must be ordered on the GUI thread")


if __name__ == "__main__":
    unittest.main()
