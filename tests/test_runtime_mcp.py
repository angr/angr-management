from __future__ import annotations

import os
import platform
import shutil
import unittest
from unittest.mock import patch

from common import test_location
from PySide6.QtCore import QThread
from test_mcp_server import MCPTestCase


@unittest.skipUnless(
    shutil.which("gdb") and platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
    "Live MCP fixtures require GDB on Linux x86-64",
)
class TestRuntimeMCP(MCPTestCase):
    """Exercise runtime tools over HTTP with the real GUI session and GDB."""

    binary = os.path.join(test_location, "x86_64", "runtime_2048", "2048.pie")

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
