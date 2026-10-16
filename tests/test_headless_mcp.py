"""
The MCP server runs over a headless workspace, in a process without PySide6.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import os
import unittest

from headless import run_without_qt, test_location  # pylint: disable=import-error

from angrmanagement.mcp import is_mcp_available

FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")

MCP_SCRIPT = """
import asyncio
import socket
import threading

import angr
from fastmcp import Client

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.mcp import MCPServerManager

workspace = HeadlessWorkspace()
instance = workspace.main_instance
instance.project.am_obj = angr.Project(BINARY, auto_load_libs=False)
instance.project.am_event()
# setting the project starts the initial analyses; their results arrive on this thread
workspace.job_manager.join_all_jobs()
cfg_built = not instance.cfg.am_none

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
manager = MCPServerManager(workspace, port=port)
manager.start()

box = {}


async def scenario():
    async with Client(manager.url) as client:
        status = (await client.call_tool("get_server_status", {})).data
        # in the background, as a tool call without a view to show it in
        background = (await client.call_tool("decompile_function", {"name": "authenticate", "focus": False})).data
        # "focused": the headless workspace has no pseudocode view and decompiles in the background instead
        focused = (await client.call_tool("decompile_function", {"name": "main"})).data
        # an edit, which the tool runs on the UI thread through the executor
        renamed = (await client.call_tool("rename_function", {"name": "accepted", "new_name": "headless_ok"})).data
        view_state = (await client.call_tool("get_view_state", {})).data
        return {
            "status": status,
            "background": background,
            "focused": focused,
            "renamed": renamed,
            "view_state": view_state,
        }


def client_thread():
    try:
        box["result"] = asyncio.run(scenario())
    except Exception as ex:  # noqa: BLE001
        box["error"] = repr(ex)


thread = threading.Thread(target=client_thread, daemon=True)
thread.start()
finished = GlobalInfo.executor.pump_until(lambda: not thread.is_alive(), timeout=600)
manager.stop()
# deliver what the last calls queued for the UI thread (the history records)
GlobalInfo.executor.process_pending()

RESULT = {
    "cfg_built": cfg_built,
    "finished": finished,
    "error": box.get("error"),
    "tools": box.get("result"),
    "renamed_in_kb": instance.kb.functions.function(name="headless_ok") is not None,
    "history": len(workspace.mcp_history.am_obj),
}
"""


@unittest.skipUnless(is_mcp_available(), "fastmcp/uvicorn are not installed")
class TestHeadlessMCP(unittest.TestCase):
    """Start the MCP server over a HeadlessWorkspace on fauxware and call its tools."""

    def test_decompile_over_a_headless_workspace(self):
        outcome = run_without_qt(f"BINARY = {FAUXWARE!r}\n" + MCP_SCRIPT)
        result = outcome["result"]

        assert outcome["qt_modules_loaded"] == []
        assert result["cfg_built"] is True
        assert result["finished"] is True
        assert result["error"] is None, result["error"]
        tools = result["tools"]
        assert tools["status"]["project_loaded"] is True
        assert tools["status"]["cfg_built"] is True

        background = tools["background"]
        assert background["function_name"] == "authenticate"
        assert background["shown_to_user"] is False
        assert "authenticate" in background["code"] and "{" in background["code"]

        focused = tools["focused"]
        assert focused["function_name"] == "main"
        assert "main" in focused["code"]

        assert tools["renamed"]["old_name"] == "accepted"
        assert result["renamed_in_kb"] is True
        assert tools["view_state"] == {"current_view": None}
        # the history recorder ran on the UI thread for every call
        assert result["history"] == 5


if __name__ == "__main__":
    unittest.main()
