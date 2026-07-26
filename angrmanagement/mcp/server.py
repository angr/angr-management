"""Construction of the angr-management MCP server."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastmcp import FastMCP

from angrmanagement.config import Conf
from angrmanagement.logic.threads import gui_thread_schedule_async

from .edit_tools import register_edit_tools
from .history import MCPHistoryMiddleware
from .tools import (
    register_project_tools,
    register_read_tools,
    register_view_tools,
)

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

try:
    from angr.mcp.server import mcp as _ANGR_MCP_SERVER
except ImportError:
    _ANGR_MCP_SERVER = None

_l = logging.getLogger(__name__)

INSTRUCTIONS = """This server exposes a running angr management GUI and the binary loaded in it.

Unprefixed tools operate on the live GUI session: analysis results and edits (renames, comments,
type changes) made through them are immediately visible to the user in angr management. Use these
tools when working with the binary the user has open.

If no binary is loaded yet, call get_server_status to check, then load_binary to open one in the
GUI; it will be analyzed and displayed to the user. Subsequent tools then operate on it.

Tools prefixed with "angr_" belong to a standalone angr analysis server running in the same
process. They manage their own separate project sessions (created via angr_load_binary) and do
NOT affect what is displayed in the GUI. Use them only for scratch analysis of other binaries.
"""


def _install_history_recorder(server: FastMCP, workspace: Workspace) -> None:
    """Record every tool call into workspace.mcp_history so the GUI can display the agent's work."""

    def record_call(record) -> None:
        # Mutate the history and notify the view on the GUI thread; the middleware runs on the
        # server thread. gui_thread_schedule_async is a no-op-safe fire-and-forget.
        def apply() -> None:
            history = workspace.mcp_history.am_obj
            history.append(record)
            # cap the retained history (read live so config changes take effect); <= 0 is unlimited
            limit = Conf.mcp_server_history_limit
            if 0 < limit < len(history):
                del history[: len(history) - limit]
            workspace.mcp_history.am_event(added=record)

        gui_thread_schedule_async(apply)

    server.add_middleware(MCPHistoryMiddleware(record_call))


def create_server(workspace: Workspace) -> FastMCP:
    """Create the angr-management MCP server, bound to the given workspace."""
    server = FastMCP("angr-management", instructions=INSTRUCTIONS)

    @server.tool()
    def get_server_status() -> dict[str, Any]:
        """
        Get the status of the angr management GUI this server is embedded in.

        Returns whether a binary is currently loaded and, if so, basic information about it.
        This is a cheap call that is useful for discovering the state of the GUI session.
        """
        instance = workspace.main_instance
        if instance.project.am_none:
            return {"project_loaded": False}
        proj = instance.project.am_obj
        return {
            "project_loaded": True,
            "binary_path": proj.filename,
            "arch": proj.arch.name,
            "entry_point": hex(proj.entry),
            "cfg_built": not instance.cfg.am_none,
        }

    register_project_tools(server, workspace)
    register_read_tools(server, workspace)
    register_view_tools(server, workspace)
    register_edit_tools(server, workspace)

    _install_history_recorder(server, workspace)

    if _ANGR_MCP_SERVER is not None:
        server.mount(_ANGR_MCP_SERVER, namespace="angr")
    else:
        _l.warning("The standalone angr MCP server is unavailable; only live GUI tools are exposed.")

    return server
