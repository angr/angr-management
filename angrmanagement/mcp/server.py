"""Construction of the angr-management MCP server."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastmcp import FastMCP

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

_l = logging.getLogger(__name__)

INSTRUCTIONS = """This server exposes the binary currently loaded in a running angr management GUI.

Unprefixed tools operate on the live GUI session: analysis results and edits (renames, comments,
type changes) made through them are immediately visible to the user in angr management. Use these
tools when working with the binary the user has open.

Tools prefixed with "angr_" belong to a standalone angr analysis server running in the same
process. They manage their own separate project sessions (created via angr_load_binary) and do
NOT affect what is displayed in the GUI. Use them only for scratch analysis of other binaries.
"""


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

    try:
        from angr.mcp.server import mcp as angr_mcp_server  # pylint:disable=import-outside-toplevel

        server.mount(angr_mcp_server, namespace="angr")
    except ImportError:
        _l.warning("The standalone angr MCP server is unavailable; only live GUI tools are exposed.", exc_info=True)

    return server
