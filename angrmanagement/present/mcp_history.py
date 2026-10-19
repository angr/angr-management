"""The MCP history view without a toolkit: the MCP tool calls an AI agent made against this session."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from .base import InstancePresenter
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.mcp.history import MCPCallRecord


class MCPHistoryTableModel(ListTableModel["MCPCallRecord"]):
    """The calls in the workspace's MCP history, oldest first; a failed call's status is red and explains why."""

    COL_TIME = 0
    COL_TOOL = 1
    COL_ARGUMENTS = 2
    COL_STATUS = 3
    COL_DURATION = 4

    COLUMNS: ClassVar[list[Column]] = [
        Column("Time", 9),
        Column("Tool", 20),
        Column("Arguments", stretch=True),
        Column("Status", 7),
        Column("Duration (ms)", 13, align="right"),
    ]
    HEADER: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def column_text(self, obj: MCPCallRecord, col: int) -> str:
        if col == self.COL_TIME:
            return obj.timestamp.strftime("%H:%M:%S")
        if col == self.COL_TOOL:
            return obj.tool
        if col == self.COL_ARGUMENTS:
            return obj.arguments_summary
        if col == self.COL_STATUS:
            return obj.status
        if col == self.COL_DURATION:
            return f"{obj.duration_ms:.0f}"
        return ""

    def column_value(self, obj: MCPCallRecord, col: int) -> Any:
        if col == self.COL_TIME:
            return obj.timestamp
        if col == self.COL_DURATION:
            return obj.duration_ms
        return self.column_text(obj, col)

    def style_key(self, obj: MCPCallRecord, col: int) -> str | None:
        return "table.error" if col == self.COL_STATUS and obj.status == "error" else None

    def tooltip(self, obj: MCPCallRecord, col: int) -> str | None:
        if col == self.COL_ARGUMENTS:
            return obj.arguments_summary
        if col == self.COL_STATUS and obj.status == "error" and obj.error:
            return obj.error
        return None


class MCPHistoryPresenter(InstancePresenter):
    """The MCP history view: it mirrors ``workspace.mcp_history``, which caps its own length."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "bottom") -> None:
        super().__init__(workspace, "mcp_history", instance, default_docking_position)
        self.base_caption = "MCP History"
        self.model = MCPHistoryTableModel()
        self.populate()
        self.workspace.mcp_history.am_subscribe(self._on_history_event)

    def close(self) -> None:
        self.workspace.mcp_history.am_unsubscribe(self._on_history_event)

    def populate(self) -> None:
        self.model.set_rows(list(self.workspace.mcp_history.am_obj or []))

    def clear(self) -> None:
        self.workspace.mcp_history.am_obj = []
        self.workspace.mcp_history.am_event()

    def _on_history_event(self, added: MCPCallRecord | None = None, **kwargs) -> None:  # pylint:disable=unused-argument
        # invoked on the GUI thread; the MCP server marshals its events here
        if added is not None:
            self.model.append_rows([added])
            # the container caps its length; drop leading rows so the table mirrors it
            excess = self.model.total_count - len(self.workspace.mcp_history.am_obj)
            self.model.remove_first_rows(excess)
        else:
            self.populate()
