"""Recording of MCP tool calls so the GUI can display the agent's work history."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastmcp.server.middleware import Middleware

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class MCPCallRecord:
    """A single MCP tool invocation."""

    tool: str
    arguments: dict[str, Any]
    status: str  # "ok" or "error"
    duration_ms: float
    timestamp: datetime = field(default_factory=datetime.now)
    error: str | None = None

    @property
    def arguments_summary(self) -> str:
        """A compact one-line rendering of the arguments."""
        if not self.arguments:
            return ""
        parts = []
        for key, value in self.arguments.items():
            text = repr(value)
            if len(text) > 60:
                text = text[:57] + "..."
            parts.append(f"{key}={text}")
        return ", ".join(parts)


class MCPHistoryMiddleware(Middleware):
    """FastMCP middleware that reports every tool call to a callback."""

    def __init__(self, record_call: Callable[[MCPCallRecord], None]) -> None:
        self._record_call = record_call

    async def on_call_tool(self, context, call_next):
        name = context.message.name
        arguments = dict(context.message.arguments or {})
        start = time.monotonic()
        try:
            result = await call_next(context)
        except Exception as e:  # noqa: BLE001  record failures too, then re-raise
            self._record_call(
                MCPCallRecord(
                    tool=name,
                    arguments=arguments,
                    status="error",
                    duration_ms=(time.monotonic() - start) * 1000,
                    error=str(e),
                )
            )
            raise
        self._record_call(
            MCPCallRecord(
                tool=name,
                arguments=arguments,
                status="ok",
                duration_ms=(time.monotonic() - start) * 1000,
            )
        )
        return result
