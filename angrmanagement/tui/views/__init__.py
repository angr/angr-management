"""The views of the terminal frontend, by category."""

from __future__ import annotations

from .base import TuiView
from .code import CodeTuiView
from .console import ConsoleTuiView
from .disassembly import DisassemblyTuiView
from .search import SearchTuiView
from .tables import (
    BookmarksTuiView,
    BreakpointsTuiView,
    CommentsTuiView,
    FunctionsTuiView,
    JobsTuiView,
    LogTuiView,
    MCPHistoryTuiView,
    PatchesTuiView,
    RegistersTuiView,
    SignaturesTuiView,
    StackTuiView,
    StringsTuiView,
    TracesTuiView,
)

#: The view class of each category the terminal frontend has.
TUI_VIEW_CLASSES: dict[str, type[TuiView]] = {
    "disassembly": DisassemblyTuiView,
    "pseudocode": CodeTuiView,
    "functions": FunctionsTuiView,
    "strings": StringsTuiView,
    "search": SearchTuiView,
    "patches": PatchesTuiView,
    "comments": CommentsTuiView,
    "bookmarks": BookmarksTuiView,
    "signatures": SignaturesTuiView,
    "traces": TracesTuiView,
    "breakpoints": BreakpointsTuiView,
    "registers": RegistersTuiView,
    "stack": StackTuiView,
    "console": ConsoleTuiView,
    "log": LogTuiView,
    "jobs": JobsTuiView,
    "mcp_history": MCPHistoryTuiView,
}

__all__ = ["TUI_VIEW_CLASSES", "TuiView"]
