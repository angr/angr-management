"""The views of the terminal frontend, by category."""

from __future__ import annotations

from .base import TuiView
from .code import CodeTuiView
from .console import ConsoleTuiView
from .disassembly import DisassemblyTuiView
from .hex import HexTuiView
from .search import SearchTuiView
from .symexec import SymexecTuiView
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
    StatesTuiView,
    StringsTuiView,
    TracesTuiView,
)
from .types import TypesTuiView

#: The view class of each category the terminal frontend has.
TUI_VIEW_CLASSES: dict[str, type[TuiView]] = {
    "disassembly": DisassemblyTuiView,
    "pseudocode": CodeTuiView,
    "hex": HexTuiView,
    "functions": FunctionsTuiView,
    "strings": StringsTuiView,
    "search": SearchTuiView,
    "patches": PatchesTuiView,
    "types": TypesTuiView,
    "comments": CommentsTuiView,
    "bookmarks": BookmarksTuiView,
    "signatures": SignaturesTuiView,
    "traces": TracesTuiView,
    "breakpoints": BreakpointsTuiView,
    "registers": RegistersTuiView,
    "stack": StackTuiView,
    "symexec": SymexecTuiView,
    "states": StatesTuiView,
    "console": ConsoleTuiView,
    "log": LogTuiView,
    "jobs": JobsTuiView,
    "mcp_history": MCPHistoryTuiView,
}

__all__ = ["TUI_VIEW_CLASSES", "TuiView"]
