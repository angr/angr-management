"""The views of the terminal frontend, by category."""

from __future__ import annotations

from .base import TuiView
from .call_explorer import CallExplorerTuiView
from .code import CodeTuiView
from .console import ConsoleTuiView
from .disassembly import DisassemblyTuiView
from .graphs import DataDepTuiView, DependencyTuiView, ProximityTuiView
from .hex import HexTuiView
from .pattern import PatternTuiView
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
from .trace_map import TraceMapTuiView
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
    "tracemap": TraceMapTuiView,
    "breakpoints": BreakpointsTuiView,
    "registers": RegistersTuiView,
    "stack": StackTuiView,
    "symexec": SymexecTuiView,
    "states": StatesTuiView,
    "call_explorer": CallExplorerTuiView,
    "proximity": ProximityTuiView,
    "dependencies": DependencyTuiView,
    "data_dependency": DataDepTuiView,
    "pattern": PatternTuiView,
    "console": ConsoleTuiView,
    "log": LogTuiView,
    "jobs": JobsTuiView,
    "mcp_history": MCPHistoryTuiView,
}

__all__ = ["TUI_VIEW_CLASSES", "TuiView"]
