from __future__ import annotations

from typing import TYPE_CHECKING

from angr.sim_type import normalize_cpp_function_name
from sortedcontainers import SortedDict

from angrmanagement.config.color import Color
from angrmanagement.plugins.base_plugin import BasePlugin

from .sinks import VulnerabilityType, sink_manager

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class DependencyViewer(BasePlugin):
    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)

        self.covered_blocks = SortedDict()

        # neutral colours, which both frontends draw (insn_style, func_style); Qt's yellow
        self.sink_color = Color(255, 255, 0)

    def insn_style(self, addr: int, selected, view) -> Color | None:
        if not selected:
            try:
                block_addr = next(self.covered_blocks.irange(maximum=addr, reverse=True))
            except StopIteration:
                return None
            block_size = self.covered_blocks[block_addr]
            if block_addr <= addr < block_addr + block_size:
                return Color(0xA5, 0xD0, 0xF3)
        return None

    FUNC_COLUMNS = ("Vuln Sink",)

    def extract_func_column(self, func, idx: int):
        assert idx == 0

        func_name = func.demangled_name
        if "<" in func_name or "{" in func_name:
            func_name = normalize_cpp_function_name(func_name)
            if "(" in func_name:
                # only take function name
                func_name = func_name[: func_name.index("(")]

        vulntype_and_sinks = sink_manager.get_function_sinks(func_name)
        if not vulntype_and_sinks:
            return 0, ""

        vuln_type, sink = vulntype_and_sinks[0]
        return 1, VulnerabilityType.to_string(vuln_type)

    def func_style(self, func) -> Color | None:
        # test if we have a match
        match = sink_manager.has_function_sink(func.demangled_name)
        if match:
            return self.sink_color

        return None
