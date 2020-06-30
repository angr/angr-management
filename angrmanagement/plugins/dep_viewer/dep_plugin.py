from typing import Set, Tuple, Optional, Dict
from sortedcontainers import SortedDict

from PySide2.QtGui import QColor, Qt

from angr.sim_type import normalize_cpp_function_name

from ..base_plugin import BasePlugin
from .sinks import sink_manager, VulnerabilityType


class DependencyViewer(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.transitions: Set[Tuple[int,int]] = set()
        self.covered_blocks = SortedDict()

        self.sink_color = Qt.yellow

    def color_insn(self, addr, selected) -> Optional[QColor]:
        if not selected:
            try:
                block_addr = next(self.covered_blocks.irange(maximum=addr, reverse=True))
            except StopIteration:
                return None
            block_size = self.covered_blocks[block_addr]
            if block_addr <= addr < block_addr + block_size:
                return QColor(0xa5, 0xd0, 0xf3)
        return None

    FUNC_COLUMNS = ('Vuln Sink',)

    def extract_func_column(self, func, idx):
        assert idx == 0

        func_name = func.demangled_name
        if "<" in func_name or "{" in func_name:
            func_name = normalize_cpp_function_name(func_name)
            if "(" in func_name:
                # only take function name
                func_name = func_name[:func_name.index("(")]

        vulntype_and_sinks = sink_manager.get_function_sinks(func_name)
        if not vulntype_and_sinks:
            return 0, ''

        vuln_type, sink = vulntype_and_sinks[0]
        return 1, VulnerabilityType.to_string(vuln_type)

    def color_func(self, func) -> Optional[QColor]:
        # test if we have a match
        match = sink_manager.has_function_sink(func.demangled_name)
        if match:
            return self.sink_color

        return None
