from typing import Set, Tuple, Optional, Dict
from sortedcontainers import SortedDict

from PySide2.QtGui import QColor, Qt

from ..base_plugin import BasePlugin


class DependencyViewer(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.transitions: Set[Tuple[int,int]] = set()
        self.covered_blocks = SortedDict()

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
