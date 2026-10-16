"""
The tree of display nodes behind each line of a disassembly block, for both frontends.

:mod:`.base` has :class:`BlockTreeNode`, the node that renders an AIL statement, a lifter IR op or a function header as
styled spans; :mod:`.ail`, :mod:`.vex` and :mod:`.header` have its subclasses. :mod:`.disasm_nodes` has the nodes of
machine code: instructions, operands, labels, variables and data.
"""

from __future__ import annotations

from .ail import QAilObj
from .base import BlockTreeNode, BlockTreeNodeOptions, QVariableObj
from .header import QFunctionHeader
from .vex import QIROpObj

__all__ = [
    "BlockTreeNode",
    "BlockTreeNodeOptions",
    "QAilObj",
    "QFunctionHeader",
    "QIROpObj",
    "QVariableObj",
]
