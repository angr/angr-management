"""
The Qt and the terminal disassembly show the same text: each block of fauxware's main, as the Qt scene's text items
lay it out and as the presenter's BlockDoc lines have it, is equal modulo whitespace. Both frontends take the text
from the same display nodes, so this is what proves the span IR carries everything the Qt items used to compute.
"""

# pylint: disable=missing-class-docstring,protected-access

from __future__ import annotations

import os
import re
import unittest

from common import AngrManagementTestCase, open_analyzed_project, test_location
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf
from angrmanagement.data.function_graph import FunctionGraph
from angrmanagement.present.disasm import DisassemblyLevel
from angrmanagement.present.disasm_controls import HeadlessDisasmView
from angrmanagement.ui.views import DisassemblyView
from angrmanagement.ui.widgets.qblock_code import QBlockCode

FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
WS = re.compile(r"\s+")


def qt_block_lines(block) -> list[str]:
    """The block's text as the scene shows it: text items grouped into rows by position, top to bottom."""
    items: list[tuple[float, float, str]] = []

    def visit(item) -> None:
        for child in item.childItems():
            if not child.isVisible():
                continue
            if isinstance(child, QGraphicsSimpleTextItem):
                pos = child.scenePos()
                items.append((pos.y(), pos.x(), child.text()))
            elif isinstance(child, QBlockCode):
                # the text document is painted, not made of items: one row per text block
                origin = child.scenePos()
                doc = child._qtextdoc
                x = origin.x() + (child._addr_item.boundingRect().width() if child._addr_item is not None else 0)
                y = origin.y() + child.obj.top_margin_lines * Conf.disasm_font_height
                text_block = doc.begin()
                while text_block.isValid():
                    top = doc.documentLayout().blockBoundingRect(text_block).top()
                    items.append((y + top, x + 1, text_block.text()))
                    text_block = text_block.next()
                if child._addr_item is not None and child._addr_item.isVisible():
                    items.append((y, origin.x(), child._addr_item.text()))
                continue
            visit(child)

    visit(block)
    items.sort()
    rows: list[list[tuple[float, str]]] = []
    last_y = None
    for y, x, text in items:
        if last_y is None or abs(y - last_y) > 2:
            rows.append([])
        rows[-1].append((x, text))
        last_y = y
    return ["".join(text for _x, text in sorted(row)) for row in rows]


def squeeze(lines) -> list[str]:
    """The lines without whitespace, empty ones dropped."""
    out = [WS.sub("", line) for line in lines]
    return [line for line in out if line]


class TestDisasmTextParity(AngrManagementTestCase):
    def setUp(self):
        super().setUp()
        self.project = open_analyzed_project(self.main, FAUXWARE)
        self.workspace = self.main.workspace
        self.instance = self.workspace.main_instance

    def _compare(self, func_name: str, level: DisassemblyLevel) -> int:
        func = self.project.kb.functions[func_name]
        qt_view = DisassemblyView(self.workspace, "center", self.instance)
        qt_view.set_disassembly_level(level)
        qt_view.display_disasm_graph()
        qt_view.display_function(func)
        qt_blocks = {(b.addr, b.idx): qt_block_lines(b) for b in qt_view.flow_graph.blocks}

        tui_view = HeadlessDisasmView(self.workspace, self.instance)
        tui_view.presenter.set_disassembly_level(level)
        result = tui_view.presenter.graph_doc(FunctionGraph(func))
        assert result is not None
        doc, _ = result
        tui_blocks = {(b.addr, b.idx): [line.text for line in b.lines] for b in doc.blocks.values()}

        assert sorted(qt_blocks) == sorted(tui_blocks)
        for key, qt_lines in qt_blocks.items():
            assert squeeze(qt_lines) == squeeze(tui_blocks[key]), f"block {key[0]:#x}"
        tui_view.close()
        qt_view.close()
        # The view has no Qt parent; delete it through Qt now. Left to Python's cyclic collector, it is torn down
        # whenever that next runs, on whatever thread, and that can crash the process (as in test_comments).
        qt_view.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        del qt_view
        return len(qt_blocks)

    def test_main_machine_code(self):
        assert self._compare("main", DisassemblyLevel.MachineCode) == 4

    def test_main_lifter_ir(self):
        assert self._compare("main", DisassemblyLevel.LifterIR) == 4

    def test_authenticate_machine_code_with_comments(self):
        func = self.project.kb.functions["authenticate"]
        insns = sorted(a for b in func.blocks for a in b.instruction_addrs)
        self.workspace.set_comment(insns[2], "two\nlines")
        self.workspace.set_comment(func.addr, "the function comment")
        assert self._compare("authenticate", DisassemblyLevel.MachineCode) > 1


if __name__ == "__main__":
    unittest.main()
