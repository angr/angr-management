from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF, Qt
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf
from angrmanagement.present.block_tree.disasm_nodes import UnknownNode

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.views.disassembly_view import DisassemblyView


class QUnknownBlock(QCachedGraphicsItem):
    """
    Undecoded bytes in the linear view: the text items of an UnknownNode.
    """

    LINEAR_INSTRUCTION_OFFSET = 120
    DEFAULT_TEXT = "Unknown"
    BYTES_PER_LINE = 16

    def __init__(
        self,
        instance: Instance,
        addr: int,
        bytes_,
        parent=None,
        disasm_view: DisassemblyView | None = None,
        node: UnknownNode | None = None,
    ) -> None:
        super().__init__(parent=parent)
        #: the byte lines' text
        self.node = node if node is not None else UnknownNode(addr, bytes_)

        self.instance = instance
        self.addr = addr
        self.bytes = bytes_
        self._disasm_view = disasm_view

        self._width = 0
        self._height = 0

        self._addr_text = None
        self._addr_item: QGraphicsSimpleTextItem | None = None
        self._byte_lines: list[QGraphicsSimpleTextItem] = []

        self._config = Conf

        self._init_widgets()

    #
    # Public methods
    #

    def paint(self, painter, option, widget=None) -> None:  # pylint: disable=unused-argument
        # painter.setRenderHints(
        #         QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        # painter.setFont(self._config.disasm_font)
        pass

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    def remove_children_from_scene(self):
        """
        Remove this item and all its children from the scene.
        """

        scene = self.scene()
        if scene is None:
            return

        if self._addr_item is not None:
            scene.removeItem(self._addr_item)
            self._addr_item = None

        if self._byte_lines:
            for byte_line in self._byte_lines:
                scene.removeItem(byte_line)
            self._byte_lines = []

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.RightButton and self._disasm_view is not None:
            # determine the address of the clicked line
            line_height = self._byte_lines[0].boundingRect().height() if self._byte_lines else 0
            line_idx = int(event.pos().y() // line_height) if line_height > 0 else 0
            addr = self.node.addr_of_line(line_idx)
            self._disasm_view.unknown_block_context_menu(addr, event.screenPos().toPoint())
            event.accept()
            return
        super().mousePressEvent(event)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        # Address
        self._addr_text = self.node.addr_text
        self._addr_item = QGraphicsSimpleTextItem(self._addr_text, self)
        self._addr_item.setBrush(Conf.disasm_view_node_address_color)
        self._addr_item.setFont(Conf.disasm_font)

        # Bytes
        self._byte_lines = []
        for line in self.node.byte_lines:
            o = QGraphicsSimpleTextItem(line, self)
            o.setFont(Conf.disasm_font)
            o.setBrush(Conf.disasm_view_unprintable_byte_color)
            self._byte_lines.append(o)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self) -> None:
        x, y = 0, 0

        # address
        self._addr_item.setPos(x, y)

        x += self._addr_item.boundingRect().width()
        x += self.LINEAR_INSTRUCTION_OFFSET

        # lines
        max_x = x
        for line in self._byte_lines:
            line.setPos(x, y)
            y += line.boundingRect().height()
            max_x = max(max_x, line.boundingRect().width())

        self._width = max_x
        self._height = y

        self.recalculate_size()
