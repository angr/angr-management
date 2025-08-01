from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class QUnknownBlock(QCachedGraphicsItem):
    LINEAR_INSTRUCTION_OFFSET = 120
    DEFAULT_TEXT = "Unknown"

    def __init__(self, workspace: Workspace, addr: int, bytes_, parent=None) -> None:
        super().__init__(parent=parent)

        self.workspace = workspace
        self.addr = addr
        self.bytes = bytes_

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

    def paint(self, painter, option, widget) -> None:  # pylint: disable=unused-argument
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
    # Private methods
    #

    def _init_widgets(self) -> None:
        # Address
        self._addr_text = f"{self.addr:08x}"
        self._addr_item = QGraphicsSimpleTextItem(self._addr_text, self)
        self._addr_item.setBrush(Conf.disasm_view_node_address_color)
        self._addr_item.setFont(Conf.disasm_font)

        # Bytes
        self._byte_lines = []
        if self.bytes:
            line = ""
            for i, b in enumerate(self.bytes):
                line += f"{b:02x} "
                if i > 0 and (i + 1) % 16 == 0:
                    o = QGraphicsSimpleTextItem(line, self)
                    o.setFont(Conf.disasm_font)
                    o.setBrush(Conf.disasm_view_unprintable_byte_color)
                    self._byte_lines.append(o)
                    line = ""

                    if len(self._byte_lines) > 100:
                        o = QGraphicsSimpleTextItem("Remaining lines are omitted", self)
                        o.setFont(Conf.disasm_font)
                        o.setBrush(Conf.disasm_view_unprintable_byte_color)
                        self._byte_lines.append(o)
                        break

            if line:
                o = QGraphicsSimpleTextItem(line, self)
                o.setFont(Conf.disasm_font)
                o.setBrush(Conf.disasm_view_unprintable_byte_color)
                self._byte_lines.append(o)

        else:
            o = QGraphicsSimpleTextItem(QUnknownBlock.DEFAULT_TEXT, self)
            o.setBrush(Conf.disasm_view_unprintable_byte_color)
            o.setFont(Conf.disasm_font)
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
