from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class QAlignmentBlock(QCachedGraphicsItem):
    """Renders an alignment function as a single summary line in the linear disassembly view."""

    SPACING = 20

    def __init__(self, instance: Instance, addr: int, size: int, disasm_view, parent=None) -> None:
        super().__init__(parent=parent)

        self.instance = instance
        self.addr = addr
        self.size = size
        self.disasm_view = disasm_view

        self._width = 0
        self._height = 0

        self._addr_item: QGraphicsSimpleTextItem | None = None
        self._content_item: QGraphicsSimpleTextItem | None = None

        self._init_widgets()

    #
    # Public methods
    #

    def refresh(self) -> None:
        self._layout_items_and_update_size()

    def setVisible(self, visible) -> None:
        super().setVisible(visible)
        self._addr_item.setVisible(visible and self.disasm_view.show_address)
        self._content_item.setVisible(visible)

    def paint(self, painter, option, widget=None) -> None:  # pylint: disable=unused-argument
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

        if self._content_item is not None:
            scene.removeItem(self._content_item)
            self._content_item = None

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._addr_item = QGraphicsSimpleTextItem(f"{self.addr:08x}", self)
        self._addr_item.setBrush(Conf.disasm_view_node_address_color)
        self._addr_item.setFont(Conf.disasm_font)

        self._content_item = QGraphicsSimpleTextItem(f"[alignment_chunk]: {self.size:#x} bytes", self)
        self._content_item.setBrush(Conf.disasm_view_alignment_color)
        self._content_item.setFont(Conf.disasm_font)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self) -> None:
        x, y = 0, Conf.disasm_font_height

        if self.disasm_view.show_address:
            self._addr_item.setVisible(True)
            self._addr_item.setPos(x, y)
            x += self._addr_item.boundingRect().width()
            x += self.SPACING
        else:
            self._addr_item.setVisible(False)

        self._content_item.setPos(x, y)

        self._width = x + self._content_item.boundingRect().width()
        self._height = y + self._content_item.boundingRect().height()

        self.recalculate_size()
