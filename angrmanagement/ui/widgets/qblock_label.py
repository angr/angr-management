from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QBrush, QPainter
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf
from angrmanagement.present.block_tree.disasm_nodes import LabelNode

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class QBlockLabel(QCachedGraphicsItem):
    """
    A label line on the scene: the text items of a LabelNode.
    """

    ADDR_SPACING = 10

    def __init__(
        self,
        addr: int,
        text: str,
        config,
        disasm_view,
        instance: Instance,
        infodock,
        parent=None,
        node: LabelNode | None = None,
    ) -> None:
        super().__init__(parent=parent)
        #: the label's text
        self.node = node if node is not None else LabelNode(addr, text, infodock)

        self.instance = instance
        self.addr = addr
        self.text = text
        self._width = 0
        self._height = 0
        self.infodock = infodock

        self._config = config
        self._disasm_view = disasm_view

        self._addr_item: QGraphicsSimpleTextItem = None
        self._text_item: QGraphicsSimpleTextItem = None

        self._init_widgets()

    def setVisible(self, visible):
        super().setVisible(visible)
        self._addr_item.setVisible(visible and self._disasm_view.show_address)
        self._text_item.setVisible(visible)

    def refresh(self):
        self._layout_items_and_update_size()

    def paint(self, painter, option, widget) -> None:  # pylint: disable=unused-argument
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        painter.setFont(self._config.code_font)

        # background
        if self.node.selected:
            highlight_color = Conf.disasm_view_label_highlight_color
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.node.activate("left")
        elif event.button() == Qt.MouseButton.RightButton:
            # select this label alone, then show the context menu
            self.node.activate("right")
            self.infodock.disasm_view.label_context_menu(self.addr, event.screenPos())

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        # address
        self._addr = self.node.addr_text
        self._addr_item = QGraphicsSimpleTextItem(self)
        self._addr_item.setBrush(QBrush(self._config.disasm_view_node_address_color))
        self._addr_item.setFont(self._config.disasm_font)
        self._addr_item.setText(self._addr)

        self._text_item = QGraphicsSimpleTextItem(self.node.text, self)
        self._text_item.setBrush(Conf.disasm_view_label_color)
        self._text_item.setFont(self._config.disasm_font)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self) -> None:

        x, y = 0, 0

        # address
        if self._disasm_view.show_address:
            self._addr_item.setVisible(True)
            self._addr_item.setPos(x, y)
            x += self._addr_item.boundingRect().width() + self.ADDR_SPACING
        else:
            self._addr_item.setVisible(False)

        self._text_item.setPos(x, y)

        self._width = x + self._text_item.boundingRect().width()
        self._height = self._text_item.boundingRect().height()
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
