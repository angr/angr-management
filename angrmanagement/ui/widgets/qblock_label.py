from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class QBlockLabel(QCachedGraphicsItem):
    def __init__(self, addr: int, text: str, config, disasm_view, instance: Instance, infodock, parent=None) -> None:
        super().__init__(parent=parent)

        self.instance = instance
        self.addr = addr
        self.text = text
        self._width = 0
        self._height = 0
        self.infodock = infodock

        self._config = config
        self._disasm_view = disasm_view

        self._text_item: QGraphicsSimpleTextItem = None

        self._init_widgets()

    def paint(self, painter, option, widget) -> None:  # pylint: disable=unused-argument
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        painter.setFont(self._config.code_font)

        # background
        if self.infodock.is_label_selected(self.addr):
            highlight_color = Conf.disasm_view_label_highlight_color
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.infodock.select_label(self.addr)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._text_item = QGraphicsSimpleTextItem(self.text, self)
        self._text_item.setBrush(Conf.disasm_view_label_color)
        self._text_item.setFont(self._config.disasm_font)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self) -> None:
        self._text_item.setPos(0, 0)

        self._width = self._text_item.boundingRect().width()
        self._height = self._text_item.boundingRect().height()
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
