from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.config.config_manager import ConfigurationManager
    from angrmanagement.data.instance import Instance


class QFunctionCommentBanner(QCachedGraphicsItem):
    """
    The function comment, drawn as a header block above a function's first block.

    Collapses to zero height when the function has no comment, so a plain ``refresh()`` is enough
    to make it appear and disappear.
    """

    COMMENT_PREFIX = "; "

    def __init__(self, instance: Instance, func_addr: int, config: ConfigurationManager, parent=None) -> None:
        super().__init__(parent=parent)
        self.instance = instance
        self.func_addr = func_addr
        self._config = config

        self._text_items: list[QGraphicsSimpleTextItem] = []
        self._width = 0
        self._height = 0

        self._init_widgets()

    #
    # Public methods
    #

    def refresh(self) -> None:
        self._init_widgets()

    def setVisible(self, visible: bool) -> None:
        super().setVisible(visible)
        for item in self._text_items:
            item.setVisible(visible)

    def paint(self, painter, option, widget) -> None:
        pass

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        for item in self._text_items:
            item.setParentItem(None)
        self._text_items = []

        text = None
        if self.instance.kb is not None:
            text = self.instance.annotations.function_comment(self.func_addr)

        x, y = 0, 0
        if text:
            for line in text.split("\n"):
                item = QGraphicsSimpleTextItem(self.COMMENT_PREFIX + line, self)
                item.setFont(self._config.disasm_font)
                item.setBrush(self._config.disasm_view_comment_color)
                item.setPos(0, y)
                x = max(x, item.boundingRect().width())
                y += item.boundingRect().height()
                self._text_items.append(item)

        self._width = x
        self._height = y
        self.recalculate_size()

    def _boundingRect(self) -> QRectF:
        return QRectF(0, 0, self._width, self._height)
