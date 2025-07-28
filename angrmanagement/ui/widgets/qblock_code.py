from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QPainter, QTextCursor, QTextDocument
from PySide6.QtWidgets import QGraphicsSceneMouseEvent, QGraphicsSimpleTextItem

from angrmanagement.config import Conf, ConfigurationManager

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.disassembly.info_dock import InfoDock
    from angrmanagement.ui.views import DisassemblyView

    from .block_code_objects import QBlockCodeObj


class QBlockCode(QCachedGraphicsItem):
    """
    Top-level code widget for a selection of text. Will construct an AST using
    QBlockCodeObj, mirroring the structure associated with the target object.
    This text is then rendered using a QTextDocument, with appropriate styles
    applied to it. Interaction events will be propagated to corresponding
    objects.
    """

    GRAPH_ADDR_SPACING = 20

    addr: int
    _addr_str: str
    obj: QBlockCodeObj
    _config: ConfigurationManager
    disasm_view: DisassemblyView
    infodock: InfoDock
    parent: Any

    def __init__(
        self,
        addr: int,
        obj: QBlockCodeObj,
        config: ConfigurationManager,
        disasm_view: DisassemblyView,
        instance: Instance,
        infodock: InfoDock,
        parent: Any = None,
    ) -> None:
        super().__init__(parent=parent)
        self.addr = addr
        self._addr_str = f"{self.addr:08x}"
        self.obj = obj
        self._width = 0
        self._height = 0
        self._config = config
        self.parent = parent
        self.instance = instance
        self.infodock = infodock
        self._disasm_view = disasm_view
        self._qtextdoc = QTextDocument()
        self._qtextdoc.setDefaultFont(self._config.disasm_font)
        self._qtextdoc.setDocumentMargin(0)

        self._addr_item = QGraphicsSimpleTextItem(self._addr_str, self)
        self._addr_item.setBrush(Conf.disasm_view_node_address_color)
        self._addr_item.setFont(Conf.disasm_font)

        self.update_document()
        self.setToolTip("Address: " + self._addr_str)

        self.refresh()

    def refresh(self) -> None:
        self._addr_item.setVisible(self._disasm_view.show_address)
        self._layout_items_and_update_size()

    def update_document(self) -> None:
        self._qtextdoc.clear()
        cur = QTextCursor(self._qtextdoc)
        self.obj.render_to_doc(cur)

    def paint(self, painter, option, widget=None) -> None:  # pylint: disable=unused-argument
        self.update_document()
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        painter.setFont(self._config.disasm_font)

        if self.infodock.is_instruction_selected(self.addr) or self.obj.should_highlight_line:
            highlight_color = Conf.disasm_view_node_instruction_selected_background_color
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

        x = 0

        if self._disasm_view.show_address:
            x += self._addr_item.boundingRect().width() + self.GRAPH_ADDR_SPACING

        painter.translate(QPointF(x, 0))
        self._qtextdoc.drawContents(painter)

    #
    # Event handlers
    #

    def get_obj_for_mouse_event(self, event: QGraphicsSceneMouseEvent) -> QBlockCodeObj | None:
        p = event.pos()

        if self._disasm_view.show_address:
            offset = self._addr_item.boundingRect().width() + self.GRAPH_ADDR_SPACING
            p.setX(p.x() - offset)

        if p.x() >= 0:
            hitpos = self._qtextdoc.documentLayout().hitTest(p, Qt.HitTestAccuracy.ExactHit)
            if hitpos >= 0:
                return self.obj.get_hit_obj(hitpos)

        return None

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.infodock.select_instruction(self.addr)

        obj = self.get_obj_for_mouse_event(event)
        if obj is not None:
            obj.mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        obj = self.get_obj_for_mouse_event(event)
        if obj is not None:
            obj.mouseDoubleClickEvent(event)

    #
    # Private methods
    #

    def _layout_items_and_update_size(self) -> None:
        self.update_document()

        x, y = 0, 0
        if self._disasm_view.show_address:
            self._addr_item.setPos(x, y)
            x += self._addr_item.boundingRect().width() + self.GRAPH_ADDR_SPACING

        x += self._qtextdoc.size().width()
        y += self._qtextdoc.size().height()
        self._width = x
        self._height = y
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
