from typing import List, Tuple, Type, TYPE_CHECKING, Optional
import logging

from PySide2 import QtWidgets, QtCore, QtGui

from angr.analyses.data_dependency import MemDepNode, VarDepNode, ConstantDepNode
from ...config import Conf
from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angr.analyses.data_dependency import BaseDepNode
    from angrmanagement.ui.views.data_dep_view import DataDepView

_l = logging.getLogger(__name__)


class QDataDepGraphBlock(QCachedGraphicsItem):
    """Represents a node in a QDataDepGraph, used to visualize a BaseDepNode"""

    HORIZONTAL_PADDING = 20
    VERTICAL_PADDING = 20
    LINE_MARGIN = 3

    DEFAULT_BACKGROUND = QtGui.QColor(0xB5, 0xF8, 0xFE)  # Blue
    CONSTANT_BACKGROUND = QtGui.QColor(0x87, 0xFF, 0x65)  # Green
    TMP_BACKGROUND = QtGui.QColor(0xEF, 0x47, 0x6F)  # Pink

    def __init__(self, is_selected: bool, data_dep_view: 'DataDepView', node: 'BaseDepNode'):
        super().__init__()
        self.setFlags(self.ItemIsFocusable | self.ItemIsMovable)

        self._selected = is_selected
        self._data_dep_view = data_dep_view
        self._workspace = self._data_dep_view.workspace
        self._node: 'BaseDepNode' = node

        self._text: Optional[str] = None
        self._text_item: Optional[QtWidgets.QGraphicsSimpleTextItem] = None

        self._init_widgets()
        self._update_size()

        self.setAcceptHoverEvents(True)

    @property
    def node(self) -> 'BaseDepNode':
        return self._node

    def _init_widgets(self):
        self._text = str(self._node)
        self._text_item = QtWidgets.QGraphicsSimpleTextItem(self._text, self)
        self._text_item.setFont(Conf.symexec_font)
        self._text_item.setBrush(QtCore.Qt.black)
        self._text_item.setPos(self.HORIZONTAL_PADDING, self.VERTICAL_PADDING)

    def refresh(self):
        self._update_size()

    def _paint_boundary(self, painter: QtGui.QPainter):
        painter.setFont(Conf.symexec_font)

        # Pick background color based on node type
        if isinstance(self._node, ConstantDepNode):
            color = QDataDepGraphBlock.CONSTANT_BACKGROUND
        elif isinstance(self._node, VarDepNode) and self._node.is_tmp:
            color = QDataDepGraphBlock.TMP_BACKGROUND
        else:
            color = QDataDepGraphBlock.DEFAULT_BACKGROUND

        # If the node is selected, darken this color
        if self._selected:
            color = color.darker(150)
        painter.setBrush(color)

        painter.setPen(QtGui.QPen(QtGui.QColor(0xf0, 0xf0, 0xf0), 1.5))
        painter.drawRect(0, 0, self.width, self.height)

    def paint(self, painter: QtGui.QPainter, option: QtWidgets.QStyleOptionGraphicsItem,
              widget: Optional[QtWidgets.QWidget] = ...) -> None:
        self._paint_boundary(painter)

    def _boundingRect(self):
        return QtCore.QRectF(0, 0, self._width, self._height)

    def _update_size(self):
        self._width = self.HORIZONTAL_PADDING * 2 + self._text_item.boundingRect().width()
        self._height = self.VERTICAL_PADDING * 2 + self._text_item.boundingRect().width()

        self._width = max(30, self._width)
        self._height = max(10, self._height)
        self.recalculate_size()

    #
    # Event Handlers
    #
    def hoverEnterEvent(self, event: QtWidgets.QGraphicsSceneHoverEvent):
        _l.warning("HoverEnterEvent called!")
        self._selected = True
        self.setFocus(QtCore.Qt.MouseFocusReason)
        self.grabKeyboard()
        self._data_dep_view.hover_enter_block(self, event.modifiers())

    def hoverLeaveEvent(self, event: QtWidgets.QGraphicsSceneHoverEvent):
        _l.warning("HoverLeaveEvent called!")
        self._selected = False
        self.ungrabKeyboard()
        self.clearFocus()
        self._data_dep_view.hover_leave_block()

    def contextMenuEvent(self, event: QtWidgets.QGraphicsSceneContextMenuEvent):
        ctxt_menu = QtWidgets.QMenu("")
        ctxt_menu.addAction("Trace backward", lambda: self._data_dep_view.use_subgraph(self))
        ctxt_menu.addAction("Trace forward", lambda: None)
        ctxt_menu.exec_(event.screenPos())

    def keyPressEvent(self, event: QtGui.QKeyEvent) -> None:
        """Handle change from ancestor to descendant tracing"""
        _l.warning("KeyPressEvent called with key: %r!", event.key())
        if self._selected and event.key() == QtCore.Qt.Key_Control:
            self._data_dep_view.update_descendants(self)
        else:
            super().keyPressEvent(event)

    def keyReleaseEvent(self, event: QtGui.QKeyEvent) -> None:
        """Handle change form descendant to ancestor tracing"""
        _l.warning("KeyReleaseEvent called!")
        if self._selected and event.key() == QtCore.Qt.Key_Control:
            self._data_dep_view.update_ancestors(self)
        else:
            super().keyReleaseEvent(event)

    def mousePressEvent(self, event: QtWidgets.QGraphicsSceneMouseEvent) -> None:
        event.accept()
