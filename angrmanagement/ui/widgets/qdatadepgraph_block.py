import logging
from typing import TYPE_CHECKING, Optional

from angr.analyses.data_dep import ConstantDepNode, TmpDepNode
from PySide6 import QtCore, QtGui, QtWidgets

from angrmanagement.config import Conf

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angr.analyses.data_dep import BaseDepNode
    from capstone import CsInsn

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

    def __init__(self, is_selected: bool, data_dep_view: "DataDepView", node: "BaseDepNode", instr: Optional["CsInsn"]):
        super().__init__()
        self.setFlags(QtWidgets.QGraphicsItem.ItemIsFocusable)

        self._selected = is_selected
        self._data_dep_view = data_dep_view
        self._workspace = self._data_dep_view.workspace
        self._node: BaseDepNode = node
        self._instr = instr

        self._header_text: Optional[str] = None
        self._instruction_text: Optional[str] = None
        self._y_off = 0  # Used to track height
        self._header_text_item: Optional[QtWidgets.QGraphicsSimpleTextItem] = None
        self._instruction_text_item: Optional[QtWidgets.QGraphicsSimpleTextItem] = None

        self._init_widgets()
        self._update_size()

        self.setAcceptHoverEvents(True)

    @property
    def selected(self) -> bool:
        return self._selected

    @selected.setter
    def selected(self, new_val: bool):
        self._selected = new_val
        self.update()

    @property
    def node(self) -> "BaseDepNode":
        return self._node

    def _build_simple_text_item(self, text: str) -> QtWidgets.QGraphicsSimpleTextItem:
        text_item = QtWidgets.QGraphicsSimpleTextItem(text, self)
        text_item.setFont(Conf.symexec_font)
        text_item.setBrush(QtCore.Qt.black)
        text_item.setPos(self.HORIZONTAL_PADDING, self.VERTICAL_PADDING + self._y_off)
        return text_item

    def _init_widgets(self):
        self._y_off = 0

        if not isinstance(self._node, ConstantDepNode):
            # ConstantDepNodes already display their value, by default
            self.setToolTip(f"Value: {hex(self._node.value)}")

        # Display the instruction, if applicable
        self._header_text = str(self._node)
        self._header_text_item = self._build_simple_text_item(self._header_text)
        self._y_off += self._header_text_item.boundingRect().height() + 3
        # Make header bold
        header_font = self._header_text_item.font()

        header_font.setBold(True)
        self._header_text_item.setFont(header_font)

        self._instruction_text = (
            f"{hex(self._instr.address)}: {self._instr.mnemonic} {self._instr.op_str}"
            if self._instr
            else f"{hex(self._node.ins_addr)}:{self._node.stmt_idx}"
        )  # TODO: Reset else to ''
        self._instruction_text_item = self._build_simple_text_item(self._instruction_text)
        if self._instruction_text:
            self._y_off += self._instruction_text_item.boundingRect().height() + 3

    def refresh(self):
        self._update_size()

    def _paint_boundary(self, painter: QtGui.QPainter):
        painter.setFont(Conf.symexec_font)

        # Pick background color based on node type
        if isinstance(self._node, ConstantDepNode):
            color = QDataDepGraphBlock.CONSTANT_BACKGROUND
        elif isinstance(self._node, TmpDepNode):
            color = QDataDepGraphBlock.TMP_BACKGROUND
        else:
            color = QDataDepGraphBlock.DEFAULT_BACKGROUND

        # If the node is selected, darken this color
        if self._selected:
            color = color.darker(150)
        painter.setBrush(color)

        border_color = QtGui.QColor(0, 254, 254) if self._selected else QtGui.QColor(240, 240, 240)
        painter.setPen(QtGui.QPen(border_color, 1.5))
        painter.drawRect(0, 0, self.width, self.height)

    def paint(
        self,
        painter: QtGui.QPainter,
        option: QtWidgets.QStyleOptionGraphicsItem,  # pylint: disable=unused-argument
        widget: Optional[QtWidgets.QWidget] = ...,
    ):  # pylint: disable=unused-argument
        self._paint_boundary(painter)

    def _boundingRect(self):
        return QtCore.QRectF(0, 0, self._width, self._height)

    def _update_size(self):
        max_text_item_width = max(
            self._header_text_item.boundingRect().width(),
            self._instruction_text_item.boundingRect().width(),
        )

        self._width = self.HORIZONTAL_PADDING * 2 + max_text_item_width
        self._height = self.VERTICAL_PADDING * 2 + self._y_off

        self._width = max(30, self._width)
        self._height = max(10, self._height)
        self.recalculate_size()

    #
    # Event Handlers
    #

    def mouseDoubleClickEvent(self, event: QtWidgets.QGraphicsSceneMouseEvent) -> None:
        if event.button() == QtCore.Qt.LeftButton and self._node.ins_addr:
            self._workspace.viz(self._node.ins_addr)

    def hoverEnterEvent(self, event: QtWidgets.QGraphicsSceneHoverEvent):
        self._selected = True
        self.refresh()
        self.setFocus(QtCore.Qt.MouseFocusReason)
        self.grabKeyboard()
        self._data_dep_view.hover_enter_block(self, event.modifiers())

    def hoverLeaveEvent(self, event: QtWidgets.QGraphicsSceneHoverEvent):  # pylint: disable=unused-argument
        self._selected = False
        self.refresh()
        self.ungrabKeyboard()
        self.clearFocus()
        self._data_dep_view.hover_leave_block()

    def contextMenuEvent(self, event: QtWidgets.QGraphicsSceneContextMenuEvent):
        ctxt_menu = QtWidgets.QMenu("")
        ctxt_menu.addAction("Trace backward", lambda: self._data_dep_view.use_subgraph(self, True))
        ctxt_menu.addAction("Trace forward", lambda: self._data_dep_view.use_subgraph(self, False))
        ctxt_menu.exec_(event.screenPos())

    def keyPressEvent(self, event: QtGui.QKeyEvent) -> None:
        """Handle change from ancestor to descendant tracing"""
        if self._selected and event.key() == QtCore.Qt.Key_Control:
            self._data_dep_view.update_descendants(self)
        else:
            super().keyPressEvent(event)

    def keyReleaseEvent(self, event: QtGui.QKeyEvent) -> None:
        """Handle change form descendant to ancestor tracing"""
        if self._selected and event.key() == QtCore.Qt.Key_Control:
            self._data_dep_view.update_ancestors(self)
        else:
            super().keyReleaseEvent(event)

    def mousePressEvent(self, event: QtWidgets.QGraphicsSceneMouseEvent):  # pylint:disable=no-self-use
        event.accept()
