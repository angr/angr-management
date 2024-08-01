from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.proximity_graph import (
    BaseProxiNode,
    CallProxiNode,
    FunctionProxiNode,
    IntegerProxiNode,
    StringProxiNode,
    UnknownProxiNode,
    VariableProxiNode,
)
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QPen
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    import PySide6.QtWidgets

    from angrmanagement.ui.views.proximity_view import ProximityView


class QProximityGraphBlock(QCachedGraphicsItem):
    """
    Base Block
    """

    HORIZONTAL_PADDING = 5
    VERTICAL_PADDING = 5
    LINE_MARGIN = 3

    def __init__(self, is_selected: bool, proximity_view: ProximityView, node: BaseProxiNode) -> None:
        super().__init__()

        self._proximity_view = proximity_view
        self._workspace = self._proximity_view.workspace
        self._config = Conf

        self.selected = is_selected

        self._node = node

        #
        # Colors
        #
        self.FUNCTION_NODE_TEXT_COLOR = Conf.proximity_function_node_text_color
        self.STRING_NODE_TEXT_COLOR = Conf.proximity_string_node_text_color
        self.INTEGER_NODE_TEXT_COLOR = Conf.proximity_integer_node_text_color
        self.VARIABLE_NODE_TEXT_COLOR = Conf.proximity_variable_node_text_color
        self.UNKNOWN_NODE_TEXT_COLOR = Conf.proximity_unknown_node_text_color
        self.CALL_NODE_TEXT_COLOR = Conf.proximity_call_node_text_color
        self.CALL_NODE_TEXT_COLOR_PLT = Conf.proximity_call_node_text_color_plt
        self.CALL_NODE_TEXT_COLOR_SIMPROC = Conf.proximity_call_node_text_color_simproc

        self._init_widgets()
        self._update_size()

        self.setAcceptHoverEvents(True)

    def _init_widgets(self) -> None:
        pass

    def refresh(self) -> None:
        self._update_size()

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:  # pylint: disable=useless-super-delegation
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.selected = not self.selected
            self._proximity_view.redraw_graph()
            event.accept()

        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        # Jump to the reference address of the node
        if event.button() == Qt.MouseButton.LeftButton:
            if self._node.ref_at:
                self._workspace.viz(next(iter(self._node.ref_at)))
            event.accept()
            return

        super().mouseDoubleClickEvent(event)

    def hoverEnterEvent(
        self, event: PySide6.QtWidgets.QGraphicsSceneHoverEvent
    ) -> None:  # pylint:disable=unused-argument
        self._proximity_view.hover_enter_block(self)

    def hoverLeaveEvent(
        self, event: PySide6.QtWidgets.QGraphicsSceneHoverEvent
    ) -> None:  # pylint:disable=unused-argument
        self._proximity_view.hover_leave_block(self)

    def _paint_boundary(self, painter) -> None:
        painter.setFont(Conf.symexec_font)
        normal_background = Conf.proximity_node_background_color
        selected_background = Conf.proximity_node_selected_background_color
        border_color = Conf.proximity_node_border_color

        # The node background
        if self.selected:
            painter.setBrush(selected_background)
        else:
            painter.setBrush(normal_background)
        painter.setPen(QPen(border_color, 1.5))
        painter.drawRect(0, 0, self.width, self.height)

    def paint(self, painter, option, widget) -> None:  # pylint: disable=unused-argument
        """
        Paint a state block on the scene.

        :param painter:
        :return: None
        """

        self._paint_boundary(painter)

        x = 0
        y = 0

        x += self.HORIZONTAL_PADDING
        y += self.VERTICAL_PADDING

        # text
        # text_label_x = x
        # painter.setPen(Qt.gray)
        # painter.drawText(text_label_x, y + self._config.symexec_font_ascent, "Unknown block")

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    #
    # Private methods
    #

    def _update_size(self) -> None:
        self._width = 25
        self._height = 25
        self.recalculate_size()


class QProximityGraphFunctionBlock(QProximityGraphBlock):
    """
    Function Block
    """

    def __init__(self, is_selected: bool, proximity_view: ProximityView, node: FunctionProxiNode) -> None:
        self._text = None
        self._text_item: QGraphicsSimpleTextItem = None
        super().__init__(is_selected, proximity_view, node)

    def _init_widgets(self) -> None:
        self._text = f"Function {self._node.func.name}"
        self._text_item = QGraphicsSimpleTextItem(self._text, self)
        self._text_item.setFont(Conf.symexec_font)
        self._text_item.setBrush(self.FUNCTION_NODE_TEXT_COLOR)
        self._text_item.setPos(self.HORIZONTAL_PADDING, self.VERTICAL_PADDING)

    def mouseDoubleClickEvent(self, event) -> None:
        if (
            event.button() == Qt.MouseButton.LeftButton
            and (event.modifiers() & Qt.KeyboardModifier.ControlModifier) == Qt.KeyboardModifier.ControlModifier
        ):
            # ctrl + double click to collapse a function call
            event.accept()
            self._proximity_view.collapse_function(self._node.func)
            return

        super().mouseDoubleClickEvent(event)

    def paint(self, painter, option, widget) -> None:
        self._paint_boundary(painter)

    def _update_size(self) -> None:
        width_candidates = [
            self.HORIZONTAL_PADDING * 2 + self._text_item.boundingRect().width(),
        ]

        self._width = max(width_candidates)
        self._height = self.VERTICAL_PADDING * 2 + self._text_item.boundingRect().height()

        self._width = max(30, self._width)
        self._height = max(10, self._height)
        self.recalculate_size()


class QProximityGraphCallBlock(QProximityGraphBlock):
    """
    Call Block
    """

    def __init__(self, is_selected: bool, proximity_view: ProximityView, node: CallProxiNode) -> None:
        self._func_name: str = None
        self._args: list[tuple[type, str]] = None

        self._func_name_item: QGraphicsSimpleTextItem = None
        self._left_parenthesis_item: QGraphicsSimpleTextItem = None
        self._args_list: list[QGraphicsSimpleTextItem] = None
        self._right_parenthesis_item: QGraphicsSimpleTextItem = None

        super().__init__(is_selected, proximity_view, node)

    def _init_widgets(self) -> None:
        self._node: CallProxiNode
        self._func_name = self._node.callee.name
        if self._node.args is not None:
            self._args = [self._argument_text(arg) for arg in self._node.args]
        else:
            self._args = []

        # func name
        self._func_name_item = QGraphicsSimpleTextItem(self._func_name, self)
        if self._node.callee.is_simprocedure or self._node.callee.is_plt:
            pen_color = self.CALL_NODE_TEXT_COLOR_SIMPROC
        else:
            pen_color = self.CALL_NODE_TEXT_COLOR
        self._func_name_item.setBrush(pen_color)
        self._func_name_item.setFont(Conf.symexec_font)
        self._func_name_item.setPos(self.HORIZONTAL_PADDING, self.VERTICAL_PADDING)

        x = self.HORIZONTAL_PADDING + self._func_name_item.boundingRect().width()
        y = self.VERTICAL_PADDING
        # left parenthesis
        self._left_parenthesis_item = QGraphicsSimpleTextItem("(", self)
        self._left_parenthesis_item.setBrush(pen_color)
        self._left_parenthesis_item.setFont(Conf.symexec_font)
        self._left_parenthesis_item.setPos(x, y)

        x += self._left_parenthesis_item.boundingRect().width()

        # arguments
        self._args_list = []
        for i, (type_, arg) in enumerate(self._args):
            if type_ is StringProxiNode:
                color = self.STRING_NODE_TEXT_COLOR
            elif type_ is IntegerProxiNode:
                color = self.INTEGER_NODE_TEXT_COLOR
            elif type_ is VariableProxiNode:
                color = self.VARIABLE_NODE_TEXT_COLOR
            elif type_ is UnknownProxiNode:
                color = self.UNKNOWN_NODE_TEXT_COLOR
            else:
                color = self.CALL_NODE_TEXT_COLOR
            o = QGraphicsSimpleTextItem(arg, self)
            o.setBrush(color)
            o.setFont(Conf.symexec_font)
            o.setPos(x, y)
            self._args_list.append(o)
            x += o.boundingRect().width()

            # comma
            if i != len(self._args) - 1:
                comma = QGraphicsSimpleTextItem(", ", self)
                comma.setBrush(pen_color)
                comma.setFont(Conf.symexec_font)
                comma.setPos(x, y)
                self._args_list.append(comma)
                x += comma.boundingRect().width()

        # right parenthesis
        self._right_parenthesis_item = QGraphicsSimpleTextItem(")", self)
        self._right_parenthesis_item.setBrush(pen_color)
        self._right_parenthesis_item.setFont(Conf.symexec_font)
        self._right_parenthesis_item.setPos(x, y)

    def _argument_text(self, arg) -> tuple[type, str]:  # pylint: disable=no-self-use
        if isinstance(arg, StringProxiNode):
            return StringProxiNode, '"' + arg.content.decode("utf-8").replace("\n", "\\n") + '"'
        elif isinstance(arg, IntegerProxiNode):
            return IntegerProxiNode, str(arg.value)
        elif isinstance(arg, VariableProxiNode):
            return VariableProxiNode, str(arg.name)
        elif isinstance(arg, UnknownProxiNode):
            return UnknownProxiNode, str(arg.dummy_value)
        return object, "Unknown"

    def mouseDoubleClickEvent(self, event) -> None:
        if (
            event.button() == Qt.MouseButton.LeftButton
            and (event.modifiers() & Qt.KeyboardModifier.ControlModifier) == Qt.KeyboardModifier.ControlModifier
        ):
            # ctrl + double click to expand a function call
            event.accept()
            self._proximity_view.expand_function(self._node.callee)
            return

        super().mouseDoubleClickEvent(event)

    def paint(self, painter, option, widget) -> None:
        self._paint_boundary(painter)

    def _update_size(self) -> None:
        width_candidates = [
            self.HORIZONTAL_PADDING * 2
            + self._func_name_item.boundingRect().width()
            + self._left_parenthesis_item.boundingRect().width()
            + sum(x.boundingRect().width() for x in self._args_list)
            + self._right_parenthesis_item.boundingRect().width()
        ]

        self._width = max(width_candidates)
        self._height = self.VERTICAL_PADDING * 2 + self._func_name_item.boundingRect().height()

        self._width = max(30, self._width)
        self._height = max(10, self._height)
        self.recalculate_size()


class QProximityGraphStringBlock(QProximityGraphBlock):
    """
    String Block
    """

    def __init__(self, is_selected: bool, proximity_view: ProximityView, node: StringProxiNode) -> None:
        self._text = None
        self._text_item: QGraphicsSimpleTextItem = None
        super().__init__(is_selected, proximity_view, node)

    def _init_widgets(self) -> None:
        self._text = '"' + self._node.content.decode("utf-8") + '"'

        self._text_item = QGraphicsSimpleTextItem(self._text, self)
        self._text_item.setBrush(self.STRING_NODE_TEXT_COLOR)
        self._text_item.setFont(Conf.symexec_font)
        self._text_item.setPos(self.HORIZONTAL_PADDING, self.VERTICAL_PADDING)

    def paint(self, painter, option, widget) -> None:
        self._paint_boundary(painter)

    def _update_size(self) -> None:
        width_candidates = [
            self.HORIZONTAL_PADDING * 2 + self._text_item.boundingRect().width(),
        ]

        self._width = max(width_candidates)
        self._height = self.VERTICAL_PADDING * 2 + self._text_item.boundingRect().height()

        self._width = max(30, self._width)
        self._height = max(10, self._height)
        self.recalculate_size()
