from typing import TYPE_CHECKING, Optional
import logging

import PySide2.QtWidgets
from PySide2.QtGui import QColor, QPen
from PySide2.QtCore import Qt, QRectF

from angr.analyses.proximity_graph import BaseProxiNode, FunctionProxiNode, CallProxiNode, StringProxiNode

from ...config import Conf
from ...utils import locate_function, get_string_for_display
from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.ui.views.proximity_view import ProximityView



_l = logging.getLogger(__name__)


class QProximityGraphBlock(QCachedGraphicsItem):

    HORIZONTAL_PADDING = 5
    VERTICAL_PADDING = 5
    LINE_MARGIN = 3

    #
    # Colors
    #

    FUNCTION_NODE_TEXT_COLOR = Qt.blue
    STRING_NODE_TEXT_COLOR = Qt.darkGreen
    CALL_NODE_TEXT_COLOR = Qt.darkBlue
    CALL_NODE_TEXT_COLOR_PLT = Qt.darkMagenta
    CALL_NODE_TEXT_COLOR_SIMPROC = Qt.darkMagenta

    def __init__(self, is_selected, proximity_view: 'ProximityView', node: 'BaseProxiNode'):
        super().__init__()

        self._proximity_view = proximity_view
        self._workspace = self._proximity_view.workspace
        self._config = Conf

        self.selected = is_selected

        self._node = node

        self._init_widgets()
        self._update_size()

        self.setAcceptHoverEvents(True)

    def _init_widgets(self):
        raise NotImplementedError()

    def refresh(self):
        self._update_size()

    #
    # Event handlers
    #

    def mousePressEvent(self, event): #pylint: disable=no-self-use
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.selected = not self.selected
            self._proximity_view.redraw_graph()
            event.accept()

        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        # Jump to the reference address of the node
        if event.button() == Qt.LeftButton:
            if self._node.ref_at:
                self._workspace.viz(next(iter(self._node.ref_at)))
            event.accept()
            return

        super().mouseDoubleClickEvent(event)

    def hoverEnterEvent(self, event: PySide2.QtWidgets.QGraphicsSceneHoverEvent):
        self._proximity_view.hover_enter_block(self)

    def hoverLeaveEvent(self, event: PySide2.QtWidgets.QGraphicsSceneHoverEvent):
        self._proximity_view.hover_leave_block(self)

    def _paint_boundary(self, painter):
        painter.setFont(Conf.symexec_font)
        normal_background = QColor(0xfa, 0xfa, 0xfa)
        selected_background = QColor(0xcc, 0xcc, 0xcc)

        # The node background
        if self.selected:
            painter.setBrush(selected_background)
        else:
            painter.setBrush(normal_background)
        painter.setPen(QPen(QColor(0xf0, 0xf0, 0xf0), 1.5))
        painter.drawRect(0, 0, self.width, self.height)

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
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

        # The text
        text_label_x = x
        painter.setPen(Qt.gray)
        painter.drawText(text_label_x, y + self._config.symexec_font_ascent, "Unknown block")

        painter.setPen(Qt.black)
        y += self._config.symexec_font_height + self.LINE_MARGIN
        x = 0

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    #
    # Private methods
    #

    def _update_size(self):
        fm = self._config.symexec_font_metrics
        dpr = self.currentDevicePixelRatioF()

        width_candidates = [
            self.HORIZONTAL_PADDING * 2 * dpr,
        ]

        self._width = max(width_candidates)
        self._height = self.VERTICAL_PADDING * 2 + (self.LINE_MARGIN + self._config.symexec_font_height) * 2
        self._height *= dpr

        self._width = max(100, self._width)
        self._height = max(50, self._height)

        self.recalculate_size()


class QProximityGraphFunctionBlock(QProximityGraphBlock):

    def __init__(self, is_selected, proximity_view: 'ProximityView', node: FunctionProxiNode):
        self._text = None
        super().__init__(is_selected, proximity_view, node)

    def _init_widgets(self):
        self._text = "Function %s" % self._node.func.name

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton and (event.modifiers() & Qt.ControlModifier) == Qt.ControlModifier:
            # ctrl + double click to collapse a function call
            event.accept()
            self._proximity_view.collapse_function(self._node.func)
            return

        super().mouseDoubleClickEvent(event)

    def paint(self, painter, option, widget):
        self._paint_boundary(painter)

        x = self.HORIZONTAL_PADDING
        y = self.VERTICAL_PADDING
        painter.setPen(self.FUNCTION_NODE_TEXT_COLOR)
        painter.drawText(x, y + self._config.symexec_font_ascent, self._text)

    def _update_size(self):
        fm = self._config.symexec_font_metrics
        dpr = self.currentDevicePixelRatioF()

        width_candidates = [
            (self.HORIZONTAL_PADDING * 2 + self._config.symexec_font_metrics.width(self._text)) * dpr,
        ]

        self._width = max(width_candidates)
        self._height = self.VERTICAL_PADDING * 2 + self._config.symexec_font_height
        self._height *= dpr

        self._width = max(30, self._width)
        self._height = max(10, self._height)

        self.recalculate_size()


class QProximityGraphCallBlock(QProximityGraphBlock):

    def __init__(self, is_selected, proximity_view: 'ProximityView', node: CallProxiNode):
        self._text = None
        super().__init__(is_selected, proximity_view, node)

    def _init_widgets(self):
        self._text = "%s()" % self._node.callee.name

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton and (event.modifiers() & Qt.ControlModifier) == Qt.ControlModifier:
            # ctrl + double click to expand a function call
            event.accept()
            self._proximity_view.expand_function(self._node.callee)
            return

        super().mouseDoubleClickEvent(event)

    def paint(self, painter, option, widget):
        self._paint_boundary(painter)

        x = self.HORIZONTAL_PADDING
        y = self.VERTICAL_PADDING
        if self._node.callee.is_simprocedure:
            pen_color = self.CALL_NODE_TEXT_COLOR_SIMPROC
        if self._node.callee.is_plt:
            pen_color = self.CALL_NODE_TEXT_COLOR_SIMPROC
        else:
            pen_color = self.CALL_NODE_TEXT_COLOR
        painter.setPen(pen_color)
        painter.drawText(x, y + self._config.symexec_font_ascent, self._text)

    def _update_size(self):
        fm = self._config.symexec_font_metrics
        dpr = self.currentDevicePixelRatioF()

        width_candidates = [
            (self.HORIZONTAL_PADDING * 2 + self._config.symexec_font_metrics.width(self._text)) * dpr,
        ]

        self._width = max(width_candidates)
        self._height = self.VERTICAL_PADDING * 2 + self._config.symexec_font_height
        self._height *= dpr

        self._width = max(30, self._width)
        self._height = max(10, self._height)

        self.recalculate_size()


class QProximityGraphStringBlock(QProximityGraphBlock):

    def __init__(self, is_selected, proximity_view: 'ProximityView', node: StringProxiNode):
        self._text = None
        super().__init__(is_selected, proximity_view, node)

    def _init_widgets(self):
        self._text = '"' + self._node.content.decode("utf-8") + '"'

    def paint(self, painter, option, widget):
        self._paint_boundary(painter)

        x = self.HORIZONTAL_PADDING
        y = self.VERTICAL_PADDING
        painter.setPen(self.STRING_NODE_TEXT_COLOR)
        painter.drawText(x, y + self._config.symexec_font_ascent, self._text)

    def _update_size(self):
        fm = self._config.symexec_font_metrics
        dpr = self.currentDevicePixelRatioF()

        width_candidates = [
            (self.HORIZONTAL_PADDING * 2 + self._config.symexec_font_metrics.width(self._text)) * dpr,
        ]

        self._width = max(width_candidates)
        self._height = self.VERTICAL_PADDING * 2 + self._config.symexec_font_height
        self._height *= dpr

        self._width = max(30, self._width)
        self._height = max(10, self._height)

        self.recalculate_size()
