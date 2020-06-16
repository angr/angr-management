from typing import TYPE_CHECKING
import logging

import PySide2.QtWidgets
from PySide2.QtGui import QColor, QPen
from PySide2.QtCore import Qt, QRectF

from ...config import Conf
from ...utils import locate_function
from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.ui.views.dep_view import DependencyView


_l = logging.getLogger(__name__)


class QDepGraphBlock(QCachedGraphicsItem):

    HORIZONTAL_PADDING = 5
    VERTICAL_PADDING = 5
    LINE_MARGIN = 3

    def __init__(self, is_selected, dep_view: 'DependencyView', addr: int):
        super().__init__()

        self._dep_view = dep_view
        self._workspace = self._dep_view.workspace
        self._config = Conf

        self.selected = is_selected

        # widgets
        self._label_str = None
        self._function_str = None

        self.addr = addr

        self._init_widgets()
        self._update_size()

        self.setAcceptHoverEvents(True)

    def _init_widgets(self):

        if self.addr is None:
            self._function_str = "Unknown"
            self._label_str = "Unknown"
        else:
            the_func = locate_function(self._workspace.instance, self.addr)
            if the_func is None:
                # is it a SimProcedure?
                if self._workspace.instance.project.is_hooked(self.addr):
                    hooker = self._workspace.instance.project.hooked_by(self.addr)
                    self._function_str = "SimProcedure " + hooker.__class__.__name__.split('.')[-1]
                else:
                    self._function_str = "Unknown"
            else:
                offset = self.addr - the_func.addr
                if not the_func.name:
                    self._function_str = "%#x%+x" % (the_func.addr, offset)
                else:
                    self._function_str = "%s%+x" % (the_func.name, offset)
            self._label_str = "%#x:   %s" % (self.addr, self._workspace.instance.get_instruction_text_at(self.addr))

        self._function_str = "Function: %s" % self._function_str

    #
    # Event handlers
    #

    def mousePressEvent(self, event): #pylint: disable=no-self-use
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        # _l.debug('QStateBlock received mouse release event')
        if event.button() == Qt.LeftButton:
            self.selected = not self.selected
            self._dep_view.redraw_graph()
            event.accept()

        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        # _l.debug('QStateBlock received mouse double click event')
        if event.button() == Qt.LeftButton:
            self._workspace.viz(self.addr)
            event.accept()

        super().mouseDoubleClickEvent(event)

    def hoverEnterEvent(self, event: PySide2.QtWidgets.QGraphicsSceneHoverEvent):
        self._dep_view.hover_enter_block(self)

    def hoverLeaveEvent(self, event: PySide2.QtWidgets.QGraphicsSceneHoverEvent):
        self._dep_view.hover_leave_block(self)

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        """
        Paint a state block on the scene.

        :param painter:
        :return: None
        """

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

        x = 0
        y = 0

        # The addr label
        addr_label_x = x + self.HORIZONTAL_PADDING
        addr_label_y = y + self.VERTICAL_PADDING
        painter.setPen(Qt.black)
        painter.drawText(addr_label_x, addr_label_y + self._config.symexec_font_ascent, self._label_str)

        y += self._config.symexec_font_height + self.LINE_MARGIN
        x = 0

        # The function label
        function_label_x = x + self.HORIZONTAL_PADDING
        function_label_y = y + self.VERTICAL_PADDING
        painter.drawText(function_label_x, function_label_y + self._config.symexec_font_ascent, self._function_str)

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    #
    # Private methods
    #

    def _update_size(self):
        width_candidates = [ self.HORIZONTAL_PADDING * 2 * self.currentDevicePixelRatioF() +
                             len(self._label_str) * self._config.symexec_font_width * self.currentDevicePixelRatioF(),
                             self.HORIZONTAL_PADDING * 2 * self.currentDevicePixelRatioF() +
                             len(self._function_str) * self._config.symexec_font_width * self.currentDevicePixelRatioF(),
                             ]
        height_candidates = [ 0 ]
        self._width = max(width_candidates)
        self._height = max(height_candidates)

        self._width = max(100, self._width)
        self._height = max(50, self._height)
