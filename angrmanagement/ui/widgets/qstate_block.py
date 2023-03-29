import logging

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QPen
from PySide6.QtWidgets import QGraphicsItem

from angrmanagement.config import Conf
from angrmanagement.utils import locate_function

_l = logging.getLogger(__name__)


class QStateBlock(QGraphicsItem):
    HORIZONTAL_PADDING = 5
    VERTICAL_PADDING = 5
    LINE_MARGIN = 3

    def __init__(self, is_selected, symexec_view, state=None, history=None):
        super().__init__()

        self.symexec_view = symexec_view
        self._instance = self.symexec_view.instance
        self._config = Conf

        self.state = state
        self.history = history
        if history is None and state is not None:
            self.history = state.history
        if history is not None and state is None:
            self.state = history.state
        self.selected = is_selected

        # widgets
        self._label_str = None
        self._function_str = None

        self.addr = None

        self._init_widgets()
        self._update_size()

    def get_state(self):
        if self.state is not None:
            return self.state
        elif self.history is not None:
            return self.history.state
        else:
            return None

    def _init_widgets(self):
        addr = None
        if self.state.regs._ip.symbolic:
            self._label_str = str(self.state.regs._ip)
        else:
            addr = self.state.regs._ip._model_concrete.value
            self._label_str = "%#x" % addr
        self._label_str = "State " + self._label_str

        self.addr = addr

        if addr is None:
            self._function_str = "Unknown"
        else:
            the_func = locate_function(self._instance, addr)
            if the_func is None:
                # is it a SimProcedure?
                if self._instance.project.is_hooked(addr):
                    hooker = self._instance.project.hooked_by(addr)
                    self._function_str = "SimProcedure " + hooker.__class__.__name__.split(".")[-1]
                else:
                    self._function_str = "Unknown"
            else:
                offset = addr - the_func.addr
                if not the_func.name:
                    self._function_str = f"{the_func.addr:#x}{offset:+x}"
                else:
                    self._function_str = f"{the_func.name}{offset:+x}"
        self._function_str = "Function: %s" % self._function_str

    def mousePressEvent(self, event):  # pylint: disable=no-self-use
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        # _l.debug('QStateBlock received mouse release event')
        if event.button() == Qt.LeftButton:
            self.selected = not self.selected
            self.symexec_view.redraw_graph()
            event.accept()

        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        # _l.debug('QStateBlock received mouse double click event')
        if event.button() == Qt.LeftButton:
            if self.state is not None:
                self.symexec_view.workspace.viz(self.state.addr)
                event.accept()
            elif self.history is not None:
                self.symexec_view_instance.workspace.viz(self.history.state.addr)
                event.accept()

        super().mouseDoubleClickEvent(event)

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        """
        Paint a state block on the scene.

        :param painter:
        :return: None
        """

        painter.setFont(Conf.symexec_font)
        normal_background = QColor(0xFA, 0xFA, 0xFA)
        selected_background = QColor(0xCC, 0xCC, 0xCC)

        # The node background
        if self.selected:
            painter.setBrush(selected_background)
        else:
            painter.setBrush(normal_background)
        painter.setPen(QPen(QColor(0xF0, 0xF0, 0xF0), 1.5))
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

    @property
    def height(self):
        return self.boundingRect().height()

    @property
    def width(self):
        return self.boundingRect().width()

    def boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    #
    # Private methods
    #

    def _update_size(self):
        width_candidates = [
            self.HORIZONTAL_PADDING * 2 + len(self._label_str) * self._config.symexec_font_width,
            self.HORIZONTAL_PADDING * 2 + len(self._function_str) * self._config.symexec_font_width,
        ]
        height_candidates = [0]
        self._width = max(width_candidates)
        self._height = max(height_candidates)

        self._width = max(100, self._width)
        self._height = max(50, self._height)
