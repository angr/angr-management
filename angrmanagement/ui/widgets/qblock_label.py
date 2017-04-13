
from PySide.QtGui import QPainter
from PySide.QtCore import Qt

from .qgraph_object import QGraphObject


class QBlockLabel(QGraphObject):
    def __init__(self, addr, text, config):
        super(QBlockLabel, self).__init__()

        self.addr = addr
        self.text = text

        self._config = config

    @property
    def label(self):
        return self.text

    @label.setter
    def label(self, v):
        self._clear_size()
        self.text = v

    @property
    def width(self):
        if self._width is None:
            self._update_size()
        return self._width

    @property
    def height(self):
        if self._height is None:
            self._update_size()
        return self._height

    def size(self):
        return self.width, self.height

    def paint(self, painter):
        """

        :param QPainter painter:
        :return:
        """
        painter.setPen(Qt.blue)
        painter.drawText(self.x, self.y + self._config.disasm_font_ascent, self.text)

    def _clear_size(self):
        self._width = None
        self._height = None

    def _update_size(self):
        self._width = self._config.disasm_font_width * len(self.text)
        self._height = self._config.disasm_font_height
