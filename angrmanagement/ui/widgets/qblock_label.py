
from PySide2.QtGui import QPainter
from PySide2.QtCore import Qt, QRectF

from ...config import Conf
from .qgraph_object import QCachedGraphicsItem


class QBlockLabel(QCachedGraphicsItem):

    def __init__(self, addr, text, config, disasm_view, workspace, infodock, parent=None, container=None):
        super().__init__(parent=parent, container=container)

        self.workspace = workspace
        self.addr = addr
        self.text = text
        self.infodock = infodock

        self._config = config
        self._disasm_view = disasm_view

    def paint(self, painter, option, widget):  #pylint: disable=unused-argument
        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.code_font)

        if self.infodock.is_label_selected(self.addr):
            highlight_color = Conf.disasm_view_label_highlight_color
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

        painter.setPen(Qt.blue)
        painter.drawText(0, self._config.disasm_font_ascent, self.text)

    #
    # Event handlers
    #

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.infodock.select_label(self.addr)

    #
    # Private methods
    #

    def _boundingRect(self):
        width = self._config.disasm_font_metrics.width(self.text) * self.currentDevicePixelRatioF()
        height = self._config.disasm_font_height * self.currentDevicePixelRatioF()
        return QRectF(0, 0, width, height)
