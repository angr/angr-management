
from PySide2.QtWidgets import QGraphicsItem, QGraphicsTextItem
from PySide2.QtGui import QPainter
from PySide2.QtCore import Qt, QRectF

from .qgraph_object import QCachedGraphicsItem


class QBlockLabel(QCachedGraphicsItem):

    def __init__(self, addr, text, config, disasm_view, workspace, parent=None):
        super().__init__(parent=parent)

        self.workspace = workspace
        self.addr = addr
        self.text = text
        # TODO: Reimplement me
        # self.workspace.instance.subscribe_to_selected_label(lambda *args, **kwargs: self.update())

        self._config = config
        self._disasm_view = disasm_view

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.code_font)

        # TODO: Reimplement selected_label
        # if self.workspace.instance.selected_label == self.addr:
        #     painter.setBrush(Qt.magenta)
        #     painter.setPen(Qt.magenta)
        #     painter.drawRect(0, 0, self.width, self.height)
        painter.setPen(Qt.blue)
        painter.drawText(0, self._config.disasm_font_ascent, self.text)

    def _boundingRect(self):
        return QRectF(0, 0, self._config.disasm_font_metrics.width(self.text), self._config.disasm_font_height)
