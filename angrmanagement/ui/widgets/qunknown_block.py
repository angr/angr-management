
from PySide2.QtCore import Qt

from ...config import Conf
from .qgraph_object import QCachedGraphicsItem
from PySide2.QtWidgets import QGraphicsItem
from PySide2.QtCore import QRectF
from PySide2.QtGui import QPainter


class QUnknownBlock(QCachedGraphicsItem):

    LINEAR_INSTRUCTION_OFFSET = 120
    DEFAULT_TEXT = 'Unknown'

    def __init__(self, workspace, addr, bytes_, parent=None, container=None):
        super().__init__(parent=parent, container=container)

        self.workspace = workspace
        self.addr = addr
        self.bytes = bytes_

        self._bytes_text = None
        self._addr_text = None
        self._addr_width = None
        self._bytes_width = None
        self._bytes_height = None

        self._config = Conf

        self._init_widgets()

    #
    # Public methods
    #

    @property
    def width(self):
        return self.boundingRect().width()

    @property
    def height(self):
        return self.boundingRect().height()

    def paint(self, painter, option, widget): #pylint: disable=unused-argument

        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.disasm_font)

        x, y = 0, 0

        # Address
        painter.setPen(Qt.black)
        painter.drawText(x, y+Conf.disasm_font_ascent, self._addr_text)
        x += self._addr_width

        x += self.LINEAR_INSTRUCTION_OFFSET * self.currentDevicePixelRatioF()

        # Content
        if self._bytes_text:
            for line in self._bytes_text:
                painter.drawText(x, y+Conf.disasm_font_ascent, line)
                y += Conf.disasm_font_height * self.currentDevicePixelRatioF()
        else:
            painter.drawText(x, y+Conf.disasm_font_ascent, QUnknownBlock.DEFAULT_TEXT)

    def _boundingRect(self):
        height, width = 0, 0

        width += self._addr_width
        width += self.LINEAR_INSTRUCTION_OFFSET

        if self._bytes_text:
            height += Conf.disasm_font_height * len(self._bytes_text) * self.currentDevicePixelRatioF()
        else:
            height += Conf.disasm_font_height * self.currentDevicePixelRatioF()

        if self._bytes_text:
            width += max(len(line) for line in self._bytes_text) * Conf.disasm_font_width * self.currentDevicePixelRatioF()
        else:
            width += Conf.disasm_font_metrics.width(QUnknownBlock.DEFAULT_TEXT) * self.currentDevicePixelRatioF()
        return QRectF(0, 0, width, height)

    #
    # Private methods
    #

    def _init_widgets(self):
        # Address
        self._addr_text = "%08x" % self.addr
        self._addr_width = Conf.disasm_font_width * len(self._addr_text) * self.currentDevicePixelRatioF()

        # Bytes
        if self.bytes:
            self._bytes_text = [ ]
            line = ""
            for i, b in enumerate(self.bytes):
                line += "%02x " % b
                if i > 0 and (i + 1) % 16 == 0:
                    self._bytes_text.append(line)
                    line = ""

            if line:
                self._bytes_text.append(line)

            self._bytes_height = Conf.disasm_font_height * len(self._bytes_text) * self.currentDevicePixelRatioF()

        else:
            self._bytes_height = Conf.disasm_font_height * self.currentDevicePixelRatioF()
