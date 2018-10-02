
from PySide2.QtCore import Qt

from ...config import Conf
from .qgraph_object import QGraphObject


class QUnknownBlock(QGraphObject):

    LINEAR_INSTRUCTION_OFFSET = 120

    def __init__(self, workspace, addr, bytes_):

        super(QUnknownBlock, self).__init__()

        self.workspace = workspace
        self.addr = addr
        self.bytes = bytes_

        self._bytes_text = None
        self._addr_text = None
        self._addr_width = None
        self._bytes_width = None
        self._bytes_height = None

        self._init_widgets()

    #
    # Properties
    #

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

    #
    # Public methods
    #

    def paint(self, painter):

        x = self.x
        y = self.y

        # Address
        painter.setPen(Qt.black)
        painter.drawText(x, y + Conf.disasm_font_ascent, self._addr_text)
        x += self._addr_width

        x += self.LINEAR_INSTRUCTION_OFFSET

        # Content
        if self._bytes_text:
            for line in self._bytes_text:
                painter.drawText(x, y + Conf.disasm_font_ascent, line)
                y += Conf.disasm_font_height
        else:
            painter.drawText(x, y + Conf.disasm_font_ascent, "Unknown")

    #
    # Private methods
    #

    def _init_widgets(self):
        # Address
        self._addr_text = "%08x" % self.addr
        self._addr_width = Conf.disasm_font_width * len(self._addr_text)

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

            self._bytes_height = Conf.disasm_font_height * len(self._bytes_text)

        else:
            self._bytes_height = Conf.disasm_font_height

    def _update_size(self):
        self._height = self._bytes_height
        self._width = 20
