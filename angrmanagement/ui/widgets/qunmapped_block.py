
from PySide.QtCore import Qt

from ...config import Conf
from .qgraph_object import QGraphObject


class QUnmappedBlock(QGraphObject):

    LINEAR_INSTRUCTION_OFFSET = 120

    def __init__(self, workspace, addr):

        super(QUnmappedBlock, self).__init__()

        self.workspace = workspace
        self.addr = addr

        self._addr_text = "%08x" % self.addr

        self._config = Conf

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
        painter.drawText(x, y + self._config.disasm_font_ascent, self._addr_text)

        x += self.LINEAR_INSTRUCTION_OFFSET

        # Content
        painter.drawText(x, y + self._config.disasm_font_ascent, "Unmapped")

    #
    # Private methods
    #

    def _update_size(self):
        self._height = self._config.disasm_font_height
        self._width = 20
