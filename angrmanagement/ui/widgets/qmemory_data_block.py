import math
import string

from PySide2.QtCore import Qt, QRectF

from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort, MemoryData

from ...config import Conf
from .qgraph_object import QCachedGraphicsItem


class QMemoryDataBlock(QCachedGraphicsItem):

    LINEAR_INSTRUCTION_OFFSET = 120
    BYTE_SPACING = 6
    BYTE_AREA_SPACING = 25

    def __init__(self, workspace, addr, memory_data, bytes_per_line=16, parent=None, container=None):
        super().__init__(parent=parent, container=container)
        self.workspace = workspace
        self.addr = addr
        self.memory_data: MemoryData = memory_data
        self.bytes_per_line: int = bytes_per_line  # TODO: Move it to Conf

        self._addr_text = None
        self._addr_text_width = None
        self._width = None
        self._height = None

        self._bytes = [ ]
        self.byte_width = None
        self.character_width = None

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

    def paint(self, painter, option, widget):

        painter.setFont(Conf.disasm_font)
        painter.setPen(Qt.black)

        y = 0
        # label
        painter.drawText(0, y + Conf.disasm_font_ascent, self._addr_text)
        y += Conf.disasm_font_height

        # Content bytes
        addr = self.addr
        i = 0

        # print("Start from %#x" % addr)

        while i < len(self._bytes):
            byte_offset = addr % self.bytes_per_line
            if byte_offset == 0:
                end_pos = i + self.bytes_per_line
            else:
                end_pos = self.bytes_per_line - byte_offset

            all_bytes = self._bytes[i : end_pos]
            # print("... print %#x, %d bytes" % (addr, len(all_bytes)))
            self._paint_line(painter, 0, y, addr, byte_offset, all_bytes)

            addr += end_pos - i
            i = end_pos
            y += Conf.disasm_font_height

    def _paint_line(self, painter, x, y, addr, byte_offset, all_bytes):
        # address
        addr_text = "%08x" % addr

        painter.drawText(x, y + Conf.disasm_font_ascent, addr_text)
        x += Conf.disasm_font_metrics.width(addr_text) * self.currentDevicePixelRatioF()

        x += self.LINEAR_INSTRUCTION_OFFSET * self.currentDevicePixelRatioF()

        # skip byte_offset
        x += byte_offset * (self.byte_width + self.BYTE_SPACING * self.currentDevicePixelRatioF())

        # draw each byte
        for byt in all_bytes:
            painter.drawText(x, y + Conf.disasm_font_ascent, "%02x" % byt)
            x += self.byte_width + self.BYTE_SPACING * self.currentDevicePixelRatioF()

        if (len(all_bytes) + addr) % self.bytes_per_line != 0:
            more_chars = self.bytes_per_line - ((len(all_bytes) + addr) % self.bytes_per_line)
            x += more_chars * (self.byte_width + self.BYTE_SPACING * self.currentDevicePixelRatioF())

        x += self.BYTE_AREA_SPACING

        # draw printable characters
        x += byte_offset * self.character_width
        for byt in all_bytes:
            if self._is_printable(byt):
                ch = chr(byt)
            else:
                ch = "."
            painter.drawText(x, y + Conf.disasm_font_ascent, ch)
            x += self.character_width

    #
    # Private methods
    #

    @staticmethod
    def _is_printable(ch):
        return ch >= 32 and ch < 127

    def _init_widgets(self):

        self._addr_text = "%08x" % self.addr

        if self.memory_data.content:
            for byt in self.memory_data.content:
                self._bytes.append(byt)
            if len(self._bytes) < self.memory_data.size:
                # TODO: read more bytes from memory
                self._bytes += [0] * (self.memory_data.size - len(self._bytes))

        self._update_sizes()

    def _update_sizes(self):

        self.byte_width = Conf.disasm_font_metrics.width("aa") * self.currentDevicePixelRatioF()
        self.character_width = Conf.disasm_font_metrics.width("a") * self.currentDevicePixelRatioF()
        self._addr_text_width = Conf.disasm_font_metrics.width(self._addr_text) * self.currentDevicePixelRatioF()

        self._width = (self._addr_text_width +
                       self.LINEAR_INSTRUCTION_OFFSET * self.currentDevicePixelRatioF() +
                       self.bytes_per_line * (self.byte_width + self.BYTE_SPACING * self.currentDevicePixelRatioF()) +
                       self.BYTE_AREA_SPACING * self.currentDevicePixelRatioF() +
                       self.bytes_per_line * self.character_width
                       )
        lines = 1 + math.ceil(((self.addr + self.memory_data.size) - (self.addr - (self.addr % self.bytes_per_line))) / self.bytes_per_line)
        # print(hex(self.addr), self.memory_data.size, "lines:", lines)
        self._height = lines * Conf.disasm_font_height

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
