import math
import string

from PySide2.QtCore import Qt, QRectF
from PySide2.QtGui import QColor

from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort, MemoryData

from ...utils import get_label_text
from ...config import Conf
from .qgraph_object import QCachedGraphicsItem


class QMemoryDataBlock(QCachedGraphicsItem):

    ADDRESS_LABEL_OFFSET = 20
    LINEAR_INSTRUCTION_OFFSET = 120
    BYTE_AREA_SPACING = 15

    def __init__(self, workspace, infodock, addr, memory_data, bytes_per_line=16, parent=None, container=None):
        super().__init__(parent=parent, container=container)
        self.workspace = workspace
        self.infodock = infodock
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

        should_highlight = self.infodock.is_label_selected(self.addr)

        x, y = 0, 0

        highlight_color = Conf.disasm_view_label_highlight_color
        if should_highlight:
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

        # address
        painter.setFont(Conf.disasm_font)
        painter.setPen(Qt.black)
        painter.drawText(x, y + Conf.disasm_font_ascent, self._addr_text)
        x += self._addr_text_width
        # label
        x += self.ADDRESS_LABEL_OFFSET * self.currentDevicePixelRatioF()
        lbl_text = get_label_text(self.addr, self.workspace.instance.kb)
        if lbl_text:
            painter.setFont(Conf.code_font)
            painter.setPen(Qt.blue)
            painter.drawText(x, y + Conf.disasm_font_ascent, lbl_text)

        painter.setFont(Conf.disasm_font)

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

        # colors
        printable_byte_color = Conf.disasm_view_printable_byte_color
        printable_char_color = Conf.disasm_view_printable_character_color
        unprintable_byte_color = Conf.disasm_view_unprintable_byte_color
        unprintable_char_color = Conf.disasm_view_unprintable_character_color
        unknown_byte_color = Conf.disasm_view_unknown_byte_color
        unknown_char_color = Conf.disasm_view_unknown_character_color

        # address
        addr_text = "%08x" % addr

        painter.setPen(Qt.black)
        painter.drawText(x, y + Conf.disasm_font_ascent, addr_text)
        x += Conf.disasm_font_metrics.width(addr_text) * self.currentDevicePixelRatioF()

        x += self.LINEAR_INSTRUCTION_OFFSET * self.currentDevicePixelRatioF()

        # skip byte_offset
        x += byte_offset * (self.byte_width + self.byte_spacing)

        # draw each byte
        for idx, byt in enumerate(all_bytes):
            if type(byt) is int:
                if self._is_printable(byt):
                    painter.setPen(printable_byte_color)
                else:
                    painter.setPen(unprintable_byte_color)
                painter.drawText(x, y + Conf.disasm_font_ascent, "%02x" % byt)
            else:  # str, usually because it is an unknown byte, in which case the str is "??"
                painter.setPen(unknown_byte_color)
                painter.drawText(x, y + Conf.disasm_font_ascent, byt)
            x += self.byte_width
            line_chars = byte_offset + idx + 1  # the number of existing characters on this line, including spaces
            if line_chars % 8 == 0 and line_chars != self.bytes_per_line:
                # print a deliminator
                painter.setPen(Qt.black)
                painter.drawText(x, y + Conf.disasm_font_ascent, "-")
            x += self.byte_spacing

        if (len(all_bytes) + addr) % self.bytes_per_line != 0:
            more_chars = self.bytes_per_line - ((len(all_bytes) + addr) % self.bytes_per_line)
            x += more_chars * (self.byte_width + self.byte_spacing)

        x += self.BYTE_AREA_SPACING

        # draw printable characters
        x += byte_offset * self.character_width
        for byt in all_bytes:
            if type(byt) is int:
                if self._is_printable(byt):
                    painter.setPen(printable_char_color)
                    ch = chr(byt)
                else:
                    painter.setPen(unprintable_char_color)
                    ch = "."
            else:
                painter.setPen(unknown_char_color)
                ch = "?"
            painter.drawText(x, y + Conf.disasm_font_ascent, ch)
            x += self.character_width

    #
    # Event handlers
    #

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            # unselect all other labels
            self.infodock.unselect_all_labels()
            # select this label
            self.infodock.select_label(self.addr)

    #
    # Private methods
    #

    @staticmethod
    def _is_printable(ch):
        return ch >= 32 and ch < 127

    def _init_widgets(self):

        self._addr_text = "%08x" % self.addr

        self._bytes = [ ]
        if self.memory_data.content:
            for byt in self.memory_data.content:
                self._bytes.append(byt)

        if len(self._bytes) < self.memory_data.size:
            # load more from mapped memory
            start_address = self.memory_data.addr + len(self._bytes)
            size = self.memory_data.size - len(self._bytes)
            try:
                mem_bytes = self.workspace.instance.project.loader.memory.load(start_address, size)
            except KeyError:
                mem_bytes = b""
            self._bytes += [ b for b in mem_bytes ] + [ '??' ] * (size - len(mem_bytes))

        self._update_sizes()

    def _update_sizes(self):

        self.byte_width = Conf.disasm_font_metrics.width("aa") * self.currentDevicePixelRatioF()
        self.byte_spacing = Conf.disasm_font_metrics.width("-") * self.currentDevicePixelRatioF()
        self.character_width = Conf.disasm_font_metrics.width("a") * self.currentDevicePixelRatioF()
        self._addr_text_width = Conf.disasm_font_metrics.width(self._addr_text) * self.currentDevicePixelRatioF()

        self._width = (self._addr_text_width +
                       self.LINEAR_INSTRUCTION_OFFSET * self.currentDevicePixelRatioF() +
                       self.bytes_per_line * (self.byte_width + self.byte_width * self.currentDevicePixelRatioF()) +
                       self.BYTE_AREA_SPACING * self.currentDevicePixelRatioF() +
                       self.bytes_per_line * self.character_width
                       )
        lines = 1 + math.ceil(((self.addr + self.memory_data.size) - (self.addr - (self.addr % self.bytes_per_line))) / self.bytes_per_line)
        # print(hex(self.addr), self.memory_data, self.memory_data.size, "lines:", lines)
        self._height = lines * Conf.disasm_font_height

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
