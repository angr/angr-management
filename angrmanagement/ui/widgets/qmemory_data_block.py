from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF, Qt
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf
from angrmanagement.utils import get_label_text, is_printable

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.memory_data import MemoryData

    from angrmanagement.data.instance import Instance


class QMemoryDataBlock(QCachedGraphicsItem):
    ADDRESS_LABEL_OFFSET = 20
    LINEAR_INSTRUCTION_OFFSET = 120
    BYTE_AREA_SPACING = 15

    def __init__(
        self, instance: Instance, infodock, addr: int, memory_data, bytes_per_line: int = 16, parent=None
    ) -> None:
        super().__init__(parent=parent)
        self.instance = instance
        self.infodock = infodock
        self.addr = addr
        self.memory_data: MemoryData = memory_data
        self.bytes_per_line: int = bytes_per_line  # TODO: Move it to Conf

        self._addr_text = None
        self._width = None
        self._height = None

        self._bytes = []

        # widgets
        self._addr_item: QGraphicsSimpleTextItem = None
        self._label_item: QGraphicsSimpleTextItem | None = None
        self._line_items: list[
            tuple[int, QGraphicsSimpleTextItem, list[QGraphicsSimpleTextItem], list[QGraphicsSimpleTextItem]]
        ] = None

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

    def paint(self, painter, option, widget) -> None:
        should_highlight = self.infodock.is_label_selected(self.addr)

        highlight_color = Conf.disasm_view_label_highlight_color
        if should_highlight:
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            # unselect all other labels
            self.infodock.unselect_all_labels()
            # select this label
            self.infodock.select_label(self.addr)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._addr_text = f"{self.addr:08x}"
        self._bytes = []
        if self.memory_data.content:
            cnt = self.memory_data.content
            if self.memory_data.size is not None:
                cnt = cnt[: self.memory_data.size]
            self._bytes += list(cnt)

        if self.memory_data.size is not None and len(self._bytes) < self.memory_data.size:
            # load more from mapped memory
            start_address = self.memory_data.addr + len(self._bytes)
            size = self.memory_data.size - len(self._bytes)
            try:
                mem_bytes = self.instance.project.loader.memory.load(start_address, size)
            except KeyError:
                mem_bytes = b""
            self._bytes += list(mem_bytes) + ["??"] * (size - len(mem_bytes))

        # address
        self._addr_item = QGraphicsSimpleTextItem(self._addr_text, self)
        self._addr_item.setFont(Conf.disasm_font)
        self._addr_item.setBrush(Conf.disasm_view_node_address_color)

        # label
        self._init_label_item()

        # bytes
        self._init_bytes()

        self._layout_items_and_update_size()

    def _init_label_item(self) -> None:
        lbl_text = get_label_text(self.addr, self.instance.kb)
        if lbl_text:
            self._label_item = QGraphicsSimpleTextItem(lbl_text, self)
            self._label_item.setFont(Conf.code_font)
            self._label_item.setBrush(Conf.disasm_view_label_color)
        else:
            if self._label_item is not None:
                self._label_item.setParentItem(None)
                self._label_item = None

    def _init_bytes(self) -> None:
        if self._line_items:
            # remove existing items
            for line in self._line_items:
                for item in line:
                    item.setParentItem(None)
            self._line_items = None

        addr = self.addr
        i = 0
        self._line_items = []

        while i < len(self._bytes):
            byte_offset = addr % self.bytes_per_line
            end_pos = i + self.bytes_per_line if byte_offset == 0 else self.bytes_per_line - byte_offset

            all_bytes = self._bytes[i:end_pos]
            # print("... print %#x, %d bytes, byte_offset %d" % (addr, len(all_bytes), byte_offset))
            addr_item, bytes_list, character_list = self._init_line(addr, byte_offset, all_bytes)
            self._line_items.append((byte_offset, addr_item, bytes_list, character_list))

            addr += end_pos - i
            i = end_pos

    def _init_line(self, addr: int, byte_offset, all_bytes):
        # colors
        printable_byte_color = Conf.disasm_view_printable_byte_color
        printable_char_color = Conf.disasm_view_printable_character_color
        unprintable_byte_color = Conf.disasm_view_unprintable_byte_color
        unprintable_char_color = Conf.disasm_view_unprintable_character_color
        unknown_byte_color = Conf.disasm_view_unknown_byte_color
        unknown_char_color = Conf.disasm_view_unknown_character_color

        # address
        addr_text = f"{addr:08x}"
        addr_item = QGraphicsSimpleTextItem(addr_text, self)
        addr_item.setBrush(Conf.disasm_view_node_address_color)
        addr_item.setFont(Conf.disasm_font)

        # draw each byte
        bytes_list = []
        for idx, byt in enumerate(all_bytes):
            if isinstance(byt, int):
                color = printable_byte_color if is_printable(byt) else unprintable_byte_color
                o = QGraphicsSimpleTextItem(f"{byt:02x}", self)
                o.setFont(Conf.disasm_font)
                o.setBrush(color)
            else:  # str, usually because it is an unknown byte, in which case the str is "??"
                o = QGraphicsSimpleTextItem(byt, self)
                o.setBrush(unknown_byte_color)
                o.setFont(Conf.disasm_font)
            bytes_list.append(o)

            line_chars = byte_offset + idx + 1  # the number of existing characters on this line, including spaces
            if line_chars % 8 == 0 and line_chars != self.bytes_per_line:
                # print a deliminator
                o = QGraphicsSimpleTextItem("-", self)
                o.setBrush(Qt.GlobalColor.black)
                o.setFont(Conf.disasm_font)
                bytes_list.append(o)

        # printable characters
        character_list = []
        for byt in all_bytes:
            if isinstance(byt, int):
                if is_printable(byt):
                    color = printable_char_color
                    ch = chr(byt)
                else:
                    color = unprintable_char_color
                    ch = "."
            else:
                color = unknown_char_color
                ch = "?"
            o = QGraphicsSimpleTextItem(ch, self)
            o.setBrush(color)
            o.setFont(Conf.disasm_font)
            character_list.append(o)

        return addr_item, bytes_list, character_list

    def _layout_items_and_update_size(self) -> None:
        x, y = 0, 0

        #
        # first line
        #

        # address
        self._addr_item.setPos(x, y)
        x += self._addr_item.boundingRect().width()

        # label
        if self._label_item:
            x += self.ADDRESS_LABEL_OFFSET
            self._label_item.setPos(x, y)

        #
        # the following lines: content
        #

        max_x = x
        x = 0
        y += self._addr_item.boundingRect().height()

        for byte_offset, addr_item, bytes_line, characters_line in self._line_items:
            addr_item.setPos(x, y)
            x += addr_item.boundingRect().width() + self.LINEAR_INSTRUCTION_OFFSET

            # skip byte offset
            byte_width = bytes_line[0].boundingRect().width()
            byte_spacing = byte_width // 2
            x += byte_offset * (byte_width + byte_spacing)

            all_bytes = 0
            pos = 0
            while pos < len(bytes_line):
                byte_ = bytes_line[pos]
                byte_.setPos(x, y)
                x += byte_width

                line_chars = (
                    byte_offset + all_bytes + 1
                )  # the number of existing characters on this line, including spaces
                if line_chars % 8 == 0 and line_chars != self.bytes_per_line:
                    # now we get a delimiter
                    pos += 1
                    delimiter = bytes_line[pos]
                    delimiter.setPos(x, y)

                x += byte_spacing
                pos += 1
                all_bytes += 1

            if (byte_offset + all_bytes) % self.bytes_per_line != 0:
                more_chars = self.bytes_per_line - (byte_offset + all_bytes % self.bytes_per_line)
                x += more_chars * (byte_width + byte_spacing)

            x += self.BYTE_AREA_SPACING

            # printable characters
            character_width = characters_line[0].boundingRect().width()
            x += byte_offset * character_width
            for o in characters_line:
                o.setPos(x, y)
                x += character_width

            max_x = max(x, max_x)

            # next line!
            x = 0
            y += bytes_line[0].boundingRect().height()

        self._width = max_x
        self._height = y
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
