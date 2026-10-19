from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QRectF, Qt
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf
from angrmanagement.present.block_tree.disasm_nodes import DATA_DELIMITER_STYLE, MemoryDataNode

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.memory_data import MemoryData

    from angrmanagement.data.instance import Instance


class QMemoryDataBlock(QCachedGraphicsItem):
    """
    A data item in the linear view: the text items of a MemoryDataNode.
    """

    ADDRESS_LABEL_OFFSET = 20
    LINEAR_INSTRUCTION_OFFSET = 120
    BYTE_AREA_SPACING = 15

    def __init__(
        self,
        instance: Instance,
        infodock,
        addr: int,
        memory_data,
        bytes_per_line: int = 16,
        parent=None,
        node: MemoryDataNode | None = None,
    ) -> None:
        super().__init__(parent=parent)
        #: the item's label and byte lines
        self.node = node if node is not None else MemoryDataNode(instance, infodock, addr, memory_data, bytes_per_line)
        self.instance = instance
        self.infodock = infodock
        self.addr = addr
        self.memory_data: MemoryData = memory_data
        self.bytes_per_line: int = bytes_per_line  # TODO: Move it to Conf

        self._addr_text = None
        self._width: float = 0.0
        self._height: float = 0.0

        self._bytes = []

        # widgets
        self._addr_item: QGraphicsSimpleTextItem | None = None
        self._label_item: QGraphicsSimpleTextItem | None = None
        self._line_items: list[
            tuple[int, QGraphicsSimpleTextItem, list[QGraphicsSimpleTextItem], list[QGraphicsSimpleTextItem]]
        ] = []

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

    def paint(self, painter, option, widget=None) -> None:
        should_highlight = self.node.selected

        highlight_color = Conf.disasm_view_label_highlight_color
        if should_highlight:
            painter.setBrush(highlight_color)
            painter.setPen(highlight_color)
            painter.drawRect(0, 0, self.width, self.height)

    def remove_children_from_scene(self):
        """
        Remove this item and all its children from the scene.
        """
        scene = self.scene()
        if scene is None:
            return

        if self._addr_item is not None:
            scene.removeItem(self._addr_item)
            self._addr_item = None

        if self._label_item is not None:
            scene.removeItem(self._label_item)
            self._label_item = None

        if self._line_items:
            for _, addr_item, bytes_line, characters_line in self._line_items:
                for byte_item in bytes_line:
                    scene.removeItem(byte_item)
                for char_item in characters_line:
                    scene.removeItem(char_item)
                scene.removeItem(addr_item)
            self._line_items = []

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            # select this label alone
            self.node.activate("left")
        elif event.button() == Qt.MouseButton.RightButton:
            # select this label alone, then show the context menu
            self.node.activate("right")
            self.infodock.disasm_view.label_context_menu(self.addr, event.screenPos())

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._addr_text = self.node.addr_text
        self._bytes = self.node.bytes

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
        lbl_text = self.node.label
        if lbl_text:
            self._label_item = QGraphicsSimpleTextItem(lbl_text, self)
            self._label_item.setFont(Conf.code_font)
            self._label_item.setBrush(Conf.disasm_view_label_color)
        else:
            if self._label_item is not None and (scene := self.scene()) is not None:
                scene.removeItem(self._label_item)
                self._label_item = None

    def _init_bytes(self) -> None:
        if self._line_items and (scene := self.scene()) is not None:
            # remove existing items
            for _, addr_item, bytes_list, character_list in self._line_items:
                scene.removeItem(addr_item)
                for item in bytes_list:
                    scene.removeItem(item)
                for line in character_list:
                    scene.removeItem(line)
            self._line_items = []

        self._line_items = []
        for addr_text, byte_offset, byte_parts, char_parts in self.node.rows:
            addr_item, bytes_list, character_list = self._init_line(addr_text, byte_parts, char_parts)
            self._line_items.append((byte_offset, addr_item, bytes_list, character_list))

    def _text_item(self, text: str, style: str) -> QGraphicsSimpleTextItem:
        item = QGraphicsSimpleTextItem(text, self)
        item.setBrush(Qt.GlobalColor.black if style == DATA_DELIMITER_STYLE else getattr(Conf, style))
        item.setFont(Conf.disasm_font)
        return item

    def _init_line(self, addr_text: str, byte_parts, char_parts):
        # address
        addr_item = self._text_item(addr_text, "disasm_view_node_address_color")
        # each byte, with a delimiter after every eighth, then the characters
        bytes_list = [self._text_item(text, style) for text, style in byte_parts]
        character_list = [self._text_item(ch, style) for ch, style in char_parts]
        return addr_item, bytes_list, character_list

    def _layout_items_and_update_size(self) -> None:
        x, y = 0, 0

        assert self._addr_item is not None

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
