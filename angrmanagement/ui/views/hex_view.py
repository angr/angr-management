from typing import Sequence, Union, Optional, Tuple, Callable
import logging

import PySide2
from PySide2.QtWidgets import QApplication, QHBoxLayout, QMainWindow, QVBoxLayout, QFrame, QGraphicsView, \
    QGraphicsScene, QGraphicsItem, QGraphicsObject, QGraphicsSimpleTextItem, \
    QGraphicsSceneMouseEvent, QLabel, QMenu, QPushButton, QAction
from PySide2.QtGui import QPainterPath, QPen, QFont, QColor, QWheelEvent, QCursor
from PySide2.QtCore import Qt, QRectF, QPointF, QSizeF, Signal, QEvent, QMarginsF, QTimer

from angr import Block
from angr.knowledge_plugins.cfg import MemoryData

from .view import SynchronizedView
from ..dialogs.jumpto import JumpTo
from ...utils import is_printable
from ...config import Conf

l = logging.getLogger(__name__)

RowCol = Tuple[int, int]
HexByteValue = Union[int, str]
HexAddress = int
HexDataBuffer = Union[bytes, bytearray]
HexDataProvider = Callable[[HexAddress], HexByteValue]

class HexHighlightRegion:
    """
    Defines a highlighted region.
    """

    def __init__(self, color: QColor, addr: HexAddress, size: int):
        self.color: QColor = color
        self.addr: HexAddress = addr
        self.size: int = size
        self.active: bool = False


class HexGraphicsObject(QGraphicsObject):
    """
    A graphics item providing a conventional hex-editor interface for a contiguous region of memory.
    """

    cursor_changed = Signal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setFlag(QGraphicsItem.ItemUsesExtendedStyleOption, True)  # Give me more specific paint update rect info
        self.setFlag(QGraphicsItem.ItemIsFocusable, True)  # Give me focus/key events
        self.start_addr: HexAddress = 0
        self.num_bytes: int = 0
        self.end_addr: HexAddress = 0  # Exclusive
        self.read_func: Optional[HexDataProvider] = None
        self.data: HexDataBuffer = b''
        self.addr_offset: int = 0
        self.addr_width: int = 0
        self.ascii_column_offsets: Sequence[int] = []
        self.ascii_space: int = 0
        self.ascii_width: int = 0
        self.byte_column_offsets: Sequence[int] = []
        self.byte_group_space: int = 0
        self.byte_space: int = 0
        self.byte_width: int = 0
        self.char_width: int = 0
        self.max_x: int = 0
        self.max_y: int = 0
        self.row_height: int = 0
        self.row_padding: int = 0
        self.section_space: int = 0
        self.cursor: HexAddress = self.start_addr
        self.selection_start: Optional[HexAddress] = None
        self.mouse_pressed: bool = False
        self.num_rows: int = 0
        self.font: QFont = QFont(Conf.disasm_font)
        self.font.setPointSizeF(12)
        self.ascii_column_active: bool = False
        self.cursor_blink_state: bool = True
        self.highlighted_regions: Sequence[HexHighlightRegion] = []

        self.cursor_blink_timer: QTimer = QTimer(self)
        self.cursor_blink_timer.timeout.connect(self.toggle_cursor_blink)
        self.show_cursor: bool = True
        self._processing_cursor_update: bool = False
        self.always_show_cursor: bool = False

        self._update_layout()

    def focusInEvent(self, event: PySide2.QtGui.QFocusEvent):  # pylint: disable=unused-argument
        """
        Item receives focus.
        """
        self.show_cursor = True
        self.restart_cursor_blink_timer()
        self.update()

    def focusOutEvent(self, event: PySide2.QtGui.QFocusEvent):  # pylint: disable=unused-argument
        """
        Item lost focus.
        """
        self.cursor_blink_timer.stop()
        self.show_cursor = self.always_show_cursor
        self.cursor_blink_state = self.always_show_cursor
        self.update()

    def set_always_show_cursor(self, always_show: bool):
        """
        Set policy of whether the cursor should always be shown (when focus is lost) or not.
        """
        self.always_show_cursor = always_show
        if not self.cursor_blink_timer.isActive():
            self.show_cursor = self.always_show_cursor
            self.cursor_blink_state = self.always_show_cursor
            self.update()

    def _set_data_common(self):
        """
        Common handler for set_data_*
        """
        assert self.num_bytes >= 0
        self.end_addr = self.start_addr + self.num_bytes
        self.set_cursor(self.start_addr)
        self._update_layout()

    def set_data(self, data: HexDataBuffer, start_addr: HexAddress = 0, num_bytes: Optional[int] = None):
        """
        Assign the buffer to be displayed with bytes.
        """
        self.start_addr = start_addr
        self.num_bytes = num_bytes if num_bytes is not None else len(data)
        self.data = data
        self.read_func = None
        self._set_data_common()

    def set_data_callback(self, read_func: HexDataProvider, start_addr: HexAddress, num_bytes: int):
        """
        Assign the buffer to be displayed using a callback function.
        """
        self.start_addr = start_addr
        self.num_bytes = num_bytes
        self.read_func = read_func
        self._set_data_common()

    def point_to_row(self, p: QPointF) -> Optional[int]:
        """
        Return index of row containing point `p`, or None if the point is not contained.
        """
        row = int(p.y() / self.row_height)
        return row if row < self.num_rows else None

    @staticmethod
    def point_to_column(p: QPointF, columns: Sequence[int]) -> Optional[int]:
        """
        Given a point `p` and list of column offsets `columns`, return the index of column point p or None if the point
        is not contained.
        """
        x = p.x()
        for i in range(len(columns)-1):
            if columns[i] <= x < columns[i + 1]:
                return i
        return None

    def point_to_addr(self, pt: QPointF) -> Optional[Tuple[int, bool]]:
        """
        Get the (address, ascii_column) tuple for a given point. If the point falls within the bytes display region,
        ascii_column is False. If the point falls within the ASCII display region, ascii_column is True.
        """
        ascii_column = False
        row = self.point_to_row(pt)
        if row is None:
            return None
        col = self.point_to_column(pt, self.byte_column_offsets)
        if col is None:
            col = self.point_to_column(pt, self.ascii_column_offsets)
            if col is None:
                return None
            else:
                ascii_column = True
        addr = self.row_col_to_addr(row, col)
        if addr < self.start_addr or addr >= self.end_addr:
            return None
        return addr, ascii_column

    def row_to_point(self, row: int) -> QPointF:
        """
        Get a point in the scene for a given row.
        """
        return QPointF(0, row * self.row_height)

    def row_col_to_point(self, row: int, col: int, ascii_section: bool = False) -> QPointF:
        """
        Get point for (row, col) in either ASCII section or bytes section.
        """
        columns = self.ascii_column_offsets if ascii_section else self.byte_column_offsets
        return QPointF(columns[col], self.row_to_point(row).y())

    def addr_to_point(self, addr: HexAddress, ascii_section: bool = False) -> QPointF:
        """
        Get point for address `addr` in either ASCII section or bytes section.
        """
        return self.row_col_to_point(*self.addr_to_row_col(addr), ascii_section)

    def addr_to_rect(self, addr: HexAddress) -> QRectF:
        """
        Get rect for address `addr` in whichever section is currently active.
        """
        if self.ascii_column_active:
            column_width = self.ascii_width
            column_space = self.ascii_space
        else:
            column_width = self.byte_width
            column_space = self.byte_space

        pt = self.addr_to_point(addr, self.ascii_column_active)
        pt.setX(pt.x() - column_space / 2)
        return QRectF(pt, QSizeF(column_width + column_space, self.row_height))

    def row_to_addr(self, row: int) -> int:
        """
        Get address for a given row.
        """
        return (self.start_addr & ~15) + row * 16

    def row_col_to_addr(self, row: int, col: int) -> int:
        """
        Get address for a given row, column.
        """
        return (self.start_addr & ~15) + row*16 + col

    def addr_to_row_col(self, addr: int) -> RowCol:
        """
        Get (row, column) for a given address.
        """
        addr = addr - (self.start_addr & ~0xf)
        row = addr >> 4
        col = addr & 15
        return row, col

    def begin_selection(self):
        """
        Begin selection at current cursor.
        """
        self.selection_start = self.cursor
        self.update()

    def clear_selection(self):
        """
        Clear selection.
        """
        self.selection_start = None
        self.update()

    def restart_cursor_blink_timer(self):
        """
        Restart the cursor blink timer.
        """
        self.cursor_blink_timer.stop()
        self.cursor_blink_state = True
        self.cursor_blink_timer.start(750)

    def update_active_highlight_regions(self):
        """
        Update active property on highlight regions.
        """
        if self.selection_start is None:
            minaddr = self.cursor
            maxaddr = self.cursor
        else:
            minaddr = min(self.cursor, self.selection_start)
            maxaddr = max(self.cursor, self.selection_start)

        for region in self.highlighted_regions:
            region_end = region.addr + region.size - 1
            region.active = not (region.addr > maxaddr or minaddr > region_end)

    def get_highlight_region_under_cursor(self) -> Optional[HexHighlightRegion]:
        """
        Return the region under the cursor, or None if there isn't a region under the cursor.
        """
        for region in self.highlighted_regions:
            if region.addr <= self.cursor < (region.addr + region.size):
                return region
        return None

    def set_cursor(self, addr: int, ascii_column: Optional[bool] = None):
        """
        Move cursor to address `addr`.
        """
        if addr >= self.end_addr or addr < self.start_addr:
            return
        if self._processing_cursor_update:
            return
        self._processing_cursor_update = True
        if ascii_column is not None:
            self.ascii_column_active = ascii_column
        if self.hasFocus():
            self.restart_cursor_blink_timer()
        cursor_changed = self.cursor != addr
        self.cursor = addr
        self.cursor_changed.emit()
        if cursor_changed:
            self.update_active_highlight_regions()
            self.update()
        self._processing_cursor_update = False

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent):
        """
        Handle mouse press events (e.g. updating selection).
        """
        if event.button() == Qt.LeftButton:
            addr = self.point_to_addr(event.pos())
            if addr is None:
                return
            addr, ascii_column = addr
            self.mouse_pressed = True
            if QApplication.keyboardModifiers() in (Qt.ShiftModifier,):
                if self.selection_start is None:
                    self.begin_selection()
            else:
                self.clear_selection()
            self.set_cursor(addr, ascii_column)
            event.accept()

    def mouseDoubleClickEvent(self, event: QGraphicsSceneMouseEvent):
        """
        Handle mouse double-click events (e.g. update selection)
        """
        if event.button() == Qt.LeftButton:
            region = self.get_highlight_region_under_cursor()
            if region is not None:
                self.set_cursor(region.addr + region.size - 1)
                self.begin_selection()
                self.set_cursor(region.addr)

    def mouseMoveEvent(self, event: QGraphicsSceneMouseEvent):
        """
        Handle mouse move events (e.g. updating selection).
        """
        if self.mouse_pressed:
            addr = self.point_to_addr(event.pos())
            if addr is None:
                return
            addr, ascii_column = addr
            if self.selection_start is None:
                self.begin_selection()
            self.set_cursor(addr, ascii_column)

    def mouseReleaseEvent(self, event: QGraphicsSceneMouseEvent):
        """
        Handle mouse release events.
        """
        if event.button() == Qt.LeftButton:
            self.mouse_pressed = False

    def keyPressEvent(self, event: PySide2.QtGui.QKeyEvent):
        """
        Handle key press events (e.g. moving cursor around).
        """
        movement_keys = (Qt.Key_Up, Qt.Key_Down, Qt.Key_Right, Qt.Key_Left, Qt.Key_PageUp, Qt.Key_PageDown)
        if event.key() in movement_keys:
            if QApplication.keyboardModifiers() in (Qt.ShiftModifier,):
                if self.selection_start is None:
                    self.begin_selection()
            else:
                self.clear_selection()
            new_cursor = self.cursor
            if event.key() == Qt.Key_Up:
                new_cursor -= 16
            elif event.key() == Qt.Key_Down:
                new_cursor += 16
            elif event.key() == Qt.Key_Right:
                new_cursor += 1
            elif event.key() == Qt.Key_Left:
                new_cursor -= 1
            elif event.key() == Qt.Key_PageDown:
                new_cursor += 8*16
            elif event.key() == Qt.Key_PageUp:
                new_cursor -= 8*16
            self.set_cursor(new_cursor)
            event.accept()
            return
        super().keyPressEvent(event)

    def _update_layout(self):
        """
        Update various layout settings based on font and data store
        """
        self.prepareGeometryChange()

        ti = QGraphicsSimpleTextItem()  # Get font metrics using text item
        ti.setFont(self.font)
        ti.setText('0')

        self.row_padding = int(ti.boundingRect().height() * 0.25)
        self.row_height = ti.boundingRect().height() + self.row_padding
        self.char_width = ti.boundingRect().width()
        self.section_space = self.char_width * 4
        self.addr_offset = self.char_width * 1
        self.addr_width = self.char_width * 8
        self.byte_width = self.char_width * 2
        self.byte_space = self.char_width * 1
        self.byte_group_space = self.char_width * 2
        self.ascii_width = self.char_width * 1
        self.ascii_space = 0

        self.byte_column_offsets = [self.addr_offset + self.addr_width + self.section_space]
        for i in range(1, 17):
            x = self.byte_column_offsets[-1] + self.byte_width + (self.byte_group_space if i == 8 else self.byte_space)
            self.byte_column_offsets.append(x)

        self.ascii_column_offsets = [self.byte_column_offsets[-1] + self.section_space]
        for _ in range(1, 17):
            x = self.ascii_column_offsets[-1] + self.ascii_width + self.ascii_space
            self.ascii_column_offsets.append(x)

        if self.num_bytes > 0:
            self.num_rows = int((self.num_bytes + (self.start_addr & 0xf) + 0xf) / 16)
        else:
            self.num_rows = 0
        self.max_x = self.ascii_column_offsets[-1]
        self.max_y = self.num_rows * self.row_height

        self.update()

    def build_selection_path(self, min_addr: HexAddress, max_addr: HexAddress,
                             ascii_section: bool = False, shrink: float = 0.0) -> QPainterPath:
        """
        Build a QPainterPath that selects a given (inclusive addresses) range of bytes.
        """
        row_start, col_start = self.addr_to_row_col(min_addr)
        row_end, col_end = self.addr_to_row_col(max_addr)

        num_selected_rows = row_end - row_start + 1

        if ascii_section:
            column_offsets = self.ascii_column_offsets
            column_width = self.ascii_width
            column_space = self.ascii_space
        else:
            column_offsets = self.byte_column_offsets
            column_width = self.byte_width
            column_space = self.byte_space

        # Build top rect
        trect = QRectF()
        p = self.row_to_point(row_start)
        p.setX(column_offsets[col_start] - column_space / 2)
        trect.setTopLeft(p)
        p = QPointF(column_offsets[col_end if num_selected_rows == 1 else 15] + column_width + column_space / 2,
                    p.y() + self.row_height)
        trect.setBottomRight(p)
        trect = trect.marginsRemoved(QMarginsF(shrink, shrink, shrink, shrink))

        # Build middle rect
        if num_selected_rows > 2:
            mrect = QRectF()
            p = self.row_to_point(row_start + 1)
            p.setX(column_offsets[0] - column_space / 2)
            mrect.setTopLeft(p)
            p = QPointF(column_offsets[15] + column_width + column_space / 2,
                        p.y() + self.row_height * (num_selected_rows - 2))
            mrect.setBottomRight(p)
            mrect = mrect.marginsRemoved(QMarginsF(shrink, shrink, shrink, shrink))
        else:
            mrect = None

        # Build bottom rect
        if num_selected_rows > 1:
            brect = QRectF()
            p = self.row_to_point(row_end)
            p.setX(column_offsets[0] - column_space / 2)
            brect.setTopLeft(p)
            p = QPointF(column_offsets[col_end] + column_width + column_space / 2,
                        p.y() + self.row_height)
            brect.setBottomRight(p)
            brect = brect.marginsRemoved(QMarginsF(shrink, shrink, shrink, shrink))
        else:
            brect = None

        close_to_top = True
        spath = QPainterPath()
        spath.moveTo(trect.topLeft())
        spath.lineTo(trect.topRight())
        spath.lineTo(trect.bottomRight())
        last = trect.bottomRight()
        if mrect:
            spath.lineTo(mrect.bottomRight())
            last = mrect.bottomRight()
        if brect:
            if mrect is None and col_end < col_start:
                # Don't try to connect disjoint top and bottom
                spath.lineTo(trect.bottomLeft())
                spath.closeSubpath()
                spath.moveTo(brect.topLeft())
                last = brect.topLeft()
                close_to_top = False
            spath.lineTo(QPointF(brect.topRight().x(), last.y()))
            spath.lineTo(brect.bottomRight())
            spath.lineTo(brect.bottomLeft())
            spath.lineTo(brect.topLeft())
            last = brect.topLeft()
        if mrect:
            spath.lineTo(mrect.topLeft())
            last = mrect.topLeft()
        if close_to_top:
            spath.lineTo(QPointF(trect.bottomLeft().x(), last.y()))
        spath.closeSubpath()
        return spath

    def get_value_for_addr(self, addr: int) -> Union[int, str]:
        """
        Get the value for given address `addr`.
        """
        if self.read_func is not None:
            return self.read_func(addr)
        else:
            return self.data[addr - self.start_addr]

    def get_selection(self) -> Optional[Tuple[int, int]]:
        """
        Get active selection, returning (minaddr, maxaddr) inclusive.
        """
        if self.start_addr <= self.cursor < self.end_addr:
            if self.selection_start is None:
                minaddr = self.cursor
                maxaddr = self.cursor
            else:
                minaddr = min(self.cursor, self.selection_start)
                maxaddr = max(self.cursor, self.selection_start)
            return (minaddr, maxaddr)
        return None

    def toggle_cursor_blink(self):
        """
        Simply toggles cursor blink status.
        """
        self.cursor_blink_state = not self.cursor_blink_state
        self.update()

    def set_highlight_regions(self, regions: Sequence[HexHighlightRegion]):
        """
        Sets the list of highlighted regions.
        """
        self.highlighted_regions = regions
        self.update_active_highlight_regions()
        self.update()

    def paint_highlighted_region(self, painter, region: HexHighlightRegion):
        """
        Paint a highlighted region of bytes.
        """
        pen_width = 1.0
        half_pen_width = pen_width / 2.0
        end_addr = region.addr + region.size - 1

        path = self.build_selection_path(region.addr, end_addr, False, half_pen_width)

        color = QColor(region.color)
        if not region.active:
            color = color.darker(150)

        r = path.boundingRect()
        bg = PySide2.QtGui.QLinearGradient(r.topLeft(), r.bottomLeft())
        top_color = QColor(color)
        top_color.setAlpha(50)
        bg.setColorAt(0, top_color)
        bottom_color = QColor(color)
        bottom_color.setAlpha(10)
        bg.setColorAt(1, bottom_color)

        painter.setBrush(bg)
        painter.setPen(QPen(color, pen_width))
        painter.drawPath(path)
        painter.drawPath(self.build_selection_path(region.addr, end_addr, True, half_pen_width))

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        """
        Repaint the item.
        """
        min_row = self.point_to_row(option.exposedRect.topLeft())
        if min_row is None:
            min_row = 0
        max_row = self.point_to_row(option.exposedRect.bottomLeft())
        if max_row is None:
            max_row = self.num_rows - 1

        # Paint background
        painter.setPen(Qt.NoPen)
        for row in range(min_row, max_row + 1):
            pt = self.row_to_point(row)
            painter.setBrush(Conf.palette_base if row % 2 == 0 else Conf.palette_alternatebase)
            painter.drawRect(QRectF(0, pt.y(), self.boundingRect().width(), self.row_height))

        for region in self.highlighted_regions:
            self.paint_highlighted_region(painter, region)

        # Paint selection
        if self.selection_start is not None:
            minaddr = min(self.cursor, self.selection_start)
            maxaddr = max(self.cursor, self.selection_start)

            pen_width = 1.0
            half_pen_width = pen_width / 2.0

            def set_pen_brush_for_active_selection(active):
                if active:
                    painter.setPen(QPen(Conf.hex_view_selection_color, pen_width))
                    painter.setBrush(QColor(255, 255, 255, 10))
                else:
                    painter.setPen(QPen(Conf.hex_view_selection_alt_color, pen_width))
                    painter.setBrush(QColor(255, 255, 255, 10))

            set_pen_brush_for_active_selection(not self.ascii_column_active)
            painter.drawPath(self.build_selection_path(minaddr, maxaddr, False, half_pen_width))

            set_pen_brush_for_active_selection(self.ascii_column_active)
            painter.drawPath(self.build_selection_path(minaddr, maxaddr, True, half_pen_width))

        # Paint text
        painter.setFont(self.font)

        for row in range(min_row, max_row + 1):
            pt = self.row_to_point(row)
            pt.setY(pt.y() + self.row_height - self.row_padding)

            # Paint address
            addr_text = '%08x' % self.row_to_addr(row)
            pt.setX(self.addr_offset)
            painter.setPen(Conf.disasm_view_node_address_color)
            painter.drawText(pt, addr_text)

            # Paint byte values
            for col in range(0, 16):
                addr = self.row_col_to_addr(row, col)
                if addr < self.start_addr or addr >= self.end_addr:
                    continue
                val = self.get_value_for_addr(addr)
                pt.setX(self.byte_column_offsets[col])

                if type(val) is int:
                    if is_printable(val):
                        color = Conf.disasm_view_printable_byte_color
                    else:
                        color = Conf.disasm_view_unprintable_byte_color
                    byte_text = '%02x' % val
                else:
                    byte_text = '??'
                    color = Conf.disasm_view_unknown_byte_color

                pt.setX(self.byte_column_offsets[col])
                painter.setPen(color)
                painter.drawText(pt, byte_text)

            # Paint ASCII representation
            for col in range(0, 16):
                addr = self.row_col_to_addr(row, col)
                if addr < self.start_addr or addr >= self.end_addr:
                    continue
                val = self.get_value_for_addr(addr)
                pt.setX(self.ascii_column_offsets[col])

                if type(val) is int:
                    if is_printable(val):
                        color = Conf.disasm_view_printable_character_color
                        ch = chr(val)
                    else:
                        color = Conf.disasm_view_unprintable_character_color
                        ch = '.'
                else:
                    color = Conf.disasm_view_unknown_character_color
                    ch = '?'

                pt.setX(self.ascii_column_offsets[col])
                painter.setPen(color)
                painter.drawText(pt, ch)

        # Paint cursor
        if self.show_cursor and (self.start_addr <= self.cursor < self.end_addr):
            cursor_height = self.row_padding / 2
            def set_pen_brush_for_active_cursor(active):
                painter.setPen(Qt.NoPen)
                if active:
                    if self.cursor_blink_state:
                        col = Conf.palette_text
                    else:
                        col = Qt.NoBrush
                else:
                    col = Conf.palette_disabled_text
                painter.setBrush(col)

            # Byte cursor
            set_pen_brush_for_active_cursor(not self.ascii_column_active)
            tl = self.addr_to_point(self.cursor)
            tl.setY(tl.y() + self.row_height - cursor_height)
            painter.drawRect(QRectF(tl, QSizeF(self.byte_width, cursor_height)))

            # ASCII cursor
            set_pen_brush_for_active_cursor(self.ascii_column_active)
            tl = self.addr_to_point(self.cursor, True)
            tl.setY(tl.y() + self.row_height - cursor_height)
            painter.drawRect(QRectF(tl, QSizeF(self.ascii_width, cursor_height)))

    def boundingRect(self) -> PySide2.QtCore.QRectF:
        return QRectF(0, 0, self.max_x, self.max_y)


class HexGraphicsView(QGraphicsView):
    """
    Container view for the HexGraphicsObject.
    """

    cursor_changed = Signal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._scene: QGraphicsScene = QGraphicsScene(parent=self)
        self.hex: HexGraphicsObject = HexGraphicsObject()
        self.hex.cursor_changed.connect(self.on_cursor_changed)
        self._scene.addItem(self.hex)
        self.setScene(self._scene)

        self.setBackgroundBrush(Conf.palette_base)
        self.setResizeAnchor(QGraphicsView.NoAnchor)
        self.setTransformationAnchor(QGraphicsView.NoAnchor)
        self.setAlignment(Qt.AlignTop | Qt.AlignLeft)

    def set_region_callback(self, mem, addr, size):
        s = self.scene().itemsBoundingRect()
        self.hex.setPos(s.bottomLeft())
        self.hex.set_data_callback(mem, addr, size)
        self.setSceneRect(self.scene().itemsBoundingRect())

    def on_cursor_changed(self):
        """
        Handle cursor change events.
        """
        self.cursor_changed.emit()
        self.move_viewport_to_cursor()

    def move_viewport_to_cursor(self):
        """
        Ensure cursor is visible in viewport.
        """
        target = self.hex.addr_to_rect(self.hex.cursor)
        target.translate(self.hex.pos())
        vp_rect = self.viewport().geometry()
        vp_rect.moveTo(0, 0)
        current = self.mapToScene(vp_rect).boundingRect()

        if target.bottomRight().x() > current.bottomRight().x():
            dX = current.bottomRight().x() - target.bottomRight().x()  # Scroll right
        elif target.bottomLeft().x() < current.bottomLeft().x():
            dX = current.bottomLeft().x() - target.bottomLeft().x()  # Scroll left
        else:
            dX = 0

        if target.bottomLeft().y() > current.bottomLeft().y():
            dY = current.bottomLeft().y() - target.bottomLeft().y()  # Scroll down
        elif target.topLeft().y() < current.topLeft().y():
            dY = current.topLeft().y() - target.topLeft().y()  # Scroll up
        else:
            dY = 0

        if dX != 0 or dY != 0:
            self.translate(dX, dY)

    def adjust_viewport_scale(self, scale: Optional[float] = None):
        """
        Reset viewport scaling. If `scale` is None, viewport scaling is reset to default.
        """
        # Ensure top-left position visible in scene remains at the top left when changing scale
        old_pos = self.mapToScene(self.viewport().geometry().topLeft())
        if scale is None:
            self.resetTransform()
        else:
            self.scale(scale, scale)
        new_pos = self.mapToScene(self.viewport().geometry().topLeft())
        delta = new_pos - old_pos
        self.translate(delta.x(), delta.y())

    def wheelEvent(self, event: QWheelEvent):
        """
        Handle wheel events, specifically for changing font size when holding Ctrl key.
        """
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            self.adjust_viewport_scale(1.25 if event.delta() > 0 else 1/1.25)
            event.accept()
        else:
            super().wheelEvent(event)

    def changeEvent(self, event: QEvent):
        """
        Redraw on color scheme update.
        """
        if event.type() == QEvent.PaletteChange:
            self.setBackgroundBrush(Conf.palette_base)
            self.update()

    def keyPressEvent(self, event: PySide2.QtGui.QKeyEvent):
        """
        Handle key events.
        """
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            if event.key() == Qt.Key_0:
                self.adjust_viewport_scale()
                event.accept()
                return
            elif event.key() == Qt.Key_Equal:
                self.adjust_viewport_scale(1.25)
                event.accept()
                return
            elif event.key() == Qt.Key_Minus:
                self.adjust_viewport_scale(1/1.25)
                event.accept()
                return
        super().keyPressEvent(event)


class HexView(SynchronizedView):
    """
    View and edit memory/object code in classic hex editor format.
    """

    _widgets_initialized: bool = False

    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('hex', workspace, default_docking_position, *args, **kwargs)
        self.base_caption: str = 'Hex'
        self.smart_highlighting_enabled: bool = True
        self._cfb_highlights: Sequence[HexHighlightRegion] = []
        self._sync_view_highlights: Sequence[HexHighlightRegion] = []
        self._init_widgets()
        self.reload_cfb()
        self.workspace.instance.cfb.am_subscribe(self.reload_cfb)

    def project_memory_read_func(self, addr: int) -> HexByteValue:
        """
        Callback to populate hex view with bytes.
        """
        p = self.workspace.instance.project.am_obj
        try:
            return p.loader.memory[addr]
        except KeyError:
            return '?'

    def reload_cfb(self):
        """
        Callback when project CFB changes.
        """
        cfb = self.workspace.instance.cfb.am_obj
        if cfb is None:
            return

        p = self.workspace.instance.project.am_obj
        self.inner_widget.set_region_callback(
            self.project_memory_read_func,
            p.loader.min_addr,
            p.loader.max_addr - p.loader.min_addr + 1
        )

        self.inner_widget.cursor_changed.connect(self.on_cursor_changed)

    def set_smart_highlighting_enabled(self, enable: bool):
        """
        Control whether smart highlighting is enabled or not.
        """
        self.smart_highlighting_enabled = enable
        self._update_highlight_regions_under_cursor()

    def _init_widgets(self):
        """
        Initialize widgets for this view.
        """
        window = QMainWindow()
        window.setWindowFlags(Qt.Widget)

        status_bar = QFrame()
        status_lyt = QHBoxLayout()
        status_lyt.setContentsMargins(0, 0, 0, 0)

        self._status_lbl = QLabel()
        self._status_lbl.setText('Address: ')

        status_lyt.addWidget(self._status_lbl)
        status_lyt.addStretch(0)

        option_btn = QPushButton()
        option_btn.setText('Options')
        option_mnu = QMenu(self)
        smart_hl_act = QAction('Smart &highlighting', self)
        smart_hl_act.setCheckable(True)
        smart_hl_act.setChecked(self.smart_highlighting_enabled)
        smart_hl_act.toggled.connect(self.set_smart_highlighting_enabled)
        option_mnu.addAction(smart_hl_act)
        option_btn.setMenu(option_mnu)
        status_lyt.addWidget(option_btn)

        status_bar.setLayout(status_lyt)

        self.inner_widget = HexGraphicsView(parent=self)
        lyt = QVBoxLayout()
        lyt.addWidget(self.inner_widget)
        lyt.addWidget(status_bar)
        self.setLayout(lyt)

        self._widgets_initialized = True

    def contextMenuEvent(self, event: PySide2.QtGui.QContextMenuEvent):  # pylint: disable=unused-argument
        """
        Display view context menu.
        """
        mnu = QMenu(self)
        mnu.addMenu(self.get_synchronize_with_submenu())
        mnu.exec_(QCursor.pos())

    def set_cursor(self, addr: int):
        """
        Move cursor to specific address and clear any active selection.
        """
        self.inner_widget.hex.clear_selection()
        self.inner_widget.hex.set_cursor(addr)

    def on_cursor_changed(self):
        """
        Handle updates to cursor.
        """
        self.update_status_text()
        self._update_highlight_regions_under_cursor()
        self.set_synchronized_cursor_address(self.inner_widget.hex.cursor)

    def update_status_text(self):
        """
        Update status text with current cursor info.
        """
        s = 'Address: %08x' % self.inner_widget.hex.cursor
        sel = self.inner_widget.hex.get_selection()
        if sel is not None:
            minaddr, maxaddr = sel
            bytes_selected = maxaddr - minaddr + 1
            if bytes_selected > 1:
                s = 'Address: [%08x, %08x], %d bytes selected' % (minaddr, maxaddr, bytes_selected)
        self._status_lbl.setText(s)

    def keyPressEvent(self, event: PySide2.QtGui.QKeyEvent):
        """
        Handle key events.
        """
        if event.key() == Qt.Key_G:
            self.popup_jumpto_dialog()
            return

        super().keyPressEvent(event)

    def popup_jumpto_dialog(self):
        """
        Display 'Jump To' dialog.
        """
        JumpTo(self, parent=self).exec_()

    def jump_to(self, addr: int) -> bool:
        """
        Jump to a specific address.
        """
        self.set_cursor(addr)
        return True

    def on_synchronized_view_group_changed(self):
        """
        Handle view being added to or removed from the view synchronization group.
        """
        if self._widgets_initialized:
            self.inner_widget.hex.set_always_show_cursor(len(self.sync_state.views) > 1)

    def on_synchronized_highlight_regions_changed(self):
        """
        Handle synchronized highlight region change event.
        """
        self._update_highlight_regions_from_synchronized_views()

    def _generate_highlight_regions_under_cursor(self) -> Sequence[HexHighlightRegion]:
        """
        Generate list of highlighted regions from CFB under cursor.
        """
        regions = []

        try:
            item = self.workspace.instance.cfb.floor_item(self.inner_widget.hex.cursor)
        except KeyError:
            item = None
        if item is None:
            return regions

        addr, item = item
        if self.inner_widget.hex.cursor >= (addr + item.size):
            return regions

        if isinstance(item, MemoryData):
            color = Conf.hex_view_string_color if item.sort == 'string' else Conf.hex_view_data_color
            regions.append(HexHighlightRegion(color, item.addr, item.size))
        elif isinstance(item, Block):
            for insn in item.disassembly.insns:
                regions.append(HexHighlightRegion(Conf.hex_view_instruction_color, insn.address, insn.size))

        return regions

    def _update_highlight_regions_under_cursor(self):
        """
        Update cached list of highlight regions under cursor.
        """
        self._cfb_highlights = []
        if self.smart_highlighting_enabled:
            self._cfb_highlights.extend(self._generate_highlight_regions_under_cursor())
        self._set_highlighted_regions()

    def _generate_highlight_regions_from_synchronized_views(self) -> Sequence[HexHighlightRegion]:
        """
        Generate list of highlighted regions from any synchronized views.
        """
        regions = []
        for v in self.sync_state.highlight_regions:
            if v is not self:
                for r in self.sync_state.highlight_regions[v]:
                    regions.append(HexHighlightRegion(Qt.green, r.addr, r.size))
        return regions

    def _update_highlight_regions_from_synchronized_views(self):
        """
        Update cached list of highlight regions from synchronized views.
        """
        self._sync_view_highlights = self._generate_highlight_regions_from_synchronized_views()
        self._set_highlighted_regions()

    def _set_highlighted_regions(self):
        """
        Update highlighted regions, with data from CFB and synchronized views.
        """
        regions = []
        regions.extend(self._cfb_highlights)
        regions.extend(self._sync_view_highlights)
        self.inner_widget.hex.set_highlight_regions(regions)
