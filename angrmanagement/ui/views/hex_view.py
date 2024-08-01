from __future__ import annotations

import functools
import logging
from collections.abc import Callable, Sequence
from enum import Enum
from typing import TYPE_CHECKING

import angr
import PySide6
from angr import Block
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort
from angr.knowledge_plugins.patches import Patch
from PySide6.QtCore import QEvent, QMarginsF, QPointF, QRectF, QSizeF, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QCursor, QFont, QPainterPath, QPen, QWheelEvent
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QAbstractSlider,
    QApplication,
    QComboBox,
    QFrame,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsScene,
    QGraphicsSceneMouseEvent,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from angrmanagement.config import Conf
from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.logic.debugger import DebuggerWatcher
from angrmanagement.ui.dialogs.input_prompt import InputPromptDialog
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.utils import is_printable

from .view import SynchronizedInstanceView

if TYPE_CHECKING:
    from PySide6.QtGui import QPainter
    from PySide6.QtWidgets import QStyleOptionGraphicsItem, QWidget

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

log = logging.getLogger(__name__)

RowCol = tuple[int, int]
HexByteValue = int | str
HexAddress = int
HexDataBuffer = bytes | bytearray
HexDataProvider = Callable[[HexAddress], HexByteValue]


class HexDataSource(Enum):
    """
    Data source to be displayed in the hex view.
    """

    Loader = 0
    Debugger = 1


class HexHighlightRegion:
    """
    Defines a highlighted region.
    """

    def __init__(self, color: QColor, addr: HexAddress, size: int, tooltip: str | None = None) -> None:
        self.color: QColor = color
        self.addr: HexAddress = addr
        self.size: int = size
        self.active: bool = False
        self._tooltip: str | None = tooltip

    def gen_context_menu_actions(self) -> QMenu | None:  # pylint: disable=no-self-use
        """
        Get submenu for this highlight region.
        """
        return None

    def get_tooltip(self) -> str | None:
        """
        Return a tooltip for this region.
        """
        return self._tooltip


class BreakpointHighlightRegion(HexHighlightRegion):
    """
    Defines a highlighted region indicating a patch.
    """

    def __init__(self, bp: Breakpoint, view: HexView) -> None:
        super().__init__(Qt.GlobalColor.cyan, bp.addr, bp.size)
        self.bp: Breakpoint = bp
        self.view: HexView = view

    def gen_context_menu_actions(self) -> QMenu | None:
        """
        Get submenu for this highlight region.
        """
        bp_type_str = {
            BreakpointType.Execute: "Execute",
            BreakpointType.Read: "Read",
            BreakpointType.Write: "Write",
        }.get(self.bp.type)
        mnu = QMenu(f"Breakpoint 0x{self.bp.addr:x} {bp_type_str} ({self.bp.size} bytes)")
        act = QAction("&Remove", mnu)
        act.triggered.connect(self.remove)
        mnu.addAction(act)
        return mnu

    def remove(self) -> None:
        """
        Remove this breakpoint.
        """
        self.view.instance.breakpoint_mgr.remove_breakpoint(self.bp)

    def get_tooltip(self) -> str | None:
        """
        Return a tooltip for this region.
        """
        bp_type_str = {
            BreakpointType.Execute: "Execute",
            BreakpointType.Read: "Read",
            BreakpointType.Write: "Write",
        }.get(self.bp.type)
        return f"Breakpoint 0x{self.bp.addr:x} {bp_type_str} ({self.bp.size} bytes)"


class PatchHighlightRegion(HexHighlightRegion):
    """
    Defines a highlighted region indicating a patch.
    """

    def __init__(self, patch: Patch, view: HexView) -> None:
        super().__init__(Qt.GlobalColor.yellow, patch.addr, len(patch))
        self.patch: Patch = patch
        self.view: HexView = view

    def get_tooltip(self) -> str | None:
        """
        Return a tooltip for this region.
        """
        return f"Patch 0x{self.patch.addr:x} ({len(self.patch)} bytes)"

    def gen_context_menu_actions(self) -> QMenu | None:
        """
        Get submenu for this highlight region.
        """
        mnu = QMenu(f"Patch 0x{self.patch.addr:x} ({len(self.patch)} bytes)")
        act = QAction("&Split", mnu)
        act.triggered.connect(self.split)
        act.setEnabled(self.can_split())
        mnu.addAction(act)
        act = QAction("Set &Comment...", mnu)
        act.triggered.connect(self.comment)
        mnu.addAction(act)
        mnu.addSeparator()
        act = QAction("&Revert", mnu)
        act.triggered.connect(self.revert_with_prompt)
        mnu.addAction(act)
        return mnu

    def revert_with_prompt(self) -> None:
        """
        Revert this patch. Prompt for confirmation.
        """
        dlg = QMessageBox()
        dlg.setWindowTitle("Revert patch")
        dlg.setText("Are you sure you want to revert this patch?")
        dlg.setIcon(QMessageBox.Icon.Question)
        dlg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        dlg.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if dlg.exec_() != QMessageBox.StandardButton.Yes:
            return
        self.revert()

    def revert(self) -> None:
        """
        Revert this patch.
        """
        pm = self.view.instance.patches
        pm.remove_patch(self.patch.addr)
        pm.am_event()

    def can_split(self) -> bool:
        """
        Determine if this patch can be split based on current cursor location.
        """
        cursor = self.view.inner_widget.hex.cursor
        return self.patch.addr < cursor < (self.patch.addr + len(self.patch))

    def split(self) -> None:
        """
        Split this patch at view's current cursor location.
        """
        cursor = self.view.inner_widget.hex.cursor
        if self.can_split():
            o = cursor - self.patch.addr
            new_patch = Patch(cursor, self.patch.new_bytes[o:], self.patch.comment)
            self.patch.new_bytes = self.patch.new_bytes[0:o]
            pm = self.view.instance.patches
            pm.add_patch_obj(new_patch)
            pm.am_event()

    def can_merge_with(self, other: PatchHighlightRegion) -> bool:
        """
        Determine if this patch can be merged with `other`. We only consider directly adjacent patches.
        """
        return other.patch.addr == (self.patch.addr + len(self.patch))

    def merge_with(self, other: PatchHighlightRegion) -> None:
        """
        Merge `other` into this patch.
        """
        if self.can_merge_with(other):
            self.patch.new_bytes += other.patch.new_bytes
            pm = self.view.instance.patches
            pm.remove_patch(other.patch.addr)
            pm.am_event()

    def comment(self) -> None:
        """
        Set the comment for this patch.
        """
        dlg = InputPromptDialog("Set Patch Comment", "Patch comment:", self.patch.comment, parent=self.view)
        dlg.exec_()
        if dlg.result:
            self.patch.comment = dlg.result
            pm = self.view.instance.patches
            pm.am_event()


class HexGraphicsObject(QGraphicsObject):
    """
    A graphics item providing a conventional hex-editor interface for a contiguous region of memory.
    """

    cursor_changed = Signal()
    viewport_changed = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setFlag(
            QGraphicsItem.GraphicsItemFlag.ItemUsesExtendedStyleOption, True
        )  # Give me more specific paint update rect info
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsFocusable, True)  # Give me focus/key events
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemClipsToShape, True)
        self.display_offset_addr: HexAddress = 0
        self.display_num_rows: int = 1
        self.display_start_addr: HexAddress = 0
        self.display_end_addr: HexAddress = 0
        self.start_addr: HexAddress = 0
        self.num_bytes: int = 0
        self.end_addr: HexAddress = 0  # Exclusive
        self.read_func: HexDataProvider | None = None
        self.write_func: Callable[[HexAddress, HexByteValue], bool] = None
        self.data: HexDataBuffer | None = None
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
        self.cursor_nibble: int | None = None
        self.selection_start: HexAddress | None = None
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

    def focusInEvent(self, event: PySide6.QtGui.QFocusEvent) -> None:  # pylint: disable=unused-argument
        """
        Item receives focus.
        """
        self.show_cursor = True
        self.restart_cursor_blink_timer()
        self.update()

    def focusOutEvent(self, event: PySide6.QtGui.QFocusEvent) -> None:  # pylint: disable=unused-argument
        """
        Item lost focus.
        """
        self.cursor_blink_timer.stop()
        self.show_cursor = self.always_show_cursor
        self.cursor_blink_state = self.always_show_cursor
        self.update()

    def set_always_show_cursor(self, always_show: bool) -> None:
        """
        Set policy of whether the cursor should always be shown (when focus is lost) or not.
        """
        self.always_show_cursor = always_show
        if not self.cursor_blink_timer.isActive():
            self.show_cursor = self.always_show_cursor
            self.cursor_blink_state = self.always_show_cursor
            self.update()

    def _set_display_common(self) -> None:
        """
        Handle common update of offset or row count changed.
        """
        self.display_end_addr = min(self.end_addr, self.display_start_addr + self.display_num_rows * 16)
        self._update_layout()
        self.viewport_changed.emit()

    def set_display_num_rows(self, num_rows: int) -> None:
        """
        Set number of rows to display.
        """
        self.display_num_rows = max(num_rows, 1)
        self._set_display_common()

    def set_display_offset(self, offset: HexAddress) -> None:
        """
        Set displayed range offset.
        """
        self.display_offset_addr = max(0, min(offset & ~0xF, self.end_addr - self.start_addr - 0x10))
        self.display_start_addr = self.start_addr + self.display_offset_addr
        self._set_display_common()

    def move_viewport_to(self, addr: HexAddress, preserve_relative_offset: bool = False) -> None:
        """
        Translate the visible range so `addr` is visible.
        """
        assert self.start_addr <= addr < self.end_addr

        if preserve_relative_offset and (self.display_start_addr <= self.cursor < self.display_end_addr):
            # Let the target addr be on the same relative row from top of screen
            self.set_display_offset(addr - self.cursor + self.display_start_addr - self.start_addr)
            return

        if addr < self.display_start_addr:
            # Let the target addr be on the first displayed row
            self.set_display_offset(addr - self.start_addr)
            return

        # Let the target addr be on last fully displayed row
        max_fully_visible_bytes = 0x10 * (self.display_num_rows - 1)
        display_end = self.display_start_addr + max_fully_visible_bytes
        if addr >= display_end:
            offset = addr - max_fully_visible_bytes - self.start_addr + 0x10
            self.set_display_offset(offset)

    def _set_data_common(self) -> None:
        """
        Common handler for set_data_*
        """
        assert self.num_bytes >= 0
        self.num_rows = int((self.num_bytes + (self.start_addr & 0xF) + 0xF) / 16)
        self.end_addr = self.start_addr + self.num_bytes
        self.clear_selection()
        self.set_display_offset(0)
        self.set_cursor(self.start_addr)
        self._update_layout()

    def _simple_read_callback(self, addr: HexAddress) -> HexByteValue:
        """
        Handler for simple data buffers.
        """
        return self.data[addr - self.start_addr]

    # pylint:disable=unused-argument,no-self-use
    def _simple_write_callback(self, addr: HexAddress, value: HexByteValue) -> bool:
        """
        Handler for simple data buffers.
        """
        return False

    def set_data(self, data: HexDataBuffer, start_addr: HexAddress = 0, num_bytes: int | None = None) -> None:
        """
        Assign the buffer to be displayed with bytes.
        """
        self.data = data
        self.start_addr = start_addr
        self.num_bytes = num_bytes if num_bytes is not None else len(data)
        self.read_func = self._simple_read_callback
        self.write_func = self._simple_write_callback
        self._set_data_common()

    def set_data_callback(self, write_func, read_func: HexDataProvider, start_addr: HexAddress, num_bytes: int) -> None:
        """
        Assign the buffer to be displayed using a callback function.
        """
        self.data = None
        self.start_addr = start_addr
        self.num_bytes = num_bytes
        self.write_func = write_func
        self.read_func = read_func
        self._set_data_common()

    def clear(self) -> None:
        """
        Clear the current buffer.
        """
        self.set_data(b"")

    def point_to_row(self, p: QPointF) -> int | None:
        """
        Return index of row containing point `p`, or None if the point is not contained.
        """
        row = int(p.y() / self.row_height)
        return row if row < self.num_rows else None

    @staticmethod
    def point_to_column(p: QPointF, columns: Sequence[int]) -> int | None:
        """
        Given a point `p` and list of column offsets `columns`, return the index of column point p or None if the point
        is not contained.
        """
        x = p.x()
        for i in range(len(columns) - 1):
            if columns[i] <= x < columns[i + 1]:
                return i
        return None

    def point_to_addr(self, pt: QPointF) -> tuple[int, bool] | None:
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
        return (self.display_start_addr & ~15) + row * 16

    def row_col_to_addr(self, row: int, col: int) -> int:
        """
        Get address for a given row, column.
        """
        return (self.display_start_addr & ~15) + row * 16 + col

    def addr_to_row_col(self, addr: int) -> RowCol:
        """
        Get (row, column) for a given address.
        """
        addr = addr - (self.display_start_addr & ~0xF)
        row = addr >> 4
        col = addr & 15
        return row, col

    def begin_selection(self) -> None:
        """
        Begin selection at current cursor.
        """
        self.selection_start = self.cursor
        self.update()

    def clear_selection(self) -> None:
        """
        Clear selection.
        """
        self.selection_start = None
        self.update()

    def restart_cursor_blink_timer(self) -> None:
        """
        Restart the cursor blink timer.
        """
        self.cursor_blink_timer.stop()
        self.cursor_blink_state = True
        self.cursor_blink_timer.start(750)

    def update_active_highlight_regions(self) -> None:
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

    def get_active_highlight_regions(self) -> Sequence[HexHighlightRegion]:
        """
        Get currently active highlight regions.
        """
        return [rgn for rgn in self.highlighted_regions if rgn.active]

    def get_highlight_regions_at_addr(self, addr: HexAddress) -> Sequence[HexHighlightRegion]:
        """
        Return the highlight regions at specified address.
        """
        regions = []
        for region in self.highlighted_regions:
            if region.addr <= addr < (region.addr + region.size):
                regions.append(region)
        return regions

    def get_highlight_regions_under_cursor(self) -> Sequence[HexHighlightRegion]:
        """
        Return the highlight regions under the cursor.
        """
        return self.get_highlight_regions_at_addr(self.cursor)

    def set_cursor(
        self, addr: int, ascii_column: bool | None = None, nibble: int | None = None, update_viewport: bool = True
    ) -> None:
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
        if cursor_changed:
            if update_viewport:
                self.move_viewport_to(addr)
            self.cursor = addr
        self.cursor_nibble = nibble
        self.cursor_changed.emit()
        self.update_active_highlight_regions()
        self.update()
        self._processing_cursor_update = False

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        """
        Handle mouse press events (e.g. updating selection).
        """
        if event.button() == Qt.MouseButton.LeftButton:
            addr = self.point_to_addr(event.pos())
            if addr is None:
                return
            addr, ascii_column = addr
            self.mouse_pressed = True
            if QApplication.keyboardModifiers() in (Qt.KeyboardModifier.ShiftModifier,):
                if self.selection_start is None:
                    self.begin_selection()
            else:
                self.clear_selection()
            self.set_cursor(addr, ascii_column)
            event.accept()

    def mouseDoubleClickEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        """
        Handle mouse double-click events (e.g. update selection)
        """
        if event.button() == Qt.MouseButton.LeftButton:
            regions = sorted(self.get_highlight_regions_under_cursor(), key=lambda r: self.cursor - r.addr)
            if len(regions) > 0:
                region = regions[0]
                self.set_cursor(region.addr + region.size - 1)
                self.begin_selection()
                self.set_cursor(region.addr)

    def mouseMoveEvent(self, event: QGraphicsSceneMouseEvent) -> None:
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

    def mouseReleaseEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        """
        Handle mouse release events.
        """
        if event.button() == Qt.MouseButton.LeftButton:
            self.mouse_pressed = False

    def _set_byte_value(self, value: int) -> None:
        """
        Handle byte modification via user entry.
        """
        if not self.write_func(self.cursor, value):
            return
        self.set_cursor(self.cursor + 1)

    def _set_nibble_value(self, value: int) -> None:
        nibble = 1 if (self.cursor_nibble is None) else self.cursor_nibble
        new_byte_value = self.read_func(self.cursor)
        if not isinstance(new_byte_value, int):
            new_byte_value = 0
        else:
            new_byte_value &= ~(0xF << (nibble * 4))
        new_byte_value |= value << (nibble * 4)
        if not self.write_func(self.cursor, new_byte_value):
            return
        next_nibble = 1 - nibble
        self.set_cursor(self.cursor + next_nibble, nibble=next_nibble)

    def keyPressEvent(self, event: PySide6.QtGui.QKeyEvent) -> None:
        """
        Handle key press events (e.g. moving cursor around).
        """
        movement_keys = {
            Qt.Key.Key_Up: -16,
            Qt.Key.Key_Down: 16,
            Qt.Key.Key_Right: 1,
            Qt.Key.Key_Left: -1,
            Qt.Key.Key_PageUp: 0,
            Qt.Key.Key_PageDown: 0,
            Qt.Key.Key_Home: 0,
            Qt.Key.Key_End: 0,
        }
        if event.key() in movement_keys:
            if QApplication.keyboardModifiers() & Qt.KeyboardModifier.ShiftModifier:
                if self.selection_start is None:
                    self.begin_selection()
            else:
                self.clear_selection()

            # FIXME: When holding Ctrl, only scroll the viewport
            preserve_relative_offset = False
            if event.key() == Qt.Key.Key_PageUp:
                new_cursor = max(self.start_addr, self.cursor - (self.display_num_rows - 1) * 16)
                preserve_relative_offset = True
            elif event.key() == Qt.Key.Key_PageDown:
                new_cursor = min(self.end_addr - 1, self.cursor + (self.display_num_rows - 1) * 16)
                preserve_relative_offset = True
            elif event.key() == Qt.Key.Key_Home:
                new_cursor = max(self.start_addr, self.cursor & ~0xF)
            elif event.key() == Qt.Key.Key_End:
                new_cursor = min(self.end_addr - 1, (self.cursor & ~0xF) + 0xF)
            else:
                new_cursor = self.cursor + movement_keys[event.key()]
            if self.start_addr <= new_cursor < self.end_addr:
                self.move_viewport_to(new_cursor, preserve_relative_offset)
                self.set_cursor(new_cursor, update_viewport=False)
            event.accept()
            return
        elif QApplication.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier:
            if event.key() == Qt.Key.Key_Space:
                self.set_cursor(self.cursor, ascii_column=not self.ascii_column_active)
                event.accept()
                return
        else:
            t = event.text()
            if len(t) == 1:
                if self.ascii_column_active:
                    if t.isascii() and t.isprintable():
                        self._set_byte_value(ord(t))
                        event.accept()
                        return
                else:
                    if t in "0123456789abcdefABCDEF":
                        self._set_nibble_value(int(t, 16))
                        event.accept()
                        return
        super().keyPressEvent(event)

    def _update_layout(self) -> None:
        """
        Update various layout settings based on font and data store
        """
        self.prepareGeometryChange()

        ti = QGraphicsSimpleTextItem()  # Get font metrics using text item
        ti.setFont(self.font)
        ti.setText("0")

        self.row_padding = int(ti.boundingRect().height() * 0.25)
        self.row_height = ti.boundingRect().height() + self.row_padding
        self.char_width = ti.boundingRect().width()
        self.section_space = self.char_width * 4
        self.addr_offset = self.char_width * 1
        self.addr_width = self.char_width * len(f"{self.display_end_addr:8x}")
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

        self.max_x = self.ascii_column_offsets[-1]
        self.max_y = self.display_num_rows * self.row_height

        self.update()

    def build_selection_path(
        self, min_addr: HexAddress, max_addr: HexAddress, ascii_section: bool = False, shrink: float = 0.0
    ) -> QPainterPath:
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
        p = QPointF(
            column_offsets[col_end if num_selected_rows == 1 else 15] + column_width + column_space / 2,
            p.y() + self.row_height,
        )
        trect.setBottomRight(p)
        trect = trect.marginsRemoved(QMarginsF(shrink, shrink, shrink, shrink))

        # Build middle rect
        if num_selected_rows > 2:
            mrect = QRectF()
            p = self.row_to_point(row_start + 1)
            p.setX(column_offsets[0] - column_space / 2)
            mrect.setTopLeft(p)
            p = QPointF(
                column_offsets[15] + column_width + column_space / 2, p.y() + self.row_height * (num_selected_rows - 2)
            )
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
            p = QPointF(column_offsets[col_end] + column_width + column_space / 2, p.y() + self.row_height)
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

    def get_selection(self) -> tuple[int, int] | None:
        """
        Get active selection, returning (minaddr, maxaddr) inclusive.
        """
        if self.selection_start is None:
            return None
        if self.start_addr <= self.cursor < self.end_addr:
            minaddr = min(self.cursor, self.selection_start)
            maxaddr = max(self.cursor, self.selection_start)
            return (minaddr, maxaddr)
        return None

    def toggle_cursor_blink(self) -> None:
        """
        Simply toggles cursor blink status.
        """
        self.cursor_blink_state = not self.cursor_blink_state
        self.update()

    def set_highlight_regions(self, regions: Sequence[HexHighlightRegion]) -> None:
        """
        Sets the list of highlighted regions.
        """
        self.highlighted_regions = regions
        self.update_active_highlight_regions()
        self.update()

    def paint_highlighted_region(self, painter, region: HexHighlightRegion) -> None:
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
        bg = PySide6.QtGui.QLinearGradient(r.topLeft(), r.bottomLeft())
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

    def paint(
        self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget | None = None
    ) -> None:  # pylint: disable=unused-argument
        """
        Repaint the item.
        """
        min_row = self.point_to_row(option.exposedRect.topLeft())
        if min_row is None:
            min_row = 0
        max_row = self.point_to_row(option.exposedRect.bottomLeft())
        if max_row is None:
            max_row = self.display_num_rows - 1

        # Paint background
        painter.setPen(Qt.PenStyle.NoPen)
        for row in range(min_row, max_row + 1):
            row_addr = self.row_to_addr(row)
            if row_addr >= self.display_end_addr:
                break
            pt = self.row_to_point(row)
            painter.setBrush(Conf.palette_base if row_addr & 0x10 else Conf.palette_alternatebase)
            painter.drawRect(QRectF(0, pt.y(), self.boundingRect().width(), self.row_height))

        for region in self.highlighted_regions:
            self.paint_highlighted_region(painter, region)

        # Paint selection
        if self.selection_start is not None:
            minaddr = min(self.cursor, self.selection_start)
            maxaddr = max(self.cursor, self.selection_start)

            pen_width = 1.0
            half_pen_width = pen_width / 2.0

            def set_pen_brush_for_active_selection(active: bool) -> None:
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
            row_addr = self.row_to_addr(row)
            if row_addr >= self.display_end_addr:
                break

            pt = self.row_to_point(row)
            pt.setY(pt.y() + self.row_height - self.row_padding)

            # Paint address
            addr_text = f"{row_addr:08x}"
            pt.setX(self.addr_offset)
            painter.setPen(Conf.disasm_view_node_address_color)
            painter.drawText(pt, addr_text)

            # Paint byte values
            for col in range(16):
                addr = self.row_col_to_addr(row, col)
                if addr < self.display_start_addr or addr >= self.display_end_addr:
                    continue
                val = self.read_func(addr)
                pt.setX(self.byte_column_offsets[col])

                if isinstance(val, int):
                    if is_printable(val):
                        color = Conf.disasm_view_printable_byte_color
                    else:
                        color = Conf.disasm_view_unprintable_byte_color
                    byte_text = f"{val:02x}"
                else:
                    byte_text = val * 2 if isinstance(val, str) and len(val) == 1 else "??"
                    color = Conf.disasm_view_unknown_byte_color

                pt.setX(self.byte_column_offsets[col])
                painter.setPen(color)
                painter.drawText(pt, byte_text)

            # Paint ASCII representation
            for col in range(16):
                addr = self.row_col_to_addr(row, col)
                if addr < self.display_start_addr or addr >= self.display_end_addr:
                    continue
                val = self.read_func(addr)
                pt.setX(self.ascii_column_offsets[col])

                if isinstance(val, int):
                    if is_printable(val):
                        color = Conf.disasm_view_printable_character_color
                        ch = chr(val)
                    else:
                        color = Conf.disasm_view_unprintable_character_color
                        ch = "."
                else:
                    color = Conf.disasm_view_unknown_character_color
                    ch = val if isinstance(val, str) and len(val) == 1 else "?"

                pt.setX(self.ascii_column_offsets[col])
                painter.setPen(color)
                painter.drawText(pt, ch)

        # Paint cursor
        if self.show_cursor and (self.display_start_addr <= self.cursor < self.display_end_addr):
            cursor_height = self.row_padding / 2

            def set_pen_brush_for_active_cursor(active: bool) -> None:
                painter.setPen(Qt.PenStyle.NoPen)
                if active:
                    col = Conf.palette_text if self.cursor_blink_state else Qt.BrushStyle.NoBrush
                else:
                    col = Conf.palette_disabled_text
                painter.setBrush(col)

            # Byte cursor
            set_pen_brush_for_active_cursor(not self.ascii_column_active)
            tl = self.addr_to_point(self.cursor)
            tl.setY(tl.y() + self.row_height - cursor_height)
            cursor_width = self.byte_width
            if self.cursor_nibble is not None:
                cursor_width /= 2
                tl.setX(tl.x() + cursor_width * (1 - self.cursor_nibble))
            painter.drawRect(QRectF(tl, QSizeF(cursor_width, cursor_height)))

            # ASCII cursor
            set_pen_brush_for_active_cursor(self.ascii_column_active)
            tl = self.addr_to_point(self.cursor, True)
            tl.setY(tl.y() + self.row_height - cursor_height)
            painter.drawRect(QRectF(tl, QSizeF(self.ascii_width, cursor_height)))

    def boundingRect(self) -> PySide6.QtCore.QRectF:
        return QRectF(0, 0, self.max_x, self.max_y)

    def on_mouse_move_event_from_view(self, point: QPointF) -> None:
        """
        Highlight memory region under cursor.
        """
        self.setToolTip("")
        addr = self.point_to_addr(point)
        if addr is None:
            return
        addr, _ = addr
        regions = self.get_highlight_regions_at_addr(addr)
        if len(regions):
            t = "\n".join(t for t in [r.get_tooltip() for r in regions] if t)
            self.setToolTip(t)


class HexGraphicsSubView(QGraphicsView):
    """
    Wrapper QGraphicsView used for rendering and event propagation.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.setMouseTracking(True)
        self.setBackgroundBrush(Conf.palette_base)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.NoAnchor)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.NoAnchor)
        self.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

    def wheelEvent(self, event) -> None:
        self.parent().wheelEvent(event)
        super().wheelEvent(event)

    def mouseMoveEvent(self, event) -> None:
        """
        Handle mouse move events.

        Mouse move events whilst not holding a mouse button will not be propagated down to QGraphicsItems, so we catch
        the movement events here in the view and forward them to the feature map item.
        """
        scene_pt = self.mapToScene(event.pos().x(), event.pos().y())
        item_pt = self.mapFromScene(scene_pt)
        self.parent().hex.on_mouse_move_event_from_view(item_pt)
        super().mouseMoveEvent(event)


class HexGraphicsView(QAbstractScrollArea):
    """
    Container view for the HexGraphicsObject.
    """

    cursor_changed = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent=parent)
        self._processing_scroll_event: bool = False

        self._view: QGraphicsView = HexGraphicsSubView(parent=self)
        self._scene: QGraphicsScene = QGraphicsScene(parent=self._view)
        self.hex: HexGraphicsObject = HexGraphicsObject()
        self.hex.cursor_changed.connect(self.on_cursor_changed)
        self._scene.addItem(self.hex)
        self._view.setScene(self._scene)

        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.verticalScrollBar().actionTriggered.connect(self._on_vertical_scroll_bar_triggered)
        self.horizontalScrollBar().actionTriggered.connect(self._on_horizontal_scroll_bar_triggered)
        self._view.setFrameStyle(QFrame.Shape.NoFrame)
        self.setFrameStyle(QFrame.Shape.NoFrame)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._view)
        self.setLayout(layout)

        self.scrollbar_range = 100
        self.verticalScrollBar().setRange(0, self.scrollbar_range)
        self._update_vertical_scrollbar()

    def _update_vertical_scrollbar(self) -> None:
        if self._processing_scroll_event:
            return
        addr_range = (self.hex.end_addr - self.hex.start_addr) >> 4
        if addr_range > 0:
            offset = (self.hex.display_start_addr - self.hex.start_addr) >> 4
            scrollbar_value = (offset + 1) / addr_range
            self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        else:
            scrollbar_value = 0
            self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.verticalScrollBar().setValue(int(scrollbar_value * self.scrollbar_range))

    def _update_horizontal_scrollbar(self) -> None:
        if self._processing_scroll_event:
            return
        hex_rect = self.hex.boundingRect()
        hex_rect.translate(self.hex.pos())
        vp_rect = self._view.sceneRect()
        scroll_range = max(0, int(hex_rect.width()) - int(vp_rect.width()))
        if scroll_range == 0:
            self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        else:
            self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
            self.horizontalScrollBar().setRange(0, scroll_range)
            self.horizontalScrollBar().setPageStep(hex_rect.width() / 10)
            self.horizontalScrollBar().setValue(vp_rect.left())

    def _get_num_rows_visible(self, fully_visible: bool = False):
        num_rows_visible = int(self._view.mapToScene(0, self.viewport().height()).y() / self.hex.row_height)
        if not fully_visible:
            num_rows_visible += 1
        return num_rows_visible

    def update_display_num_rows(self) -> None:
        self.hex.set_display_num_rows(self._get_num_rows_visible())

    def set_display_offset(self, offset: HexAddress) -> None:
        self.hex.set_display_offset(offset)
        self._update_vertical_scrollbar()

    def get_display_start_addr(self) -> HexAddress:
        return self.hex.display_start_addr

    def set_display_start_addr(self, start: HexAddress) -> None:
        self.set_display_offset(start - self.hex.start_addr)

    def _on_vertical_scroll_bar_triggered(self, action: int) -> None:
        if self._processing_scroll_event:
            return
        self._processing_scroll_event = True
        action = QAbstractSlider.SliderAction(action)
        if action == QAbstractSlider.SliderAction.SliderSingleStepAdd:
            self.set_display_offset(self.hex.display_offset_addr + 0x10)
        elif action == QAbstractSlider.SliderAction.SliderSingleStepSub:
            self.set_display_offset(self.hex.display_offset_addr - 0x10)
        elif action == QAbstractSlider.SliderAction.SliderPageStepAdd:
            self.set_display_offset(self.hex.display_offset_addr + 0x10)
        elif action == QAbstractSlider.SliderAction.SliderPageStepSub:
            self.set_display_offset(self.hex.display_offset_addr - 0x10)
        elif action == QAbstractSlider.SliderAction.SliderMove:
            addr_range = self.hex.end_addr - self.hex.start_addr
            if addr_range <= 0:
                return

            sb_value = self.verticalScrollBar().value()
            if sb_value < 5:
                sb = 0
            elif sb_value > (self.scrollbar_range - 5):
                sb = 1.0
            else:
                sb = sb_value / self.scrollbar_range
            display_offset_addr = int(sb * addr_range) & ~0xF
            self.set_display_offset(display_offset_addr)
        self._processing_scroll_event = False

    def _on_horizontal_scroll_bar_triggered(self, action: int) -> None:
        self._processing_scroll_event = True
        action = QAbstractSlider.SliderAction(action)
        if action == QAbstractSlider.SliderAction.SliderMove:
            vp = self.viewport().geometry()
            vp.moveTo(0, 0)
            vp = self._view.mapToScene(vp).boundingRect()
            vp.moveTo(self.horizontalScrollBar().value(), 0)
            self._view.setSceneRect(vp)
        self._processing_scroll_event = False

    def wheelEvent(self, event: QWheelEvent) -> None:
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier == Qt.KeyboardModifier.ControlModifier:
            self.adjust_viewport_scale(1.25 if event.angleDelta().y() > 0 else 1 / 1.25)
        else:
            d = event.angleDelta().y()
            if d != 0:
                self.set_display_offset(self.hex.display_offset_addr - 0x10 * d // 32)
        event.accept()

    def update_scene_rect(self) -> None:
        hex_rect = self.hex.boundingRect()
        hex_rect.translate(self.hex.pos())
        cursor_rect = self.hex.addr_to_rect(self.hex.cursor)
        cursor_rect.translate(self.hex.pos())
        vp_rect = self.viewport().geometry()
        vp_rect.moveTo(0, 0)
        vp_rect = self._view.mapToScene(vp_rect).boundingRect()

        if cursor_rect.right() > vp_rect.right():
            dX = vp_rect.right() - cursor_rect.right()  # Scroll right
        elif cursor_rect.left() < vp_rect.left():
            dX = vp_rect.left() - cursor_rect.left()  # Scroll left
        elif vp_rect.width() < hex_rect.width() and vp_rect.right() > hex_rect.right():
            dX = vp_rect.right() - hex_rect.right()  # Reveal left
        elif vp_rect.width() > hex_rect.width():
            dX = vp_rect.left()  # Reveal all
        else:
            dX = 0

        vp_rect.translate(-dX, 0)
        self._view.setSceneRect(vp_rect)
        self._update_horizontal_scrollbar()

    def resizeEvent(self, event: PySide6.QtGui.QResizeEvent) -> None:  # pylint: disable=unused-argument
        self._view.resize(self.viewport().size())
        self.update_scene_rect()
        self.update_display_num_rows()

    def set_region_callback(self, write, mem, addr: int, size: int) -> None:
        """
        Set current buffer.
        """
        self.hex.set_data_callback(write, mem, addr, size)
        self.update_scene_rect()
        self.set_display_offset(0)

    def clear(self) -> None:
        """
        Clear current buffer.
        """
        self.hex.clear()
        self.update_scene_rect()

    def on_cursor_changed(self) -> None:
        """
        Handle cursor change events.
        """
        self.cursor_changed.emit()
        self.update_scene_rect()
        self._update_vertical_scrollbar()

    def adjust_viewport_scale(self, scale: float | None = None) -> None:
        """
        Reset viewport scaling. If `scale` is None, viewport scaling is reset to default.
        """
        if scale is None:
            self._view.resetTransform()
        else:
            self._view.scale(scale, scale)
        self.update_scene_rect()
        self.update_display_num_rows()

    def changeEvent(self, event: QEvent) -> None:
        """
        Redraw on color scheme update.
        """
        if event.type() == QEvent.Type.PaletteChange:
            self._view.setBackgroundBrush(Conf.palette_base)
            self.update()

    def keyPressEvent(self, event: PySide6.QtGui.QKeyEvent) -> None:
        """
        Handle key events.
        """
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier == Qt.KeyboardModifier.ControlModifier:
            if event.key() == Qt.Key.Key_0:
                self.adjust_viewport_scale()
                event.accept()
                return
            elif event.key() == Qt.Key.Key_Equal:
                self.adjust_viewport_scale(1.25)
                event.accept()
                return
            elif event.key() == Qt.Key.Key_Minus:
                self.adjust_viewport_scale(1 / 1.25)
                event.accept()
                return
        super().keyPressEvent(event)


class HexView(SynchronizedInstanceView):
    """
    View and edit memory/object code in classic hex editor format.
    """

    _widgets_initialized: bool = False

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("hex", workspace, default_docking_position, instance)
        self.base_caption: str = "Hex"
        self.smart_highlighting_enabled: bool = True
        self._clipboard = None
        self._cfb_highlights: Sequence[HexHighlightRegion] = []
        self._sync_view_highlights: Sequence[HexHighlightRegion] = []
        self._patch_highlights: Sequence[PatchHighlightRegion] = []
        self._changed_data_highlights: Sequence[HexHighlightRegion] = []
        self._breakpoint_highlights: Sequence[BreakpointHighlightRegion] = []

        self._init_widgets()
        self.instance.cfb.am_subscribe(self._on_cfb_event)
        self.instance.patches.am_subscribe(self._update_highlight_regions_from_patches)
        self.instance.breakpoint_mgr.breakpoints.am_subscribe(self._update_highlight_regions_from_breakpoints)
        self._data_cache = {}

        self._reload_data()

        self._dbg_manager = self.instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    def _on_cfb_event(self, **kwargs) -> None:
        if not kwargs:
            self._reload_data()

    def closeEvent(self, event) -> None:
        self._dbg_watcher.shutdown()
        super().closeEvent(event)

    def _clear_highlights(self) -> None:
        """
        Clear all highlight regions
        """
        self._cfb_highlights = []
        self._sync_view_highlights = []
        self._patch_highlights = []
        self._changed_data_highlights = []
        self._breakpoint_highlights = []

    def _reload_data(self):
        """
        Callback when hex backing data store should be updated.
        """
        self._clear_highlights()
        start = self.inner_widget.get_display_start_addr()
        cursor = self.inner_widget.hex.cursor
        source = self._data_source_combo.currentData()
        if source == HexDataSource.Loader:
            if self.instance.cfb.am_none:
                self.inner_widget.clear()
                return
            loader = self.instance.project.loader
            self.inner_widget.set_region_callback(
                self.project_memory_write_func,
                self.project_memory_read_func,
                loader.min_addr,
                loader.max_addr - loader.min_addr + 1,
            )
            self._update_highlight_regions_from_patches()
        elif source == HexDataSource.Debugger:
            self._data_cache = {}
            self.inner_widget.set_region_callback(
                self.debugger_memory_write_func,
                self.debugger_memory_read_func,
                0,
                0x10000000000000000,  # FIXME: Get actual ranges and add them
            )
        else:
            raise NotImplementedError

        self.inner_widget.set_display_start_addr(start)
        self.inner_widget.hex.set_cursor(cursor)
        self._update_highlight_regions_from_synchronized_views()
        self._update_cfb_highlight_regions()
        self._set_highlighted_regions()

    def _data_source_changed(self, index: int) -> None:  # pylint:disable=unused-argument
        self._reload_data()

    def _on_debugger_state_updated(self) -> None:
        source = self._data_source_combo.currentData()
        if source == HexDataSource.Debugger:
            #
            # Calculate differences in state memory and highlight
            #
            previous_data = self._data_cache
            self._data_cache = {}
            addr = self.inner_widget.hex.display_start_addr
            regions = []
            r = None
            while addr < self.inner_widget.hex.display_end_addr:
                if addr in previous_data:
                    differs = self.debugger_memory_read_func(addr) != previous_data[addr]
                else:
                    differs = False
                if differs:
                    if r is None:
                        r = HexHighlightRegion(Qt.GlobalColor.red, addr, 0)
                        regions.append(r)
                    r.size += 1
                else:
                    r = None
                addr += 1
            self._changed_data_highlights = regions
            self.inner_widget.hex.update()
            self._set_highlighted_regions()

    def debugger_memory_read_func(self, addr: int) -> HexByteValue:
        """
        Callback to populate hex view with bytes from debugger state.
        """
        if addr not in self._data_cache:
            dbg = self.instance.debugger_mgr.debugger
            if dbg.am_none:
                v = "?"
            else:
                state: angr.SimState | None = dbg.simstate
                if state is None:
                    v = "?"
                else:
                    try:
                        r = state.memory.load(addr, 1)
                        v = "S" if r.symbolic else state.solver.eval(r)
                    except Exception:  # pylint:disable=broad-except
                        log.exception("Failed to read @ %#x", addr)
                        v = "?"
            self._data_cache[addr] = v
        return self._data_cache[addr]

    def debugger_memory_write_func(self, addr: int, value: int) -> bool:  # pylint:disable=unused-argument,no-self-use
        """
        Callback to populate hex view with bytes.
        """
        # FIXME: For debuggers that support it, allow editing
        return False

    def project_memory_read_func(self, addr: int) -> HexByteValue:
        """
        Callback to populate hex view with bytes.
        """
        p = self.instance.project

        patches = p.kb.patches.get_all_patches(addr, 1)
        if len(patches) > 0:
            patch = patches[0]
            return patch.new_bytes[addr - patch.addr]

        try:
            return p.loader.memory[addr]
        except KeyError:
            return "?"

    def auto_patch(self, addr: int, new_bytes: bytearray):
        """
        Automatically update or create patches to ensure new_bytes are patched at addr.
        """
        pm = self.instance.project.kb.patches
        max_addr = addr + len(new_bytes) - 1

        for p in pm.get_all_patches(addr, len(new_bytes)):
            patch_max_addr = p.addr + len(p) - 1
            if (p.addr <= addr) and (patch_max_addr >= max_addr):
                # Existing patch contains new patch entirely. Update it.
                p.new_bytes = p.new_bytes[: addr - p.addr] + new_bytes + p.new_bytes[max_addr - p.addr + 1 :]
                return
            elif (p.addr >= addr) and (patch_max_addr <= max_addr):
                # Patch will be entirely overwritten, remove it.
                pm.remove_patch(p.addr)
            elif (p.addr >= addr) and (patch_max_addr > max_addr):
                # Lower portion of patch will be overwritten, shrink patch up.
                pm.remove_patch(p.addr)
                new_p_addr = max_addr + 1
                p.new_bytes = p.new_bytes[(new_p_addr - p.addr) :]
                p.addr = new_p_addr
                pm.add_patch_obj(p)
            elif (p.addr < addr) and (patch_max_addr <= max_addr):
                # Upper portion of patch will be overwritten, shrink patch down.
                pm.remove_patch(p.addr)
                p.new_bytes = p.new_bytes[0 : (addr - p.addr)]
                pm.add_patch_obj(p)
            else:
                raise AssertionError

        # Check to see if we should extend an adjacent patch
        if addr > 0:
            p = pm.get_all_patches(addr - 1, 1)
            if len(p) > 0:
                p = p[0]
                p.new_bytes += new_bytes
                return

        pm.add_patch_obj(Patch(addr, new_bytes))

    def project_memory_write_bytearray(self, addr: int, value: bytearray) -> bool:
        """
        Callback to write array of bytes as patch.
        """
        self.auto_patch(addr, bytearray(value))
        pm = self.instance.project.kb.patches
        pm_notifier = self.instance.patches
        if pm_notifier.am_none:
            pm_notifier.am_obj = pm
        pm_notifier.am_event()
        return True

    def project_memory_write_func(self, addr: int, value: int) -> bool:
        """
        Callback to populate hex view with bytes.
        """
        return self.project_memory_write_bytearray(addr, bytearray([value]))

    def set_smart_highlighting_enabled(self, enable: bool) -> None:
        """
        Control whether smart highlighting is enabled or not.
        """
        self.smart_highlighting_enabled = enable
        self._update_cfb_highlight_regions()

    def _init_widgets(self) -> None:
        """
        Initialize widgets for this view.
        """
        window = QMainWindow()
        window.setWindowFlags(Qt.WindowType.Widget)

        status_bar = QFrame()
        status_lyt = QHBoxLayout()
        status_lyt.setContentsMargins(3, 3, 3, 3)
        status_lyt.setSpacing(3)

        self._status_lbl = QLabel()
        self._status_lbl.setText("Address: ")

        status_lyt.addWidget(self._status_lbl)
        status_lyt.addStretch(0)

        self._data_source_combo = QComboBox(self)
        self._data_source_combo.addItem("Loader", HexDataSource.Loader)
        self._data_source_combo.addItem("Debugger", HexDataSource.Debugger)
        self._data_source_combo.activated.connect(self._data_source_changed)
        status_lyt.addWidget(self._data_source_combo)

        option_btn = QPushButton()
        option_btn.setText("Options")
        option_mnu = QMenu(self)
        smart_hl_act = QAction("Smart &highlighting", self)
        smart_hl_act.setCheckable(True)
        smart_hl_act.setChecked(self.smart_highlighting_enabled)
        smart_hl_act.toggled.connect(self.set_smart_highlighting_enabled)
        option_mnu.addAction(smart_hl_act)
        option_btn.setMenu(option_mnu)
        status_lyt.addWidget(option_btn)

        status_bar.setLayout(status_lyt)

        self.inner_widget = HexGraphicsView(parent=self)
        lyt = QVBoxLayout()
        lyt.addWidget(status_bar)
        lyt.addWidget(self.inner_widget)
        lyt.setContentsMargins(0, 0, 0, 0)
        lyt.setSpacing(0)
        self.setLayout(lyt)
        self.inner_widget.cursor_changed.connect(self.on_cursor_changed)
        self.inner_widget.hex.viewport_changed.connect(self.on_cursor_changed)

        self._widgets_initialized = True

    def revert_selected_patches(self) -> None:
        """
        Revert any selected patches.
        """
        dlg = QMessageBox()
        dlg.setWindowTitle("Revert patches")
        dlg.setText("Are you sure you want to revert selected patches?")
        dlg.setIcon(QMessageBox.Icon.Question)
        dlg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        dlg.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if dlg.exec_() != QMessageBox.StandardButton.Yes:
            return

        selected_regions = self.inner_widget.hex.get_active_highlight_regions()
        for r in selected_regions:
            if isinstance(r, PatchHighlightRegion):
                r.revert()

    def _can_merge_any_selected_patches(self):
        """
        Determine if any of the selected patches can be merged.
        """
        return self._merge_selected_patches(True)

    def _merge_selected_patches(self, trial_only: bool = False) -> bool:
        """
        Merge selected directly-adjacent patches.
        """
        selected_patches = [
            r for r in self.inner_widget.hex.get_active_highlight_regions() if isinstance(r, PatchHighlightRegion)
        ]
        i = 0
        did_patch = False
        while i < (len(selected_patches) - 1):
            patch = selected_patches[i]
            for j, neighbor in enumerate(selected_patches[i + 1 :]):
                if patch.can_merge_with(neighbor):
                    if trial_only:
                        return True
                    patch.merge_with(neighbor)
                    did_patch = True
                else:
                    i = i + j + 1
                    break

        return did_patch

    def _get_num_selected_bytes(self) -> int:
        """
        Determine whether any bytes are selected.
        """
        sel = self.inner_widget.hex.get_selection()
        if sel is None:
            return 0
        minaddr, maxaddr = sel
        num_bytes_selected = maxaddr - minaddr + 1
        return num_bytes_selected

    def _copy_selected_bytes(self) -> None:
        """
        Copy selected bytes to view-only clipboard.
        """
        sel = self.inner_widget.hex.get_selection()
        if sel is None:
            self._clipboard = None
            return

        minaddr, maxaddr = sel
        num_bytes_selected = maxaddr - minaddr + 1

        self._clipboard = bytearray(num_bytes_selected)
        for addr in range(minaddr, maxaddr + 1):
            d = self.project_memory_read_func(addr)  # FIXME: Support multibyte read
            if isinstance(d, int):
                self._clipboard[addr - minaddr] = d

    def _paste_copied_bytes_at_cursor(self) -> None:
        """
        Paste the view-only clipboard contents at cursor location.
        """
        if self._clipboard is None:
            return
        if self._data_source_combo.currentData() == HexDataSource.Loader:
            self.project_memory_write_bytearray(self.inner_widget.hex.cursor, self._clipboard)
        # FIXME: Support pasting data to current debugger state

    def _set_breakpoint(self, bp_type: BreakpointType = BreakpointType.Execute) -> None:
        """
        Set breakpoint at current cursor.
        """
        sel = self.inner_widget.hex.get_selection()
        if sel:
            minaddr, maxaddr = sel
            num_bytes_selected = maxaddr - minaddr + 1
        else:
            minaddr = self.inner_widget.hex.cursor
            num_bytes_selected = 1
        self.instance.breakpoint_mgr.add_breakpoint(Breakpoint(bp_type, minaddr, num_bytes_selected))

    def _get_breakpoint_submenu(self) -> QMenu:
        """
        Get context menu to add new breakpoints.
        """
        mnu = QMenu("Set &breakpoint", self)
        act = QAction("Break on &Execute", mnu)
        act.triggered.connect(functools.partial(self._set_breakpoint, BreakpointType.Execute))
        mnu.addAction(act)
        act = QAction("Break on &Read", mnu)
        act.triggered.connect(functools.partial(self._set_breakpoint, BreakpointType.Read))
        mnu.addAction(act)
        act = QAction("Break on &Write", mnu)
        act.triggered.connect(functools.partial(self._set_breakpoint, BreakpointType.Write))
        mnu.addAction(act)
        return mnu

    def contextMenuEvent(self, event: PySide6.QtGui.QContextMenuEvent) -> None:  # pylint: disable=unused-argument
        """
        Display view context menu.
        """
        mnu = QMenu(self)
        add_sep = False

        # FIXME: This should also go into an Edit menu accessible from the main window
        num_selected_bytes = self._get_num_selected_bytes()
        if num_selected_bytes > 0:
            plural = "s" if num_selected_bytes != 1 else ""
            act = QAction(f"Copy {num_selected_bytes:d} byte{plural}", mnu)
            act.triggered.connect(self._copy_selected_bytes)
            mnu.addAction(act)
            add_sep = True
        if self._clipboard is not None and self._data_source_combo.currentData() == HexDataSource.Loader:
            plural = "s" if len(self._clipboard) != 1 else ""
            act = QAction(f"Paste {len(self._clipboard):d} byte{plural}", mnu)
            act.triggered.connect(self._paste_copied_bytes_at_cursor)
            mnu.addAction(act)
            add_sep = True

        if add_sep:
            mnu.addSeparator()
            add_sep = False

        mnu.addMenu(self._get_breakpoint_submenu())
        mnu.addSeparator()

        # Get context menu for specific item under cursor
        for rgn in self.inner_widget.hex.get_highlight_regions_under_cursor():
            rgn_mnu = rgn.gen_context_menu_actions()
            if rgn_mnu is not None:
                mnu.addMenu(rgn_mnu)
                add_sep = True

        if add_sep:
            mnu.addSeparator()
            add_sep = False

        # Get context menu for groups of items
        selected_regions = self.inner_widget.hex.get_active_highlight_regions()
        if any(isinstance(r, PatchHighlightRegion) for r in selected_regions):
            act = QAction("Merge selected patches", mnu)
            act.triggered.connect(self._merge_selected_patches)
            act.setEnabled(self._can_merge_any_selected_patches())
            mnu.addAction(act)
            act = QAction("Revert selected patches", mnu)
            act.triggered.connect(self.revert_selected_patches)
            mnu.addAction(act)
            add_sep = True

        if add_sep:
            mnu.addSeparator()

        mnu.addMenu(self.get_synchronize_with_submenu())
        mnu.exec_(QCursor.pos())

    def set_cursor(self, addr: int) -> None:
        """
        Move cursor to specific address and clear any active selection.
        """
        self.inner_widget.hex.clear_selection()
        self.inner_widget.hex.set_cursor(addr)

    def on_cursor_changed(self) -> None:
        """
        Handle updates to cursor or viewport.
        """
        self.update_status_text()
        self._update_cfb_highlight_regions()
        self.set_synchronized_cursor_address(self.inner_widget.hex.cursor)
        self.published_view_state.cursors = [self.inner_widget.hex.cursor]
        self.notify_view_state_updated()

    def update_status_text(self) -> None:
        """
        Update status text with current cursor info.
        """
        sel = self.inner_widget.hex.get_selection()
        if sel:
            minaddr, maxaddr = sel
            bytes_selected = maxaddr - minaddr + 1
            plural = "s" if bytes_selected != 1 else ""
            s = f"Address: [{minaddr:08x}, {maxaddr:08x}], {bytes_selected} byte{plural} selected"
        else:
            s = f"Address: {self.inner_widget.hex.cursor:08x}"
        self._status_lbl.setText(s)

    def keyPressEvent(self, event: PySide6.QtGui.QKeyEvent) -> None:
        """
        Handle key events.
        """
        if event.key() == Qt.Key.Key_G:
            self.popup_jumpto_dialog()
            return

        super().keyPressEvent(event)

    def popup_jumpto_dialog(self) -> None:
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

    def on_synchronized_view_group_changed(self) -> None:
        """
        Handle view being added to or removed from the view synchronization group.
        """
        if self._widgets_initialized:
            self.inner_widget.hex.set_always_show_cursor(len(self.sync_state.views) > 1)

    def on_synchronized_highlight_regions_changed(self) -> None:
        """
        Handle synchronized highlight region change event.
        """
        self._update_highlight_regions_from_synchronized_views()

    def _update_cfb_highlight_regions(self) -> None:
        """
        Update cached list of highlight regions under cursor.
        """
        regions = []
        cfb = self.instance.cfb
        if self.smart_highlighting_enabled and not cfb.am_none:
            for item in cfb.floor_items(self.inner_widget.hex.display_start_addr):
                item_addr, item = item
                if item.size is None:
                    continue
                if (item_addr + item.size) < self.inner_widget.hex.display_start_addr:
                    continue
                if item_addr >= self.inner_widget.hex.display_end_addr:
                    break
                if isinstance(item, MemoryData):
                    is_string = item.sort in (MemoryDataSort.String, MemoryDataSort.UnicodeString)
                    color = Conf.hex_view_string_color if is_string else Conf.hex_view_data_color
                    regions.append(HexHighlightRegion(color, item.addr, item.size, str(item)))
                elif isinstance(item, Block):
                    try:
                        for insn in item.disassembly.insns:
                            s = f"{insn} in {item}"
                            regions.append(
                                HexHighlightRegion(Conf.hex_view_instruction_color, insn.address, insn.size, s)
                            )
                    except angr.errors.SimEngineError:
                        pass  # We may get a node in CFB to a non-decodeable address
        self._cfb_highlights = regions
        self._set_highlighted_regions()

    def _update_highlight_regions_from_synchronized_views(self) -> None:
        """
        Update cached list of highlight regions from synchronized views.
        """
        regions = []
        for v in self.sync_state.highlight_regions:
            if v is not self:
                for r in self.sync_state.highlight_regions[v]:
                    regions.append(HexHighlightRegion(Qt.GlobalColor.green, r.addr, r.size))

        self._sync_view_highlights = regions
        self._set_highlighted_regions()

    def _update_highlight_regions_from_patches(self, **_) -> None:
        """
        Updates cached list of highlight regions from patches.
        """
        if self.instance.project.am_none:
            self._patch_highlights = []
        else:
            self._patch_highlights = [
                PatchHighlightRegion(patch, self) for patch in self.instance.project.kb.patches.values()
            ]
        self._set_highlighted_regions()

    def _update_highlight_regions_from_breakpoints(self, **kwargs) -> None:  # pylint:disable=unused-argument
        """
        Updates cached list of highlight regions from breakpoints.
        """
        if self.instance.project.am_none:
            self._breakpoint_highlights = []
        else:
            self._breakpoint_highlights = [
                BreakpointHighlightRegion(bp, self) for bp in self.instance.breakpoint_mgr.breakpoints
            ]
        self._set_highlighted_regions()

    def _set_highlighted_regions(self) -> None:
        """
        Update highlighted regions, with data from CFB and synchronized views.
        """
        regions = []
        regions.extend(self._cfb_highlights)
        regions.extend(self._sync_view_highlights)
        source = self._data_source_combo.currentData()
        if source == HexDataSource.Loader:
            regions.extend(self._patch_highlights)
        elif source == HexDataSource.Debugger:
            regions.extend(self._changed_data_highlights)
        regions.extend(self._breakpoint_highlights)
        self.inner_widget.hex.set_highlight_regions(regions)
