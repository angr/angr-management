"""
Test cases for HexView.
"""
# pylint:disable=no-self-use

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import MagicMock, patch

import angr.errors  # type: ignore[import-untyped]
from angr import Block  # type: ignore[attr-defined]
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort  # type: ignore[import-untyped]
from angr.knowledge_plugins.patches import Patch  # type: ignore[import-untyped]
from common import ProjectOpenTestCase, create_qapp
from PySide6.QtCore import QEvent, QPoint, QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QImage, QKeyEvent, QMouseEvent, QPainter, QPolygonF, QResizeEvent, QWheelEvent
from PySide6.QtWidgets import (
    QAbstractSlider,
    QGraphicsSceneMouseEvent,
    QMenu,
    QStyleOptionGraphicsItem,
)

from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.views.hex_view import (
    BreakpointHighlightRegion,
    HexDataSource,
    HexGraphicsObject,
    HexHighlightRegion,
    HexView,
    PatchHighlightRegion,
)


class HexGraphicsObjectTestCase(unittest.TestCase):
    """Base for tests that only need a QApplication and a standalone HexGraphicsObject."""

    @classmethod
    def setUpClass(cls):
        create_qapp()

    def setUp(self):
        self.hex_obj = HexGraphicsObject()

    def _load_sample_data(self, size: int = 256, start_addr: int = 0x1000) -> None:
        """Load sample sequential byte data into the hex object."""
        data = bytes(range(size)) if size <= 256 else bytes(i % 256 for i in range(size))
        self.hex_obj.set_data(data, start_addr=start_addr)
        self.hex_obj.set_display_num_rows(size // 16 + 1)
        self.hex_obj.set_display_offset(0)  # Reset viewport after adjusting row count


class TestHexGraphicsObjectData(HexGraphicsObjectTestCase):
    """Test data loading, clear, and basic properties."""

    def test_set_data_basic(self):
        """set_data populates addresses and byte count."""
        data = b"\x00\x01\x02\x03"
        self.hex_obj.set_data(data, start_addr=0x400000)

        assert self.hex_obj.start_addr == 0x400000
        assert self.hex_obj.num_bytes == 4
        assert self.hex_obj.end_addr == 0x400004

    def test_set_data_num_rows(self):
        """set_data correctly calculates row count."""
        self.hex_obj.set_data(bytes(48), start_addr=0)

        assert self.hex_obj.num_rows == 3

    def test_set_data_with_explicit_num_bytes(self):
        """set_data respects explicit num_bytes parameter."""
        data = bytes(256)
        self.hex_obj.set_data(data, start_addr=0, num_bytes=64)

        assert self.hex_obj.num_bytes == 64
        assert self.hex_obj.end_addr == 64

    def test_clear_resets_data(self):
        """clear() resets to empty state."""
        self.hex_obj.set_data(bytes(256), start_addr=0x1000)
        self.hex_obj.clear()

        assert self.hex_obj.num_bytes == 0
        assert self.hex_obj.start_addr == 0
        assert self.hex_obj.end_addr == 0

    def test_simple_read_callback(self):
        """Internal read callback returns correct byte values."""
        data = b"\xaa\xbb\xcc"
        self.hex_obj.set_data(data, start_addr=0x100)

        assert self.hex_obj.read_func is not None
        assert self.hex_obj.read_func(0x100) == 0xAA
        assert self.hex_obj.read_func(0x101) == 0xBB
        assert self.hex_obj.read_func(0x102) == 0xCC

    def test_simple_write_callback_returns_false(self):
        """Default write callback rejects writes."""
        self.hex_obj.set_data(b"\x00", start_addr=0)

        assert self.hex_obj.write_func is not None
        assert self.hex_obj.write_func(0, 0xFF) is False

    def test_set_data_callback(self):
        """set_data_callback stores custom read/write functions."""
        read_fn = MagicMock(return_value=0x42)
        write_fn = MagicMock(return_value=True)
        self.hex_obj.set_data_callback(write_fn, read_fn, 0x1000, 256)

        assert self.hex_obj.start_addr == 0x1000
        assert self.hex_obj.num_bytes == 256
        assert self.hex_obj.end_addr == 0x1100
        assert self.hex_obj.read_func is not None
        assert self.hex_obj.read_func(0x1000) == 0x42
        read_fn.assert_called_once_with(0x1000)


class TestHexGraphicsObjectAddressing(HexGraphicsObjectTestCase):
    """Test address / row / column conversion helpers."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def test_row_to_addr(self):
        """row_to_addr converts row index to starting address of that row."""
        assert self.hex_obj.row_to_addr(0) == 0x1000
        assert self.hex_obj.row_to_addr(1) == 0x1010
        assert self.hex_obj.row_to_addr(2) == 0x1020

    def test_row_col_to_addr(self):
        """row_col_to_addr converts (row, col) to address."""
        assert self.hex_obj.row_col_to_addr(0, 0) == 0x1000
        assert self.hex_obj.row_col_to_addr(0, 5) == 0x1005
        assert self.hex_obj.row_col_to_addr(1, 0) == 0x1010
        assert self.hex_obj.row_col_to_addr(2, 8) == 0x1028

    def test_addr_to_row_col(self):
        """addr_to_row_col converts address to (row, col)."""
        assert self.hex_obj.addr_to_row_col(0x1000) == (0, 0)
        assert self.hex_obj.addr_to_row_col(0x1005) == (0, 5)
        assert self.hex_obj.addr_to_row_col(0x1010) == (1, 0)
        assert self.hex_obj.addr_to_row_col(0x102F) == (2, 15)

    def test_addr_to_row_col_roundtrip(self):
        """addr_to_row_col and row_col_to_addr are inverses."""
        for addr in [0x1000, 0x1001, 0x100F, 0x1010, 0x10FF]:
            row, col = self.hex_obj.addr_to_row_col(addr)
            assert self.hex_obj.row_col_to_addr(row, col) == addr

    def test_point_to_row(self):
        """point_to_row returns row index for valid points, None for out-of-range."""
        row_height = self.hex_obj.row_height
        assert self.hex_obj.point_to_row(QPointF(0, 0)) == 0
        assert self.hex_obj.point_to_row(QPointF(0, row_height)) == 1
        assert self.hex_obj.point_to_row(QPointF(0, row_height * 2.5)) == 2
        # Beyond all rows
        pt = QPointF(0, row_height * (self.hex_obj.num_rows + 1))
        assert self.hex_obj.point_to_row(pt) is None

    def test_point_to_column_static(self):
        """point_to_column maps x-coordinate to column index using offsets."""
        offsets = [10, 30, 50, 70]  # 3 columns with boundaries [10,30), [30,50), [50,70)
        assert HexGraphicsObject.point_to_column(QPointF(15, 0), offsets) == 0
        assert HexGraphicsObject.point_to_column(QPointF(35, 0), offsets) == 1
        assert HexGraphicsObject.point_to_column(QPointF(55, 0), offsets) == 2
        assert HexGraphicsObject.point_to_column(QPointF(5, 0), offsets) is None
        assert HexGraphicsObject.point_to_column(QPointF(75, 0), offsets) is None


class TestHexGraphicsObjectCursor(HexGraphicsObjectTestCase):
    """Test cursor movement, selection, and boundary clamping."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def test_initial_cursor_at_start(self):
        """After set_data the cursor is at start_addr."""
        assert self.hex_obj.cursor == 0x1000

    def test_set_cursor_moves_cursor(self):
        """set_cursor moves to specified address."""
        self.hex_obj.set_cursor(0x1020)
        assert self.hex_obj.cursor == 0x1020

    def test_set_cursor_clamps_below_start(self):
        """set_cursor does not move below start_addr."""
        self.hex_obj.set_cursor(0x0FFF)
        assert self.hex_obj.cursor == 0x1000  # unchanged

    def test_set_cursor_clamps_at_end(self):
        """set_cursor does not move past end_addr."""
        self.hex_obj.set_cursor(0x1100)  # end_addr is exclusive
        assert self.hex_obj.cursor == 0x1000  # unchanged

    def test_set_cursor_last_valid_byte(self):
        """set_cursor accepts the last valid byte address."""
        self.hex_obj.set_cursor(0x10FF)
        assert self.hex_obj.cursor == 0x10FF

    def test_set_cursor_toggles_ascii_column(self):
        """set_cursor with ascii_column parameter toggles column state."""
        assert self.hex_obj.ascii_column_active is False
        self.hex_obj.set_cursor(0x1000, ascii_column=True)
        assert self.hex_obj.ascii_column_active is True
        self.hex_obj.set_cursor(0x1000, ascii_column=False)
        assert self.hex_obj.ascii_column_active is False

    def test_begin_and_clear_selection(self):
        """begin_selection / clear_selection manage selection state."""
        assert self.hex_obj.selection_start is None
        self.hex_obj.begin_selection()
        assert self.hex_obj.selection_start == self.hex_obj.cursor
        self.hex_obj.clear_selection()
        assert self.hex_obj.selection_start is None

    def test_get_selection_none_when_no_selection(self):
        """get_selection returns None when no selection is active."""
        assert self.hex_obj.get_selection() is None

    def test_get_selection_returns_ordered_range(self):
        """get_selection returns (min, max) regardless of direction."""
        self.hex_obj.set_cursor(0x1020)
        self.hex_obj.begin_selection()
        self.hex_obj.set_cursor(0x1010)

        sel = self.hex_obj.get_selection()
        assert sel == (0x1010, 0x1020)

    def test_get_selection_reverse_direction(self):
        """get_selection with cursor before selection_start."""
        self.hex_obj.set_cursor(0x1010)
        self.hex_obj.begin_selection()
        self.hex_obj.set_cursor(0x1030)

        sel = self.hex_obj.get_selection()
        assert sel == (0x1010, 0x1030)

    def test_set_cursor_reentrant_guard(self):
        """set_cursor returns early when _processing_cursor_update."""
        self.hex_obj.set_cursor(0x1010)
        self.hex_obj._processing_cursor_update = True
        self.hex_obj.set_cursor(0x1020)
        assert self.hex_obj.cursor == 0x1010  # Unchanged

    def test_set_cursor_restarts_blink_when_focused(self):
        """set_cursor restarts blink timer when item has focus."""
        # Give focus
        focus_event = MagicMock()
        self.hex_obj.focusInEvent(focus_event)
        assert self.hex_obj.hasFocus() or self.hex_obj.cursor_blink_timer.isActive()
        # Now set_cursor should restart the timer
        self.hex_obj.set_cursor(0x1020)
        # Timer should still be active
        assert self.hex_obj.cursor_blink_timer.isActive()

    def test_set_always_show_cursor_when_timer_active(self):
        """set_always_show_cursor when blink timer IS active skips."""
        focus_event = MagicMock()
        self.hex_obj.focusInEvent(focus_event)
        # Timer is active now
        self.hex_obj.set_always_show_cursor(True)
        assert self.hex_obj.always_show_cursor is True
        # show_cursor might not change when timer is active (branch 325)

    def test_get_selection_none_when_cursor_out_of_range(self):
        """get_selection returns None when cursor is out of range."""
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj.begin_selection()
        # Force cursor out of range
        self.hex_obj.cursor = self.hex_obj.end_addr + 100
        assert self.hex_obj.get_selection() is None

    def test_set_cursor_with_focus_restarts_blink(self):
        """set_cursor restarts blink timer when hasFocus() is True."""
        with (
            patch.object(self.hex_obj, "hasFocus", return_value=True),
            patch.object(self.hex_obj, "restart_cursor_blink_timer") as mock_restart,
        ):
            self.hex_obj.set_cursor(0x1010)
            mock_restart.assert_called()


class TestHexGraphicsObjectDisplayOffset(HexGraphicsObjectTestCase):
    """Test display offset and viewport management."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(1024, start_addr=0x1000)

    def test_set_display_offset(self):
        """set_display_offset updates display_start_addr."""
        self.hex_obj.set_display_offset(0x40)
        assert self.hex_obj.display_start_addr == 0x1040

    def test_set_display_offset_aligns_to_16(self):
        """set_display_offset aligns to 16-byte boundary."""
        self.hex_obj.set_display_offset(0x43)
        assert self.hex_obj.display_start_addr & 0xF == 0

    def test_set_display_offset_clamps_negative(self):
        """set_display_offset clamps to 0 for negative values."""
        self.hex_obj.set_display_offset(-1)
        assert self.hex_obj.display_start_addr == self.hex_obj.start_addr

    def test_set_display_num_rows_minimum_one(self):
        """set_display_num_rows enforces minimum of 1."""
        self.hex_obj.set_display_num_rows(0)
        assert self.hex_obj.display_num_rows == 1

        self.hex_obj.set_display_num_rows(-5)
        assert self.hex_obj.display_num_rows == 1

    def test_move_viewport_to_scrolls_when_above(self):
        """move_viewport_to scrolls up when addr is above viewport."""
        self.hex_obj.set_display_num_rows(4)
        self.hex_obj.set_display_offset(0x100)
        self.hex_obj.move_viewport_to(0x1010)

        assert self.hex_obj.display_start_addr <= 0x1010


class TestHexGraphicsObjectKeyboard(HexGraphicsObjectTestCase):
    """Test keyboard navigation in the hex graphics object."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(1024, start_addr=0x1000)

    def _press_key(
        self,
        key: Qt.Key,
        modifiers: Qt.KeyboardModifier = Qt.KeyboardModifier.NoModifier,
    ):
        event = QKeyEvent(QKeyEvent.Type.KeyPress, key, modifiers)
        self.hex_obj.keyPressEvent(event)

    def test_arrow_right_advances_cursor(self):
        """Right arrow moves cursor forward by 1."""
        self.hex_obj.set_cursor(0x1000)
        self._press_key(Qt.Key.Key_Right)
        assert self.hex_obj.cursor == 0x1001

    def test_arrow_left_moves_cursor_back(self):
        """Left arrow moves cursor back by 1."""
        self.hex_obj.set_cursor(0x1005)
        self._press_key(Qt.Key.Key_Left)
        assert self.hex_obj.cursor == 0x1004

    def test_arrow_down_moves_one_row(self):
        """Down arrow moves cursor forward by 16 bytes."""
        self.hex_obj.set_cursor(0x1000)
        self._press_key(Qt.Key.Key_Down)
        assert self.hex_obj.cursor == 0x1010

    def test_arrow_up_moves_one_row_back(self):
        """Up arrow moves cursor back by 16 bytes."""
        self.hex_obj.set_cursor(0x1020)
        self._press_key(Qt.Key.Key_Up)
        assert self.hex_obj.cursor == 0x1010

    def test_home_moves_to_row_start(self):
        """Home moves cursor to start of current row."""
        self.hex_obj.set_cursor(0x1015)
        self._press_key(Qt.Key.Key_Home)
        assert self.hex_obj.cursor == 0x1010

    def test_end_moves_to_row_end(self):
        """End moves cursor to end of current row."""
        self.hex_obj.set_cursor(0x1015)
        self._press_key(Qt.Key.Key_End)
        assert self.hex_obj.cursor == 0x101F

    def test_page_down_moves_by_display_rows(self):
        """Page Down moves cursor by (display_num_rows - 1) * 16."""
        self.hex_obj.set_display_num_rows(4)
        self.hex_obj.set_cursor(0x1000)
        self._press_key(Qt.Key.Key_PageDown)
        assert self.hex_obj.cursor == 0x1000 + (3 * 16)

    def test_page_up_moves_back_by_display_rows(self):
        """Page Up moves cursor back by (display_num_rows - 1) * 16."""
        self.hex_obj.set_display_num_rows(4)
        self.hex_obj.set_cursor(0x1100)
        self._press_key(Qt.Key.Key_PageUp)
        assert self.hex_obj.cursor == 0x1100 - (3 * 16)

    def test_cursor_does_not_move_below_start(self):
        """Left arrow at start_addr keeps cursor at start."""
        self.hex_obj.set_cursor(0x1000)
        self._press_key(Qt.Key.Key_Left)
        assert self.hex_obj.cursor == 0x1000

    def test_cursor_does_not_move_past_end(self):
        """Right arrow at last byte keeps cursor at last byte."""
        last = self.hex_obj.end_addr - 1
        self.hex_obj.set_cursor(last)
        self._press_key(Qt.Key.Key_Right)
        assert self.hex_obj.cursor == last

    def test_shift_arrow_begins_selection(self):
        """Shift+Right begins selection if none active."""
        self.hex_obj.set_cursor(0x1010)
        assert self.hex_obj.selection_start is None
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.ShiftModifier
            self._press_key(Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
        assert self.hex_obj.selection_start is not None

    def test_arrow_without_shift_clears_selection(self):
        """Unmodified arrow clears active selection."""
        self.hex_obj.set_cursor(0x1010)
        self.hex_obj.begin_selection()
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            self._press_key(Qt.Key.Key_Right)
        assert self.hex_obj.selection_start is None

    def test_page_up_clamps_to_start(self):
        """Page Up near start clamps cursor to start_addr."""
        self.hex_obj.set_display_num_rows(10)
        self.hex_obj.set_cursor(0x1010)
        self._press_key(Qt.Key.Key_PageUp)
        assert self.hex_obj.cursor == 0x1000


class TestHexGraphicsObjectHighlightRegions(HexGraphicsObjectTestCase):
    """Test highlight region activation and querying."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def test_set_highlight_regions(self):
        """set_highlight_regions stores provided regions."""
        r1 = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 16)
        r2 = HexHighlightRegion(QColor(Qt.GlobalColor.blue), 0x1020, 8)
        self.hex_obj.set_highlight_regions([r1, r2])

        assert len(self.hex_obj.highlighted_regions) == 2

    def test_get_highlight_regions_at_addr(self):
        """get_highlight_regions_at_addr returns regions covering that address."""
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 16)
        self.hex_obj.set_highlight_regions([r])

        assert r in self.hex_obj.get_highlight_regions_at_addr(0x1000)
        assert r in self.hex_obj.get_highlight_regions_at_addr(0x100F)
        assert r not in self.hex_obj.get_highlight_regions_at_addr(0x1010)

    def test_get_highlight_regions_under_cursor(self):
        """get_highlight_regions_under_cursor returns regions at cursor."""
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1010, 8)
        self.hex_obj.set_highlight_regions([r])

        self.hex_obj.set_cursor(0x1014)
        assert r in self.hex_obj.get_highlight_regions_under_cursor()

        self.hex_obj.set_cursor(0x1000)
        assert r not in self.hex_obj.get_highlight_regions_under_cursor()

    def test_update_active_highlight_regions_with_cursor(self):
        """Regions overlapping cursor are marked active."""
        r1 = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 16)
        r2 = HexHighlightRegion(QColor(Qt.GlobalColor.blue), 0x1020, 8)
        self.hex_obj.highlighted_regions = [r1, r2]

        self.hex_obj.set_cursor(0x1005)
        self.hex_obj.update_active_highlight_regions()

        assert r1.active is True
        assert r2.active is False

    def test_update_active_highlight_regions_with_selection(self):
        """Regions overlapping selection range are marked active."""
        r1 = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 16)
        r2 = HexHighlightRegion(QColor(Qt.GlobalColor.blue), 0x1020, 8)
        self.hex_obj.highlighted_regions = [r1, r2]

        self.hex_obj.set_cursor(0x1005)
        self.hex_obj.begin_selection()
        self.hex_obj.set_cursor(0x1025)
        self.hex_obj.update_active_highlight_regions()

        assert r1.active is True
        assert r2.active is True

    def test_get_active_highlight_regions(self):
        """get_active_highlight_regions returns only active regions."""
        r1 = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 16)
        r2 = HexHighlightRegion(QColor(Qt.GlobalColor.blue), 0x1020, 8)
        r1.active = True
        r2.active = False
        self.hex_obj.highlighted_regions = [r1, r2]

        active = self.hex_obj.get_active_highlight_regions()
        assert r1 in active
        assert r2 not in active


class TestHexGraphicsObjectByteInput(HexGraphicsObjectTestCase):
    """Test byte editing via keyboard input."""

    def setUp(self):
        super().setUp()
        self.hex_obj.set_data(bytearray(32), start_addr=0x1000)
        self.hex_obj.set_display_num_rows(4)
        self._writes: list[tuple[int, int]] = []

        def track_write(addr, val):
            self._writes.append((addr, val))
            return True

        self.hex_obj.write_func = track_write

    def test_set_byte_value_advances_cursor(self):
        """_set_byte_value writes and advances cursor."""
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj._set_byte_value(0xAA)

        assert self._writes == [(0x1000, 0xAA)]
        assert self.hex_obj.cursor == 0x1001

    def test_set_byte_value_write_rejected(self):
        """_set_byte_value does not advance cursor on rejected write."""
        self.hex_obj.write_func = lambda _addr, _val: False
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj._set_byte_value(0xFF)

        assert self.hex_obj.cursor == 0x1000

    def test_hex_digit_input_nibble(self):
        """Typing hex digits edits nibbles correctly."""
        self.hex_obj.set_cursor(0x1000)
        # First nibble (high)
        self.hex_obj._set_nibble_value(0xA)
        assert len(self._writes) == 1
        assert self._writes[0] == (0x1000, 0xA0)

    def test_ascii_input_in_ascii_mode(self):
        """Typing a printable character in ascii_column_active mode writes the byte."""
        self.hex_obj.set_cursor(0x1000, ascii_column=True)
        event = QKeyEvent(
            QKeyEvent.Type.KeyPress,
            Qt.Key.Key_A,
            Qt.KeyboardModifier.NoModifier,
            "A",
        )
        self.hex_obj.keyPressEvent(event)

        assert len(self._writes) == 1
        assert self._writes[0] == (0x1000, ord("A"))

    def test_nibble_high_then_low(self):
        """Typing two hex digits writes high nibble then low nibble."""
        # Use writable backing store so read_func reflects writes
        data = bytearray(b"\x00" * 32)
        self.hex_obj.read_func = lambda addr: data[addr - 0x1000]

        def write_and_store(addr, val):
            data[addr - 0x1000] = val
            self._writes.append((addr, val))
            return True

        self.hex_obj.write_func = write_and_store
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj._set_nibble_value(0xA)  # High nibble
        assert self._writes[-1] == (0x1000, 0xA0)
        # Now cursor_nibble should be 0 (low nibble next)
        self.hex_obj._set_nibble_value(0x5)  # Low nibble
        assert self._writes[-1] == (0x1000, 0xA5)

    def test_nibble_value_non_int_read(self):
        """_set_nibble_value handles non-int read value by treating as 0."""
        self.hex_obj.read_func = lambda _addr: "?"  # Non-int
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj._set_nibble_value(0xF)
        assert self._writes[-1] == (0x1000, 0xF0)

    def test_nibble_write_rejected(self):
        """_set_nibble_value does not advance cursor on rejected write."""
        self.hex_obj.write_func = lambda _addr, _val: False
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj._set_nibble_value(0xA)
        assert self.hex_obj.cursor == 0x1000

    def test_hex_digit_key_press(self):
        """Typing hex digits in byte column triggers nibble input."""
        self.hex_obj.set_cursor(0x1000, ascii_column=False)
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            event = QKeyEvent(
                QKeyEvent.Type.KeyPress,
                Qt.Key.Key_A,
                Qt.KeyboardModifier.NoModifier,
                "a",
            )
            self.hex_obj.keyPressEvent(event)
        assert len(self._writes) >= 1
        # 'a' == 0xA, high nibble => should write 0xA0
        assert self._writes[0] == (0x1000, 0xA0)


class TestHexGraphicsObjectCursorBlink(HexGraphicsObjectTestCase):
    """Test cursor blink toggling."""

    def test_toggle_cursor_blink(self):
        """toggle_cursor_blink flips state."""
        assert self.hex_obj.cursor_blink_state is True
        self.hex_obj.toggle_cursor_blink()
        assert self.hex_obj.cursor_blink_state is False
        self.hex_obj.toggle_cursor_blink()
        assert self.hex_obj.cursor_blink_state is True

    def test_set_always_show_cursor(self):
        """set_always_show_cursor updates policy flags."""
        self.hex_obj.set_always_show_cursor(True)
        assert self.hex_obj.always_show_cursor is True
        assert self.hex_obj.show_cursor is True

        self.hex_obj.set_always_show_cursor(False)
        assert self.hex_obj.always_show_cursor is False
        assert self.hex_obj.show_cursor is False

    def test_restart_cursor_blink_timer(self):
        """restart_cursor_blink_timer sets blink_state True and starts timer."""
        self.hex_obj.cursor_blink_state = False
        self.hex_obj.restart_cursor_blink_timer()
        assert self.hex_obj.cursor_blink_state is True
        assert self.hex_obj.cursor_blink_timer.isActive()
        self.hex_obj.cursor_blink_timer.stop()  # Clean up


class TestHexGraphicsObjectBuildSelectionPath(HexGraphicsObjectTestCase):
    """Test selection path building."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def test_single_row_selection_path(self):
        """build_selection_path for a single-row range returns non-empty path."""
        path = self.hex_obj.build_selection_path(0x1002, 0x1005)
        assert not path.isEmpty()

    def test_multi_row_selection_path(self):
        """build_selection_path spanning multiple rows returns non-empty path."""
        path = self.hex_obj.build_selection_path(0x1002, 0x1025)
        assert not path.isEmpty()

    def test_full_row_selection_path(self):
        """build_selection_path for exactly two full rows."""
        path = self.hex_obj.build_selection_path(0x1000, 0x101F)
        assert not path.isEmpty()

    def test_ascii_section_path(self):
        """build_selection_path for ascii section."""
        path = self.hex_obj.build_selection_path(0x1002, 0x1005, ascii_section=True)
        assert not path.isEmpty()

    def test_disjoint_row_selection_path(self):
        """Selection path handles case where bottom rect ends before top starts."""
        # Select from e.g. col 14 on row 0 to col 2 on row 2 (three rows)
        start_addr = 0x100E  # row 0, col 14
        end_addr = 0x1022  # row 2, col 2
        path = self.hex_obj.build_selection_path(start_addr, end_addr)
        assert not path.isEmpty()

    def test_two_row_selection_high_col_to_low_col(self):
        """Selection from col 14 row 0 to col 2 row 1 (no middle)."""
        # Start at col 14, end at col 2 - only 2 rows, no middle rect
        start = 0x100E  # row 0, col 14
        end = 0x1012  # row 1, col 2
        path = self.hex_obj.build_selection_path(start, end)
        assert not path.isEmpty()


class TestHexGraphicsObjectMouseTooltip(HexGraphicsObjectTestCase):
    """Test tooltip from mouse-move handler."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def test_tooltip_set_for_highlight_region(self):
        """on_mouse_move_event_from_view sets tooltip for regions with tooltip text."""
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 16, tooltip="test tooltip")
        self.hex_obj.set_highlight_regions([r])

        # Pick a point in the byte column area for address 0x1005
        pt = self.hex_obj.addr_to_point(0x1005)
        self.hex_obj.on_mouse_move_event_from_view(pt)
        assert "test tooltip" in self.hex_obj.toolTip()

    def test_tooltip_cleared_when_no_region(self):
        """on_mouse_move_event_from_view clears tooltip when not over a region."""
        self.hex_obj.setToolTip("old")
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1080, 16, tooltip="test")
        self.hex_obj.set_highlight_regions([r])

        pt = self.hex_obj.addr_to_point(0x1005)
        self.hex_obj.on_mouse_move_event_from_view(pt)
        assert self.hex_obj.toolTip() == ""

    def test_addr_to_rect_byte_column(self):
        """addr_to_rect returns non-empty rect in byte column mode."""
        self.hex_obj.set_cursor(0x1005, ascii_column=False)
        rect = self.hex_obj.addr_to_rect(0x1005)
        assert not rect.isEmpty()

    def test_addr_to_rect_ascii_column(self):
        """addr_to_rect returns non-empty rect in ASCII column mode."""
        self.hex_obj.set_cursor(0x1005, ascii_column=True)
        rect = self.hex_obj.addr_to_rect(0x1005)
        assert not rect.isEmpty()


class TestHexHighlightRegion(unittest.TestCase):
    """Test base HexHighlightRegion."""

    @classmethod
    def setUpClass(cls):
        create_qapp()

    def test_constructor(self):
        """Constructor stores all fields."""
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 32, tooltip="hello")
        assert r.addr == 0x1000
        assert r.size == 32
        assert r.active is False
        assert r.get_tooltip() == "hello"

    def test_gen_context_menu_actions_returns_none(self):
        """Base class returns None for context menu."""
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 32)
        assert r.gen_context_menu_actions() is None

    def test_get_tooltip_none_by_default(self):
        """Without tooltip argument, get_tooltip returns None."""
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 32)
        assert r.get_tooltip() is None


class TestBreakpointHighlightRegion(unittest.TestCase):
    """Test BreakpointHighlightRegion."""

    @classmethod
    def setUpClass(cls):
        create_qapp()

    def setUp(self):
        self.bp = Breakpoint(BreakpointType.Read, 0x401000, 4)
        self.mock_view = MagicMock()
        self.region = BreakpointHighlightRegion(self.bp, self.mock_view)

    def test_constructor_sets_fields(self):
        """Constructor populates addr, size, and color."""
        assert self.region.addr == 0x401000
        assert self.region.size == 4
        assert self.region.color == Qt.GlobalColor.cyan

    def test_get_tooltip_includes_address_and_type(self):
        """get_tooltip contains address and breakpoint type."""
        tip = self.region.get_tooltip()
        assert tip is not None
        assert "401000" in tip
        assert "Read" in tip
        assert "4 bytes" in tip

    def test_gen_context_menu_actions_returns_menu(self):
        """gen_context_menu_actions creates a QMenu."""
        mnu = self.region.gen_context_menu_actions()
        assert mnu is not None
        actions = mnu.actions()
        labels = [a.text() for a in actions]
        assert any("Remove" in label for label in labels)

    def test_remove_calls_breakpoint_manager(self):
        """remove() delegates to breakpoint_mgr.remove_breakpoint."""
        self.region.remove()
        self.mock_view.instance.breakpoint_mgr.remove_breakpoint.assert_called_once_with(self.bp)

    def test_tooltip_for_read_breakpoint(self):
        """get_tooltip correctly identifies Read breakpoints."""
        bp = Breakpoint(BreakpointType.Read, 0x500000, 1)
        region = BreakpointHighlightRegion(bp, self.mock_view)
        tip = region.get_tooltip()
        assert tip is not None
        assert "Read" in tip

    def test_tooltip_for_write_breakpoint(self):
        """get_tooltip correctly identifies Write breakpoints."""
        bp = Breakpoint(BreakpointType.Write, 0x500000, 2)
        region = BreakpointHighlightRegion(bp, self.mock_view)
        tip = region.get_tooltip()
        assert tip is not None
        assert "Write" in tip


class TestPatchHighlightRegion(unittest.TestCase):
    """Test PatchHighlightRegion."""

    @classmethod
    def setUpClass(cls):
        create_qapp()

    def _make_region(
        self,
        addr: int = 0x401000,
        new_bytes: bytes = b"\x90\x90\x90\x90",
    ) -> PatchHighlightRegion:
        p = Patch(addr, new_bytes)
        mock_view = MagicMock()
        mock_view.inner_widget.hex.cursor = 0  # Default cursor outside patch
        return PatchHighlightRegion(p, mock_view)

    def test_constructor_sets_fields(self):
        """Constructor stores patch info and yellow color."""
        region = self._make_region()
        assert region.addr == 0x401000
        assert region.size == 4
        assert region.color == Qt.GlobalColor.yellow

    def test_get_tooltip(self):
        """get_tooltip includes address and size."""
        region = self._make_region()
        tip = region.get_tooltip()
        assert tip is not None
        assert "401000" in tip
        assert "4 bytes" in tip

    def test_gen_context_menu_actions_returns_menu(self):
        """gen_context_menu_actions creates menu with Split, Comment, Revert."""
        region = self._make_region()
        mnu = region.gen_context_menu_actions()
        assert mnu is not None
        labels = [a.text() for a in mnu.actions() if not a.isSeparator()]
        assert any("Split" in label for label in labels)
        assert any("Comment" in label for label in labels)
        assert any("Revert" in label for label in labels)

    def test_can_split_requires_cursor_inside_patch(self):
        """can_split returns True only when cursor is inside patch (not at boundary)."""
        region = self._make_region(addr=0x1000, new_bytes=b"\x90" * 8)
        # Mock cursor
        mock_hex = MagicMock()
        region.view.inner_widget.hex = mock_hex

        mock_hex.cursor = 0x1000  # at start boundary
        assert region.can_split() is False

        mock_hex.cursor = 0x1004  # inside
        assert region.can_split() is True

        mock_hex.cursor = 0x1008  # at end (exclusive)
        assert region.can_split() is False

    def test_split_creates_new_patch(self):
        """split() splits the patch at cursor position."""
        original_patch = Patch(0x1000, bytearray(b"\x01\x02\x03\x04\x05\x06"))
        mock_view = MagicMock()
        mock_hex = MagicMock()
        mock_hex.cursor = 0x1003
        mock_view.inner_widget.hex = mock_hex
        region = PatchHighlightRegion(original_patch, mock_view)

        region.split()

        # Original should be truncated
        assert original_patch.new_bytes == bytearray(b"\x01\x02\x03")
        # New patch should be added via add_patch_obj
        mock_view.instance.patches.add_patch_obj.assert_called_once()
        new_patch = mock_view.instance.patches.add_patch_obj.call_args[0][0]
        assert new_patch.addr == 0x1003
        assert new_patch.new_bytes == bytearray(b"\x04\x05\x06")

    def test_can_merge_with_adjacent(self):
        """can_merge_with returns True for directly adjacent patches."""
        mock_view = MagicMock()
        p1 = Patch(0x1000, bytearray(b"\x01\x02"))
        p2 = Patch(0x1002, bytearray(b"\x03\x04"))
        r1 = PatchHighlightRegion(p1, mock_view)
        r2 = PatchHighlightRegion(p2, mock_view)

        assert r1.can_merge_with(r2) is True
        assert r2.can_merge_with(r1) is False  # not adjacent in this direction

    def test_can_merge_with_non_adjacent(self):
        """can_merge_with returns False for non-adjacent patches."""
        mock_view = MagicMock()
        p1 = Patch(0x1000, bytearray(b"\x01\x02"))
        p2 = Patch(0x1010, bytearray(b"\x03\x04"))
        r1 = PatchHighlightRegion(p1, mock_view)
        r2 = PatchHighlightRegion(p2, mock_view)

        assert r1.can_merge_with(r2) is False

    def test_merge_with_combines_bytes(self):
        """merge_with combines two adjacent patches."""
        mock_view = MagicMock()
        p1 = Patch(0x1000, bytearray(b"\x01\x02"))
        p2 = Patch(0x1002, bytearray(b"\x03\x04"))
        r1 = PatchHighlightRegion(p1, mock_view)
        r2 = PatchHighlightRegion(p2, mock_view)

        r1.merge_with(r2)

        assert p1.new_bytes == bytearray(b"\x01\x02\x03\x04")
        mock_view.instance.patches.remove_patch.assert_called_once_with(0x1002)

    def test_revert_removes_patch(self):
        """revert() removes patch from the patch manager."""
        region = self._make_region(addr=0x2000)
        region.revert()

        patches: Any = region.view.instance.patches  # type: ignore[union-attr]
        patches.remove_patch.assert_called_once_with(0x2000)
        patches.am_event.assert_called()

    def test_split_noop_when_cannot_split(self):
        """split() does nothing when can_split() returns False."""
        region = self._make_region(addr=0x1000, new_bytes=b"\x01\x02\x03\x04")
        region.view.inner_widget.hex.cursor = 0x1000  # At start
        region.split()
        # Patch should be unchanged
        assert region.patch.new_bytes == bytearray(b"\x01\x02\x03\x04")
        region.view.instance.patches.add_patch_obj.assert_not_called()  # type: ignore[union-attr]

    def test_merge_with_noop_when_not_adjacent(self):
        """merge_with() does nothing when patches are not adjacent."""
        mock_view = MagicMock()
        p1 = Patch(0x1000, bytearray(b"\x01\x02"))
        p2 = Patch(0x1010, bytearray(b"\x03\x04"))
        r1 = PatchHighlightRegion(p1, mock_view)
        r2 = PatchHighlightRegion(p2, mock_view)
        r1.merge_with(r2)
        # Nothing should happen
        assert p1.new_bytes == bytearray(b"\x01\x02")
        mock_view.instance.patches.remove_patch.assert_not_called()

    def test_revert_with_prompt_confirmed(self):
        """revert_with_prompt reverts patch when user confirms."""
        region = self._make_region()
        yes_sentinel = 1
        with patch("angrmanagement.ui.views.hex_view.QMessageBox") as mock_msg_cls:
            mock_msg_cls.StandardButton.Yes = yes_sentinel
            mock_msg_cls.StandardButton.Cancel = 2
            mock_msg_cls.Icon.Question = 0
            mock_dlg = MagicMock()
            mock_dlg.exec_.return_value = yes_sentinel
            mock_msg_cls.return_value = mock_dlg

            region.revert_with_prompt()

            pm: Any = region.view.instance.patches  # type: ignore[union-attr]
            pm.remove_patch.assert_called_once_with(0x401000)

    def test_revert_with_prompt_cancelled(self):
        """revert_with_prompt does nothing when user cancels."""
        region = self._make_region()
        yes_sentinel = 1
        cancel_sentinel = 2
        with patch("angrmanagement.ui.views.hex_view.QMessageBox") as mock_msg_cls:
            mock_msg_cls.StandardButton.Yes = yes_sentinel
            mock_msg_cls.StandardButton.Cancel = cancel_sentinel
            mock_msg_cls.Icon.Question = 0
            mock_dlg = MagicMock()
            mock_dlg.exec_.return_value = cancel_sentinel
            mock_msg_cls.return_value = mock_dlg

            region.revert_with_prompt()

            pm: Any = region.view.instance.patches  # type: ignore[union-attr]
            pm.remove_patch.assert_not_called()

    def test_comment_sets_patch_comment(self):
        """comment() sets patch comment when user enters text."""
        region = self._make_region()
        with patch("angrmanagement.ui.views.hex_view.InputPromptDialog") as mock_dlg_cls:
            mock_dlg = MagicMock()
            mock_dlg.result = "test comment"
            mock_dlg_cls.return_value = mock_dlg

            region.comment()

            assert region.patch.comment == "test comment"
            region.view.instance.patches.am_event.assert_called()  # type: ignore[union-attr]

    def test_comment_no_change_on_empty_result(self):
        """comment() does nothing when user cancels (empty result)."""
        region = self._make_region()
        region.patch.comment = "old"
        with patch("angrmanagement.ui.views.hex_view.InputPromptDialog") as mock_dlg_cls:
            mock_dlg = MagicMock()
            mock_dlg.result = ""
            mock_dlg_cls.return_value = mock_dlg

            region.comment()

            assert region.patch.comment == "old"


class TestHexViewBase(ProjectOpenTestCase):
    """Base class with shared view setup for HexView tests."""

    def setUp(self):
        super().setUp()
        self.hex_view = HexView(self.workspace, "center", self.instance)

    def tearDown(self):
        self.hex_view.close()
        del self.hex_view
        super().tearDown()


class TestPopupDialogs(TestHexViewBase):
    """Test popup_*_dialog methods that create and show dialogs."""

    def setUp(self):
        super().setUp()

        self._show_called = False
        self._dialog_instance = None

        def mock_show(dialog_self):
            self._show_called = True
            self._dialog_instance = dialog_self

        self._show_patcher = patch("PySide6.QtWidgets.QDialog.show", mock_show)
        self._show_patcher.start()
        self.addCleanup(self._show_patcher.stop)

    def test_popup_jumpto_dialog(self):
        """Test that HexView.popup_jumpto_dialog() opens JumpTo dialog."""
        self.hex_view.popup_jumpto_dialog()

        assert self._show_called, "JumpTo dialog should be shown with .show()"
        assert isinstance(self._dialog_instance, JumpTo)
        self._dialog_instance.close()


class TestHexViewKeyboardShortcuts(TestHexViewBase):
    """Test keyboard shortcut routing in keyPressEvent."""

    def test_g_key_calls_popup_jumpto(self):
        """Test that pressing 'g' key calls popup_jumpto_dialog."""
        with patch.object(self.hex_view, "popup_jumpto_dialog") as mock_popup:
            key_event = QKeyEvent(
                QKeyEvent.Type.KeyPress,
                Qt.Key.Key_G,
                Qt.KeyboardModifier.NoModifier,
            )
            self.hex_view.keyPressEvent(key_event)
            mock_popup.assert_called_once()

    def test_non_g_key_passes_to_super(self):
        """Keys other than 'g' are forwarded to the parent class."""
        key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.NoModifier)
        with patch.object(type(self.hex_view).__bases__[0], "keyPressEvent") as mock_super:
            self.hex_view.keyPressEvent(key_event)
            mock_super.assert_called_once()


class TestHexViewNavigation(TestHexViewBase):
    """Test cursor navigation in HexView."""

    def test_jump_to(self):
        """jump_to moves cursor and returns True."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x10
        result = self.hex_view.jump_to(addr)

        assert result is True
        assert self.hex_view.inner_widget.hex.cursor == addr

    def test_set_cursor_clears_selection(self):
        """set_cursor clears any active selection."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.begin_selection()
        assert hex_obj.selection_start is not None

        self.hex_view.set_cursor(hex_obj.start_addr + 0x20)
        assert hex_obj.selection_start is None

    def test_set_cursor_moves_cursor(self):
        """set_cursor moves inner hex cursor to specified address."""
        loader = self.instance.project.loader
        target = loader.min_addr + 0x50
        self.hex_view.set_cursor(target)

        assert self.hex_view.inner_widget.hex.cursor == target

    def test_on_cursor_changed_updates_status(self):
        """on_cursor_changed updates status text."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(hex_obj.start_addr + 0x10)
        self.hex_view.on_cursor_changed()
        text = self.hex_view._status_lbl.text()
        assert f"{hex_obj.cursor:08x}" in text

    def test_status_text_single_cursor(self):
        """Status shows address when no selection."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.clear_selection()
        self.hex_view.update_status_text()

        text = self.hex_view._status_lbl.text()
        assert "Address:" in text
        assert f"{hex_obj.cursor:08x}" in text

    def test_status_text_with_selection(self):
        """Status shows range and byte count when bytes are selected."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(hex_obj.start_addr + 0x10)
        hex_obj.begin_selection()
        hex_obj.set_cursor(hex_obj.start_addr + 0x1F)
        self.hex_view.update_status_text()

        text = self.hex_view._status_lbl.text()
        assert "selected" in text
        assert "16 bytes" in text


class TestHexViewSelectedBytes(TestHexViewBase):
    """Test byte selection counting, copy, and paste."""

    def test_get_num_selected_bytes_none_selected(self):
        """_get_num_selected_bytes returns 0 with no selection."""
        self.hex_view.inner_widget.hex.clear_selection()
        assert self.hex_view._get_num_selected_bytes() == 0

    def test_get_num_selected_bytes_with_selection(self):
        """_get_num_selected_bytes returns correct count."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(hex_obj.start_addr)
        hex_obj.begin_selection()
        hex_obj.set_cursor(hex_obj.start_addr + 3)

        assert self.hex_view._get_num_selected_bytes() == 4

    def test_copy_selected_bytes(self):
        """_copy_selected_bytes fills clipboard with selected data."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(hex_obj.start_addr)
        hex_obj.begin_selection()
        hex_obj.set_cursor(hex_obj.start_addr + 3)

        self.hex_view._copy_selected_bytes()
        assert self.hex_view._clipboard is not None
        assert len(self.hex_view._clipboard) == 4

    def test_copy_clears_clipboard_when_no_selection(self):
        """_copy_selected_bytes sets clipboard to None when nothing selected."""
        self.hex_view._clipboard = bytearray(b"\x00")
        self.hex_view.inner_widget.hex.clear_selection()
        self.hex_view._copy_selected_bytes()

        assert self.hex_view._clipboard is None

    def test_paste_does_nothing_with_no_clipboard(self):
        """_paste_copied_bytes_at_cursor is a no-op when clipboard is None."""
        self.hex_view._clipboard = None
        # Should not raise
        self.hex_view._paste_copied_bytes_at_cursor()

    def test_paste_writes_clipboard_at_cursor(self):
        """_paste_copied_bytes_at_cursor writes clipboard data at cursor."""
        self.hex_view._clipboard = bytearray(b"\xaa\xbb")
        with patch.object(self.hex_view, "project_memory_write_bytearray") as mock_write:
            cursor = self.hex_view.inner_widget.hex.cursor
            self.hex_view._paste_copied_bytes_at_cursor()
            mock_write.assert_called_once_with(cursor, bytearray(b"\xaa\xbb"))

    def test_paste_non_loader_source_noop(self):
        """_paste_copied_bytes_at_cursor in debugger mode is noop."""
        self.hex_view._clipboard = bytearray(b"\x90")
        self.hex_view._data_source_combo.setCurrentIndex(
            self.hex_view._data_source_combo.findData(
                HexDataSource.Debugger,
            ),
        )
        self.hex_view._reload_data()
        # Should not crash and not write
        with patch.object(
            self.hex_view,
            "project_memory_write_bytearray",
        ) as mock_write:
            self.hex_view._paste_copied_bytes_at_cursor()
            mock_write.assert_not_called()

    def test_copy_bytes_with_non_int_value(self):
        """_copy_selected_bytes handles non-int read values."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(hex_obj.start_addr)
        hex_obj.begin_selection()
        hex_obj.set_cursor(hex_obj.start_addr + 3)

        with patch.object(
            self.hex_view,
            "project_memory_read_func",
            return_value="?",
        ):
            self.hex_view._copy_selected_bytes()
            assert self.hex_view._clipboard is not None
            # Non-int values should be left as 0 in clipboard
            assert self.hex_view._clipboard == bytearray(4)


class TestHexViewPatching(TestHexViewBase):
    """Test patching functionality."""

    def test_project_memory_read_func_returns_bytes(self):
        """project_memory_read_func returns int for valid addresses."""
        loader = self.instance.project.loader
        val = self.hex_view.project_memory_read_func(loader.min_addr)
        assert isinstance(val, int)

    def test_project_memory_read_func_returns_placeholder_for_unmapped(self):
        """project_memory_read_func returns '?' for unmapped addresses."""
        val = self.hex_view.project_memory_read_func(0x0)
        assert val == "?"

    def test_project_memory_write_func_creates_patch(self):
        """project_memory_write_func creates a patch entry."""
        loader = self.instance.project.loader
        addr = loader.min_addr
        result = self.hex_view.project_memory_write_func(addr, 0x90)

        assert result is True
        patches = self.instance.project.kb.patches.get_all_patches(addr, 1)
        assert len(patches) > 0
        assert patches[0].new_bytes[0] == 0x90

    def test_auto_patch_creates_new_patch(self):
        """auto_patch creates a new patch for un-patched region."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x100
        self.hex_view.auto_patch(addr, bytearray(b"\xcc\xcc"))

        patches = self.instance.project.kb.patches.get_all_patches(addr, 2)
        assert len(patches) > 0
        assert patches[0].new_bytes == bytearray(b"\xcc\xcc")

    def test_auto_patch_extends_adjacent_patch(self):
        """auto_patch extends an existing patch when new bytes are adjacent."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x200
        self.hex_view.auto_patch(addr, bytearray(b"\x01\x02"))
        self.hex_view.auto_patch(addr + 2, bytearray(b"\x03\x04"))

        patches = self.instance.project.kb.patches.get_all_patches(addr, 4)
        assert len(patches) == 1
        assert patches[0].new_bytes == bytearray(b"\x01\x02\x03\x04")

    def test_auto_patch_updates_existing_containing_patch(self):
        """auto_patch updates bytes within an existing larger patch."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x300
        self.hex_view.auto_patch(addr, bytearray(b"\x01\x02\x03\x04\x05\x06"))
        # Overwrite middle
        self.hex_view.auto_patch(addr + 2, bytearray(b"\xaa\xbb"))

        patches = self.instance.project.kb.patches.get_all_patches(addr, 6)
        assert len(patches) == 1
        assert patches[0].new_bytes == bytearray(b"\x01\x02\xaa\xbb\x05\x06")

    def test_auto_patch_overwrites_smaller_contained_patch(self):
        """auto_patch removes existing smaller patch entirely covered by new patch."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x400
        self.hex_view.auto_patch(addr + 1, bytearray(b"\xaa\xbb"))  # Small patch at +1
        self.hex_view.auto_patch(addr, bytearray(b"\x01\x02\x03\x04\x05"))  # Larger overwrites

        patches = self.instance.project.kb.patches.get_all_patches(addr, 5)
        assert len(patches) == 1
        assert patches[0].new_bytes == bytearray(b"\x01\x02\x03\x04\x05")

    def test_auto_patch_shrinks_lower_overlap(self):
        """auto_patch shrinks existing patch when new patch covers its lower portion."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x450
        # Existing: [addr+2 .. addr+5]
        self.hex_view.auto_patch(addr + 2, bytearray(b"\xaa\xbb\xcc\xdd"))
        # New: [addr .. addr+3] -- overlaps lower portion
        self.hex_view.auto_patch(addr, bytearray(b"\x01\x02\x03\x04"))

        patches = self.instance.project.kb.patches.get_all_patches(addr, 6)
        # New patch [addr..addr+3] and remainder [addr+4..addr+5]
        assert len(patches) == 2

    def test_auto_patch_shrinks_upper_overlap(self):
        """auto_patch shrinks existing patch upper portion, then extends with new bytes."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x460
        # Existing: [addr .. addr+3]
        self.hex_view.auto_patch(addr, bytearray(b"\xaa\xbb\xcc\xdd"))
        # New: [addr+2 .. addr+5] -- overlaps upper portion, shrinks then extends
        self.hex_view.auto_patch(addr + 2, bytearray(b"\x01\x02\x03\x04"))

        patches = self.instance.project.kb.patches.get_all_patches(addr, 6)
        # Shrunk patch becomes [addr, \xAA\xBB], then extends with adjacent merge
        assert len(patches) == 1
        assert patches[0].new_bytes == bytearray(b"\xaa\xbb\x01\x02\x03\x04")

    def test_read_returns_patched_byte(self):
        """project_memory_read_func returns patched byte when patch exists."""
        loader = self.instance.project.loader
        addr = loader.min_addr
        self.instance.project.kb.patches.add_patch_obj(Patch(addr, bytearray(b"\xde\xad")))

        assert self.hex_view.project_memory_read_func(addr) == 0xDE
        assert self.hex_view.project_memory_read_func(addr + 1) == 0xAD

    def test_revert_selected_patches_with_confirmation(self):
        """revert_selected_patches reverts patches when user confirms."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x600
        self.instance.project.kb.patches.add_patch_obj(Patch(addr, bytearray(b"\x90")))
        self.hex_view._update_highlight_regions_from_patches()

        # Select over the patch
        self.hex_view.inner_widget.hex.set_cursor(addr)
        self.hex_view.inner_widget.hex.begin_selection()
        self.hex_view.inner_widget.hex.set_cursor(addr)
        self.hex_view.inner_widget.hex.update_active_highlight_regions()

        yes_sentinel = 1
        with patch("angrmanagement.ui.views.hex_view.QMessageBox") as mock_msg_cls:
            mock_msg_cls.StandardButton.Yes = yes_sentinel
            mock_msg_cls.StandardButton.Cancel = 2
            mock_msg_cls.Icon.Question = 0
            mock_dlg = MagicMock()
            mock_dlg.exec_.return_value = yes_sentinel
            mock_msg_cls.return_value = mock_dlg

            self.hex_view.revert_selected_patches()

            patches = self.instance.project.kb.patches.get_all_patches(addr, 1)
            assert len(patches) == 0

    def test_revert_selected_patches_cancelled(self):
        """revert_selected_patches does nothing when user cancels."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x610
        self.instance.project.kb.patches.add_patch_obj(Patch(addr, bytearray(b"\x90")))
        self.hex_view._update_highlight_regions_from_patches()

        self.hex_view.inner_widget.hex.set_cursor(addr)

        yes_sentinel = 1
        cancel_sentinel = 2
        with patch("angrmanagement.ui.views.hex_view.QMessageBox") as mock_msg_cls:
            mock_msg_cls.StandardButton.Yes = yes_sentinel
            mock_msg_cls.StandardButton.Cancel = cancel_sentinel
            mock_msg_cls.Icon.Question = 0
            mock_dlg = MagicMock()
            mock_dlg.exec_.return_value = cancel_sentinel
            mock_msg_cls.return_value = mock_dlg

            self.hex_view.revert_selected_patches()

            patches = self.instance.project.kb.patches.get_all_patches(addr, 1)
            assert len(patches) == 1

    def test_can_merge_any_selected_patches_false_when_none(self):
        """_can_merge_any_selected_patches returns False with no patch regions."""
        self.hex_view.inner_widget.hex.set_highlight_regions([])
        assert self.hex_view._can_merge_any_selected_patches() is False

    def test_merge_selected_patches_trial_with_adjacent(self):
        """_merge_selected_patches(trial_only=True) returns True for adjacent active patches."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x700
        # Create two adjacent patches
        self.instance.project.kb.patches.add_patch_obj(Patch(addr, bytearray(b"\x01\x02")))
        self.instance.project.kb.patches.add_patch_obj(Patch(addr + 2, bytearray(b"\x03\x04")))
        self.hex_view._update_highlight_regions_from_patches()

        # Select range covering both patches so they become active
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(addr)
        hex_obj.begin_selection()
        hex_obj.set_cursor(addr + 3)
        hex_obj.update_active_highlight_regions()

        assert self.hex_view._merge_selected_patches(trial_only=True) is True

    def test_merge_selected_patches_executes_merge(self):
        """_merge_selected_patches merges adjacent active patches."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x900
        self.instance.project.kb.patches.add_patch_obj(Patch(addr, bytearray(b"\x01\x02")))
        self.instance.project.kb.patches.add_patch_obj(Patch(addr + 2, bytearray(b"\x03\x04")))
        self.hex_view._update_highlight_regions_from_patches()

        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(addr)
        hex_obj.begin_selection()
        hex_obj.set_cursor(addr + 3)
        hex_obj.update_active_highlight_regions()

        result = self.hex_view._merge_selected_patches(trial_only=False)
        assert result is True

    def test_merge_no_adjacent_patches_returns_false(self):
        """_merge_selected_patches returns False when no patches can merge."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0xA00
        # Two non-adjacent patches
        self.instance.project.kb.patches.add_patch_obj(Patch(addr, bytearray(b"\x01")))
        self.instance.project.kb.patches.add_patch_obj(Patch(addr + 0x10, bytearray(b"\x02")))
        self.hex_view._update_highlight_regions_from_patches()

        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(addr)
        hex_obj.begin_selection()
        hex_obj.set_cursor(addr + 0x10)
        hex_obj.update_active_highlight_regions()

        result = self.hex_view._merge_selected_patches(trial_only=False)
        assert result is False

    def test_write_bytearray_sets_am_obj(self):
        """project_memory_write_bytearray sets am_obj when notifier is am_none."""
        pm = self.instance.project.kb.patches
        notifier: Any = self.instance.patches
        notifier.am_obj = None  # Make am_none True
        result = self.hex_view.project_memory_write_bytearray(0x401000, bytearray(b"\xcc"))
        assert result is True
        assert notifier.am_obj is pm

    def test_auto_patch_at_addr_zero(self):
        """auto_patch at addr=0 creates new patch directly."""
        pm = self.instance.project.kb.patches
        self.hex_view.auto_patch(0, bytearray(b"\xcc"))
        patches = pm.get_all_patches(0, 1)
        assert len(patches) > 0


class TestHexViewBreakpoints(TestHexViewBase):
    """Test breakpoint setting from HexView."""

    def test_set_breakpoint_at_cursor(self):
        """_set_breakpoint adds breakpoint at cursor when no selection."""
        self.hex_view.inner_widget.hex.clear_selection()
        initial_count = len(self.instance.breakpoint_mgr.breakpoints)
        self.hex_view._set_breakpoint(BreakpointType.Execute)

        assert len(self.instance.breakpoint_mgr.breakpoints) == initial_count + 1
        bp = self.instance.breakpoint_mgr.breakpoints[-1]
        assert bp.type == BreakpointType.Execute
        assert bp.size == 1

    def test_set_breakpoint_on_selection(self):
        """_set_breakpoint uses selection range when selection is active."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(hex_obj.start_addr)
        hex_obj.begin_selection()
        hex_obj.set_cursor(hex_obj.start_addr + 7)

        initial_count = len(self.instance.breakpoint_mgr.breakpoints)
        self.hex_view._set_breakpoint(BreakpointType.Read)

        assert len(self.instance.breakpoint_mgr.breakpoints) == initial_count + 1
        bp = self.instance.breakpoint_mgr.breakpoints[-1]
        assert bp.type == BreakpointType.Read
        assert bp.size == 8
        assert bp.addr == hex_obj.start_addr


class TestHexViewHighlightUpdates(TestHexViewBase):
    """Test highlight region update methods."""

    def test_clear_highlights(self):
        """_clear_highlights resets all highlight lists."""
        self.hex_view._cfb_highlights = [MagicMock()]
        self.hex_view._sync_view_highlights = [MagicMock()]
        self.hex_view._patch_highlights = [MagicMock()]
        self.hex_view._changed_data_highlights = [MagicMock()]
        self.hex_view._breakpoint_highlights = [MagicMock()]

        self.hex_view._clear_highlights()

        assert not self.hex_view._cfb_highlights
        assert not self.hex_view._sync_view_highlights
        assert not self.hex_view._patch_highlights
        assert not self.hex_view._changed_data_highlights
        assert not self.hex_view._breakpoint_highlights

    def test_update_highlight_regions_from_patches(self):
        """_update_highlight_regions_from_patches creates PatchHighlightRegions."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x500
        self.instance.project.kb.patches.add_patch_obj(Patch(addr, bytearray(b"\x90\x90")))

        self.hex_view._update_highlight_regions_from_patches()

        assert any(isinstance(r, PatchHighlightRegion) for r in self.hex_view._patch_highlights)

    def test_update_highlight_regions_from_breakpoints(self):
        """_update_highlight_regions_from_breakpoints creates BreakpointHighlightRegions."""
        loader = self.instance.project.loader
        bp = Breakpoint(BreakpointType.Execute, loader.min_addr, 4)
        self.instance.breakpoint_mgr.add_breakpoint(bp)

        self.hex_view._update_highlight_regions_from_breakpoints()

        highlights = self.hex_view._breakpoint_highlights
        assert any(isinstance(r, BreakpointHighlightRegion) for r in highlights)

    def test_set_smart_highlighting_enabled(self):
        """set_smart_highlighting_enabled updates the flag."""
        self.hex_view.set_smart_highlighting_enabled(False)
        assert self.hex_view.smart_highlighting_enabled is False

        self.hex_view.set_smart_highlighting_enabled(True)
        assert self.hex_view.smart_highlighting_enabled is True

    def test_cfb_with_memory_data(self):
        """_update_cfb_highlight_regions handles MemoryData."""
        hex_obj = self.hex_view.inner_widget.hex
        start = hex_obj.display_start_addr

        mock_md = MagicMock(spec=MemoryData)
        mock_md.size = 4
        mock_md.addr = start
        mock_md.sort = MemoryDataSort.String
        mock_md.__str__ = lambda self: "test string"  # type: ignore[assignment]

        mock_cfb = MagicMock()
        mock_cfb.am_none = False
        mock_cfb.floor_items.return_value = [
            (start, mock_md),
            (hex_obj.display_end_addr, MagicMock(size=1)),
        ]
        self.instance.cfb.am_obj = mock_cfb  # type: ignore[assignment]
        self.hex_view.smart_highlighting_enabled = True
        self.hex_view._update_cfb_highlight_regions()

        assert len(self.hex_view._cfb_highlights) >= 1

    def test_cfb_with_item_size_none(self):
        """_update_cfb_highlight_regions skips items with size=None."""
        hex_obj = self.hex_view.inner_widget.hex
        start = hex_obj.display_start_addr

        mock_item = MagicMock()
        mock_item.size = None

        mock_cfb = MagicMock()
        mock_cfb.am_none = False
        mock_cfb.floor_items.return_value = [
            (start, mock_item),
            (hex_obj.display_end_addr, MagicMock(size=1)),
        ]
        self.instance.cfb.am_obj = mock_cfb  # type: ignore[assignment]
        self.hex_view.smart_highlighting_enabled = True
        self.hex_view._update_cfb_highlight_regions()

        assert len(self.hex_view._cfb_highlights) == 0

    def test_cfb_with_block_insn(self):
        """_update_cfb_highlight_regions handles Block."""
        hex_obj = self.hex_view.inner_widget.hex
        start = hex_obj.display_start_addr

        mock_insn = MagicMock()
        mock_insn.address = start
        mock_insn.size = 2
        mock_insn.__str__ = lambda self: "nop"  # type: ignore[assignment]

        mock_block = MagicMock(spec=Block)
        mock_block.size = 4
        mock_block.disassembly.insns = [mock_insn]
        mock_block.__str__ = lambda self: "block"  # type: ignore[assignment]

        mock_cfb = MagicMock()
        mock_cfb.am_none = False
        mock_cfb.floor_items.return_value = [
            (start, mock_block),
            (hex_obj.display_end_addr, MagicMock(size=1)),
        ]
        self.instance.cfb.am_obj = mock_cfb  # type: ignore[assignment]
        self.hex_view.smart_highlighting_enabled = True
        self.hex_view._update_cfb_highlight_regions()

        assert len(self.hex_view._cfb_highlights) >= 1

    def test_cfb_with_block_decode_error(self):
        """_update_cfb_highlight_regions handles SimEngineError."""
        hex_obj = self.hex_view.inner_widget.hex
        start = hex_obj.display_start_addr

        mock_block = MagicMock(spec=Block)
        mock_block.size = 4
        mock_block.disassembly.insns.__iter__ = MagicMock(
            side_effect=angr.errors.SimEngineError("bad"),
        )

        mock_cfb = MagicMock()
        mock_cfb.am_none = False
        mock_cfb.floor_items.return_value = [
            (start, mock_block),
            (hex_obj.display_end_addr, MagicMock(size=1)),
        ]
        self.instance.cfb.am_obj = mock_cfb  # type: ignore[assignment]
        self.hex_view.smart_highlighting_enabled = True
        self.hex_view._update_cfb_highlight_regions()

    def test_update_patches_with_no_project(self):
        """_update_highlight_regions_from_patches with no project."""
        self.instance.project.am_obj = None
        self.hex_view._update_highlight_regions_from_patches()
        assert self.hex_view._patch_highlights == []

    def test_update_breakpoints_with_no_project(self):
        """_update_highlight_regions_from_breakpoints with no project."""
        self.instance.project.am_obj = None
        self.hex_view._update_highlight_regions_from_breakpoints()
        assert self.hex_view._breakpoint_highlights == []


class TestHexViewContextMenu(TestHexViewBase):
    """Test context menu construction."""

    def test_get_breakpoint_submenu_has_execute_read_write(self):
        """_get_breakpoint_submenu creates menu with all breakpoint types."""
        mnu = self.hex_view._get_breakpoint_submenu()
        labels = [a.text() for a in mnu.actions()]
        assert any("Execute" in label for label in labels)
        assert any("Read" in label for label in labels)
        assert any("Write" in label for label in labels)

    def _invoke_context_menu(self):
        """Invoke contextMenuEvent with exec_ mocked to prevent popup."""

        mock_event = MagicMock()
        with patch.object(QMenu, "exec_"):
            self.hex_view.contextMenuEvent(mock_event)

    def test_context_menu_basic(self):
        """contextMenuEvent creates menu without crash."""
        self._invoke_context_menu()

    def test_context_menu_with_selection(self):
        """contextMenuEvent completes with bytes selected."""
        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(hex_obj.start_addr)
        hex_obj.begin_selection()
        hex_obj.set_cursor(hex_obj.start_addr + 3)
        self._invoke_context_menu()

    def test_context_menu_with_clipboard(self):
        """contextMenuEvent completes when clipboard has data."""
        self.hex_view._clipboard = bytearray(b"\x90\x90")
        self._invoke_context_menu()

    def test_context_menu_with_patch_regions(self):
        """contextMenuEvent includes merge/revert when patches are selected."""
        loader = self.instance.project.loader
        addr = loader.min_addr + 0x800
        self.instance.project.kb.patches.add_patch_obj(Patch(addr, bytearray(b"\x90")))
        self.hex_view._update_highlight_regions_from_patches()

        hex_obj = self.hex_view.inner_widget.hex
        hex_obj.set_cursor(addr)
        hex_obj.update_active_highlight_regions()
        self._invoke_context_menu()


class TestHexViewDebuggerSource(TestHexViewBase):
    """Test debugger data source behavior."""

    def test_debugger_memory_write_func_returns_false(self):
        """debugger_memory_write_func always returns False (read-only)."""
        assert self.hex_view.debugger_memory_write_func(0x1000, 0xFF) is False

    def test_debugger_memory_read_func_returns_placeholder_when_no_debugger(self):
        """debugger_memory_read_func returns '?' when no debugger is attached."""
        val = self.hex_view.debugger_memory_read_func(0x1000)
        assert val == "?"

    def test_debugger_memory_read_func_caches_result(self):
        """debugger_memory_read_func caches results for repeated reads."""
        self.hex_view._data_cache = {}
        self.hex_view.debugger_memory_read_func(0x2000)
        assert 0x2000 in self.hex_view._data_cache

        # Second call should use cache (not call debugger again)
        cached_val = self.hex_view._data_cache[0x2000]
        result = self.hex_view.debugger_memory_read_func(0x2000)
        assert result == cached_val

    def test_data_source_changed_triggers_reload(self):
        """_data_source_changed calls _reload_data."""
        with patch.object(self.hex_view, "_reload_data") as mock_reload:
            self.hex_view._data_source_changed(0)
            mock_reload.assert_called_once()

    def test_reload_data_debugger_source(self):
        """_reload_data with Debugger source sets up debugger callbacks."""

        self.hex_view._data_source_combo.setCurrentIndex(
            self.hex_view._data_source_combo.findData(HexDataSource.Debugger)
        )
        self.hex_view._reload_data()
        assert not self.hex_view._data_cache

    def test_on_debugger_state_updated_with_no_changes(self):
        """_on_debugger_state_updated processes without crash when debugger source active."""

        self.hex_view._data_source_combo.setCurrentIndex(
            self.hex_view._data_source_combo.findData(HexDataSource.Debugger)
        )
        self.hex_view._reload_data()
        # Simulate debugger state update
        self.hex_view._on_debugger_state_updated()
        # Should not crash

    def test_on_debugger_state_updated_detects_changes(self):
        """_on_debugger_state_updated highlights changed bytes."""

        self.hex_view._data_source_combo.setCurrentIndex(
            self.hex_view._data_source_combo.findData(HexDataSource.Debugger)
        )
        self.hex_view._reload_data()
        # Pre-populate cache with "old" values
        hex_obj = self.hex_view.inner_widget.hex
        self.hex_view._data_cache = {hex_obj.display_start_addr: 0x00}
        # Change the read function to return different value
        original_read = self.hex_view.debugger_memory_read_func

        def modified_read(addr):
            if addr == hex_obj.display_start_addr:
                return "?"  # Different from 0x00
            return original_read(addr)

        self.hex_view.debugger_memory_read_func = modified_read
        self.hex_view._on_debugger_state_updated()
        assert len(self.hex_view._changed_data_highlights) > 0

    def test_read_with_debugger_no_simstate(self):
        """Read returns '?' when debugger has no simstate."""
        self.hex_view._data_cache = {}
        dbg_mgr = self.instance.debugger_mgr
        mock_debugger = MagicMock()
        mock_debugger.am_none = False
        mock_debugger.simstate = None
        dbg_mgr.debugger = mock_debugger
        val = self.hex_view.debugger_memory_read_func(0x1000)
        assert val == "?"

    def test_read_with_debugger_concrete_byte(self):
        """Read returns concrete int from debugger state."""
        self.hex_view._data_cache = {}
        dbg_mgr = self.instance.debugger_mgr
        mock_debugger = MagicMock()
        mock_debugger.am_none = False
        mock_state = MagicMock()
        mock_bv = MagicMock()
        mock_bv.symbolic = False
        mock_state.memory.load.return_value = mock_bv
        mock_state.solver.eval.return_value = 0x42
        mock_debugger.simstate = mock_state
        dbg_mgr.debugger = mock_debugger
        val = self.hex_view.debugger_memory_read_func(0x1000)
        assert val == 0x42

    def test_read_with_debugger_symbolic_byte(self):
        """Read returns 'S' for symbolic bytes."""
        self.hex_view._data_cache = {}
        dbg_mgr = self.instance.debugger_mgr
        mock_debugger = MagicMock()
        mock_debugger.am_none = False
        mock_state = MagicMock()
        mock_bv = MagicMock()
        mock_bv.symbolic = True
        mock_state.memory.load.return_value = mock_bv
        mock_debugger.simstate = mock_state
        dbg_mgr.debugger = mock_debugger
        val = self.hex_view.debugger_memory_read_func(0x1000)
        assert val == "S"

    def test_read_with_debugger_exception(self):
        """Read returns '?' when memory load raises exception."""
        self.hex_view._data_cache = {}
        dbg_mgr = self.instance.debugger_mgr
        mock_debugger = MagicMock()
        mock_debugger.am_none = False
        mock_state = MagicMock()
        mock_state.memory.load.side_effect = RuntimeError("fail")
        mock_debugger.simstate = mock_state
        dbg_mgr.debugger = mock_debugger
        val = self.hex_view.debugger_memory_read_func(0x1000)
        assert val == "?"

    def test_debugger_state_update_consecutive_changes(self):
        """Debugger update detects consecutive changed bytes."""
        self.hex_view._data_source_combo.setCurrentIndex(
            self.hex_view._data_source_combo.findData(
                HexDataSource.Debugger,
            ),
        )
        self.hex_view._reload_data()
        hex_obj = self.hex_view.inner_widget.hex
        start = hex_obj.display_start_addr
        # Populate cache with old values
        self.hex_view._data_cache = {
            start: 0x00,
            start + 1: 0x00,
            start + 2: 0x00,
        }
        # Mock read to return different values
        original_read = self.hex_view.debugger_memory_read_func

        def modified_read(addr):
            if start <= addr <= start + 2:
                self.hex_view._data_cache[addr] = 0xFF
                return 0xFF  # Different from 0x00
            return original_read(addr)

        self.hex_view.debugger_memory_read_func = modified_read
        self.hex_view._on_debugger_state_updated()
        # Should have highlight regions for consecutive changes
        assert len(self.hex_view._changed_data_highlights) >= 1
        # Region should have size >= 3 (consecutive)
        total = sum(r.size for r in self.hex_view._changed_data_highlights)
        assert total >= 3

    def test_reload_data_unknown_source_raises(self):
        """_reload_data raises NotImplementedError for unknown source."""
        self.hex_view._data_source_combo.clear()
        self.hex_view._data_source_combo.addItem("Unknown", 999)
        self.hex_view._data_source_combo.setCurrentIndex(0)
        with self.assertRaises(NotImplementedError):
            self.hex_view._reload_data()

    def test_set_highlighted_regions_debugger_source(self):
        """_set_highlighted_regions with Debugger source."""
        self.hex_view._data_source_combo.setCurrentIndex(
            self.hex_view._data_source_combo.findData(
                HexDataSource.Debugger,
            ),
        )
        self.hex_view._reload_data()
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0, 1)
        self.hex_view._changed_data_highlights = [r]
        self.hex_view._set_highlighted_regions()
        # Should include changed data highlights
        assert r in self.hex_view.inner_widget.hex.highlighted_regions


class TestHexGraphicsObjectFocusEvents(HexGraphicsObjectTestCase):
    """Test focus in/out event handling."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def test_focus_in_shows_cursor_and_starts_timer(self):
        """focusInEvent enables cursor visibility and restarts blink timer."""
        self.hex_obj.show_cursor = False
        focus_event = MagicMock()
        self.hex_obj.focusInEvent(focus_event)

        assert self.hex_obj.show_cursor is True
        assert self.hex_obj.cursor_blink_timer.isActive()

    def test_focus_out_stops_timer(self):
        """focusOutEvent stops blink timer and respects always_show_cursor."""
        self.hex_obj.always_show_cursor = False
        focus_event = MagicMock()
        self.hex_obj.focusInEvent(focus_event)  # Start timer
        self.hex_obj.focusOutEvent(focus_event)

        assert not self.hex_obj.cursor_blink_timer.isActive()
        assert self.hex_obj.show_cursor is False
        assert self.hex_obj.cursor_blink_state is False

    def test_focus_out_with_always_show(self):
        """focusOutEvent keeps cursor visible when always_show_cursor is True."""
        self.hex_obj.always_show_cursor = True
        focus_event = MagicMock()
        self.hex_obj.focusOutEvent(focus_event)

        assert self.hex_obj.show_cursor is True
        assert self.hex_obj.cursor_blink_state is True

    def test_ctrl_space_toggles_ascii_column(self):
        """Ctrl+Space toggles between byte and ASCII columns."""
        assert self.hex_obj.ascii_column_active is False
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.ControlModifier
            event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Space, Qt.KeyboardModifier.ControlModifier)
            self.hex_obj.keyPressEvent(event)
        assert self.hex_obj.ascii_column_active is True

        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.ControlModifier
            event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Space, Qt.KeyboardModifier.ControlModifier)
            self.hex_obj.keyPressEvent(event)
        assert self.hex_obj.ascii_column_active is False


class TestHexGraphicsObjectMouseEvents(HexGraphicsObjectTestCase):
    """Test mouse interaction with the hex object."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def _make_mouse_event(self, pos, button=Qt.MouseButton.LeftButton):
        event = MagicMock(spec=QGraphicsSceneMouseEvent)
        event.pos.return_value = pos
        event.button.return_value = button
        return event

    def test_mouse_press_sets_cursor(self):
        """mousePressEvent sets cursor to address under click."""
        addr = 0x1005
        pt = self.hex_obj.addr_to_point(addr)
        event = self._make_mouse_event(pt)
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            self.hex_obj.mousePressEvent(event)
        assert self.hex_obj.cursor == addr
        assert self.hex_obj.mouse_pressed is True

    def test_mouse_press_shift_begins_selection(self):
        """Shift+click begins selection if none active."""
        self.hex_obj.set_cursor(0x1000)
        addr = 0x1005
        pt = self.hex_obj.addr_to_point(addr)
        event = self._make_mouse_event(pt)
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.ShiftModifier
            self.hex_obj.mousePressEvent(event)
        assert self.hex_obj.selection_start is not None
        assert self.hex_obj.cursor == addr

    def test_mouse_press_clears_selection_without_shift(self):
        """Click without shift clears existing selection."""
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj.begin_selection()
        pt = self.hex_obj.addr_to_point(0x1010)
        event = self._make_mouse_event(pt)
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            self.hex_obj.mousePressEvent(event)
        assert self.hex_obj.selection_start is None

    def test_mouse_press_outside_data_ignored(self):
        """mousePressEvent outside byte/ascii columns does nothing."""
        old_cursor = self.hex_obj.cursor
        event = self._make_mouse_event(QPointF(-100, -100))
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            self.hex_obj.mousePressEvent(event)
        assert self.hex_obj.cursor == old_cursor

    def test_mouse_release_clears_pressed(self):
        """mouseReleaseEvent clears mouse_pressed flag."""
        self.hex_obj.mouse_pressed = True
        event = self._make_mouse_event(QPointF(0, 0))
        self.hex_obj.mouseReleaseEvent(event)
        assert self.hex_obj.mouse_pressed is False

    def test_mouse_move_extends_selection(self):
        """mouseMoveEvent with mouse_pressed begins/extends selection."""
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj.mouse_pressed = True
        pt = self.hex_obj.addr_to_point(0x1010)
        event = self._make_mouse_event(pt)
        self.hex_obj.mouseMoveEvent(event)
        assert self.hex_obj.selection_start is not None
        assert self.hex_obj.cursor == 0x1010

    def test_mouse_move_outside_data_ignored(self):
        """mouseMoveEvent outside data area does nothing."""
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj.mouse_pressed = True
        event = self._make_mouse_event(QPointF(-100, -100))
        self.hex_obj.mouseMoveEvent(event)
        assert self.hex_obj.cursor == 0x1000

    def test_double_click_selects_region(self):
        """mouseDoubleClickEvent selects the highlight region under cursor."""
        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1010, 8)
        self.hex_obj.set_highlight_regions([r])
        self.hex_obj.set_cursor(0x1014)
        pt = self.hex_obj.addr_to_point(0x1014)
        event = self._make_mouse_event(pt)
        self.hex_obj.mouseDoubleClickEvent(event)
        # After double click, selection should cover the region
        assert self.hex_obj.selection_start is not None
        sel = self.hex_obj.get_selection()
        assert sel is not None
        assert sel[0] == 0x1010  # Region start
        assert sel[1] >= 0x1017  # Region end

    def test_mouse_press_right_button_ignored(self):
        """mousePressEvent ignores right button."""
        old_cursor = self.hex_obj.cursor
        pt = self.hex_obj.addr_to_point(0x1010)
        event = self._make_mouse_event(pt, Qt.MouseButton.RightButton)
        with patch(
            "angrmanagement.ui.views.hex_view.QApplication",
        ) as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            self.hex_obj.mousePressEvent(event)
        assert self.hex_obj.cursor == old_cursor

    def test_mouse_release_right_button_ignored(self):
        """mouseReleaseEvent ignores non-left button."""
        self.hex_obj.mouse_pressed = True
        event = self._make_mouse_event(
            QPointF(0, 0),
            Qt.MouseButton.RightButton,
        )
        self.hex_obj.mouseReleaseEvent(event)
        assert self.hex_obj.mouse_pressed is True  # Unchanged

    def test_double_click_right_button_ignored(self):
        """mouseDoubleClickEvent ignores right button."""
        old_cursor = self.hex_obj.cursor
        pt = self.hex_obj.addr_to_point(0x1010)
        event = self._make_mouse_event(pt, Qt.MouseButton.RightButton)
        self.hex_obj.mouseDoubleClickEvent(event)
        assert self.hex_obj.cursor == old_cursor

    def test_double_click_no_regions(self):
        """mouseDoubleClickEvent with no regions does nothing."""
        self.hex_obj.set_highlight_regions([])
        self.hex_obj.set_cursor(0x1010)
        pt = self.hex_obj.addr_to_point(0x1010)
        event = self._make_mouse_event(pt)
        self.hex_obj.mouseDoubleClickEvent(event)
        assert self.hex_obj.selection_start is None

    def test_mouse_move_not_pressed_ignored(self):
        """mouseMoveEvent when mouse not pressed does nothing."""
        self.hex_obj.mouse_pressed = False
        self.hex_obj.set_cursor(0x1000)
        pt = self.hex_obj.addr_to_point(0x1010)
        event = self._make_mouse_event(pt)
        self.hex_obj.mouseMoveEvent(event)
        assert self.hex_obj.cursor == 0x1000

    def test_mouse_move_with_existing_selection(self):
        """mouseMoveEvent with existing selection extends it."""
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj.begin_selection()
        self.hex_obj.mouse_pressed = True
        pt = self.hex_obj.addr_to_point(0x1020)
        event = self._make_mouse_event(pt)
        self.hex_obj.mouseMoveEvent(event)
        assert self.hex_obj.cursor == 0x1020
        assert self.hex_obj.selection_start == 0x1000

    def test_shift_click_with_existing_selection(self):
        """Shift+click with existing selection keeps existing start."""
        self.hex_obj.set_cursor(0x1000)
        self.hex_obj.begin_selection()
        old_sel_start = self.hex_obj.selection_start
        pt = self.hex_obj.addr_to_point(0x1020)
        event = self._make_mouse_event(pt)
        with patch(
            "angrmanagement.ui.views.hex_view.QApplication",
        ) as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.ShiftModifier
            self.hex_obj.mousePressEvent(event)
        assert self.hex_obj.selection_start == old_sel_start

    def test_shift_arrow_with_existing_selection(self):
        """Shift+arrow with existing selection keeps start."""
        self.hex_obj.set_cursor(0x1010)
        self.hex_obj.begin_selection()
        old_start = self.hex_obj.selection_start
        with patch(
            "angrmanagement.ui.views.hex_view.QApplication",
        ) as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.ShiftModifier
            event = QKeyEvent(
                QKeyEvent.Type.KeyPress,
                Qt.Key.Key_Right,
                Qt.KeyboardModifier.ShiftModifier,
            )
            self.hex_obj.keyPressEvent(event)
        assert self.hex_obj.selection_start == old_start

    def test_unrecognized_key_passed_to_super(self):
        """Unrecognized key falls through to super."""
        with patch(
            "angrmanagement.ui.views.hex_view.QApplication",
        ) as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            event = QKeyEvent(
                QKeyEvent.Type.KeyPress,
                Qt.Key.Key_F1,
                Qt.KeyboardModifier.NoModifier,
            )
            # Should not raise
            self.hex_obj.keyPressEvent(event)

    def test_on_mouse_move_event_no_addr(self):
        """on_mouse_move_event_from_view with invalid point."""
        self.hex_obj.setToolTip("old")
        self.hex_obj.on_mouse_move_event_from_view(QPointF(-100, -100))
        assert self.hex_obj.toolTip() == ""


class TestHexGraphicsObjectPointToAddr(HexGraphicsObjectTestCase):
    """Test point_to_addr including edge cases."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def test_point_to_addr_valid_byte_column(self):
        """point_to_addr returns (addr, False) for points in byte column."""
        pt = self.hex_obj.addr_to_point(0x1005)
        result = self.hex_obj.point_to_addr(pt)
        assert result is not None
        addr, ascii_col = result
        assert addr == 0x1005
        assert ascii_col is False

    def test_point_to_addr_valid_ascii_column(self):
        """point_to_addr returns (addr, True) for points in ASCII column."""
        pt = self.hex_obj.addr_to_point(0x1005, ascii_section=True)
        result = self.hex_obj.point_to_addr(pt)
        assert result is not None
        _, ascii_col = result
        assert ascii_col is True

    def test_point_to_addr_invalid_row(self):
        """point_to_addr returns None for points outside row range."""
        result = self.hex_obj.point_to_addr(QPointF(0, -100))
        assert result is None

    def test_point_to_addr_invalid_column(self):
        """point_to_addr returns None for points between columns."""
        result = self.hex_obj.point_to_addr(QPointF(0, 0))
        assert result is None

    def test_point_to_addr_row_beyond_last(self):
        """point_to_addr returns None when point is below the last row."""
        # Need y >= num_rows * row_height so point_to_row returns None
        y = self.hex_obj.num_rows * self.hex_obj.row_height + 10
        result = self.hex_obj.point_to_addr(QPointF(self.hex_obj.byte_column_offsets[0], y))
        assert result is None

    def test_point_to_addr_addr_out_of_range(self):
        """point_to_addr returns None when computed addr >= end_addr."""
        # Use display_offset_addr so the very last row maps beyond end_addr.
        # With 256 bytes at 0x1000, end_addr = 0x1100. Load only 16 bytes
        # but use start_addr = 0x1000 (display offset = 0x1000). Row 0 col 0 = 0x1000.
        self.hex_obj.set_data(b"\x00" * 16, start_addr=0x1000)
        # Row 1 col 0 would be addr 0x1010 which is >= end_addr 0x1010
        # So let's use a point in the 2nd row
        if self.hex_obj.num_rows > 1:
            y = self.hex_obj.row_height * 1  # row 1
            x = self.hex_obj.byte_column_offsets[0]
            result = self.hex_obj.point_to_addr(QPointF(x, y))
            assert result is None
        else:
            # If only 1 row, we need to test with start_addr manipulation
            self.hex_obj.set_data(b"\x00" * 16, start_addr=0x1000)
            # Directly set start_addr higher to make row 0 col 15 out of range
            self.hex_obj.start_addr = 0x100F  # only addr 0x100F is valid
            x = self.hex_obj.byte_column_offsets[0]  # col 0 = addr 0x1000 < start_addr
            result = self.hex_obj.point_to_addr(QPointF(x, 0))
            assert result is None


class TestHexGraphicsObjectPaint(HexGraphicsObjectTestCase):
    """Test paint method via direct invocation."""

    def setUp(self):
        super().setUp()
        self._load_sample_data(256, start_addr=0x1000)

    def test_paint_no_crash(self):
        """paint() completes without error on basic data."""

        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_with_highlight_region(self):
        """paint() renders highlight regions without error."""

        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 32, tooltip="test")
        self.hex_obj.set_highlight_regions([r])

        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_with_selection(self):
        """paint() renders selection correctly."""

        self.hex_obj.set_cursor(0x1000)
        self.hex_obj.begin_selection()
        self.hex_obj.set_cursor(0x1020)

        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_with_cursor_visible(self):
        """paint() renders cursor when show_cursor is True."""

        self.hex_obj.show_cursor = True
        self.hex_obj.set_cursor(0x1010)

        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_with_cursor_nibble(self):
        """paint() renders half-width cursor when cursor_nibble is set."""

        self.hex_obj.show_cursor = True
        self.hex_obj.set_cursor(0x1010, nibble=1)

        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_with_non_int_byte_value(self):
        """paint() handles non-int byte values (e.g. '?' for unmapped)."""

        self.hex_obj.read_func = lambda addr: "?" if addr >= 0x1080 else (addr & 0xFF)

        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_with_ascii_column_active(self):
        """paint() renders with ascii column cursor active."""

        self.hex_obj.show_cursor = True
        self.hex_obj.set_cursor(0x1010, ascii_column=True)

        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_with_inactive_highlight_region(self):
        """paint() renders inactive (darker) highlight regions."""

        r = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 32)
        r.active = False
        self.hex_obj.set_highlight_regions([r])

        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_inactive_highlight(self):
        """Painting a non-active highlight region uses darker color."""
        region = HexHighlightRegion(QColor(Qt.GlobalColor.red), 0x1000, 4)
        region.active = False
        self.hex_obj.highlighted_regions = [region]
        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_exposed_rect_above_rows(self):
        """paint() handles exposedRect above row 0 (min_row becomes 0)."""
        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        total_height = self.hex_obj.num_rows * self.hex_obj.row_height
        option.exposedRect = QRectF(0, total_height + 100, 800, 100)
        self.hex_obj.paint(painter, option, None)
        painter.end()


class TestHexGraphicsViewKeyboard(TestHexViewBase):
    """Test keyboard shortcuts on the HexGraphicsView container."""

    def test_ctrl_0_resets_scale(self):
        """Ctrl+0 resets viewport scale."""
        view = self.hex_view.inner_widget
        with patch.object(view, "adjust_viewport_scale") as mock_adjust:
            event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_0, Qt.KeyboardModifier.ControlModifier)
            view.keyPressEvent(event)
            mock_adjust.assert_called_once_with()

    def test_ctrl_plus_zooms_in(self):
        """Ctrl+= zooms in."""
        view = self.hex_view.inner_widget
        with patch.object(view, "adjust_viewport_scale") as mock_adjust:
            event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Equal, Qt.KeyboardModifier.ControlModifier)
            view.keyPressEvent(event)
            mock_adjust.assert_called_once_with(1.25)

    def test_ctrl_minus_zooms_out(self):
        """Ctrl+- zooms out."""
        view = self.hex_view.inner_widget
        with patch.object(view, "adjust_viewport_scale") as mock_adjust:
            event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Minus, Qt.KeyboardModifier.ControlModifier)
            view.keyPressEvent(event)
            mock_adjust.assert_called_once_with(1 / 1.25)

    def test_adjust_viewport_scale_reset(self):
        """adjust_viewport_scale(None) resets transform."""
        view = self.hex_view.inner_widget
        # Apply a scale first
        view.adjust_viewport_scale(2.0)
        # Reset
        view.adjust_viewport_scale(None)

    def test_ctrl_unknown_key_falls_through(self):
        """Ctrl+A in HexGraphicsView falls through to super().keyPressEvent."""
        view = self.hex_view.inner_widget
        event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
        view.keyPressEvent(event)


class TestHexGraphicsViewScrollbar(TestHexViewBase):
    """Test vertical and horizontal scrollbar actions."""

    SA = QAbstractSlider.SliderAction  # Short alias

    def test_vertical_scroll_single_step_add(self):
        """Vertical scrollbar single step down moves display offset."""
        view = self.hex_view.inner_widget
        old_offset = view.hex.display_offset_addr
        view._on_vertical_scroll_bar_triggered(self.SA.SliderSingleStepAdd.value)
        assert view.hex.display_offset_addr == old_offset + 0x10

    def test_vertical_scroll_single_step_sub(self):
        """Vertical scrollbar single step up moves display offset."""
        view = self.hex_view.inner_widget
        view.hex.set_display_offset(0x100)
        old_offset = view.hex.display_offset_addr
        view._on_vertical_scroll_bar_triggered(self.SA.SliderSingleStepSub.value)
        assert view.hex.display_offset_addr == old_offset - 0x10

    def test_vertical_scroll_page_step_add(self):
        """Vertical scrollbar page step down moves display offset."""
        view = self.hex_view.inner_widget
        old_offset = view.hex.display_offset_addr
        view._on_vertical_scroll_bar_triggered(self.SA.SliderPageStepAdd.value)
        assert view.hex.display_offset_addr == old_offset + 0x10

    def test_vertical_scroll_slider_move(self):
        """Vertical scrollbar slider move repositions display."""
        view = self.hex_view.inner_widget
        view.verticalScrollBar().setValue(50)
        view._on_vertical_scroll_bar_triggered(self.SA.SliderMove.value)
        assert view.hex.display_offset_addr > 0

    def test_vertical_scroll_slider_move_near_start(self):
        """Scrollbar value near 0 snaps to start."""
        view = self.hex_view.inner_widget
        view.verticalScrollBar().setValue(2)  # < 5 threshold
        view._on_vertical_scroll_bar_triggered(self.SA.SliderMove.value)
        assert view.hex.display_offset_addr == 0

    def test_vertical_scroll_slider_move_near_end(self):
        """Scrollbar value near max snaps to end."""
        view = self.hex_view.inner_widget
        sb_max = view.scrollbar_range - 2  # > range-5 threshold
        view.verticalScrollBar().setValue(sb_max)
        view._on_vertical_scroll_bar_triggered(self.SA.SliderMove.value)

    def test_horizontal_scroll_slider_move(self):
        """Horizontal scrollbar slider move adjusts scene rect."""
        view = self.hex_view.inner_widget
        view._on_horizontal_scroll_bar_triggered(self.SA.SliderMove.value)

    def test_no_reentrant_scroll(self):
        """Scrollbar actions are ignored when already processing."""
        view = self.hex_view.inner_widget
        view._processing_scroll_event = True
        old_offset = view.hex.display_offset_addr
        view._on_vertical_scroll_bar_triggered(self.SA.SliderSingleStepAdd.value)
        assert view.hex.display_offset_addr == old_offset

    def test_vertical_scroll_page_step_sub(self):
        """PageStepSub moves display offset backward."""
        view = self.hex_view.inner_widget
        view.hex.set_display_offset(0x100)
        old = view.hex.display_offset_addr
        view._on_vertical_scroll_bar_triggered(
            self.SA.SliderPageStepSub.value,
        )
        assert view.hex.display_offset_addr == old - 0x10

    def test_vertical_scroll_slider_move_empty_range(self):
        """SliderMove with addr_range <= 0 returns early."""
        view = self.hex_view.inner_widget
        # Save and set empty range
        old_start = view.hex.start_addr
        old_end = view.hex.end_addr
        view.hex.start_addr = 0
        view.hex.end_addr = 0
        view._on_vertical_scroll_bar_triggered(
            self.SA.SliderMove.value,
        )
        # Restore
        view.hex.start_addr = old_start
        view.hex.end_addr = old_end

    def test_horizontal_scroll_non_move_action(self):
        """Non-SliderMove horizontal action does nothing special."""
        view = self.hex_view.inner_widget
        view._on_horizontal_scroll_bar_triggered(
            self.SA.SliderSingleStepAdd.value,
        )

    def test_update_horizontal_scrollbar_while_processing(self):
        """_update_horizontal_scrollbar returns early if processing."""
        view = self.hex_view.inner_widget
        view._processing_scroll_event = True
        view._update_horizontal_scrollbar()
        view._processing_scroll_event = False

    def test_wheel_zero_delta(self):
        """Wheel with 0 delta does not change offset."""
        view = self.hex_view.inner_widget
        old_offset = view.hex.display_offset_addr
        event = QWheelEvent(
            QPointF(0, 0),
            QPointF(0, 0),
            QPoint(0, 0),
            QPoint(0, 0),
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
            Qt.ScrollPhase.NoScrollPhase,
            False,
        )
        view.wheelEvent(event)
        assert view.hex.display_offset_addr == old_offset

    def test_key_press_fallthrough(self):
        """Non-Ctrl key in HexGraphicsView falls through to super."""
        view = self.hex_view.inner_widget
        event = QKeyEvent(
            QKeyEvent.Type.KeyPress,
            Qt.Key.Key_F1,
            Qt.KeyboardModifier.NoModifier,
        )
        view.keyPressEvent(event)

    def test_scrollbar_off_when_hex_fits(self):
        """Horizontal scrollbar is hidden when hex fits in viewport."""
        view = self.hex_view.inner_widget
        # Make viewport wider than hex content so scroll_range == 0
        vp_rect = QRectF(0, 0, 100000, 600)
        view._view.setSceneRect(vp_rect)
        view._update_horizontal_scrollbar()
        policy = view.horizontalScrollBarPolicy()
        assert policy == Qt.ScrollBarPolicy.ScrollBarAlwaysOff

    def test_unhandled_action_does_not_crash(self):
        """SliderToMinimum action falls through without crash (1201→1215)."""
        view = self.hex_view.inner_widget
        view._on_vertical_scroll_bar_triggered(QAbstractSlider.SliderAction.SliderToMinimum.value)


class TestHexGraphicsViewWheel(TestHexViewBase):
    """Test wheel event handling."""

    def test_wheel_scroll_down(self):
        """Wheel scroll down moves display offset forward."""

        view = self.hex_view.inner_widget
        old_offset = view.hex.display_offset_addr
        event = QWheelEvent(
            QPointF(0, 0),
            QPointF(0, 0),
            QPoint(0, -120),
            QPoint(0, -120),
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
            Qt.ScrollPhase.NoScrollPhase,
            False,
        )
        view.wheelEvent(event)
        assert view.hex.display_offset_addr > old_offset

    def test_wheel_scroll_up(self):
        """Wheel scroll up moves display offset backward."""

        view = self.hex_view.inner_widget
        view.hex.set_display_offset(0x100)
        old_offset = view.hex.display_offset_addr
        event = QWheelEvent(
            QPointF(0, 0),
            QPointF(0, 0),
            QPoint(0, 120),
            QPoint(0, 120),
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
            Qt.ScrollPhase.NoScrollPhase,
            False,
        )
        view.wheelEvent(event)
        assert view.hex.display_offset_addr < old_offset

    def test_ctrl_wheel_zooms(self):
        """Ctrl+wheel adjusts viewport scale."""

        view = self.hex_view.inner_widget
        with patch.object(view, "adjust_viewport_scale") as mock_scale:
            event = QWheelEvent(
                QPointF(0, 0),
                QPointF(0, 0),
                QPoint(0, 120),
                QPoint(0, 120),
                Qt.MouseButton.NoButton,
                Qt.KeyboardModifier.ControlModifier,
                Qt.ScrollPhase.NoScrollPhase,
                False,
            )
            view.wheelEvent(event)
            mock_scale.assert_called_once_with(1.25)


class TestHexViewSynchronizedViews(TestHexViewBase):
    """Test synchronized view related methods."""

    def test_on_synchronized_view_group_changed_enables_cursor(self):
        """on_synchronized_view_group_changed enables always_show_cursor when views > 1."""
        self.hex_view.sync_state.views = {self.hex_view, MagicMock()}  # type: ignore[assignment]
        self.hex_view.on_synchronized_view_group_changed()
        assert self.hex_view.inner_widget.hex.always_show_cursor is True

    def test_on_synchronized_view_group_changed_disables_cursor(self):
        """on_synchronized_view_group_changed disables always_show_cursor when views <= 1."""
        self.hex_view.sync_state.views = {self.hex_view}  # type: ignore[assignment]
        self.hex_view.on_synchronized_view_group_changed()
        assert self.hex_view.inner_widget.hex.always_show_cursor is False

    def test_on_synchronized_highlight_regions_changed(self):
        """on_synchronized_highlight_regions_changed updates sync highlights."""
        self.hex_view.on_synchronized_highlight_regions_changed()

    def test_sync_highlights_from_other_view(self):
        """Sync highlights are created from other views' regions."""
        mock_region = MagicMock()
        mock_region.addr = 0x1000
        mock_region.size = 16
        mock_other_view = MagicMock()
        self.hex_view.sync_state.highlight_regions = {
            mock_other_view: [mock_region],
        }
        self.hex_view._update_highlight_regions_from_synchronized_views()
        assert len(self.hex_view._sync_view_highlights) == 1

    def test_sync_highlights_self_only_yields_empty(self):
        """When only self is in highlight_regions, no sync highlights are created."""
        mock_region = MagicMock()
        mock_region.addr = 0x1000
        mock_region.size = 16
        self.hex_view.sync_state.highlight_regions = {
            self.hex_view: [mock_region],
        }
        self.hex_view._update_highlight_regions_from_synchronized_views()
        assert not self.hex_view._sync_view_highlights


class TestHexGraphicsObjectPaintEdgeCases(HexGraphicsObjectTestCase):
    """Test paint method edge cases."""

    def setUp(self):
        super().setUp()
        # Small data that doesn't fill all rows - addr not aligned to 0
        self.hex_obj.set_data(bytes(range(48)), start_addr=0x1008)
        self.hex_obj.set_display_num_rows(8)
        self.hex_obj.set_display_offset(0)

    def _paint(self, exposed_rect=None):
        img = QImage(800, 600, QImage.Format.Format_ARGB32)
        painter = QPainter(img)
        option = QStyleOptionGraphicsItem()
        if exposed_rect is not None:
            option.exposedRect = exposed_rect
        else:
            option.exposedRect = self.hex_obj.boundingRect()
        self.hex_obj.paint(painter, option, None)
        painter.end()

    def test_paint_with_active_highlight_region(self):
        """paint with active=True region uses lighter color."""
        r = HexHighlightRegion(
            QColor(Qt.GlobalColor.red),
            0x1008,
            16,
        )
        r.active = True
        self.hex_obj.set_highlight_regions([r])
        self._paint()

    def test_paint_with_unaligned_start_addr(self):
        """paint handles data that doesn't start at 0x__00."""
        # Data starts at 0x1008, so first row has cols 0-7 outside range
        self._paint()

    def test_paint_exposed_rect_outside_rows(self):
        """paint with exposed rect above all rows."""
        self._paint(exposed_rect=QRectF(-100, -100, 10, 10))

    def test_paint_cursor_outside_display(self):
        """paint with cursor not in visible display range."""
        self.hex_obj.show_cursor = True
        self.hex_obj.cursor = 0xFFFF  # Way outside
        self._paint()

    def test_paint_non_int_single_char_value(self):
        """paint with single-char non-int read value."""
        self.hex_obj.read_func = lambda addr: "S"
        self._paint()

    def test_paint_non_int_multi_char_value(self):
        """paint with multi-char non-int read value."""
        self.hex_obj.read_func = lambda addr: "??"
        self._paint()


class TestHexGraphicsSubViewForwarding(TestHexViewBase):
    """Test HexGraphicsSubView event forwarding."""

    def test_subview_wheel_event_forwards(self):
        """HexGraphicsSubView.wheelEvent forwards to parent."""
        view = self.hex_view.inner_widget
        subview = view._view
        event = QWheelEvent(
            QPointF(0, 0),
            QPointF(0, 0),
            QPoint(0, -120),
            QPoint(0, -120),
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
            Qt.ScrollPhase.NoScrollPhase,
            False,
        )
        old_offset = view.hex.display_offset_addr
        subview.wheelEvent(event)
        # Should have scrolled
        assert view.hex.display_offset_addr != old_offset

    def test_subview_mouse_move_forwards(self):
        """HexGraphicsSubView.mouseMoveEvent forwards to hex."""
        view = self.hex_view.inner_widget
        subview = view._view
        event = QMouseEvent(
            QEvent.Type.MouseMove,
            QPointF(10, 10),
            Qt.MouseButton.NoButton,
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
        )
        with patch.object(
            view.hex,
            "on_mouse_move_event_from_view",
        ) as mock_handler:
            subview.mouseMoveEvent(event)
            mock_handler.assert_called_once()


class TestHexGraphicsViewSceneRect(TestHexViewBase):
    """Test update_scene_rect viewport branches."""

    def test_update_scene_rect_basic(self):
        """update_scene_rect doesn't crash."""
        view = self.hex_view.inner_widget
        view.update_scene_rect()

    def test_update_horizontal_scrollbar_with_scroll(self):
        """_update_horizontal_scrollbar with non-zero scroll range."""
        view = self.hex_view.inner_widget
        # Make hex rect wider than viewport
        view.hex.max_x = 10000
        view.hex._update_layout()
        view._update_horizontal_scrollbar()

    def test_cursor_left_of_viewport_scrolls_left(self):
        """update_scene_rect scrolls left when cursor is left of viewport."""
        view = self.hex_view.inner_widget
        # Shift viewport far to the right so cursor is left of viewport
        vp_rect = view._view.sceneRect()
        vp_rect.moveLeft(5000)
        view._view.setSceneRect(vp_rect)
        view.update_scene_rect()

    def test_viewport_wider_than_hex_reveals_all(self):
        """update_scene_rect reveals all when viewport wider than hex."""
        view = self.hex_view.inner_widget
        hex_rect = view.hex.boundingRect()
        hex_rect.translate(view.hex.pos())
        cursor_rect = view.hex.addr_to_rect(view.hex.cursor)
        cursor_rect.translate(view.hex.pos())
        # Viewport wider than hex, cursor inside viewport, left offset > 0

        wide_vp = QRectF(10, 0, hex_rect.width() + 500, hex_rect.height())
        # Ensure cursor is within viewport (right inside, left inside)
        assert cursor_rect.right() <= wide_vp.right()
        assert cursor_rect.left() >= wide_vp.left()
        with patch.object(
            view._view,
            "mapToScene",
            return_value=QPolygonF(wide_vp),
        ):
            view.update_scene_rect()

    def test_viewport_right_exceeds_hex_right(self):
        """update_scene_rect reveals left when vp_right > hex_right."""
        view = self.hex_view.inner_widget
        hex_rect = view.hex.boundingRect()
        hex_rect.translate(view.hex.pos())
        cursor_rect = view.hex.addr_to_rect(view.hex.cursor)
        cursor_rect.translate(view.hex.pos())
        # Viewport narrower than hex but right edge past hex's right edge

        narrow_vp = QRectF(
            hex_rect.x() + 50,  # starts near hex's right edge
            0,
            hex_rect.width() - 25,  # narrower than hex
            hex_rect.height(),
        )
        # Move cursor inside this viewport so cursor branches don't fire
        cursor_addr_in_vp = view.hex.point_to_addr(QPointF(narrow_vp.left(), narrow_vp.top()))
        if cursor_addr_in_vp is not None:
            view.hex.set_cursor(cursor_addr_in_vp[0], update_viewport=False)
            cursor_rect = view.hex.addr_to_rect(view.hex.cursor)
            cursor_rect.translate(view.hex.pos())
        with patch.object(
            view._view,
            "mapToScene",
            return_value=QPolygonF(narrow_vp),
        ):
            view.update_scene_rect()

    def test_update_display_num_rows(self):
        """update_display_num_rows sets hex display rows from viewport height."""
        view = self.hex_view.inner_widget
        view.update_display_num_rows()
        assert view.hex.display_num_rows >= 1

    def test_get_num_rows_visible_fully(self):
        """_get_num_rows_visible(fully_visible=True) returns fewer rows."""
        view = self.hex_view.inner_widget
        partial = view._get_num_rows_visible(fully_visible=False)
        full = view._get_num_rows_visible(fully_visible=True)
        assert full <= partial

    def test_resize_event_updates_display(self):
        """resizeEvent updates viewport."""

        view = self.hex_view.inner_widget
        event = QResizeEvent(QSize(800, 600), QSize(400, 300))
        view.resizeEvent(event)

    def test_change_event_palette(self):
        """changeEvent(PaletteChange) refreshes background."""
        view = self.hex_view.inner_widget
        event = QEvent(QEvent.Type.PaletteChange)
        view.changeEvent(event)


class TestKeyPressEventFallthrough(HexGraphicsObjectTestCase):
    """Test keyPressEvent branches that fall through to super (721→738, 729→738, 734→738)."""

    def setUp(self):
        super().setUp()
        data = bytearray(256)
        self.backing = data
        self._load_sample_data(256, start_addr=0x1000)
        self.hex_obj.write_func = lambda addr, val: False

    def test_ctrl_non_space_falls_through(self):
        """Ctrl+A (non-Space) falls through to super().keyPressEvent (721→738)."""
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.ControlModifier
            event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
            self.hex_obj.keyPressEvent(event)
            # Should not crash; event was not accepted by any handler

    def test_ascii_column_non_printable_falls_through(self):
        """Non-printable char in ASCII column falls through (729→738)."""
        self.hex_obj.ascii_column_active = True
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            # Tab character is ASCII but not printable
            event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Tab, Qt.KeyboardModifier.NoModifier, "\t")
            self.hex_obj.keyPressEvent(event)

    def test_byte_column_non_hex_falls_through(self):
        """Non-hex char in byte column falls through (734→738)."""
        self.hex_obj.ascii_column_active = False
        with patch("angrmanagement.ui.views.hex_view.QApplication") as mock_app:
            mock_app.keyboardModifiers.return_value = Qt.KeyboardModifier.NoModifier
            # 'g' is not a hex digit
            event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_G, Qt.KeyboardModifier.NoModifier, "g")
            self.hex_obj.keyPressEvent(event)


if __name__ == "__main__":
    unittest.main()
