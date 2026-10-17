"""
The hex view without a toolkit.

:class:`HexGrid` is the hex editor's state over a contiguous range of memory: the cursor, which nibble of the byte it
is on, the selection, which column (bytes or ASCII) is active, the rows shown, the byte reader and writer, and the
highlighted regions. :class:`HexViewMixin` is the view around it: the data sources (the loader's memory with the
patches on top, or the debugger's current state), patching through :meth:`HexViewMixin.auto_patch`, the regions it
highlights (instructions and data from the CFB, patches, breakpoints, the synchronized views' regions, changed bytes,
find matches), find, the byte clipboard, the context menu and the status text.

The Qt hex view is a :class:`HexViewMixin` whose grid is its ``HexGraphicsObject`` (itself a :class:`HexGrid`), and
the terminal's :class:`HexPresenter` is one whose grid is a plain :class:`HexGrid`; each gives the few hooks the mixin
names. Rows hold 16 bytes; a byte reads as an int, or as a one-character string when it is not known (``"?"``) or
symbolic (``"S"``).
"""

from __future__ import annotations

import contextlib
import logging
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar

import angr
from angr import Block
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort
from angr.knowledge_plugins.patches import Patch
from archinfo.arch_arm import is_arm_arch

from angrmanagement.config import Conf
from angrmanagement.config.color import Color
from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.data.search import SCOPE_ALL, BytePattern, Searcher, SearchError
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.commands import ViewCommand
from angrmanagement.logic.debugger import DebuggerWatcher
from angrmanagement.logic.signal import Signal
from angrmanagement.utils import is_printable

from .base import (
    Synchronized,
    SynchronizedPresenter,
    ask_question,
    ask_text,
    container,
    project_of,
    resolve_address,
)
from .find import FindBarState
from .keymap import Binding, Keymap
from .menus import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from angrmanagement.data.instance import Instance

log = logging.getLogger(__name__)

RowCol = tuple[int, int]
HexByteValue = int | str
HexAddress = int
HexDataBuffer = bytes | bytearray

#: How many bytes a row shows.
ROW_BYTES = 16
#: The colours of the regions that no configuration entry names: Qt's cyan, yellow, green and red.
BREAKPOINT_COLOR = Color(0x00, 0xFF, 0xFF)
PATCH_COLOR = Color(0xFF, 0xFF, 0x00)
SYNCHRONIZED_COLOR = Color(0x00, 0xFF, 0x00)
CHANGED_COLOR = Color(0xFF, 0x00, 0x00)
#: The keys that move the cursor, and how far (0: computed from the rows shown or the row).
MOVEMENT_KEYS = {"up": -16, "down": 16, "right": 1, "left": -1, "pageup": 0, "pagedown": 0, "home": 0, "end": 0}

_BREAKPOINT_TYPE_NAMES = {
    BreakpointType.Execute: "Execute",
    BreakpointType.Read: "Read",
    BreakpointType.Write: "Write",
}


class HexDataSource(Enum):
    """
    Data source to be displayed in the hex view.
    """

    Loader = 0
    Debugger = 1


#
# Highlighted regions
#


class HexHighlightRegion:
    """
    A highlighted range of bytes. ``color`` is the frontend's colour (a :class:`Color` in the terminal).
    """

    def __init__(self, color: Any, addr: HexAddress, size: int, tooltip: str | None = None) -> None:
        self.color: Any = color
        self.addr: HexAddress = addr
        self.size: int = size
        self.active: bool = False
        self._tooltip: str | None = tooltip

    def context_menu(self) -> Menu | None:  # pylint: disable=no-self-use
        """The submenu of this region in the view's context menu, or None."""
        return None

    def get_tooltip(self) -> str | None:
        """
        Return a tooltip for this region.
        """
        return self._tooltip


class BreakpointHighlightRegion(HexHighlightRegion):
    """
    A breakpoint's bytes; ``view`` is the hex view (it gives ``instance``).
    """

    def __init__(self, bp: Breakpoint, view: Any, color: Any = BREAKPOINT_COLOR) -> None:
        super().__init__(color, bp.addr, bp.size)
        self.bp: Breakpoint = bp
        self.view: Any = view

    def describe(self) -> str:
        return f"Breakpoint 0x{self.bp.addr:x} {_BREAKPOINT_TYPE_NAMES.get(self.bp.type)} ({self.bp.size} bytes)"

    def context_menu(self) -> Menu | None:
        return Menu(self.describe(), [MenuEntry("&Remove", self.remove)])

    def remove(self) -> None:
        """
        Remove this breakpoint.
        """
        self.view.instance.breakpoint_mgr.remove_breakpoint(self.bp)

    def get_tooltip(self) -> str | None:
        return self.describe()


class PatchHighlightRegion(HexHighlightRegion):
    """
    A patch's bytes; ``view`` is the hex view (it gives ``instance`` and the cursor).
    """

    def __init__(self, patch: Patch, view: Any, color: Any = PATCH_COLOR) -> None:
        super().__init__(color, patch.addr, len(patch))
        self.patch: Patch = patch
        self.view: Any = view

    def describe(self) -> str:
        return f"Patch 0x{self.patch.addr:x} ({len(self.patch)} bytes)"

    def get_tooltip(self) -> str | None:
        return self.describe()

    def context_menu(self) -> Menu | None:
        return Menu(
            self.describe(),
            [
                MenuEntry("&Split", self.split, enabled=self.can_split()),
                MenuEntry("Set &Comment...", self.comment),
                MenuSeparator(),
                MenuEntry("&Revert", self.revert_with_prompt),
            ],
        )

    def cursor(self) -> HexAddress:
        """The cursor of the view."""
        return self.view.grid.cursor

    def revert_with_prompt(self) -> None:
        """
        Revert this patch. Prompt for confirmation.
        """

        def then(answer: str) -> None:
            if answer == "Yes":
                self.revert()

        ask_question("Revert patch", "Are you sure you want to revert this patch?", ["Yes", "Cancel"], "Cancel", then)

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
        cursor = self.cursor()
        return self.patch.addr < cursor < (self.patch.addr + len(self.patch))

    def split(self) -> None:
        """
        Split this patch at view's current cursor location.
        """
        cursor = self.cursor()
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

    def set_comment(self, text: str | None) -> None:
        """Set the patch's comment to ``text``; nothing happens for an empty answer."""
        if text:
            self.patch.comment = text
            pm = self.view.instance.patches
            pm.am_event()

    def comment(self) -> None:
        """
        Set the comment for this patch.
        """
        ask_text("Set Patch Comment", "Patch comment:", self.patch.comment or "", self.set_comment)


#
# The grid
#


class HexGrid:
    """
    A hex editor over a contiguous range of memory: what is shown, the cursor and the selection. A frontend draws
    ``display_num_rows`` rows of 16 bytes from ``display_start_addr``, reading each byte with :attr:`read_func`.

    The hooks :meth:`update`, :meth:`_update_layout`, :meth:`notify_cursor_changed`, :meth:`notify_viewport_changed`
    and :meth:`_cursor_set` let a frontend's class redraw; here they emit :attr:`changed`, :attr:`cursor_moved` and
    :attr:`viewport_moved`.
    """

    def __init__(self) -> None:
        self.display_offset_addr: HexAddress = 0
        self.display_num_rows: int = 1
        self.display_start_addr: HexAddress = 0
        self.display_end_addr: HexAddress = 0
        self.start_addr: HexAddress = 0
        self.num_bytes: int = 0
        self.end_addr: HexAddress = 0  # Exclusive
        self.read_func: Callable[[HexAddress], HexByteValue] | None = None
        self.write_func: Callable[[HexAddress, HexByteValue], bool] | None = None
        self.data: HexDataBuffer | None = None
        self.cursor: HexAddress = self.start_addr
        self.cursor_nibble: int | None = None
        self.selection_start: HexAddress | None = None
        self.mouse_pressed: bool = False
        self.num_rows: int = 0
        self.ascii_column_active: bool = False
        self.cursor_blink_state: bool = True
        self.highlighted_regions: Sequence[HexHighlightRegion] = []
        self.show_cursor: bool = True
        self._processing_cursor_update: bool = False
        self.always_show_cursor: bool = False
        #: something shown changed
        self.changed = Signal()
        #: the cursor moved or the nibble or column changed
        self.cursor_moved = Signal()
        #: the rows shown changed
        self.viewport_moved = Signal()

    #
    # Hooks
    #

    def update(self, *_args) -> None:
        """Something shown changed."""
        self.changed.emit()

    def _update_layout(self) -> None:
        """The rows shown or the data changed (Qt measures its columns again)."""

    def notify_cursor_changed(self) -> None:
        self.cursor_moved.emit()

    def notify_viewport_changed(self) -> None:
        self.viewport_moved.emit()

    def _cursor_set(self) -> None:
        """The cursor was put somewhere: a blinking cursor shows again."""
        self.cursor_blink_state = True

    def set_always_show_cursor(self, always_show: bool) -> None:
        """
        Set policy of whether the cursor should always be shown (when focus is lost) or not.
        """
        self.always_show_cursor = always_show
        self.update()

    #
    # The rows shown
    #

    def _set_display_common(self) -> None:
        """
        Handle common update of offset or row count changed.
        """
        self.display_end_addr = min(self.end_addr, self.display_start_addr + self.display_num_rows * 16)
        self._update_layout()
        self.notify_viewport_changed()

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

    #
    # The data
    #

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
        assert self.data is not None
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

    def set_data_callback(
        self,
        write_func: Callable[[HexAddress, HexByteValue], bool],
        read_func: Callable[[HexAddress], HexByteValue],
        start_addr: HexAddress,
        num_bytes: int,
    ) -> None:
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

    def read(self, addr: HexAddress) -> HexByteValue:
        """The byte at ``addr``: an int, or a one-character string for a byte that is unknown or symbolic."""
        return self.read_func(addr) if self.read_func is not None else "?"

    #
    # Rows, columns and addresses
    #

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

    #
    # The selection and the regions
    #

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

    def is_selected(self, addr: HexAddress) -> bool:
        sel = self.get_selection()
        return sel is not None and sel[0] <= addr <= sel[1]

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

    def set_highlight_regions(self, regions: Sequence[HexHighlightRegion]) -> None:
        """
        Sets the list of highlighted regions.
        """
        self.highlighted_regions = regions
        self.update_active_highlight_regions()
        self.update()

    def tooltip_at(self, addr: HexAddress) -> str:
        """The tooltips of the regions at ``addr``, one per line."""
        regions = self.get_highlight_regions_at_addr(addr)
        return "\n".join(t for t in [r.get_tooltip() for r in regions] if t)

    def select_region_under_cursor(self) -> None:
        """Select the innermost region under the cursor (a double click), leaving the cursor at its start."""
        regions = sorted(self.get_highlight_regions_under_cursor(), key=lambda r: self.cursor - r.addr)
        if len(regions) > 0:
            region = regions[0]
            self.set_cursor(region.addr + region.size - 1)
            self.begin_selection()
            self.set_cursor(region.addr)

    #
    # The cursor
    #

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
        self._cursor_set()
        cursor_changed = self.cursor != addr
        if cursor_changed:
            if update_viewport:
                self.move_viewport_to(addr)
            self.cursor = addr
        self.cursor_nibble = nibble
        self.notify_cursor_changed()
        self.update_active_highlight_regions()
        self.update()
        self._processing_cursor_update = False

    def click(self, addr: HexAddress, ascii_column: bool, extend: bool) -> None:
        """A press on the byte at ``addr``: with ``extend`` (Shift held) the selection grows to it."""
        if extend:
            if self.selection_start is None:
                self.begin_selection()
        else:
            self.clear_selection()
        self.set_cursor(addr, ascii_column)

    def drag_to(self, addr: HexAddress, ascii_column: bool) -> None:
        """The mouse, held down, moved over the byte at ``addr``."""
        if self.selection_start is None:
            self.begin_selection()
        self.set_cursor(addr, ascii_column)

    def move_cursor(self, key: str, extend: bool) -> bool:
        """
        Move the cursor for ``key`` (a name in :data:`MOVEMENT_KEYS`); with ``extend`` (Shift held) the selection
        grows. Whether ``key`` moves the cursor.
        """
        if key not in MOVEMENT_KEYS:
            return False
        if extend:
            if self.selection_start is None:
                self.begin_selection()
        else:
            self.clear_selection()

        # FIXME: When holding Ctrl, only scroll the viewport
        preserve_relative_offset = False
        if key == "pageup":
            new_cursor = max(self.start_addr, self.cursor - (self.display_num_rows - 1) * 16)
            preserve_relative_offset = True
        elif key == "pagedown":
            new_cursor = min(self.end_addr - 1, self.cursor + (self.display_num_rows - 1) * 16)
            preserve_relative_offset = True
        elif key == "home":
            new_cursor = max(self.start_addr, self.cursor & ~0xF)
        elif key == "end":
            new_cursor = min(self.end_addr - 1, (self.cursor & ~0xF) + 0xF)
        else:
            new_cursor = self.cursor + MOVEMENT_KEYS[key]
        if self.start_addr <= new_cursor < self.end_addr:
            self.move_viewport_to(new_cursor, preserve_relative_offset)
            self.set_cursor(new_cursor, update_viewport=False)
        return True

    def toggle_column(self) -> None:
        """Make the other column (bytes or ASCII) the active one (Ctrl+Space)."""
        self.set_cursor(self.cursor, ascii_column=not self.ascii_column_active)

    def type_text(self, text: str) -> bool:
        """
        A character typed: a printable one is written in the ASCII column, a hex digit as a nibble in the bytes
        column. Whether it was taken.
        """
        if len(text) != 1:
            return False
        if self.ascii_column_active:
            if text.isascii() and text.isprintable():
                self._set_byte_value(ord(text))
                return True
        elif text in "0123456789abcdefABCDEF":
            self._set_nibble_value(int(text, 16))
            return True
        return False

    def _set_byte_value(self, value: int) -> None:
        """
        Handle byte modification via user entry.
        """
        assert self.write_func is not None
        if not self.write_func(self.cursor, value):
            return
        self.set_cursor(self.cursor + 1)

    def _set_nibble_value(self, value: int) -> None:
        assert self.read_func is not None and self.write_func is not None
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

    #
    # Scrolling
    #

    def scroll_rows(self, rows: int) -> None:
        """Show the rows ``rows`` below (above, when negative) the first row shown."""
        self.set_display_offset(self.display_offset_addr + 0x10 * rows)

    def scroll_fraction(self) -> float:
        """How far down the range the first row shown is, from 0 to 1."""
        addr_range = (self.end_addr - self.start_addr) >> 4
        if addr_range <= 0:
            return 0.0
        return min(1.0, ((self.display_start_addr - self.start_addr) >> 4) / addr_range)

    def scroll_to_fraction(self, fraction: float) -> None:
        """Show the rows ``fraction`` of the way down the range, as the Qt scroll bar's thumb does."""
        addr_range = self.end_addr - self.start_addr
        if addr_range <= 0:
            return
        self.set_display_offset(int(max(0.0, min(fraction, 1.0)) * addr_range) & ~0xF)


#
# Text of a row
#


def byte_text(val: HexByteValue) -> tuple[str, str]:
    """The two characters of a byte in the bytes column and the style key of their colour."""
    if isinstance(val, int):
        key = "disasm_view_printable_byte_color" if is_printable(val) else "disasm_view_unprintable_byte_color"
        return f"{val:02x}", key
    text = val * 2 if isinstance(val, str) and len(val) == 1 else "??"
    return text, "disasm_view_unknown_byte_color"


def ascii_text(val: HexByteValue) -> tuple[str, str]:
    """The character of a byte in the ASCII column and the style key of its colour."""
    if isinstance(val, int):
        if is_printable(val):
            return chr(val), "disasm_view_printable_character_color"
        return ".", "disasm_view_unprintable_character_color"
    return (val if isinstance(val, str) and len(val) == 1 else "?"), "disasm_view_unknown_character_color"


#
# The view
#


class HexViewMixin(Synchronized):
    """
    The hex view's state and actions over its :attr:`grid`. The class it is mixed into is synchronized
    (:class:`~angrmanagement.present.base.Synchronized`) and gives ``instance``, ``published_view_state``,
    ``notify_view_state_updated``, the find bar as ``_find_bar``, :attr:`grid`, :attr:`data_source` and the
    region classes; it may override the hooks between ``grid`` and ``_focus_grid``.
    """

    #: The classes of the regions it makes.
    REGION_CLASS: ClassVar[type[HexHighlightRegion]] = HexHighlightRegion
    PATCH_REGION_CLASS: ClassVar[type[PatchHighlightRegion]] = PatchHighlightRegion
    BREAKPOINT_REGION_CLASS: ClassVar[type[BreakpointHighlightRegion]] = BreakpointHighlightRegion
    #: The colours of the synchronized views' regions and of the bytes a debugger step changed.
    SYNCHRONIZED_REGION_COLOR: ClassVar[Any] = SYNCHRONIZED_COLOR
    CHANGED_REGION_COLOR: ClassVar[Any] = CHANGED_COLOR
    FIND_HIGHLIGHT_LIMIT = 512

    instance: Instance
    published_view_state: Any
    notify_view_state_updated: Callable[[], None]
    _find_bar: Any
    smart_highlighting_enabled: bool
    _clipboard: bytearray | None
    _cfb_highlights: Sequence[HexHighlightRegion]
    _sync_view_highlights: Sequence[HexHighlightRegion]
    _patch_highlights: Sequence[PatchHighlightRegion]
    _changed_data_highlights: Sequence[HexHighlightRegion]
    _breakpoint_highlights: Sequence[BreakpointHighlightRegion]
    _find_matches: list[tuple[int, int]]
    _find_index: int
    _find_highlights: Sequence[HexHighlightRegion]
    _find_regions: list[tuple[int, bytes]] | None
    _find_capped: bool
    _data_cache: dict[int, HexByteValue]
    _dbg_watcher: DebuggerWatcher

    def _init_hex_state(self) -> None:
        """The view's state before it shows anything."""
        self.smart_highlighting_enabled = True
        self._clipboard = None
        self._cfb_highlights = []
        self._sync_view_highlights = []
        self._patch_highlights = []
        self._changed_data_highlights = []
        self._breakpoint_highlights = []
        self._find_matches = []
        self._find_index = -1
        self._find_highlights = []
        self._find_regions = None
        self._find_capped = False
        self._data_cache = {}

    def _start_hex(self) -> None:
        """Listen to the instance and the debugger, and show the data."""
        container(self.instance.cfb).am_subscribe(self._on_cfb_event)
        container(self.instance.patches).am_subscribe(self._update_highlight_regions_from_patches)
        self.instance.breakpoint_mgr.breakpoints.am_subscribe(self._update_highlight_regions_from_breakpoints)
        self._data_cache = {}

        self._reload_data()

        self._dbg_manager = self.instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    def _stop_hex(self) -> None:
        """Stop listening."""
        self._dbg_watcher.shutdown()
        for listened, handler in (
            (container(self.instance.cfb), self._on_cfb_event),
            (container(self.instance.patches), self._update_highlight_regions_from_patches),
            (self.instance.breakpoint_mgr.breakpoints, self._update_highlight_regions_from_breakpoints),
        ):
            with contextlib.suppress(ValueError, KeyError):
                listened.am_unsubscribe(handler)

    #
    # Hooks
    #

    @property
    def grid(self) -> HexGrid:
        raise NotImplementedError

    @property
    def data_source(self) -> HexDataSource:
        raise NotImplementedError

    def _grid_if_ready(self) -> HexGrid | None:
        """The grid, or None while the view is being made (the synchronization group asks before there is one)."""
        raise NotImplementedError

    def _set_region_callback(self, write, read, addr: int, size: int) -> None:
        """Show ``size`` bytes from ``addr``, read and written through the two callables."""
        self.grid.set_data_callback(write, read, addr, size)
        self.grid.set_display_offset(0)

    def _clear_grid(self) -> None:
        self.grid.clear()

    def _display_start_addr(self) -> HexAddress:
        return self.grid.display_start_addr

    def _set_display_start_addr(self, start: HexAddress) -> None:
        self.grid.set_display_offset(start - self.grid.start_addr)

    def update_status_text(self) -> None:
        """The status text changed."""

    def _find_bar_opened(self) -> None:
        """The find bar opened."""

    def _focus_grid(self) -> None:
        """Give the focus back to the bytes (the find bar closed)."""

    #
    # Events
    #

    def _on_cfb_event(self, **kwargs) -> None:
        if not kwargs:
            self._find_regions = None
            self._reload_data()
            if self._find_bar is not None and self.find_bar_is_open():
                self._update_find_matches()

    def find_bar_is_open(self) -> bool:
        bar = self._find_bar
        is_open = getattr(bar, "is_open", None)
        if is_open is not None:
            return bool(is_open)
        return not bar.isHidden()

    def _clear_highlights(self) -> None:
        """
        Clear all highlight regions
        """
        self._cfb_highlights = []
        self._sync_view_highlights = []
        self._patch_highlights = []
        self._changed_data_highlights = []
        self._breakpoint_highlights = []
        self._find_highlights = []

    def _reload_data(self) -> None:
        """
        Callback when hex backing data store should be updated.
        """
        self._clear_highlights()
        start = self._display_start_addr()
        cursor = self.grid.cursor
        source = self.data_source
        if source == HexDataSource.Loader:
            if container(self.instance.cfb).am_none:
                self._clear_grid()
                return
            loader = self.instance.project.loader
            self._set_region_callback(
                self.project_memory_write_func,
                self.project_memory_read_func,
                loader.min_addr,
                loader.max_addr - loader.min_addr + 1,
            )
            self._update_highlight_regions_from_patches()
        elif source == HexDataSource.Debugger:
            self._data_cache = {}
            self._set_region_callback(
                self.debugger_memory_write_func,
                self.debugger_memory_read_func,
                0,
                0x10000000000000000,  # FIXME: Get actual ranges and add them
            )
        else:
            raise NotImplementedError

        self._set_display_start_addr(start)
        self.grid.set_cursor(cursor)
        self._update_highlight_regions_from_synchronized_views()
        self._update_cfb_highlight_regions()
        self._set_highlighted_regions()

    def _data_source_changed(self, index: int) -> None:  # pylint:disable=unused-argument
        self._reload_data()

    def _on_debugger_state_updated(self) -> None:
        source = self.data_source
        if source == HexDataSource.Debugger:
            #
            # Calculate differences in state memory and highlight
            #
            previous_data = self._data_cache
            self._data_cache = {}
            grid = self.grid
            addr = grid.display_start_addr
            regions = []
            r = None
            while addr < grid.display_end_addr:
                if addr in previous_data:
                    differs = self.debugger_memory_read_func(addr) != previous_data[addr]
                else:
                    differs = False
                if differs:
                    if r is None:
                        r = self.REGION_CLASS(self.CHANGED_REGION_COLOR, addr, 0)
                        regions.append(r)
                    r.size += 1
                else:
                    r = None
                addr += 1
            self._changed_data_highlights = regions
            grid.update()
            self._set_highlighted_regions()

    #
    # Reading and writing
    #

    def debugger_memory_read_func(self, addr: int) -> HexByteValue:
        """
        Callback to populate hex view with bytes from debugger state.
        """
        if addr not in self._data_cache:
            dbg = self.instance.debugger_mgr.debugger
            if dbg.am_none:
                v: HexByteValue = "?"
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
        pm_notifier = container(self.instance.patches)
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

    #
    # Patches, the clipboard and breakpoints
    #

    def revert_selected_patches(self) -> None:
        """
        Revert any selected patches, after asking.
        """

        def then(answer: str) -> None:
            if answer == "Yes":
                self._revert_selected_patches()

        ask_question(
            "Revert patches", "Are you sure you want to revert selected patches?", ["Yes", "Cancel"], "Cancel", then
        )

    def _revert_selected_patches(self) -> None:
        selected_regions = self.grid.get_active_highlight_regions()
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
        selected_patches = [r for r in self.grid.get_active_highlight_regions() if isinstance(r, PatchHighlightRegion)]
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
        sel = self.grid.get_selection()
        if sel is None:
            return 0
        minaddr, maxaddr = sel
        num_bytes_selected = maxaddr - minaddr + 1
        return num_bytes_selected

    def _copy_selected_bytes(self) -> None:
        """
        Copy selected bytes to view-only clipboard.
        """
        sel = self.grid.get_selection()
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
        if self.data_source == HexDataSource.Loader:
            self.project_memory_write_bytearray(self.grid.cursor, self._clipboard)
        # FIXME: Support pasting data to current debugger state

    def _set_breakpoint(self, bp_type: BreakpointType = BreakpointType.Execute) -> None:
        """
        Set breakpoint at current cursor.
        """
        sel = self.grid.get_selection()
        if sel:
            minaddr, maxaddr = sel
            num_bytes_selected = maxaddr - minaddr + 1
        else:
            minaddr = self.grid.cursor
            num_bytes_selected = 1
        self.instance.breakpoint_mgr.add_breakpoint(Breakpoint(bp_type, minaddr, num_bytes_selected))

    def breakpoint_menu(self) -> Menu:
        """The "Set breakpoint" submenu."""
        return Menu(
            "Set &breakpoint",
            [
                MenuEntry("Break on &Execute", lambda: self._set_breakpoint(BreakpointType.Execute)),
                MenuEntry("Break on &Read", lambda: self._set_breakpoint(BreakpointType.Read)),
                MenuEntry("Break on &Write", lambda: self._set_breakpoint(BreakpointType.Write)),
            ],
        )

    def context_menu(self, *_args, **_kwargs) -> Menu:
        """
        The view's context menu: copy and paste, breakpoints, the menus of the regions under the cursor, the selected
        patches, and the views to synchronize with.
        """
        mnu = Menu("Hex")
        add_sep = False

        # FIXME: This should also go into an Edit menu accessible from the main window
        num_selected_bytes = self._get_num_selected_bytes()
        if num_selected_bytes > 0:
            plural = "s" if num_selected_bytes != 1 else ""
            mnu.add(MenuEntry(f"Copy {num_selected_bytes:d} byte{plural}", self._copy_selected_bytes))
            add_sep = True
        if self._clipboard is not None and self.data_source == HexDataSource.Loader:
            plural = "s" if len(self._clipboard) != 1 else ""
            mnu.add(MenuEntry(f"Paste {len(self._clipboard):d} byte{plural}", self._paste_copied_bytes_at_cursor))
            add_sep = True

        if add_sep:
            mnu.add(MenuSeparator())
            add_sep = False

        mnu.add(self.breakpoint_menu())
        mnu.add(MenuSeparator())

        # Get context menu for specific item under cursor
        for rgn in self.grid.get_highlight_regions_under_cursor():
            rgn_mnu = rgn.context_menu()
            if rgn_mnu is not None:
                mnu.add(rgn_mnu)
                add_sep = True

        if add_sep:
            mnu.add(MenuSeparator())
            add_sep = False

        # Get context menu for groups of items
        selected_regions = self.grid.get_active_highlight_regions()
        if any(isinstance(r, PatchHighlightRegion) for r in selected_regions):
            mnu.add(
                MenuEntry(
                    "Merge selected patches",
                    self._merge_selected_patches,
                    enabled=self._can_merge_any_selected_patches(),
                )
            )
            mnu.add(MenuEntry("Revert selected patches", self.revert_selected_patches))
            add_sep = True

        if add_sep:
            mnu.add(MenuSeparator())

        mnu.add(self.synchronize_with_menu())
        return mnu

    def options_menu(self) -> Menu:
        """The Options button's menu."""
        return Menu(
            "Options",
            [
                MenuEntry(
                    "Smart &highlighting",
                    self.set_smart_highlighting_enabled,
                    checkable=True,
                    checked=self.smart_highlighting_enabled,
                )
            ],
        )

    #
    # Find in view
    #

    def show_find_bar(self) -> None:
        """Open the incremental find bar."""
        self._find_bar.activate()
        self._find_bar_opened()
        self._update_find_matches()

    def find_next(self) -> None:
        self._step_find_match(1)

    def find_previous(self) -> None:
        self._step_find_match(-1)

    def _iter_find_regions(self) -> list[tuple[int, bytes]]:
        if self._find_regions is None:
            project = project_of(self.instance)
            if project is None:
                self._find_regions = []
            else:
                searcher = Searcher(project, kb=self.instance.kb)
                self._find_regions = list(searcher.iter_regions(SCOPE_ALL))
        return self._find_regions

    def _compute_find_matches(self, query: str) -> list[tuple[int, int]]:
        matches: list[tuple[int, int]] = []
        limit = Conf.find_match_limit
        if self._find_bar.mode == "Hex":
            pattern = BytePattern.parse(query)
            for start, data in self._iter_find_regions():
                for addr in pattern.finditer(data, base=start):
                    if len(matches) >= limit:
                        self._find_capped = True
                        return matches
                    matches.append((addr, len(pattern)))
        else:
            regex = self._find_bar.compile_query()
            if regex is None:
                raise SearchError("Malformed query")
            for start, data in self._iter_find_regions():
                text = data.decode("latin-1")
                for match in regex.finditer(text):
                    if len(matches) >= limit:
                        self._find_capped = True
                        return matches
                    matches.append((start + match.start(), max(match.end() - match.start(), 1)))
        return matches

    def _update_find_matches(self) -> None:
        self._find_bar.set_text_options_visible(self._find_bar.mode != "Hex")
        query = self._find_bar.query
        self._find_index = -1
        self._find_matches = []
        self._find_capped = False
        if not self.instance.project.am_none and query:
            try:
                self._find_matches = self._compute_find_matches(query)
                self._find_bar.set_error(False)
            except SearchError:
                self._find_bar.set_error(True)
        else:
            self._find_bar.set_error(False)
        self._update_find_highlights()
        if self._find_matches:
            self._step_find_match(1)
        else:
            self._find_bar.set_match_status(0, 0)

    def _step_find_match(self, delta: int) -> None:
        if not self._find_matches:
            self._find_bar.set_match_status(0, 0)
            return
        self._find_index = (self._find_index + delta) % len(self._find_matches)
        addr, _size = self._find_matches[self._find_index]
        self.set_cursor(addr)
        self._find_bar.set_match_status(self._find_index, len(self._find_matches), capped=self._find_capped)

    def _update_find_highlights(self) -> None:
        self._find_highlights = [
            self.REGION_CLASS(Conf.disasm_view_operand_highlight_color, addr, size, "Find match")
            for addr, size in self._find_matches[: self.FIND_HIGHLIGHT_LIMIT]
        ]
        self._set_highlighted_regions()

    def _on_find_bar_closed(self) -> None:
        self._find_matches = []
        self._find_index = -1
        self._find_regions = None
        self._update_find_highlights()
        self._focus_grid()

    #
    # The cursor
    #

    def set_cursor(self, addr: int) -> None:
        """
        Move cursor to specific address and clear any active selection.
        """
        self.grid.clear_selection()
        self.grid.set_cursor(addr)

    def on_cursor_changed(self) -> None:
        """
        Handle updates to cursor or viewport.
        """
        cursor = self.grid.cursor
        self.update_status_text()
        self._update_cfb_highlight_regions()
        self.set_synchronized_cursor_address(cursor)
        self.published_view_state.cursors = [cursor]
        self.notify_view_state_updated()

    def status_text(self) -> str:
        """
        The status text: the cursor's address, or the selection and its size.
        """
        sel = self.grid.get_selection()
        if sel:
            minaddr, maxaddr = sel
            bytes_selected = maxaddr - minaddr + 1
            plural = "s" if bytes_selected != 1 else ""
            return f"Address: [{minaddr:08x}, {maxaddr:08x}], {bytes_selected} byte{plural} selected"
        return f"Address: {self.grid.cursor:08x}"

    def jump_to(self, addr: int) -> bool:
        """
        Jump to a specific address.
        """
        self.set_cursor(addr)
        return True

    def popup_jumpto_dialog(self) -> None:
        """Ask for an address or a function name and go there."""

        def then(answer: str | None) -> None:
            if not answer:
                return
            addr = resolve_address(self.instance, answer.strip())
            if addr is None:
                GlobalInfo.ui_services.message("warning", "Jump to", f"Cannot find {answer!r}.")
                return
            self.jump_to(addr)

        ask_text("Jump to", "Address or function name:", "", then)

    #
    # Synchronization
    #

    def on_synchronized_view_group_changed(self) -> None:
        """
        Handle view being added to or removed from the view synchronization group: the cursor shows without the focus
        while other views follow it.
        """
        grid = self._grid_if_ready()
        if grid is not None:
            grid.set_always_show_cursor(len(self.sync_state.views) > 1)

    def on_synchronized_highlight_regions_changed(self) -> None:
        """
        Handle synchronized highlight region change event.
        """
        self._update_highlight_regions_from_synchronized_views()

    #
    # Highlighted regions
    #

    def _update_cfb_highlight_regions(self) -> None:
        """
        Update cached list of highlight regions under cursor.
        """
        regions = []
        cfb = container(self.instance.cfb)
        is_arm = is_arm_arch(self.instance.project.arch) if not self.instance.project.am_none else False
        grid = self.grid
        if self.smart_highlighting_enabled and not cfb.am_none:
            try:
                for item in cfb.floor_items(grid.display_start_addr):
                    item_addr, item = item
                    if item.size is None:
                        continue
                    if (item_addr + item.size) < grid.display_start_addr:
                        continue
                    if item_addr >= grid.display_end_addr:
                        break
                    if isinstance(item, MemoryData):
                        is_string = item.sort in (MemoryDataSort.String, MemoryDataSort.UnicodeString)
                        color = Conf.hex_view_string_color if is_string else Conf.hex_view_data_color
                        regions.append(self.REGION_CLASS(color, item.addr, item.size, str(item)))
                    elif isinstance(item, Block):
                        try:
                            for insn in item.disassembly.insns:
                                s = f"{insn} in {item}"
                                insn_addr = insn.address & 0xFFFF_FFFE if is_arm else insn.address
                                regions.append(
                                    self.REGION_CLASS(Conf.hex_view_instruction_color, insn_addr, insn.size, s)
                                )
                        except angr.errors.SimEngineError:
                            pass  # We may get a node in CFB to a non-decodeable address
            except (RuntimeError, KeyError, IndexError):
                # the CFB may be mutated by the CFG recovery job thread while we iterate over it; keep what we have
                # collected so far - a following event will refresh the regions
                pass
        self._cfb_highlights = regions
        self._set_highlighted_regions()

    def _update_highlight_regions_from_synchronized_views(self) -> None:
        """
        Update cached list of highlight regions from synchronized views.
        """
        regions = []
        sync_state = self.sync_state
        for v in sync_state.highlight_regions:
            if v is not self:
                for r in sync_state.highlight_regions[v]:
                    regions.append(self.REGION_CLASS(self.SYNCHRONIZED_REGION_COLOR, r.addr, r.size))

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
                self.PATCH_REGION_CLASS(patch, self) for patch in self.instance.project.kb.patches.values()
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
                self.BREAKPOINT_REGION_CLASS(bp, self) for bp in self.instance.breakpoint_mgr.breakpoints
            ]
        self._set_highlighted_regions()

    def _set_highlighted_regions(self) -> None:
        """
        Update highlighted regions, with data from CFB and synchronized views.
        """
        regions = []
        regions.extend(self._cfb_highlights)
        regions.extend(self._sync_view_highlights)
        source = self.data_source
        if source == HexDataSource.Loader:
            regions.extend(self._patch_highlights)
            # find matches come from loader memory, so they may not reflect debugger memory
            regions.extend(self._find_highlights)
        elif source == HexDataSource.Debugger:
            regions.extend(self._changed_data_highlights)
        regions.extend(self._breakpoint_highlights)
        self.grid.set_highlight_regions(regions)


#: The hex view's palette commands: caption and method.
HEX_COMMANDS = [
    ("Find", "show_find_bar"),
    ("Find Next", "find_next"),
    ("Find Previous", "find_previous"),
]


def register_hex_commands(workspace) -> None:
    """Register the hex view's palette commands; they run on the focused hex view of either frontend."""
    view_class: type = HexViewMixin
    workspace.command_manager.register_commands(
        [
            ViewCommand("hex_view_" + method, "Hex: " + caption, getattr(view_class, method), view_class, workspace)
            for caption, method in HEX_COMMANDS
        ]
    )


def hex_keymap() -> Keymap:
    """
    The hex view's keys: HexView.keyPressEvent (G), its find shortcuts, and Ctrl+Space from HexGraphicsObject's. The
    arrows, Page Up/Down, Home and End (with Shift to select), hex digits and printable characters are the widget's.
    The terminal adds Shift+F10 for the context menu and Enter for what a double click does.
    """
    return Keymap(
        "hex",
        [
            Binding("G", "popup_jumpto_dialog", "Jump to an address or a function"),
            Binding("Ctrl+F", "show_find_bar", "Find"),
            Binding("F3", "find_next", "Find next"),
            Binding("Shift+F3", "find_previous", "Find previous", 2, "Shift+N"),
            Binding("Ctrl+Space", "toggle_column", "Switch between the bytes and the ASCII column"),
            Binding("Shift+F10", "context_menu", "Context menu"),
            Binding("Return", "select_region", "Select the region under the cursor (a double click)"),
        ],
    )


class HexPresenter(HexViewMixin, SynchronizedPresenter):
    """The hex view of a frontend that draws a :class:`HexGrid` itself."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "hex", instance, default_docking_position)
        self.base_caption = "Hex"
        self._grid = HexGrid()
        self._data_source = HexDataSource.Loader
        self._init_hex_state()
        self._find_bar = FindBarState(modes=["Hex", "Text"])
        self._find_bar.set_text_options_visible(False)  # the default mode is Hex
        self._find_bar.query_changed.connect(self._update_find_matches)
        self._find_bar.closed.connect(self._on_find_bar_closed)
        self._grid.cursor_moved.connect(self.on_cursor_changed)
        self._grid.viewport_moved.connect(self.on_cursor_changed)
        self._start_hex()

    @property
    def grid(self) -> HexGrid:
        return self._grid

    def _grid_if_ready(self) -> HexGrid | None:
        return getattr(self, "_grid", None)

    @property
    def find_bar(self) -> FindBarState:
        return self._find_bar

    @property
    def data_source(self) -> HexDataSource:
        return self._data_source

    def set_data_source(self, source: HexDataSource) -> None:
        """Show the loader's memory or the debugger's state."""
        if source != self._data_source:
            self._data_source = source
            self._data_source_changed(source.value)

    def data_source_menu(self) -> Menu:
        """The data source selector's menu."""
        return Menu(
            "Data source",
            [
                MenuEntry(
                    source.name,
                    lambda _checked=None, s=source: self.set_data_source(s),
                    checkable=True,
                    checked=source == self._data_source,
                )
                for source in HexDataSource
            ],
        )

    def close(self) -> None:
        self._stop_hex()
        self.desync()

    def reload(self) -> None:
        self._reload_data()

    @property
    def keymap(self) -> Keymap:
        return hex_keymap()

    def commands(self) -> list:
        return [cmd for cmd in self.workspace.command_manager.get_commands() if cmd.name.startswith("hex_view_")]

    def update_status_text(self) -> None:
        view = self.view
        status_changed = getattr(view, "status_changed", None)
        if status_changed is not None:
            status_changed()

    def _find_bar_opened(self) -> None:
        opened = getattr(self.view, "find_bar_opened", None)
        if opened is not None:
            opened()

    def _focus_grid(self) -> None:
        focus = getattr(self.view, "focus_view", None)
        if focus is not None:
            focus()

    def toggle_column(self) -> None:
        self._grid.toggle_column()

    def select_region(self) -> None:
        self._grid.select_region_under_cursor()


__all__ = [
    "BreakpointHighlightRegion",
    "HexDataSource",
    "HexGrid",
    "HexHighlightRegion",
    "HexPresenter",
    "HexViewMixin",
    "PatchHighlightRegion",
    "ascii_text",
    "byte_text",
    "hex_keymap",
    "register_hex_commands",
]
