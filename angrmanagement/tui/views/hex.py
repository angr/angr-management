"""
The hex view of the terminal frontend.

:class:`HexTuiView` draws a :class:`~angrmanagement.present.hexdump.HexPresenter`: a header line (the cursor's address
or the selection, the data source and the options, as the Qt view's tool bar), the find bar, and :class:`HexWidget`,
which shows one row of 16 bytes per line (the address, the bytes and their ASCII) with the cursor, the selection and
the highlighted regions, and a scroll bar over the whole range at its right edge.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.segment import Segment
from rich.style import Style
from textual.strip import Strip
from textual.widget import Widget

from angrmanagement.config.color import Color
from angrmanagement.present.hexdump import (
    MOVEMENT_KEYS,
    HexDataSource,
    HexGrid,
    HexPresenter,
    ascii_text,
    byte_text,
)
from angrmanagement.tui.theme import rich_color
from angrmanagement.tui.widgets.find_bar import FindBarWidget
from angrmanagement.tui.widgets.header import HeaderBar, HeaderItem
from angrmanagement.tui.widgets.styles import StyleCache, current_theme

from .base import TuiView

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events
    from textual.app import ComposeResult
    from textual.timer import Timer

    from angrmanagement.present.hexdump import HexHighlightRegion
    from angrmanagement.present.menus import Menu

#: How many rows a mouse wheel step scrolls.
WHEEL_ROWS = 3
#: How strongly a region's colour tints the bytes: inactive, and with the cursor or the selection in it.
REGION_ALPHA = 0.18
ACTIVE_REGION_ALPHA = 0.4
#: How often the cursor blinks, in seconds, as the Qt view's.
BLINK_INTERVAL = 0.75


def blend(color: Color, base: Color, alpha: float) -> Color:
    """``color`` laid over ``base`` with opacity ``alpha``."""
    return Color(
        round(color.r * alpha + base.r * (1 - alpha)),
        round(color.g * alpha + base.g * (1 - alpha)),
        round(color.b * alpha + base.b * (1 - alpha)),
    )


class HexLayout:
    """
    Where things are in a row, in cells, as the Qt view spaces them: one cell, the address, four cells, 16 bytes of two
    cells with one between them and two between the 8th and the 9th, four cells, and 16 ASCII characters.
    """

    def __init__(self, addr_width: int = 8) -> None:
        self.addr_x = 1
        self.addr_width = addr_width
        self.bytes_x = self.addr_x + addr_width + 4
        self.byte_columns = [self.bytes_x + 3 * i + (1 if i >= 8 else 0) for i in range(16)]
        self.ascii_x = self.byte_columns[15] + 3 + 4
        self.width = self.ascii_x + 16

    @classmethod
    def for_grid(cls, grid: HexGrid) -> HexLayout:
        return cls(max(8, len(f"{max(grid.display_end_addr - 1, 0):x}")))

    def column_at(self, x: int) -> tuple[int, bool] | None:
        """The byte column (0 to 15) of cell ``x`` and whether it is in the ASCII column, or None between columns."""
        if self.ascii_x <= x < self.ascii_x + 16:
            return x - self.ascii_x, True
        for col, start in enumerate(self.byte_columns):
            if start <= x < start + 2:
                return col, False
        return None


class HexWidget(Widget, can_focus=True):
    """
    The bytes: one row of 16 per line from the grid's first row shown. The arrows, Page Up and Page Down, Home and
    End move the cursor (with Shift they select), a hex digit writes a nibble in the bytes column and a character a
    byte in the ASCII column, a click puts the cursor and a drag selects, a double click selects the region under the
    cursor, a right click opens the context menu, and the wheel scrolls.
    """

    DEFAULT_CSS = """
    HexWidget {
        height: 1fr;
        width: 1fr;
    }
    """

    #: Whether the cursor blinks while the widget has the focus (snapshot tests turn it off).
    cursor_blink: ClassVar[bool] = True

    def __init__(self, view: HexTuiView) -> None:
        super().__init__()
        self.view = view
        self.style_of = StyleCache(self)
        self._dragging = False
        self._blink_timer: Timer | None = None
        self._hover: int | None = None
        grid = self.grid
        grid.changed.connect(self.refresh_rows)
        grid.viewport_moved.connect(self.refresh_rows)

    @property
    def grid(self) -> HexGrid:
        return self.view.presenter.grid

    @property
    def layout_cells(self) -> HexLayout:
        return HexLayout.for_grid(self.grid)

    def refresh_rows(self) -> None:
        if self.is_attached:
            self.refresh()

    #
    # Size and blinking
    #

    def on_mount(self) -> None:
        self._fit_rows()

    def on_resize(self, _event: events.Resize) -> None:
        self._fit_rows()

    def _fit_rows(self) -> None:
        # as the Qt view counts them: the rows shown and one more, the one Qt shows in part at the bottom, so the
        # cursor's row can be the last line and Page Down moves by the lines shown
        rows = self.size.height + 1
        if rows > 1 and self.grid.display_num_rows != rows:
            self.grid.set_display_num_rows(rows)

    def on_focus(self) -> None:
        grid = self.grid
        grid.show_cursor = True
        grid.cursor_blink_state = True
        if self.cursor_blink and self._blink_timer is None:
            self._blink_timer = self.set_interval(BLINK_INTERVAL, self._blink)
        self.refresh()

    def on_blur(self) -> None:
        grid = self.grid
        if self._blink_timer is not None:
            self._blink_timer.stop()
            self._blink_timer = None
        grid.show_cursor = grid.always_show_cursor
        grid.cursor_blink_state = grid.always_show_cursor
        self.refresh()

    def _blink(self) -> None:
        self.grid.cursor_blink_state = not self.grid.cursor_blink_state
        self.refresh()

    #
    # Drawing
    #

    def _background(self, row_addr: int) -> Color:
        theme = current_theme(self)
        return theme.background if row_addr & 0x10 else theme.alternate

    def _region_backgrounds(self, row_addr: int, base: Color) -> list[Color | None]:
        """The background of each byte of the row from the regions it is in (the last one listed on top)."""
        grid = self.grid
        out: list[Color | None] = [None] * 16
        end = row_addr + 16
        regions: list[HexHighlightRegion] = [
            r for r in grid.highlighted_regions if r.addr < end and r.addr + r.size > row_addr
        ]
        for region in regions:
            color = region.color if isinstance(region.color, Color) else None
            if color is None:
                continue
            shade = blend(color, base, ACTIVE_REGION_ALPHA if region.active else REGION_ALPHA)
            for addr in range(max(region.addr, row_addr), min(region.addr + region.size, end)):
                out[addr - row_addr] = shade
        return out

    def row_strip(self, row: int, width: int) -> Strip:
        """Row ``row`` of the rows shown, ``width`` cells wide."""
        grid = self.grid
        layout = self.layout_cells
        row_addr = grid.row_to_addr(row)
        base = self._background(row_addr)
        base_style = Style(bgcolor=rich_color(base))
        if row_addr >= grid.display_end_addr:
            return Strip.blank(width, Style(bgcolor=rich_color(current_theme(self).background)))
        cells: list[tuple[str, Style]] = [(" ", base_style)] * layout.width
        addr_style = self.style_of("disasm_view_node_address_color") + base_style

        def put(x: int, text: str, style: Style) -> None:
            for idx, char in enumerate(text):
                if 0 <= x + idx < len(cells):
                    cells[x + idx] = (char, style)

        put(layout.addr_x, f"{row_addr:0{layout.addr_width}x}", addr_style)
        backgrounds = self._region_backgrounds(row_addr, base)
        theme = current_theme(self)
        selection_bg = rich_color(theme.primary)
        for col in range(16):
            addr = row_addr + col
            if addr < grid.display_start_addr or addr >= grid.display_end_addr:
                continue
            val = grid.read(addr)
            region_bg = backgrounds[col]
            bg = rich_color(region_bg) if region_bg is not None else base_style.bgcolor
            selected = grid.is_selected(addr)
            text, key = byte_text(val)
            byte_style = self.style_of(key) + Style(bgcolor=bg)
            char, char_key = ascii_text(val)
            char_style = self.style_of(char_key) + Style(bgcolor=bg)
            if selected:
                byte_style += Style(
                    bgcolor=selection_bg, color=rich_color(theme.primary_text), dim=grid.ascii_column_active
                )
                char_style += Style(
                    bgcolor=selection_bg, color=rich_color(theme.primary_text), dim=not grid.ascii_column_active
                )
            x = layout.byte_columns[col]
            put(x, text, byte_style)
            # the gap after a byte takes the region's (or the selection's) background when the next byte shares it
            if col < 15 and col != 7:
                nxt = addr + 1
                if selected and grid.is_selected(nxt):
                    put(x + 2, " ", Style(bgcolor=selection_bg))
                elif region_bg is not None and backgrounds[col + 1] == region_bg:
                    put(x + 2, " ", Style(bgcolor=bg))
            put(layout.ascii_x + col, char, char_style)
        self._draw_cursor(cells, row_addr, layout)
        segments = [Segment(char, style) for char, style in cells]
        strip = Strip(segments, len(cells))
        return strip.crop(0, width).extend_cell_length(width, base_style)

    def _draw_cursor(self, cells: list[tuple[str, Style]], row_addr: int, layout: HexLayout) -> None:
        grid = self.grid
        if not row_addr <= grid.cursor < row_addr + 16:
            return
        if not grid.show_cursor and not self.has_focus:
            return
        col = grid.cursor - row_addr
        shown = grid.cursor_blink_state or not self.has_focus
        active = Style(reverse=True) if shown and self.has_focus else Style(underline=True)
        inactive = Style(underline=True)
        byte_x = layout.byte_columns[col]
        byte_cells = [byte_x, byte_x + 1]
        if grid.cursor_nibble is not None:
            byte_cells = [byte_x + (1 - grid.cursor_nibble)]
        for x in byte_cells:
            char, style = cells[x]
            cells[x] = (char, style + (inactive if grid.ascii_column_active else active))
        x = layout.ascii_x + col
        char, style = cells[x]
        cells[x] = (char, style + (active if grid.ascii_column_active else inactive))

    def scrollbar_strip(self, y: int) -> Strip:
        """The scroll bar's cell on line ``y``: the thumb where the first row shown is in the range."""
        grid = self.grid
        height = max(self.size.height, 1)
        theme = current_theme(self)
        if grid.end_addr - grid.start_addr <= 16 * height:
            return Strip.blank(1, Style(bgcolor=rich_color(theme.background)))
        thumb = min(height - 1, int(grid.scroll_fraction() * height))
        style = Style(bgcolor=rich_color(theme.primary if y == thumb else theme.panel))
        return Strip([Segment(" ", style)], 1)

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        return Strip.join([self.row_strip(y, max(width - 1, 0)), self.scrollbar_strip(y)])

    #
    # Keys
    #

    def on_key(self, event: events.Key) -> None:
        key = event.key
        parts = key.split("+")
        extend = "shift" in parts[:-1]
        base = "+".join([*(part for part in parts[:-1] if part != "shift"), parts[-1]])
        handled = True
        if base in MOVEMENT_KEYS:
            self.grid.move_cursor(base, extend)
        elif event.character is not None and event.is_printable and self.grid.type_text(event.character):
            pass
        else:
            handled = self.view.handle_hex_key(key)
        if handled:
            event.stop()
            event.prevent_default()

    #
    # Mouse
    #

    def address_at(self, event: events.MouseEvent) -> tuple[int, bool] | None:
        """The address under the mouse and whether it is in the ASCII column, or None off the bytes."""
        grid = self.grid
        hit = self.layout_cells.column_at(int(event.x))
        if hit is None:
            return None
        col, ascii_column = hit
        row = int(event.y)
        addr = grid.row_col_to_addr(row, col)
        if not grid.start_addr <= addr < grid.end_addr or addr >= grid.display_end_addr:
            return None
        return addr, ascii_column

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button != 1:
            return
        if int(event.x) == self.size.width - 1:
            self._scroll_to_line(int(event.y))
            return
        hit = self.address_at(event)
        if hit is None:
            return
        self.focus()
        self.grid.mouse_pressed = True
        self.grid.click(hit[0], hit[1], bool(event.shift))
        self._dragging = True
        self.capture_mouse()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        hit = self.address_at(event)
        if self._dragging:
            if hit is not None:
                self.grid.drag_to(*hit)
            return
        addr = hit[0] if hit is not None else None
        if addr != self._hover:
            self._hover = addr
            text = self.grid.tooltip_at(addr) if addr is not None else ""
            self.tooltip = text or None

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        if self._dragging:
            self._dragging = False
            self.grid.mouse_pressed = False
            self.release_mouse()

    def on_click(self, event: events.Click) -> None:
        if int(event.x) == self.size.width - 1:
            return
        hit = self.address_at(event)
        if event.button == 3:
            self.focus()
            if hit is not None and not self.grid.is_selected(hit[0]):
                self.grid.click(hit[0], hit[1], False)
            self.view.open_context_menu((int(event.screen_x), int(event.screen_y)))
        elif event.chain >= 2 and hit is not None:
            self.grid.select_region_under_cursor()

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        event.stop()
        self.grid.scroll_rows(WHEEL_ROWS)

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        event.stop()
        self.grid.scroll_rows(-WHEEL_ROWS)

    def _scroll_to_line(self, y: int) -> None:
        height = max(self.size.height - 1, 1)
        self.grid.scroll_to_fraction(y / height)


class HexHeader(HeaderBar):
    """The cursor's address or the selection; the data source and the options."""

    view: HexTuiView

    def items(self) -> tuple[list[HeaderItem], list[HeaderItem]]:
        view = self.view
        presenter = view.presenter
        return [(presenter.status_text(), None)], [
            (f"{presenter.data_source.name} ▾", lambda: view.open_header_menu(presenter.data_source_menu())),
            ("Options ▾", lambda: view.open_header_menu(presenter.options_menu())),
        ]


class HexTuiView(TuiView):
    """The hex view: header, find bar and the bytes."""

    PRESENTER_CLASS = HexPresenter

    presenter: HexPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.header = HexHeader(self)
        self.find_widget = FindBarWidget(self.presenter.find_bar, self.focus_view)
        self.hex = HexWidget(self)
        #: the presenter asked for the focus before the view was in the screen
        self._focus_on_mount = False

    def compose(self) -> ComposeResult:
        yield self.header
        yield self.find_widget
        yield self.hex

    def on_mount(self) -> None:
        if self._focus_on_mount:
            self._focus_on_mount = False
            self.hex.focus()

    #
    # What the presenter asks of its view
    #

    def status_changed(self) -> None:
        if self.is_mounted:
            self.header.refresh()

    def find_bar_opened(self) -> None:
        if self.is_mounted:
            self.find_widget.open()

    def focus_view(self) -> None:
        if self.is_mounted:
            self.hex.focus()
        else:
            self._focus_on_mount = True

    def jump_to(self, addr: int, **_kwargs) -> bool:
        return self.presenter.jump_to(addr)

    #
    # Menus and keys
    #

    def open_menu(self, menu: Menu, offset: tuple[int, int]) -> None:
        open_context_menu = getattr(self.app, "open_context_menu", None) if self.is_attached else None
        if open_context_menu is not None:
            open_context_menu(menu, offset)

    def open_header_menu(self, menu: Menu) -> None:
        region = self.header.region
        self.open_menu(menu, (region.right - 20, region.y + 1))

    def _cursor_offset(self) -> tuple[int, int]:
        grid = self.presenter.grid
        widget = self.hex
        layout = widget.layout_cells
        row, col = grid.addr_to_row_col(grid.cursor)
        x = layout.ascii_x + col if grid.ascii_column_active else layout.byte_columns[col]
        return widget.region.x + x, widget.region.y + row + 1

    def open_context_menu(self, offset: tuple[int, int] | None = None) -> None:
        self.open_menu(self.presenter.context_menu(), offset or self._cursor_offset())

    def handle_hex_key(self, key: str) -> bool:
        """Run the action bound to ``key``; whether one was."""
        action = self.key_actions().get(key)
        if action is None:
            return False
        special: dict[str, Callable[[], Any]] = {"context_menu": self.open_context_menu}
        if action in special:
            special[action]()
        else:
            getattr(self.presenter, action)()
        return True

    def show_find_bar(self) -> None:
        self.presenter.show_find_bar()

    def set_data_source(self, source: HexDataSource) -> None:
        self.presenter.set_data_source(source)
        self.status_changed()


__all__ = ["HexLayout", "HexTuiView", "HexWidget"]
