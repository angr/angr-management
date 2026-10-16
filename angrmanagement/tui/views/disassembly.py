"""
The disassembly view of the terminal frontend.

:class:`DisassemblyTuiView` draws a :class:`~angrmanagement.present.disasm.DisasmPresenter`: a header line (back,
forward, the function, and the save, mode, level and options buttons, as the Qt view's tool bar), the find bar, and
either the graph (:class:`GraphWidget`, the function's blocks and edges on a :class:`~angrmanagement.tui.canvas.
CharCanvas`) or the linear listing (:class:`LinearWidget`). The presenter's controls are
:class:`~angrmanagement.present.disasm_controls.GraphControl` and :class:`~angrmanagement.present.disasm_controls.
LinearControl`; the widgets draw them and turn keys and clicks into the presenter's actions.
"""

from __future__ import annotations

import io
import os
from typing import TYPE_CHECKING, Any, ClassVar

from rich.segment import Segment
from rich.text import Text
from textual.containers import Horizontal
from textual.geometry import Region, Size
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widget import Widget
from textual.widgets import Checkbox, Input, Label

from angrmanagement.logic import GlobalInfo
from angrmanagement.present.block_tree.base import BlockTreeNode
from angrmanagement.present.block_tree.disasm_nodes import (
    CodeNode,
    InsnNode,
    LabelNode,
    MemoryDataNode,
    OperandNode,
    UnknownNode,
    VariableNode,
)
from angrmanagement.present.disasm import LEVEL_NAMES, DisasmPresenter
from angrmanagement.present.disasm_controls import GraphControl, LinearControl
from angrmanagement.present.disasm_style import (
    BLOCK_BORDER_STYLE,
    BLOCK_SELECTED_BORDER_STYLE,
    edge_style,
)
from angrmanagement.present.find import FindBarState
from angrmanagement.present.marks import Mark
from angrmanagement.present.menus import Menu, MenuEntry
from angrmanagement.present.theme import BACKGROUND_PREFIX, Theme
from angrmanagement.tui.canvas import DOWN, CharCanvas
from angrmanagement.tui.theme import rich_style

from .base import TuiView

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.style import Style
    from textual import events
    from textual.app import ComposeResult

    from angrmanagement.present.disasm import GraphDoc
    from angrmanagement.present.spans import Line

#: The background of the graph view.
CANVAS_STYLE = BACKGROUND_PREFIX + "disasm_view_background_color"
#: How many lines a mouse wheel step or a key scrolls the linear view.
WHEEL_LINES = 3


def current_theme(widget: Widget) -> Theme:
    theme = getattr(widget.app, "am_theme", None)
    return theme if isinstance(theme, Theme) else Theme.from_conf()


class StyleCache:
    """Rich styles of style keys through the app's theme, cached until the theme changes."""

    def __init__(self, widget: Widget) -> None:
        self.widget = widget
        self._theme: Theme | None = None
        self._styles: dict[str, Style] = {}

    def __call__(self, key: str) -> Style:
        theme = current_theme(self.widget)
        if theme is not self._theme:
            self._theme = theme
            self._styles = {}
        style = self._styles.get(key)
        if style is None:
            style = self._styles[key] = rich_style(theme.style(key))
        return style


def line_strip(line: Line, style_of: Callable[[str], Style], x0: int, width: int, base: str = "") -> Strip:
    """A line of spans as a Strip from column ``x0``, ``width`` cells wide."""
    segments = [Segment(span.text, style_of(f"{base} {span.style}".strip())) for span in line.spans]
    strip = Strip(segments).crop(x0, x0 + width)
    return strip.extend_cell_length(width, style_of(base))


def _span_node(line: Line | None, column: int) -> Any:
    if line is None:
        return None
    return line.node_at(column)


#
# The header
#

#: A header word and what a click on it does (None: it is a label).
HeaderItem = tuple[str, "Callable[[], Any] | None"]


class DisasmHeader(Widget):
    """
    One line: ◀ Back, ▶ Forward, the function, and Save image..., the mode, the level and Options, as the Qt view's
    status bar has them. Each word is a button; the drop-down marks open menus.
    """

    DEFAULT_CSS = """
    DisasmHeader {
        height: 1;
        width: 1fr;
        background: $panel;
    }
    """

    def __init__(self, view: DisassemblyTuiView) -> None:
        super().__init__()
        self.view = view
        self._buttons: list[tuple[int, int, Callable[[], Any]]] = []

    @property
    def presenter(self) -> DisasmPresenter:
        return self.view.presenter

    def items(self) -> tuple[list[HeaderItem], list[HeaderItem]]:
        """The left and right groups: (text, what a click does)."""
        p = self.presenter
        func = p.function.am_obj
        name = ""
        if func is not None:
            name = func.demangled_name
            if len(name) > 55:
                name = name[:55] + "..."
            name += f" ({func.addr:x})"
        mode = "Linear Disassembly" if p.is_linear else "Graph Disassembly"
        left: list[HeaderItem] = [
            ("◀ Back", p.jump_back),
            ("▾", lambda: self.view.open_menu(p.history_menu())),
            ("▶ Forward", p.jump_forward),
            ("▾", lambda: self.view.open_menu(p.history_menu())),
            (name, None),
        ]
        right: list[HeaderItem] = [
            ("Save image...", self.view.save_image),
            (f"{mode} ▾", lambda: self.view.open_menu(self.view.mode_menu())),
            (f"{LEVEL_NAMES[p.disassembly_level]} ▾", lambda: self.view.open_menu(p.level_menu())),
            ("Options ▾", lambda: self.view.open_menu(p.options_menu())),
        ]
        return left, right

    def render(self) -> Text:
        left, right = self.items()
        width = self.size.width
        text = Text(no_wrap=True)
        self._buttons = []

        def add(items) -> None:
            for idx, (label, action) in enumerate(items):
                if idx:
                    text.append("  " if label != "▾" else " ")
                start = len(text)
                text.append(label, style="bold" if action is not None else "")
                if action is not None:
                    self._buttons.append((start, len(text), action))

        add(left)
        right_width = sum(len(label) for label, _ in right) + 2 * (len(right) - 1)
        text.append(" " * max(2, width - len(text) - right_width))
        add(right)
        return text

    def on_click(self, event: events.Click) -> None:
        for start, end, action in self._buttons:
            if start <= event.x < end:
                event.stop()
                action()
                return


#
# The find bar
#


class FindBarWidget(Horizontal):
    """The find bar: the query, the mode, case and regex switches, and the match counter."""

    DEFAULT_CSS = """
    FindBarWidget {
        height: 1;
        display: none;
        background: $panel;
    }
    FindBarWidget > Input {
        width: 40;
        height: 1;
        border: none;
        padding: 0 1;
    }
    FindBarWidget > Checkbox {
        height: 1;
        border: none;
        padding: 0;
        margin: 0 1;
    }
    FindBarWidget > Label {
        padding: 0 1;
    }
    """

    def __init__(self, state: FindBarState, on_close: Callable[[], Any]) -> None:
        super().__init__()
        self.state = state
        self.on_close = on_close
        self.query_input = Input(placeholder="Find...", compact=True)
        self.mode_label = Label("", id="find-mode")
        self.case_box = Checkbox("Case", compact=True)
        self.regex_box = Checkbox("Regex", compact=True)
        self.status_label = Label("", id="find-status")
        state.changed.connect(self._update)

    def compose(self) -> ComposeResult:
        yield self.query_input
        yield self.mode_label
        yield self.case_box
        yield self.regex_box
        yield self.status_label

    def _update(self) -> None:
        if not self.is_attached:
            return
        self.display = self.state.is_open
        self.mode_label.update(f"[{self.state.mode}]" if self.state.mode else "")
        self.status_label.update(self.state.status)
        self.case_box.display = self.state.text_options_visible
        self.regex_box.display = self.state.text_options_visible
        if self.query_input.value != self.state.query:
            self.query_input.value = self.state.query

    def open(self) -> None:
        self._update()
        self.query_input.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        if event.value != self.state.query:
            self.state.set_query(event.value)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        if event.checkbox is self.case_box:
            self.state.set_case_sensitive(event.value)
        elif event.checkbox is self.regex_box:
            self.state.set_use_regex(event.value)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self.mode_label:
            self.state.next_mode()

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            event.stop()
            self.state.close_bar()
            self.on_close()
        elif event.key == "enter":
            event.stop()
            self.view_presenter().find_next()
        elif event.key == "shift+enter":
            event.stop()
            self.view_presenter().find_previous()
        elif event.key == "ctrl+t":
            event.stop()
            self.state.next_mode()

    def view_presenter(self) -> DisasmPresenter:
        view = self.parent
        assert isinstance(view, DisassemblyTuiView)
        return view.presenter


#
# Drawing a graph
#


def draw_block(canvas: CharCanvas, doc: GraphDoc, key: Any, control: GraphControl, presenter: DisasmPresenter) -> None:
    """One block on the canvas: its background, its frame (heavier when selected) and its lines."""
    block = doc.blocks[key]
    x, y = doc.layout[key]
    w, h = doc.sizes[key]
    selected = presenter.infodock.is_block_selected(block.addr)
    border = BLOCK_SELECTED_BORDER_STYLE if selected else BLOCK_BORDER_STYLE
    # the lowest level of detail shows only the headers, as the Qt graph zoomed out shows no text
    background = presenter.block_background_style(block.addr, zoomed_out=control.detail >= 3)
    canvas.clear(x, y, w, h)
    canvas.fill(x, y, w, h, background, " ")
    canvas.box(x, y, w, h, style=f"{background} {border}")
    canvas.blit(control.block_lines(block), x + 2, y + 1, base_style=background, width=w - 4)
    # where edges leave the block, its bottom border joins them
    for edge in doc.edges:
        if edge.src_addr == block.addr and len(edge.points) >= 2:
            sx, _sy = edge.points[0]
            if x < sx < x + w - 1:
                canvas.mark(sx, y + h - 1, DOWN, f"{background} {border}")


def draw_graph(doc: GraphDoc, control: GraphControl, presenter: DisasmPresenter, margin: int = 2) -> CharCanvas:
    """The graph on a canvas: the blocks, then the edges in their colours."""
    width, height = doc.size
    canvas = CharCanvas(width + margin, height + margin, style=CANVAS_STYLE)
    for key in doc.blocks:
        draw_block(canvas, doc, key, control, presenter)
    for edge in doc.edges:
        if len(edge.points) >= 2:
            canvas.polyline(edge.points, f"{CANVAS_STYLE} {edge_style(edge.sort)}")
    return canvas


def draw_minimap(doc: GraphDoc, viewport: tuple[int, int, int, int], max_width: int = 24, max_height: int = 12):
    """
    The layout in braille, one cell for each 2x4 dots: blocks filled, the viewport's corners marked. Returns
    ``(rows, scale)`` where each row is a list of (char, is_viewport) and scale maps a minimap cell to layout cells.
    """
    width, height = doc.size
    if width <= 0 or height <= 0:
        return [], (1.0, 1.0)
    dots_w, dots_h = max_width * 2, max_height * 4
    scale = max(width / dots_w, height / dots_h, 1e-9)
    cols = max(1, min(max_width, int(width / scale / 2) + 1))
    rows = max(1, min(max_height, int(height / scale / 4) + 1))
    dots = [[0] * cols for _ in range(rows)]
    bits = ((0x01, 0x08), (0x02, 0x10), (0x04, 0x20), (0x40, 0x80))

    def set_dot(dx: int, dy: int) -> None:
        cx, cy = dx // 2, dy // 4
        if 0 <= cx < cols and 0 <= cy < rows:
            dots[cy][cx] |= bits[dy % 4][dx % 2]

    for key, (x, y) in doc.layout.items():
        w, h = doc.sizes[key]
        for dy in range(int(y / scale), max(int((y + h) / scale), int(y / scale) + 1)):
            for dx in range(int(x / scale), max(int((x + w) / scale), int(x / scale) + 1)):
                set_dot(dx, dy)
    vx, vy, vw, vh = viewport
    view_cells = set()
    for dy in range(int(vy / scale), int((vy + vh) / scale) + 1):
        for dx in range(int(vx / scale), int((vx + vw) / scale) + 1):
            view_cells.add((dx // 2, dy // 4))
    out = []
    for cy in range(rows):
        out.append([(chr(0x2800 + dots[cy][cx]), (cx, cy) in view_cells) for cx in range(cols)])
    return out, (scale * 2, scale * 4)


class GraphWidget(ScrollView, can_focus=True):
    """The graph of the function shown, drawn from its GraphControl; arrows and PgUp/PgDn/Home/End pan."""

    DEFAULT_CSS = """
    GraphWidget {
        height: 1fr;
        width: 1fr;
    }
    """

    def __init__(self, view: DisassemblyTuiView, control: GraphControl) -> None:
        super().__init__()
        self.view = view
        self.control = control
        self.canvas: CharCanvas | None = None
        self.style_of = StyleCache(self)
        self._drag_from: tuple[int, int] | None = None
        #: blank space around the canvas, so any block can be scrolled to the middle (Qt's scene margins)
        self.pad = (0, 0)
        self.minimap_rows: list = []
        self.minimap_scale = (1.0, 1.0)
        control.on_change = self.rebuild

    @property
    def presenter(self) -> DisasmPresenter:
        return self.view.presenter

    def rebuild(self) -> None:
        """Draw the graph again and apply the scroll position the control asked for."""
        doc = self.control.doc
        changed = self.control.changed_blocks
        if changed is not None and doc is not None and self.canvas is not None:
            self._redraw_blocks(doc, changed)
            return
        self.canvas = draw_graph(doc, self.control, self.presenter) if doc is not None else None
        self._update_virtual_size()
        if self.is_mounted and self.size.width and self.size.height:
            self.apply_focus()
        self.refresh()
        self.view.header_changed()

    def _redraw_blocks(self, doc: GraphDoc, keys: set[Any]) -> None:
        """Draw only the blocks in ``keys`` again (a selection changed), and repaint only their cells."""
        assert self.canvas is not None
        sx, sy = self.scroll_offset
        for key in keys:
            draw_block(self.canvas, doc, key, self.control, self.presenter)
            x, y = doc.layout[key]
            w, h = doc.sizes[key]
            self.refresh(Region(x + self.pad[0] - sx, y + self.pad[1] - sy, w, h))
        if self.presenter.show_minimap:
            self.refresh(Region(0, 0, 32, len(self.minimap_rows) + 2))
        if self.control.focus is not None and self.is_mounted:
            self.apply_focus()

    def _update_virtual_size(self) -> None:
        vw, vh = self.size.width, self.size.height
        width, height = (self.canvas.width, self.canvas.height) if self.canvas is not None else (0, 0)
        # narrower than the view: centre it, as a QGraphicsView centres a small scene
        pad_x = (vw - width) // 2 if width < vw else vw // 2
        pad_y = vh // 2
        self.pad = (pad_x, pad_y)
        self.virtual_size = Size(width + 2 * pad_x if width >= vw else vw, height + 2 * pad_y)

    def apply_focus(self) -> None:
        """
        Scroll to what the control wants shown: first the entry block's initial view if the graph is new, then an
        instruction, which moves the view only if it is not already in it (centred if it must move).
        """
        control = self.control
        doc = control.doc
        if doc is None or (control.focus is None and not control.reset_pending):
            return
        vw, vh = self.size.width, self.size.height
        sx, sy = self.scroll_offset
        if control.reset_pending:
            sx, sy = self._entry_target(doc, vw, vh)
            control.reset_pending = False
        if control.focus is not None:
            x, y = control.focus[0] + self.pad[0], control.focus[1] + self.pad[1]
            control.focus = None
            if control.focus_center or not (sx <= x < sx + vw and sy <= y < sy + vh):
                sx, sy = x - vw // 2, y - vh // 2
        sx, sy = max(sx, 0), max(sy, 0)
        # after the next refresh, when the scroll range knows the new virtual size
        self.call_after_refresh(self.scroll_to, sx, sy, animate=False, force=True)

    def _entry_target(self, doc: GraphDoc, vw: int, vh: int) -> tuple[int, int]:
        # as QDisassemblyGraph._initial_position: the entry block's centre in the middle, its top a quarter down
        pad_x, pad_y = self.pad
        if doc.entry is None or doc.entry not in doc.layout:
            return 0, 0
        x, y = doc.layout[doc.entry]
        w, _h = doc.sizes[doc.entry]
        width, height = doc.size
        if height < vh // 1.5:
            return pad_x + width // 2 - vw // 2, pad_y + height // 2 - vh // 2
        return pad_x + x + w // 2 - vw // 2, pad_y + y - vh // 4

    def on_resize(self, _event: events.Resize) -> None:
        self._update_virtual_size()
        self.apply_focus()

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        scroll_x, scroll_y = self.scroll_offset
        if self.canvas is None:
            return Strip.blank(width, self.style_of(CANVAS_STYLE))
        strip = self.canvas.strip(scroll_y + y - self.pad[1], self.style_of, scroll_x - self.pad[0], width)
        if self.presenter.show_minimap and self.control.doc is not None:
            strip = self._with_minimap(strip, y)
        return strip

    def _with_minimap(self, strip: Strip, y: int) -> Strip:
        if y == 0:
            sx, sy = self.scroll_offset
            assert self.control.doc is not None
            self.minimap_rows, self.minimap_scale = draw_minimap(
                self.control.doc, (sx - self.pad[0], sy - self.pad[1], self.size.width, self.size.height)
            )
        if not 1 <= y <= len(self.minimap_rows):
            return strip
        row = self.minimap_rows[y - 1]
        segments = [
            Segment(
                char,
                self.style_of(
                    "disasm_view_minimap_viewport_color bg:disasm_view_minimap_background_color"
                    if in_view
                    else "disasm_view_minimap_outline_color bg:disasm_view_minimap_background_color"
                ),
            )
            for char, in_view in row
        ]
        overlay = Strip(segments)
        left = strip.crop(0, 2)
        right = strip.crop(2 + overlay.cell_length, strip.cell_length)
        return Strip.join([left, overlay, right])

    #
    # Mouse
    #

    def _layout_cell(self, event: events.MouseEvent) -> tuple[int, int]:
        sx, sy = self.scroll_offset
        return int(event.x) + sx - self.pad[0], int(event.y) + sy - self.pad[1]

    def _minimap_target(self, event: events.MouseEvent) -> tuple[int, int] | None:
        if not self.presenter.show_minimap or not self.minimap_rows:
            return None
        mx, my = int(event.x) - 2, int(event.y) - 1
        if 0 <= my < len(self.minimap_rows) and 0 <= mx < len(self.minimap_rows[0]):
            return int(mx * self.minimap_scale[0]), int(my * self.minimap_scale[1])
        return None

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button != 1:
            return
        target = self._minimap_target(event)
        if target is not None:
            x, y = target[0] + self.pad[0], target[1] + self.pad[1]
            self.scroll_to(max(x - self.size.width // 2, 0), max(y - self.size.height // 2, 0), animate=False)
            return
        hit = self.control.node_at(*self._layout_cell(event))
        if hit is None:
            self._drag_from = (int(event.screen_x), int(event.screen_y))
            self.capture_mouse()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if self._drag_from is None:
            return
        x, y = int(event.screen_x), int(event.screen_y)
        dx, dy = self._drag_from[0] - x, self._drag_from[1] - y
        self._drag_from = (x, y)
        sx, sy = self.scroll_offset
        self.scroll_to(max(sx + dx, 0), max(sy + dy, 0), animate=False)

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        if self._drag_from is not None:
            self._drag_from = None
            self.release_mouse()

    def on_click(self, event: events.Click) -> None:
        self.focus()
        if self._minimap_target(event) is not None:
            return
        hit = self.control.node_at(*self._layout_cell(event))
        if hit is None:
            return
        key, node, column = hit
        line = None
        if node is not None and self.control.doc is not None:
            block = self.control.doc.blocks[key]
            _x, y = self.control.doc.layout[key]
            row = self._layout_cell(event)[1] - y - 1
            lines = self.control.block_lines(block)
            line = lines[row] if 0 <= row < len(lines) else None
        button = "right" if event.button == 3 else "left"
        self.view.activate(
            _span_node(line, column),
            node,
            button,
            event.chain,
            bool(event.ctrl),
            key.addr,
            (int(event.screen_x), int(event.screen_y)),
        )

    #
    # Keys
    #

    def pan(self, dx: int, dy: int) -> None:
        sx, sy = self.scroll_offset
        self.scroll_to(max(sx + dx, 0), max(sy + dy, 0), animate=False)

    def on_key(self, event: events.Key) -> None:
        moves = {
            "up": (0, -1),
            "down": (0, 1),
            "left": (-2, 0),
            "right": (2, 0),
            "pageup": (0, -max(self.size.height - 2, 1)),
            "pagedown": (0, max(self.size.height - 2, 1)),
        }
        if event.key in moves:
            event.stop()
            self.pan(*moves[event.key])
        elif event.key == "home":
            event.stop()
            self.control.reset_pending = self.control.doc is not None
            self.apply_focus()
        elif event.key == "end":
            event.stop()
            self.scroll_to(0, max(self.virtual_size.height - self.size.height, 0), animate=False)
        elif self.view.handle_disasm_key(event.key):
            event.stop()


#
# The linear listing
#


class LinearWidget(Widget, can_focus=True):
    """
    The linear listing from its LinearControl: one row per line of the objects on screen, and a scroll bar in the
    last column that maps to byte offsets, as the Qt view's does.
    """

    DEFAULT_CSS = """
    LinearWidget {
        height: 1fr;
        width: 1fr;
    }
    """

    LEFT_MARGIN = 2

    def __init__(self, view: DisassemblyTuiView, control: LinearControl) -> None:
        super().__init__()
        self.view = view
        self.control = control
        self.style_of = StyleCache(self)
        self.hscroll = 0
        self._lines: list[tuple[Any, Line]] = []
        control.on_change = self.rebuild

    @property
    def presenter(self) -> DisasmPresenter:
        return self.view.presenter

    def rebuild(self) -> None:
        self._lines = self.control.lines()
        self.refresh()
        self.view.header_changed()

    def on_resize(self, event: events.Resize) -> None:
        rows = max(event.size.height, 1)
        if rows != self.control.rows:
            self.control.rows = rows
            self.control.refresh()

    def _thumb_row(self) -> int:
        height = max(self.size.height, 1)
        max_offset = max(self.control.max_offset, 1)
        offset = self.control.offset or 0
        return min(height - 1, int(offset / max_offset * height))

    def render_line(self, y: int) -> Strip:
        width = max(self.size.width - 1, 0)
        background = CANVAS_STYLE
        if y < len(self._lines):
            _node, line = self._lines[y]
            body = line_strip(line, self.style_of, self.hscroll, width - self.LEFT_MARGIN, background)
            strip = Strip.join([Strip.blank(self.LEFT_MARGIN, self.style_of(background)), body])
        else:
            strip = Strip.blank(width, self.style_of(background))
        bar = "█" if y == self._thumb_row() else "│"
        return Strip.join([strip, Strip([Segment(bar, self.style_of("disasm_view_minimap_outline_color"))])])

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        event.stop()
        self.control.scroll(WHEEL_LINES)

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        event.stop()
        self.control.scroll(-WHEEL_LINES)

    def on_click(self, event: events.Click) -> None:
        self.focus()
        x, y = int(event.x), int(event.y)
        if x >= self.size.width - 1:
            # the scroll bar: jump to the offset of that row
            offset = int(y / max(self.size.height, 1) * self.control.max_offset)
            self.presenter.workspace.note_user_navigation()
            self.control.navigate_to(offset)
            return
        if not 0 <= y < len(self._lines):
            return
        node, line = self._lines[y]
        column = x - self.LEFT_MARGIN + self.hscroll
        button = "right" if event.button == 3 else "left"
        block_addr = getattr(node, "addr", None)
        self.view.activate(
            _span_node(line, column),
            node,
            button,
            event.chain,
            bool(event.ctrl),
            block_addr,
            (int(event.screen_x), int(event.screen_y)),
        )

    def on_key(self, event: events.Key) -> None:
        page = max(self.size.height - 1, 1)
        moves = {"up": -1, "down": 1, "pageup": -page, "pagedown": page}
        if event.key in moves:
            event.stop()
            self.control.scroll(moves[event.key])
        elif event.key in ("left", "right"):
            event.stop()
            self.hscroll = max(self.hscroll + (-4 if event.key == "left" else 4), 0)
            self.refresh()
        elif event.key == "home":
            event.stop()
            self.control.navigate_to(0)
        elif event.key == "end":
            event.stop()
            self.control.navigate_to(max(self.control.max_offset - 1, 0))
        elif self.view.handle_disasm_key(event.key):
            event.stop()


#
# The view
#


class DisassemblyTuiView(TuiView):
    """The disassembly view: header, find bar, and the graph or the linear listing."""

    PRESENTER_CLASS = DisasmPresenter

    DEFAULT_CSS = """
    DisassemblyTuiView {
        height: 1fr;
        width: 1fr;
    }
    """

    #: The keys of the terminal only: selecting instructions without a mouse.
    EXTRA_KEYS: ClassVar[dict[str, str]] = {"j": "select_next", "k": "select_previous"}

    presenter: DisasmPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        presenter = self.presenter
        self.header = DisasmHeader(self)
        self.find_state = FindBarState(DisasmPresenter.FIND_MODES)
        presenter.find_bar = self.find_state
        self.find_state.query_changed.connect(presenter.update_find_matches)
        self.find_state.closed.connect(presenter.on_find_bar_closed)
        self.find_widget = FindBarWidget(self.find_state, self.focus_view)
        self.flow_graph = GraphControl(presenter)
        self.linear_viewer = LinearControl(presenter)
        self.linear_viewer.viewport_changed.connect(presenter.on_linear_viewport_changed)
        self.graph_widget = GraphWidget(self, self.flow_graph)
        self.linear_widget = LinearWidget(self, self.linear_viewer)
        self.linear_widget.display = False
        self._last_mouse: tuple[int, int] | None = None
        self._key_actions: dict[str, str] | None = None
        presenter.level_changed.connect(lambda _level: self.header_changed())
        presenter.view_visibility_changed.connect(self.header_changed)
        presenter.attach(self, node_target=presenter)
        presenter.display_disasm_graph()
        plugins = getattr(workspace, "plugins", None)
        if plugins is not None:
            plugins.instrument_disassembly_view(self)

    def compose(self) -> ComposeResult:
        yield self.header
        yield self.find_widget
        yield self.graph_widget
        yield self.linear_widget

    #
    # What the presenter asks of its view
    #

    def show_control(self, control) -> None:
        graph = control is self.flow_graph
        self.graph_widget.display = graph
        self.linear_widget.display = not graph
        self.flow_graph.visible = graph
        self.linear_viewer.visible = not graph

    def control_switched(self, control) -> None:
        widget = self.graph_widget if control is self.flow_graph else self.linear_widget
        if self.is_mounted:
            widget.focus()

    def set_status_function(self, _func) -> None:
        self.header_changed()

    def header_changed(self) -> None:
        if self.is_mounted:
            self.header.refresh()

    def open_menu(self, menu: Menu) -> None:
        open_context_menu = getattr(self.app, "open_context_menu", None) if self.is_attached else None
        if open_context_menu is None:
            return
        offset = self._last_mouse or self._cursor_offset()
        open_context_menu(menu, offset)

    def _cursor_offset(self) -> tuple[int, int]:
        widget = self.graph_widget if self.graph_widget.display else self.linear_widget
        region = widget.region
        return region.x + 4, region.y + 2

    def focus_view(self) -> None:
        widget = self.graph_widget if self.graph_widget.display else self.linear_widget
        widget.focus()

    def mode_menu(self) -> Menu:
        presenter = self.presenter
        return Menu(
            "&Mode",
            [
                MenuEntry(
                    "Linear Disassembly",
                    lambda _checked=True: presenter.display_linear_viewer(),
                    checkable=True,
                    checked=presenter.is_linear,
                ),
                MenuEntry(
                    "Graph Disassembly",
                    lambda _checked=True: presenter.display_disasm_graph(),
                    checkable=True,
                    checked=not presenter.is_linear,
                ),
            ],
        )

    def save_image(self) -> None:
        """Save the graph (or the linear page) as an SVG of its text, as the Qt view saves a PNG."""

        async def flow() -> None:
            services: Any = GlobalInfo.ui_services
            if not hasattr(services, "ask_save_file"):
                return
            func = self.presenter.function.am_obj
            default = f"{func.name if func is not None else 'disassembly'}.svg"
            path = await services.ask_save_file("Save image...", default, "SVG files (*.svg)")
            if path:
                self.write_image(path)

        run_flow = getattr(self.app, "run_flow", None)
        if run_flow is not None:
            run_flow(flow())

    def write_image(self, path: str) -> str:
        """Write the whole graph (or the linear page) to ``path`` as SVG; returns the path."""
        from rich.console import Console  # pylint:disable=import-outside-toplevel

        if self.graph_widget.display and self.graph_widget.canvas is not None:
            canvas = self.graph_widget.canvas
            strips = canvas.to_strips(None, self.graph_widget.style_of)
        else:
            strips = [
                line_strip(line, self.linear_widget.style_of, 0, 160) for _node, line in self.linear_viewer.lines()
            ]
        width = max((strip.cell_length for strip in strips), default=1)
        console = Console(record=True, width=width, file=io.StringIO(), color_system="truecolor")
        for strip in strips:
            console.print(Text.assemble(*((seg.text, seg.style or "") for seg in strip)), soft_wrap=True)
        svg = console.export_svg(title=os.path.basename(path))
        with open(path, "w", encoding="utf-8") as f:
            f.write(svg)
        return path

    #
    # Keys and clicks
    #

    def key_actions(self) -> dict[str, str]:
        if self._key_actions is None:
            caps = getattr(self.app, "caps", 2)
            actions = {}
            for binding in self.presenter.keymap.for_tier(caps):
                key = binding.textual_key()
                if key is not None:
                    actions.setdefault(key, binding.action)
            for key, action in self.EXTRA_KEYS.items():
                actions.setdefault(key, action)
            self._key_actions = actions
        return self._key_actions

    def handle_disasm_key(self, key: str) -> bool:
        """Run the action bound to ``key``; whether one was."""
        action = self.key_actions().get(key)
        if action is None:
            return False
        self.run_disasm_action(action)
        return True

    def run_disasm_action(self, action: str) -> None:
        presenter = self.presenter
        special: dict[str, Callable[[], Any]] = {
            "xrefs": presenter.xrefs_for_selection,
            "more_detail": lambda: self.flow_graph.set_detail(self.flow_graph.detail - 1),
            "less_detail": lambda: self.flow_graph.set_detail(self.flow_graph.detail + 1),
            "reset_detail": lambda: self.flow_graph.set_detail(0),
            "context_menu": self.open_context_menu,
            "activate": self.activate_selection,
            "select_next": lambda: self.step_selection(1),
            "select_previous": lambda: self.step_selection(-1),
            "show_find_bar": self.show_find_bar,
        }
        handler = special.get(action) or getattr(presenter, action)
        self._last_mouse = None
        handler()

    def show_find_bar(self) -> None:
        self.presenter.show_find_bar()
        self.find_widget.open()

    def open_context_menu(self) -> None:
        menu = self.presenter.context_menu()
        if menu is not None:
            self.open_menu(menu)

    def activate_selection(self) -> None:
        """Enter: follow the selected operand, run the selected instruction's mark, or follow its branch."""
        presenter = self.presenter
        infodock = presenter.infodock
        info = presenter.get_selected_operand_info()
        if info is not None and info[2] is not None and info[2].jump_target is not None:
            presenter.jump_to(info[2].jump_target, src_ins_addr=info[1])
            return
        if len(infodock.selected_insns) != 1:
            return
        addr = next(iter(infodock.selected_insns))
        if presenter.activate_insn(addr, "left"):
            return
        actions = [m.action for m in presenter.marks_at(addr) if m.action is not None]
        if actions:
            actions[0]()
            return
        insn = self._insn_node(addr)
        if insn is not None:
            target = next((op.jump_target for op in insn.operands if op.branch_target is not None), None)
            if target is not None:
                presenter.jump_to(target, src_ins_addr=addr)

    def _insn_node(self, addr: int) -> InsnNode | None:
        control = self.linear_viewer if self.presenter.is_linear else self.flow_graph
        return control.insn_node(addr)

    def step_selection(self, delta: int) -> None:
        """Select the next (or previous) instruction of the function shown, or the first one."""
        presenter = self.presenter
        func = presenter.function.am_obj
        if func is None:
            return
        addrs = sorted(a for block in func.blocks for a in block.instruction_addrs)
        if not addrs:
            return
        selected = sorted(presenter.infodock.selected_insns)
        if not selected:
            target = addrs[0]
        else:
            current = selected[0] if delta < 0 else selected[-1]
            idx = addrs.index(current) if current in addrs else 0
            target = addrs[max(0, min(len(addrs) - 1, idx + delta))]
        presenter.infodock.select_instruction(target, unique=True, use_animation=False)

    def activate(
        self,
        target: Any,
        node: Any,
        button: str,
        chain: int,
        ctrl: bool,
        block_addr: int | None,
        screen_pos: tuple[int, int] | None,
    ) -> None:
        """
        A click on the text of ``node`` (``target`` is the span's owner: an operand, a mark, a block tree node, or
        the node itself) with ``button``, ``chain`` clicks in a row.
        """
        presenter = self.presenter
        infodock = presenter.infodock
        self._last_mouse = screen_pos
        if isinstance(target, Mark):
            if target.action is not None:
                target.action()
            return
        if isinstance(node, InsnNode):
            if presenter.activate_insn(node.addr, button):
                return
            if isinstance(target, OperandNode):
                if chain >= 2 and button == "left":
                    target.activate_double("left", presenter.jump_to)
                    return
                if button == "left":
                    target.activate("left", unique=not ctrl)
                    return
            node.activate(button, unique=not ctrl)
            if button == "right":
                with presenter.context_menu_address(node.addr):
                    self.open_menu(presenter.insn_context_menu(node.addr, node.insn))
            elif chain >= 2:
                with presenter.context_menu_address(node.addr):
                    presenter.popup_patch_dialog()
            return
        if isinstance(node, (LabelNode, MemoryDataNode)):
            node.activate(button)
            menu = presenter.label_context_menu(node.addr) if button == "right" else None
            if menu is not None:
                self.open_menu(menu)
            return
        if isinstance(node, UnknownNode):
            if button == "right":
                self.open_menu(presenter.unknown_context_menu(node.addr))
            return
        if isinstance(node, VariableNode):
            node.activate(button, unique=not ctrl)
            return
        if isinstance(node, CodeNode):
            node.activate(button)
            if isinstance(target, BlockTreeNode):
                if chain >= 2:
                    target.activate_double(button)
                else:
                    target.activate(button)
            return
        if node is None and block_addr is not None:
            infodock.select_block(block_addr)
            if button == "right":
                self.open_context_menu()

    #
    # What the workspace, plugins and the Qt view's callers use
    #

    @property
    def infodock(self):
        return self.presenter.infodock

    @property
    def jump_history(self):
        return self.presenter.jump_history

    @property
    def function(self):
        return self.presenter.function

    @function.setter
    def function(self, func) -> None:
        self.presenter.display_function(func, send_event=False)

    @property
    def current_graph(self):
        return self.presenter.current_graph

    @property
    def disasm(self):
        return self.presenter.disasm

    def jump_to(self, addr: int, *args, **kwargs) -> bool:
        return self.presenter.jump_to(addr, *args, **kwargs)

    def _instruction_address_in_selection(self) -> int | None:
        return self.presenter.instruction_address_in_selection()

    def display_function(self, func, send_event: bool = True) -> None:
        self.presenter.display_function(func, send_event=send_event)

    def display_disasm_graph(self, prefer: bool = True) -> None:
        self.presenter.display_disasm_graph(prefer)

    def display_linear_viewer(self, prefer: bool = True) -> None:
        self.presenter.display_linear_viewer(prefer)

    def decompile_current_function(self) -> None:
        self.presenter.decompile_current_function()

    def highlight_pattern_addrs(self, addrs) -> None:
        self.presenter.highlight_pattern_addrs(addrs)

    def clear_pattern_highlight(self) -> bool:
        return self.presenter.clear_pattern_highlight()

    def on_cc_recovered(self, func_addr: int) -> None:
        self.presenter.on_cc_recovered(func_addr)

    def on_variable_recovered(self, func_addr: int) -> None:
        self.presenter.on_variable_recovered(func_addr)

    def redraw_current_graph(self, **kwargs) -> None:
        self.presenter.redraw_current_graph(**kwargs)

    def reload(self) -> None:
        self.presenter.reload()

    def refresh_view(self) -> None:
        self.presenter.refresh()

    def close_view(self) -> None:
        self.presenter.close()


__all__ = ["DisasmHeader", "DisassemblyTuiView", "FindBarWidget", "GraphWidget", "LinearWidget", "draw_graph"]
