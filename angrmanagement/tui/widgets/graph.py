"""
A graph of boxes in the terminal: the picture of a :class:`~angrmanagement.present.graphs.TreeGraphPresenter` drawn
on a :class:`~angrmanagement.tui.canvas.CharCanvas`, for the symbolic execution path tree and the proximity,
dependency, data dependency and pattern graphs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.segment import Segment
from textual.geometry import Region, Size
from textual.scroll_view import ScrollView
from textual.strip import Strip

from angrmanagement.present.theme import BACKGROUND_PREFIX
from angrmanagement.tui.canvas import DOWN, CharCanvas
from angrmanagement.tui.widgets.styles import StyleCache

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events

    from angrmanagement.present.graphs import GraphBox, GraphPicture, TreeGraphPresenter

#: The canvas behind the boxes, as the Qt graph views' white scene.
GRAPH_CANVAS_STYLE = BACKGROUND_PREFIX + "palette_base"
NODE_STYLE = "graph.node"
SELECTED_NODE_STYLE = "graph.node.selected"
BORDER_STYLE = "graph.node.border"
SELECTED_BORDER_STYLE = "graph.node.selected.border"
EDGE_STYLE = "graph.edge"
#: How far a key moves the view.
PAN_STEP = (8, 3)


def draw_picture(picture: GraphPicture, selected: Any = None, margin: int = 2) -> CharCanvas:
    """The picture on a canvas: each box (its background, frame and lines), then the edges."""
    width, height = picture.size
    canvas = CharCanvas(width + margin, height + margin, style=GRAPH_CANVAS_STYLE)
    for box, (x, y) in picture.layout.items():
        is_selected = selected is not None and box.node is selected
        background = box.style or (SELECTED_NODE_STYLE if is_selected else NODE_STYLE)
        if is_selected and box.style:
            background = f"{box.style} {SELECTED_NODE_STYLE}"
        border = box.border_style or (SELECTED_BORDER_STYLE if is_selected else BORDER_STYLE)
        w, h = box.width, box.height
        canvas.fill(x, y, w, h, background, " ")
        canvas.box(x, y, w, h, style=f"{background} {border}")
        canvas.blit(box.lines, x + 2, y + 1, base_style=background, width=w - 4)
        for edge in picture.edges:
            if edge.src is box and len(edge.points) >= 2:
                sx, sy = edge.points[0]
                if sy == y + h and x < sx < x + w - 1:
                    canvas.mark(sx, y + h - 1, DOWN, f"{background} {border}")
    for edge in picture.edges:
        if len(edge.points) >= 2:
            canvas.polyline(edge.points, f"{GRAPH_CANVAS_STYLE} {edge.style or EDGE_STYLE}")
    return canvas


class BoxGraphWidget(ScrollView, can_focus=True):
    """
    The boxes of a graph presenter. The arrows and Page Up/Down pan, ``[`` and ``]`` select the previous and the
    next box, Enter and a double click activate the selected box, a click selects one, a right click opens its
    context menu, and dragging the background pans. A graph smaller than the widget sits in its middle, as the Qt
    graph views center theirs.

    :param on_select:       Called with the node a click or ``[``/``]`` selects.
    :param on_activate:     Called with the node Enter or a double click activates.
    :param on_context_menu: Called with the node under a right click (None off the boxes) and the screen offset.
    :param tooltip_of:      The tooltip of a node, or None.
    :param on_key:          Called with the key of a press the widget does not use; returns whether it was used.
    :param before_draw:     Called before each drawing (to restyle the edges, say).
    """

    DEFAULT_CSS = """
    BoxGraphWidget {
        height: 1fr;
        width: 1fr;
    }
    """

    def __init__(
        self,
        presenter: TreeGraphPresenter,
        empty_text: str = "",
        on_select: Callable[[Any], Any] | None = None,
        on_activate: Callable[[Any], Any] | None = None,
        on_context_menu: Callable[[Any, tuple[int, int]], Any] | None = None,
        tooltip_of: Callable[[Any], str | None] | None = None,
        on_key: Callable[[str], bool] | None = None,
        before_draw: Callable[[], Any] | None = None,
    ) -> None:
        super().__init__()
        self.presenter = presenter
        self.empty_text = empty_text
        self.on_select = on_select
        self.on_activate = on_activate
        self.on_context_menu = on_context_menu
        self.tooltip_of = tooltip_of
        self.key_handler = on_key
        self.before_draw = before_draw
        self.style_of = StyleCache(self)
        self.canvas: CharCanvas | None = None
        self._drag: tuple[int, int, float, float] | None = None
        self._hover: GraphBox | None = None
        self._centered = False

    #
    # Drawing
    #

    def rebuild(self, keep_view: bool = False) -> None:
        """Lay the graph out again and draw it; the view centers on it unless ``keep_view``."""
        self.presenter.invalidate()
        self.redraw()
        if not keep_view:
            self._centered = False
            self.call_after_refresh(self.center)

    def redraw(self) -> None:
        """Draw the picture again (a selection changed)."""
        picture = self.presenter.picture
        if self.before_draw is not None:
            self.before_draw()
        self.canvas = draw_picture(picture, self.presenter.selected) if picture.boxes else None
        width, height = (self.canvas.width, self.canvas.height) if self.canvas is not None else (0, 0)
        self.virtual_size = Size(width, height)
        self.refresh()

    @property
    def canvas_offset(self) -> tuple[int, int]:
        """Where the canvas starts in the widget when it is smaller than the widget (it sits in the middle)."""
        if self.canvas is None:
            return 0, 0
        return max((self.size.width - self.canvas.width) // 2, 0), max((self.size.height - self.canvas.height) // 2, 0)

    def center(self) -> None:
        """
        Scroll so the middle of the graph is in the middle of the widget across, and its top row at the top. The Qt
        graph views center on the middle both ways because their graphs fit; a graph taller than the widget shows its
        root first, where reading starts, instead of a middle that shows neither end.
        """
        if self.canvas is None:
            return
        self._centered = True
        self.scroll_to(max((self.canvas.width - self.size.width) // 2, 0), 0, animate=False, immediate=True)

    def on_resize(self, _event: events.Resize) -> None:
        if not self._centered:
            self.center()

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        base = self.style_of(GRAPH_CANVAS_STYLE)
        if self.canvas is None:
            if y == self.size.height // 2 and self.empty_text:
                text = self.empty_text.center(width)[:width]
                return Strip([Segment(text, base)], len(text)).extend_cell_length(width, base)
            return Strip.blank(width, base)
        ox, oy = self.canvas_offset
        sx, sy = self.scroll_offset
        return self.canvas.strip(sy + y - oy, self.style_of, sx - ox, width)

    #
    # Boxes under the mouse
    #

    def box_at(self, event: events.MouseEvent) -> GraphBox | None:
        ox, oy = self.canvas_offset
        sx, sy = self.scroll_offset
        return self.presenter.picture.box_at(int(event.x) + sx - ox, int(event.y) + sy - oy)

    def scroll_to_box(self, box: GraphBox) -> None:
        pos = self.presenter.picture.layout.get(box)
        if pos is None:
            return
        ox, oy = self.canvas_offset
        self.scroll_to_region(Region(pos[0] + ox, pos[1] + oy, box.width, box.height), animate=False, immediate=True)

    def select(self, node: Any) -> None:
        self.presenter.selected = node
        self.redraw()
        box = self.presenter.picture.box_of(node)
        if box is not None:
            self.scroll_to_box(box)
        if self.on_select is not None:
            self.on_select(node)

    #
    # Events
    #

    def on_key(self, event: events.Key) -> None:
        key = event.key
        dx, dy = PAN_STEP
        moves = {"left": (-dx, 0), "right": (dx, 0), "up": (0, -dy), "down": (0, dy)}
        moves["pageup"] = (0, -max(self.size.height - 2, 1))
        moves["pagedown"] = (0, max(self.size.height - 2, 1))
        handled = True
        if key in moves:
            mx, my = moves[key]
            self.scroll_to(self.scroll_offset.x + mx, self.scroll_offset.y + my, animate=False)
        elif key in ("left_square_bracket", "right_square_bracket"):
            node = self.presenter.select_next(1 if key == "right_square_bracket" else -1)
            if node is not None:
                self.select(node)
        elif key == "enter" and self.presenter.selected is not None and self.on_activate is not None:
            self.on_activate(self.presenter.selected)
        else:
            handled = self.key_handler(key) if self.key_handler is not None else False
        if handled:
            event.stop()
            event.prevent_default()

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button == 1 and self.box_at(event) is None:
            self._drag = (int(event.screen_x), int(event.screen_y), self.scroll_offset.x, self.scroll_offset.y)
            self.capture_mouse()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if self._drag is not None:
            x0, y0, sx, sy = self._drag
            self.scroll_to(sx - (int(event.screen_x) - x0), sy - (int(event.screen_y) - y0), animate=False)
            return
        box = self.box_at(event)
        if box is not self._hover:
            self._hover = box
            tip = self.tooltip_of(box.node) if box is not None and self.tooltip_of is not None else None
            self.tooltip = tip or None

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        if self._drag is not None:
            self._drag = None
            self.release_mouse()

    def on_click(self, event: events.Click) -> None:
        box = self.box_at(event)
        self.focus()
        if event.button == 3:
            if box is not None and box.node is not self.presenter.selected:
                self.select(box.node)
            if self.on_context_menu is not None:
                self.on_context_menu(box.node if box is not None else None, (int(event.screen_x), int(event.screen_y)))
            return
        if box is None:
            return
        if event.chain >= 2:
            if self.on_activate is not None:
                self.on_activate(box.node)
        else:
            self.select(box.node)

    def on_focus(self) -> None:
        self.refresh()


__all__ = ["BoxGraphWidget", "draw_picture"]
