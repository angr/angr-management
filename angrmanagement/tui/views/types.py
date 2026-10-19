"""
The types view of the terminal frontend.

:class:`TypesTuiView` draws a :class:`~angrmanagement.present.types.TypesPresenter`: which types it shows, each type
definition as a block of lines with the offset of each member (:class:`TypesWidget`), and the Qt view's two buttons.
The line under the mouse, or under the keyboard's cursor, is highlighted; a double click or Enter opens the C type
editor (:class:`TypeEditorScreen`) on that member or type.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.geometry import Region, Size
from textual.screen import ModalScreen
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widgets import Button, Input, Label, TextArea

from angrmanagement.present.types import ParsedTypes, TypesPresenter, parse_types
from angrmanagement.tui.screens import dialog_css
from angrmanagement.tui.theme import rich_color
from angrmanagement.tui.widgets.styles import StyleCache, current_theme

from .base import TuiView
from .tables import toolbar_css

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events
    from textual.app import ComposeResult


class TypeEditorScreen(ModalScreen["ParsedTypes | None"]):
    """
    The C type editor: C type definitions, or one declaration, read as they are typed; the line under the text says
    what was read or why it does not parse, and OK is enabled only for text that does. The multi-line editor confirms
    with Ctrl+Enter (or Ctrl+S), the one-line editor with Enter.
    """

    DEFAULT_CSS = (
        dialog_css("TypeEditorScreen")
        + "TypeEditorScreen TextArea { width: 80; height: 14; } TypeEditorScreen Input { width: 80; }"
    )
    BINDINGS: ClassVar = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+enter", "confirm", "OK", priority=True),
        Binding("ctrl+s", "confirm", "OK", priority=True),
    ]

    def __init__(
        self,
        title: str,
        text: str,
        multiline: bool,
        parse: Callable[[str], ParsedTypes],
    ) -> None:
        super().__init__()
        self.title_text = title
        self.text = text
        self.multiline = multiline
        self.parse = parse
        self.parsed = ParsedTypes()

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            if self.multiline:
                yield TextArea(self.text, id="answer", soft_wrap=False)
                yield Label(Text("Ctrl+Enter (or Ctrl+S) to confirm, Escape to cancel"))
            else:
                yield Input(self.text, id="answer")
            yield Label(Text(""), id="status")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        for widget in self.query("#answer"):
            widget.focus()
            if isinstance(widget, TextArea):
                widget.select_all()
        self._check(self.text)

    def _check(self, text: str) -> None:
        self.parsed = self.parse(text)
        if self.parsed.ok:
            names = ", ".join(str(name) for name, _ty in self.parsed.main)
            status = f"Valid: {names}"
        else:
            status = f"Invalid: {self.parsed.error}"
        self.query_one("#status", Label).update(Text(status))
        self.query_one("#ok", Button).disabled = not self.parsed.ok

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        self._check(event.text_area.text)

    def on_input_changed(self, event: Input.Changed) -> None:
        self._check(event.value)

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self.action_confirm()

    def action_confirm(self) -> None:
        if self.parsed.ok:
            self.dismiss(self.parsed)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.action_confirm()
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class TypesWidget(ScrollView, can_focus=True):
    """The type definitions, one line per line of their C text; Up and Down move a line cursor, Enter edits."""

    DEFAULT_CSS = """
    TypesWidget {
        height: 1fr;
        width: 1fr;
    }
    """

    def __init__(self, view: TypesTuiView) -> None:
        super().__init__()
        self.view = view
        self.style_of = StyleCache(self)
        self.lines: list[tuple[int, int, str]] = []
        #: the line the keys move, and the line under the mouse (None: off the text)
        self.cursor = 0
        self.hover: int | None = None

    def rebuild(self) -> None:
        self.lines = self.view.presenter.lines()
        width = max((len(text) for _t, _r, text in self.lines), default=0)
        self.virtual_size = Size(width, len(self.lines))
        self.cursor = min(self.cursor, max(len(self.lines) - 1, 0))
        self.refresh()

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        scroll_x, scroll_y = self.scroll_offset
        row = scroll_y + y
        theme = current_theme(self)
        base = Style(bgcolor=rich_color(theme.background), color=rich_color(theme.foreground))
        if row >= len(self.lines):
            return Strip.blank(width, base)
        style = base
        if row == self.hover or (row == self.cursor and self.has_focus):
            style = base + Style(bgcolor=rich_color(theme.alternate if row == self.hover else theme.primary))
            if row == self.cursor and self.has_focus:
                style += Style(color=rich_color(theme.primary_text), bgcolor=rich_color(theme.primary))
        text = self.lines[row][2]
        strip = Strip([Segment(text, style)], len(text))
        return strip.crop(scroll_x, scroll_x + width).extend_cell_length(width, style)

    def move(self, rows: int) -> None:
        if not self.lines:
            return
        self.cursor = max(0, min(self.cursor + rows, len(self.lines) - 1))
        self.scroll_to_region(Region(0, self.cursor, 1, 1), animate=False, immediate=True)
        self.refresh()

    def edit(self, row: int) -> None:
        if 0 <= row < len(self.lines):
            type_index, line, _text = self.lines[row]
            self.view.presenter.edit_line(type_index, line)

    def on_key(self, event: events.Key) -> None:
        page = max(self.size.height - 1, 1)
        moves = {"up": -1, "down": 1, "pageup": -page, "pagedown": page, "home": -len(self.lines)}
        moves["end"] = len(self.lines)
        if event.key in moves:
            self.move(moves[event.key])
        elif not self.view.handle_types_key(event.key):
            return
        event.stop()
        event.prevent_default()

    def row_at(self, event: events.MouseEvent) -> int | None:
        row = int(event.y) + self.scroll_offset.y
        return row if 0 <= row < len(self.lines) else None

    def on_mouse_move(self, event: events.MouseMove) -> None:
        row = self.row_at(event)
        if row != self.hover:
            self.hover = row
            self.refresh()

    def on_leave(self, _event: events.Leave) -> None:
        self.hover = None
        self.refresh()

    def on_click(self, event: events.Click) -> None:
        row = self.row_at(event)
        if row is None:
            return
        self.focus()
        self.cursor = row
        self.refresh()
        if event.chain >= 2:
            self.edit(row)

    def on_focus(self) -> None:
        self.refresh()

    def on_blur(self) -> None:
        self.refresh()


class TypesTuiView(TuiView):
    """The types view: which types it shows, the type definitions, and the Qt view's buttons."""

    PRESENTER_CLASS = TypesPresenter
    DEFAULT_CSS = toolbar_css("TypesTuiView") + "TypesTuiView > .caption { padding: 0 1; }"

    presenter: TypesPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.caption_label = Label("", classes="caption")
        self.types_widget = TypesWidget(self)
        self.presenter.on_reloaded = self.reloaded
        self.presenter.type_editor = self.ask_types

    def compose(self) -> ComposeResult:
        yield self.caption_label
        yield self.types_widget
        with Horizontal(classes="toolbar"):
            yield Button("Add types", id="add-types")
            yield Button("Persistent types", id="persistent-types")

    def on_mount(self) -> None:
        self.presenter.reload()

    def reloaded(self) -> None:
        if self.is_attached:
            self.caption_label.update(Text(self.presenter.caption_text()))
            self.types_widget.rebuild()

    def focus_view(self) -> None:
        self.types_widget.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "add-types":
            self.presenter.add_types()
        elif event.button.id == "persistent-types":
            self.presenter.show_persistent_types()

    def ask_types(
        self, title: str, text: str, multiline: bool, editing_single: str | None, predefined: Any, then: Callable
    ) -> None:
        """The presenter's type editor: a modal screen that reads the text as it is typed."""
        arch = self.presenter.arch

        def parse(source: str) -> ParsedTypes:
            return parse_types(source, arch, predefined, editing_single)

        self.app.push_screen(TypeEditorScreen(title, text, multiline, parse), then)

    def handle_types_key(self, key: str) -> bool:
        """Run the action bound to ``key``; whether one was."""
        action = self.key_actions().get(key)
        if action is None:
            return False
        if action == "edit_line":
            self.types_widget.edit(self.types_widget.cursor)
        else:
            getattr(self.presenter, action)()
        return True


__all__ = ["TypeEditorScreen", "TypesTuiView", "TypesWidget"]
