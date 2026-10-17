"""
The pseudocode view of the terminal frontend.

:class:`CodeTuiView` draws a :class:`~angrmanagement.present.code.CodePresenter`: a header line (back, forward, the
function, and the summary, options and patterns panes and the flavor, as the Qt view's tool bar), the find bar, the
decompiled text (:class:`CodeWidget`, one strip per line of the presenter's :class:`~angrmanagement.present.code.
CodeDoc`, with a cursor and a selection), and a side panel whose tabs are the Qt view's docks: the decompilation
options, the project's patterns and the function summary.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, ClassVar

from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual.containers import Horizontal, Vertical
from textual.geometry import Region, Size
from textual.scroll_view import ScrollView
from textual.strip import Strip
from textual.widgets import Button, Label, Static, TabbedContent, TabPane, Tree

from angrmanagement.logic import GlobalInfo
from angrmanagement.present.code import (
    BOOKMARK_LINE_STYLE,
    CHUNK_STYLE,
    CODE_BACKGROUND,
    FIND_STYLE,
    MENU_ACTIONS,
    PATTERN_LINE_STYLE,
    SELECTION_STYLE,
    CodePresenter,
    context_menu_keys,
    node_at_position,
    parse_type_text,
)
from angrmanagement.present.code_options import PASSES_GROUP, PEEPHOLE_GROUP, preset_names, value_kind
from angrmanagement.present.code_patterns import PatternLibraryModel
from angrmanagement.present.find import FindBarState
from angrmanagement.present.menus import Menu, MenuEntry
from angrmanagement.tui.code_screens import CommentScreen, RenameScreen, RetypeScreen
from angrmanagement.tui.screens import PromptScreen
from angrmanagement.tui.widgets.find_bar import FindBarWidget
from angrmanagement.tui.widgets.header import HeaderBar, HeaderItem, function_label
from angrmanagement.tui.widgets.styles import StyleCache
from angrmanagement.tui.widgets.table import TableWidget

from .base import TuiView

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from textual import events
    from textual.app import ComposeResult

    from angrmanagement.present.code import CodeDoc
    from angrmanagement.present.spans import Line

#: The node actions of the context menu: what the keys run only when the menu of the node under the cursor has it.
NODE_ACTIONS = {method: key for key, (_caption, _shortcut, method) in MENU_ACTIONS.items()}
#: How many lines a mouse wheel step scrolls.
WHEEL_LINES = 3
#: The cursor cell.
CURSOR_STYLE = Style(reverse=True)


def line_number_width(doc: CodeDoc | None) -> int:
    """The width of the line number gutter: the widest number and a space, as the Qt view's line number panel."""
    if doc is None or not doc.lines:
        return 0
    return len(str(len(doc.lines))) + 1


def column_ranges(doc: CodeDoc, start: int, end: int) -> dict[int, tuple[int, int]]:
    """The columns ``[start, end)`` covers on each row, from text positions."""
    out: dict[int, tuple[int, int]] = {}
    if end <= start:
        return out
    row0, col0 = doc.row_column(start)
    row1, col1 = doc.row_column(end)
    for row in range(row0, row1 + 1):
        first = col0 if row == row0 else 0
        last = col1 if row == row1 else doc.lines[row].width + 1
        if last > first:
            out[row] = (first, last)
    return out


def styled_cells(line: Line, overlays: Sequence[tuple[int, int, str]]) -> list[tuple[str, str]]:
    """``(character, style key)`` for each cell of ``line``: its span's style with the overlays laid over in order."""
    cells = [(char, f"{CODE_BACKGROUND} {span.style}".strip()) for span in line.spans for char in span.text]
    for first, last, style in overlays:
        for col in range(max(first, 0), min(last, len(cells))):
            char, key = cells[col]
            cells[col] = (char, f"{key} {style}")
    return cells


#
# The header
#


class CodeHeader(HeaderBar):
    """One line: ◀ Back, ▶ Forward, the function, and the Summary, Options and Patterns panes and the flavor."""

    view: CodeTuiView

    def items(self) -> tuple[list[HeaderItem], list[HeaderItem]]:
        """The left and right groups: (text, what a click does, or None for a label)."""
        presenter = self.view.presenter
        name = function_label(presenter.function.am_obj)
        panel = self.view.panel_shown
        left: list[HeaderItem] = [
            ("◀ Back", presenter.jump_back),
            ("▾", lambda: self.view.open_menu(presenter.history_menu())),
            ("▶ Forward", presenter.jump_forward),
            ("▾", lambda: self.view.open_menu(presenter.history_menu())),
            (name, None),
        ]
        right: list[HeaderItem] = [
            (("▸ " if panel != "summary" else "▾ ") + "Function Summary", lambda: self.view.toggle_panel("summary")),
            (
                ("▸ " if panel != "options" else "▾ ") + "Decompilation Options",
                lambda: self.view.toggle_panel("options"),
            ),
            (("▸ " if panel != "patterns" else "▾ ") + "Patterns", lambda: self.view.toggle_panel("patterns")),
            (f"{presenter.flavor or 'pseudocode'} ▾", lambda: self.view.open_menu(presenter.flavor_menu())),
        ]
        return left, right


#
# The text
#


class CodeWidget(ScrollView, can_focus=True):
    """
    The decompiled text, one line per strip, with a gutter of line numbers. A cursor moves with the arrows, Home, End,
    Page Up and Page Down, and with a click; Shift and a drag select. A double click follows the node, a right click
    opens the context menu, and hovering over a call shows its prototype after a pause.
    """

    DEFAULT_CSS = """
    CodeWidget {
        height: 1fr;
        width: 1fr;
    }
    """

    def __init__(self, view: CodeTuiView) -> None:
        super().__init__()
        self.view = view
        self.style_of = StyleCache(self)
        #: the cursor's text position, and where the selection started (None: nothing is selected)
        self.cursor = 0
        self.sel_anchor: int | None = None
        self._dragging = False
        self._hover_node: Any = None
        self._overlays: dict[int, list[tuple[int, int, str]]] | None = None
        self._bands: dict[int, str] | None = None

    @property
    def presenter(self) -> CodePresenter:
        return self.view.presenter

    @property
    def doc(self) -> CodeDoc | None:
        return self.presenter.doc

    @property
    def number_width(self) -> int:
        return line_number_width(self.doc)

    def rebuild(self) -> None:
        """The document changed: size the scroll area again and draw it."""
        doc = self.doc
        width = (doc.width + self.number_width + 1) if doc is not None else 0
        self.virtual_size = Size(width, doc.height if doc is not None else 0)
        self.highlights_changed()

    def highlights_changed(self) -> None:
        self._overlays = None
        self._bands = None
        self.refresh()

    #
    # The cursor and the selection
    #

    def selection_range(self) -> tuple[int, int]:
        if self.sel_anchor is None:
            return self.cursor, self.cursor
        return min(self.sel_anchor, self.cursor), max(self.sel_anchor, self.cursor)

    def selected_text(self) -> str:
        start, end = self.selection_range()
        return self.presenter.plain_text()[start:end]

    def set_cursor(self, pos: int, extend: bool = False, notify: bool = True) -> None:
        """Move the cursor to text position ``pos``; with ``extend`` the selection grows from where it was."""
        doc = self.doc
        length = doc.text_length if doc is not None else 0
        pos = max(0, min(pos, length))
        if extend:
            if self.sel_anchor is None:
                self.sel_anchor = self.cursor
        else:
            self.sel_anchor = None
        self.cursor = pos
        if self.sel_anchor == self.cursor:
            self.sel_anchor = None
        self.scroll_cursor_into_view()
        self.highlights_changed()
        if notify:
            self.presenter.cursor_moved(pos)

    def select_range(self, start: int, end: int) -> None:
        self.sel_anchor = start
        self.set_cursor(end, extend=True)

    def select_all(self) -> None:
        doc = self.doc
        if doc is not None:
            self.select_range(0, doc.text_length)

    def scroll_cursor_into_view(self) -> None:
        doc = self.doc
        if doc is None or not self.is_mounted:
            return
        row, col = doc.row_column(self.cursor)
        self.scroll_to_region(Region(col + self.number_width, row, 1, 1), animate=False, immediate=True)

    def move(self, rows: int = 0, cols: int = 0, extend: bool = False) -> None:
        doc = self.doc
        if doc is None:
            return
        if cols:
            self.set_cursor(self.cursor + cols, extend)
            return
        row, col = doc.row_column(self.cursor)
        self.set_cursor(doc.position(row + rows, col), extend)

    #
    # Drawing
    #

    def _compute_overlays(self) -> None:
        doc = self.doc
        overlays: dict[int, list[tuple[int, int, str]]] = {}
        bands: dict[int, str] = {}
        if doc is not None:
            presenter = self.presenter
            for pos in presenter.bookmark_positions():
                bands[doc.row_column(pos)[0]] = BOOKMARK_LINE_STYLE
            for row in presenter.pattern_highlight_rows():
                bands.setdefault(row, PATTERN_LINE_STYLE)
            ranges = [(start, end, CHUNK_STYLE) for start, end in presenter.chunks]
            ranges += [(start, end, FIND_STYLE) for start, end in presenter.find_matches]
            start, end = self.selection_range()
            ranges.append((start, end, SELECTION_STYLE))
            for first, last, style in ranges:
                for row, (col0, col1) in column_ranges(doc, first, last).items():
                    overlays.setdefault(row, []).append((col0, col1, style))
        self._overlays = overlays
        self._bands = bands

    def text_strip(self, row: int, x0: int = 0, width: int | None = None) -> Strip:
        """Line ``row`` of the text, from column ``x0``, ``width`` cells wide (the line's own width when None)."""
        doc = self.doc
        if doc is None or not 0 <= row < len(doc.lines):
            return Strip.blank(width or 0, self.style_of(CODE_BACKGROUND))
        if self._overlays is None or self._bands is None:
            self._compute_overlays()
        assert self._overlays is not None and self._bands is not None
        line = doc.lines[row]
        band = self._bands.get(row, "")
        cells = styled_cells(line, self._overlays.get(row, ()))
        segments: list[Segment] = []
        col = 0
        while col < len(cells):
            key = cells[col][1]
            end = col + 1
            while end < len(cells) and cells[end][1] == key:
                end += 1
            text = "".join(char for char, _ in cells[col:end])
            segments.append(Segment(text, self.style_of(f"{key} {band}".strip() if band else key)))
            col = end
        strip = Strip(segments, len(cells))
        if width is None:
            width = len(cells)
        strip = strip.crop(x0, x0 + width).extend_cell_length(width, self.style_of(f"{CODE_BACKGROUND} {band}"))
        cursor_row, cursor_col = doc.row_column(self.cursor)
        if row == cursor_row and self.has_focus and x0 <= cursor_col < x0 + width:
            idx = cursor_col - x0
            strip = Strip.join(
                [strip.crop(0, idx), strip.crop(idx, idx + 1).apply_style(CURSOR_STYLE), strip.crop(idx + 1)]
            )
        return strip

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        scroll_x, scroll_y = self.scroll_offset
        row = scroll_y + y
        doc = self.doc
        gutter = self.number_width
        if doc is None or row >= len(doc.lines):
            return Strip.blank(width, self.style_of(CODE_BACKGROUND))
        numbers = Strip([Segment(f"{row + 1:>{gutter - 1}} ", self.style_of("palette_text bg:palette_window"))])
        return Strip.join([numbers, self.text_strip(row, scroll_x, max(width - gutter, 0))])

    #
    # Keys
    #

    def on_key(self, event: events.Key) -> None:
        page = max(self.size.height - 1, 1)
        key = event.key
        parts = key.split("+")
        extend = "shift" in parts[:-1]
        base = "+".join([*(part for part in parts[:-1] if part != "shift"), parts[-1]])
        doc = self.doc
        handled = True
        if base == "up":
            self.move(rows=-1, extend=extend)
        elif base == "down":
            self.move(rows=1, extend=extend)
        elif base == "left":
            self.move(cols=-1, extend=extend)
        elif base == "right":
            self.move(cols=1, extend=extend)
        elif base == "pageup":
            self.move(rows=-page, extend=extend)
        elif base == "pagedown":
            self.move(rows=page, extend=extend)
        elif base in ("home", "end") and doc is not None:
            row, _col = doc.row_column(self.cursor)
            self.set_cursor(doc.position(row, 0 if base == "home" else doc.lines[row].width), extend)
        elif base in ("ctrl+home", "ctrl+end") and doc is not None:
            self.set_cursor(0 if base == "ctrl+home" else doc.text_length, extend)
        else:
            handled = self.view.handle_code_key(key)
        if handled:
            event.stop()
            event.prevent_default()

    #
    # Mouse
    #

    def position_at(self, event: events.MouseEvent) -> int | None:
        """The text position under the mouse, or None off the text."""
        doc = self.doc
        if doc is None or not doc.lines:
            return None
        scroll_x, scroll_y = self.scroll_offset
        row = int(event.y) + scroll_y
        col = int(event.x) + scroll_x - self.number_width
        if row >= len(doc.lines):
            row = len(doc.lines) - 1
            col = doc.lines[row].width
        return doc.position(row, max(col, 0))

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button != 1:
            return
        pos = self.position_at(event)
        if pos is None:
            return
        self.focus()
        self.set_cursor(pos, extend=bool(event.shift))
        self._dragging = True
        self.capture_mouse()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        pos = self.position_at(event)
        if self._dragging and pos is not None:
            self.set_cursor(pos, extend=True)
            return
        node = node_at_position(self.presenter.codegen, pos) if pos is not None and self.presenter.rendered else None
        if node is not self._hover_node:
            self._hover_node = node
            self.tooltip = self.presenter.hover_text(node) if node is not None else None

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        if self._dragging:
            self._dragging = False
            self.release_mouse()

    def on_click(self, event: events.Click) -> None:
        pos = self.position_at(event)
        if pos is None:
            return
        self.focus()
        if event.button == 3:
            # as the Qt editor: the cursor moves to the click unless it is inside the selection
            start, end = self.selection_range()
            if not start <= pos < end:
                self.set_cursor(pos)
            self.view.open_context_menu((int(event.screen_x), int(event.screen_y)))
        elif event.chain >= 2:
            self.view.presenter.activate()

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        event.stop()
        self.scroll_to(y=self.scroll_offset.y + WHEEL_LINES, animate=False)

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        event.stop()
        self.scroll_to(y=max(self.scroll_offset.y - WHEEL_LINES, 0), animate=False)

    def on_focus(self) -> None:
        self.refresh()

    def on_blur(self) -> None:
        self.refresh()


#
# The side panel
#


class OptionsSheetWidget(Vertical):
    """
    The decompilation options: the preset, a tree of the options by category, the passes and the peephole
    optimizations, and Apply. Enter or Space on an option turns it on or off, picks the next of its choices, or asks
    for its number.
    """

    DEFAULT_CSS = """
    OptionsSheetWidget {
        height: 1fr;
    }
    OptionsSheetWidget > Tree {
        height: 1fr;
    }
    OptionsSheetWidget > Label {
        height: auto;
        max-height: 4;
    }
    OptionsSheetWidget Button {
        min-width: 8;
        margin: 0 1 0 0;
    }
    OptionsSheetWidget > Horizontal {
        height: auto;
    }
    """

    def __init__(self, view: CodeTuiView) -> None:
        super().__init__()
        self.view = view
        self.preset_label = Label("", id="preset")
        self.options_tree: Tree[Any] = Tree("Options", id="options-tree")
        self.options_tree.show_root = False
        self.description = Label("", id="option-description")

    @property
    def sheet(self) -> Any:
        return self.view.presenter.options

    def compose(self) -> ComposeResult:
        yield self.preset_label
        yield self.options_tree
        yield self.description
        with Horizontal():
            yield Button("Apply", id="apply-options", variant="primary")

    def on_mount(self) -> None:
        self.reload()

    @staticmethod
    def label_of(item: Any, value: Any) -> str:
        if value_kind(item) == "bool":
            return f"[{'x' if value else ' '}] {item.NAME}"
        return f"{item.NAME}: {value}"

    def reload(self) -> None:
        """Fill the tree from the sheet again."""
        sheet = self.sheet
        self.preset_label.update(Text(f"Preset: {getattr(sheet, 'preset', '')} ▾", style="bold"))
        tree = self.options_tree
        tree.clear()
        groups = sheet.groups() if hasattr(sheet, "groups") else []
        for group, items in groups:
            branch = tree.root.add(group, expand=group not in (PASSES_GROUP, PEEPHOLE_GROUP))
            for item in items:
                branch.add_leaf(self.label_of(item, sheet.values.get(item)), data=item)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self.preset_label:
            self.view.open_menu(
                Menu(
                    "&Preset",
                    [
                        MenuEntry(
                            name,
                            lambda _checked=True, n=name: self.set_preset(n),
                            checkable=True,
                            checked=name == getattr(self.sheet, "preset", None),
                        )
                        for name in preset_names()
                    ],
                )
            )

    def set_preset(self, name: str) -> None:
        self.sheet.set_preset(name)
        self.reload()

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        item = event.node.data
        self.description.update(Text(getattr(item, "DESCRIPTION", "") or "" if item is not None else ""))

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        item = event.node.data
        if item is None:
            return
        event.stop()
        self.edit(event.node, item)

    def edit(self, node: Any, item: Any) -> None:
        """Change ``item``: flip a switch, take the next choice, or ask for a number."""
        sheet = self.sheet
        value = sheet.values.get(item)
        kind = value_kind(item)
        if kind == "bool":
            sheet.set_value(item, not value)
        elif kind == "choice":
            choices = list(item.candidate_values)
            idx = choices.index(value) if value in choices else -1
            sheet.set_value(item, choices[(idx + 1) % len(choices)])
        elif kind in ("int", "float"):
            convert = int if kind == "int" else float

            def then(answer: str | None) -> None:
                if answer is None:
                    return
                try:
                    number = convert(answer, 0) if convert is int else convert(answer)
                except ValueError:
                    GlobalInfo.ui_services.message("warning", item.NAME, f"{answer!r} is not a number.")
                    return
                sheet.set_value(item, number)
                node.set_label(self.label_of(item, number))

            self.app.push_screen(PromptScreen(item.NAME, item.DESCRIPTION or item.NAME, str(value)), then)
            return
        else:
            return
        node.set_label(self.label_of(item, sheet.values.get(item)))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply-options":
            event.stop()
            self.view.presenter.apply_options()


class PatternTable(TableWidget):
    """The patterns table: Space marks a pattern to turn on or off, H highlights it, Enter edits it."""

    def on_key(self, event: events.Key) -> None:
        if event.key == "h" and self.row_count:
            event.stop()
            model: Any = self.model
            row = self.cursor_row
            model.set_checked(row, model.HIGHLIGHT, not model.cell(row, model.HIGHLIGHT).checked)
            return
        super().on_key(event)


class PatternsPane(Vertical):
    """The project's patterns and their numbers in the function shown; Apply writes the marks and decompiles."""

    DEFAULT_CSS = """
    PatternsPane {
        height: 1fr;
    }
    PatternsPane > PatternTable {
        height: 1fr;
    }
    PatternsPane > Horizontal {
        height: auto;
    }
    PatternsPane Button {
        min-width: 8;
        margin: 0 1 0 0;
    }
    """

    def __init__(self, view: CodeTuiView) -> None:
        super().__init__()
        self.view = view
        self.model = PatternLibraryModel(view.presenter, on_status=view.status)
        self.table = PatternTable(self.model)

    def compose(self) -> ComposeResult:
        yield self.table
        with Horizontal():
            yield Button("Apply Patterns & Redecompile", id="apply-patterns", variant="primary")
            yield Button("Clear highlights", id="clear-highlights")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "apply-patterns":
            self.model.apply_pending()
        elif event.button.id == "clear-highlights":
            self.view.presenter.clear_pattern_highlight()


class CodeSidePanel(TabbedContent):
    """The Qt view's docks as tabs: the decompilation options, the patterns and the function summary."""

    DEFAULT_CSS = """
    CodeSidePanel {
        width: 48;
        height: 1fr;
        display: none;
        border-left: solid $panel;
    }
    """

    def __init__(self, view: CodeTuiView) -> None:
        super().__init__(id="code-side-panel")
        self.view = view
        self.options = OptionsSheetWidget(view)
        self.patterns = PatternsPane(view)
        self.summary = Static(Text("No summary available. Use AI > Summarize Function to generate one."))

    def panes(self) -> list[TabPane]:
        """The tabs, for the view to compose into the panel."""
        return [
            TabPane("Options", self.options, id="options"),
            TabPane("Patterns", self.patterns, id="patterns"),
            TabPane("Summary", self.summary, id="summary"),
        ]


#
# The view
#


class CodeTuiView(TuiView):
    """The pseudocode view: header, find bar, the text, and the side panel."""

    PRESENTER_CLASS = CodePresenter

    DEFAULT_CSS = """
    CodeTuiView {
        height: 1fr;
        width: 1fr;
    }
    CodeTuiView > Horizontal {
        height: 1fr;
    }
    """

    #: Keys the terminal adds: the flavor menu without the mouse.
    EXTRA_KEYS: ClassVar[dict[str, str]] = {"f": "flavor_menu"}

    presenter: CodePresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        presenter = self.presenter
        self.header = CodeHeader(self)
        self.find_state = FindBarState()
        presenter.find_bar = self.find_state
        self.find_state.query_changed.connect(presenter.update_find_matches)
        self.find_state.closed.connect(presenter.on_find_bar_closed)
        self.find_widget = FindBarWidget(self.find_state, self.focus_view)
        self.code = CodeWidget(self)
        self.side_panel = CodeSidePanel(self)
        #: which side panel tab is shown, or None
        self.panel_shown: str | None = None
        self._key_actions: dict[str, str] | None = None
        self._last_mouse: tuple[int, int] | None = None
        presenter.function.am_subscribe(self._on_new_function)
        presenter.codegen.am_subscribe(self._on_codegen_changes)
        presenter.addr.am_subscribe(self._on_new_addr)
        presenter.current_node.am_subscribe(self._on_new_node)
        instance.annotations.bookmarks.am_subscribe(self._on_bookmarks_changed)
        plugins = getattr(workspace, "plugins", None)
        if plugins is not None:
            plugins.instrument_code_view(self)

    def compose(self) -> ComposeResult:
        yield self.header
        yield self.find_widget
        with Horizontal():
            yield self.code
            with self.side_panel:
                yield from self.side_panel.panes()

    def close_view(self) -> None:
        presenter = self.presenter
        presenter.function.am_unsubscribe(self._on_new_function)
        presenter.codegen.am_unsubscribe(self._on_codegen_changes)
        presenter.addr.am_unsubscribe(self._on_new_addr)
        presenter.current_node.am_unsubscribe(self._on_new_node)
        with contextlib.suppress(ValueError, KeyError):
            self.instance.annotations.bookmarks.am_unsubscribe(self._on_bookmarks_changed)
        super().close_view()

    #
    # Events of the presenter's containers
    #

    def _on_new_function(self, **kwargs) -> None:
        self.presenter.on_new_function(**kwargs)
        self.header_changed()

    def _on_new_addr(self, **kwargs) -> None:
        self.presenter.on_new_addr(**kwargs)

    def _on_new_node(self, **kwargs) -> None:
        self.presenter.on_new_node(**kwargs)

    def _on_bookmarks_changed(self, **_kwargs) -> None:
        self.code.highlights_changed()

    def _on_codegen_changes(self, already_regenerated: bool = False, event: str | None = None, **kwargs) -> None:
        """Show the codegen again: regenerate its text as the event asks, keep the cursor on its node and line."""
        presenter = self.presenter
        if presenter.codegen.am_none:
            presenter.doc = None
            presenter.rendered = False
            self.code.cursor, self.code.sel_anchor = 0, None
            self.code.rebuild()
            self.header_changed()
            return
        if presenter.sync_kb_comments():
            # newly mirrored comments are only visible after a re-render
            already_regenerated = False
        same_function = presenter.last_function is presenter.function.am_obj and presenter.doc is not None
        old_row = old_col = None
        old_node = None
        if same_function:
            assert presenter.doc is not None
            old_row, old_col = presenter.doc.row_column(self.code.cursor)
            old_node = node_at_position(presenter.codegen, self.code.cursor)
        presenter.regenerate_codegen(already_regenerated, event, **kwargs)
        doc = presenter.build_doc()
        presenter.rendered = True
        cursor = 0
        if doc is not None and old_row is not None and old_col is not None:
            cursor = doc.position(old_row, old_col)
            if old_node is not None:
                # the first mention of the node on its old line
                start = doc.position(old_row, 0)
                end = start + doc.lines[min(old_row, len(doc.lines) - 1)].width
                posmap = presenter.codegen.map_pos_to_node._posmap
                for pos in posmap.irange(minimum=start, maximum=end):
                    if posmap[pos].obj is old_node:
                        cursor = pos
                        break
        self.code.cursor, self.code.sel_anchor = cursor, None
        self.code.rebuild()
        if not same_function:
            # another function starts at its top, as the Qt editor's new text does
            self.code.scroll_to(0, 0, animate=False, immediate=True)
        presenter.cursor_moved(cursor)
        self.header_changed()
        self.update_summary()
        self.side_panel.patterns.model.reload()

    #
    # What the presenter asks of its view
    #

    def cursor_position(self) -> int:
        return self.code.cursor

    def selection_range(self) -> tuple[int, int]:
        return self.code.selection_range()

    def selected_text(self) -> str:
        return self.code.selected_text()

    def set_cursor_position(self, pos: int) -> None:
        self.code.set_cursor(pos)

    def select_range(self, start: int, end: int) -> None:
        self.code.select_range(start, end)

    def focus_text(self) -> None:
        if self.is_mounted:
            self.code.focus()

    focus_requested = focus_text

    def on_flavors_changed(self) -> None:
        self.header_changed()

    def on_chunks_changed(self) -> None:
        self.code.highlights_changed()

    def on_pattern_highlight_changed(self) -> None:
        self.code.highlights_changed()
        self.side_panel.patterns.model.reload()

    def on_pattern_highlight_cleared(self) -> None:
        self.code.highlights_changed()

    def on_find_matches_changed(self) -> None:
        self.code.highlights_changed()

    def find_bar_opened(self) -> None:
        if self.is_mounted:
            self.find_widget.open()

    def find_bar_closed(self) -> None:
        self.focus_view()

    def close_view_requested(self) -> None:
        self.workspace.view_manager.remove_view(self)

    def copy(self) -> None:
        text = self.code.selected_text()
        if text:
            GlobalInfo.ui_services.set_clipboard_text(text)

    def select_all(self) -> None:
        self.code.select_all()

    def zoom_in(self) -> None:
        self.status("The terminal's font size is the terminal's: zoom there")

    zoom_out = zoom_in

    def reload_patterns(self) -> None:
        self.side_panel.patterns.model.reload()

    def _update_clear_highlights(self) -> None:
        self.side_panel.patterns.model.reload()

    def ask_rename(self, _node: Any, default: str, suggestions: Sequence[str], then: Callable) -> None:
        self.app.push_screen(RenameScreen("Rename", default, suggestions), then)

    def ask_type(self, _node: Any, default: str, type_names: Sequence[str], then: Callable) -> None:
        predefined = self.presenter.predefined_types()

        def validate(text: str) -> tuple[bool, str]:
            valid, reason, _type = parse_type_text(text, predefined)
            return valid, reason

        self.app.push_screen(RetypeScreen("Specify a type", default, type_names, validate), then)

    def ask_comment(self, addr: int, text: str, multiline: bool, then: Callable) -> None:
        if multiline:
            self.app.push_screen(CommentScreen("Statement Comment", f"Comment at {addr:#x}:", text), then)
        else:
            self.app.push_screen(PromptScreen("Statement Comment", f"Comment at {addr:#x}:", text), then)

    #
    # The header, the panels and the menus
    #

    def header_changed(self) -> None:
        if self.is_mounted:
            self.header.refresh()

    def status(self, text: str) -> None:
        show = getattr(self.app, "show_status", None) if self.is_attached else None
        if show is not None:
            show(text)

    def toggle_panel(self, name: str) -> None:
        """Show the side panel's tab ``name``, or hide the panel if that tab is already shown."""
        if self.panel_shown == name:
            self.panel_shown = None
            self.side_panel.display = False
        else:
            self.panel_shown = name
            self.side_panel.display = True
            self.side_panel.active = name
            if name == "options":
                self.side_panel.options.reload()
            elif name == "patterns":
                self.side_panel.patterns.model.reload()
            elif name == "summary":
                self.update_summary()
        self.header_changed()

    def update_summary(self) -> None:
        summary = self.presenter.function_summary()
        self.side_panel.summary.update(
            Text(summary or "No summary available. Use AI > Summarize Function to generate one.")
        )

    def open_menu(self, menu: Menu, offset: tuple[int, int] | None = None) -> None:
        open_context_menu = getattr(self.app, "open_context_menu", None) if self.is_attached else None
        if open_context_menu is None:
            return
        open_context_menu(menu, offset or self._last_mouse or self._cursor_offset())

    def _cursor_offset(self) -> tuple[int, int]:
        code = self.code
        doc = code.doc
        if doc is None:
            return code.region.x + 4, code.region.y + 2
        row, col = doc.row_column(code.cursor)
        sx, sy = code.scroll_offset
        return code.region.x + code.number_width + col - sx, code.region.y + row - sy + 1

    def open_context_menu(self, offset: tuple[int, int] | None = None) -> None:
        menu = self.presenter.context_menu()
        if menu is not None:
            self.open_menu(menu, offset)

    def focus_view(self) -> None:
        if self.is_mounted:
            self.code.focus()

    def show_find_bar(self) -> None:
        self.presenter.show_find_bar()

    #
    # Keys
    #

    def key_actions(self) -> dict[str, str]:
        if self._key_actions is None:
            caps = getattr(self.app, "caps", 2)
            actions: dict[str, str] = {}
            for binding in self.presenter.keymap.for_tier(caps):
                key = binding.textual_key()
                if key is not None:
                    actions.setdefault(key, binding.action)
            for key, action in self.EXTRA_KEYS.items():
                actions.setdefault(key, action)
            self._key_actions = actions
        return self._key_actions

    def handle_code_key(self, key: str) -> bool:
        """Run the action bound to ``key``; whether one was."""
        action = self.key_actions().get(key)
        if action is None:
            return False
        self.run_code_action(action)
        return True

    def run_code_action(self, action: str) -> None:
        presenter = self.presenter
        self._last_mouse = None
        special: dict[str, Callable[[], Any]] = {
            "context_menu": self.open_context_menu,
            "flavor_menu": lambda: self.open_menu(presenter.flavor_menu()),
        }
        if action in special:
            special[action]()
            return
        if action in NODE_ACTIONS:
            # as the Qt view's keys, a node action runs only when the context menu of the node under the cursor has it
            node = node_at_position(presenter.codegen, self.code.cursor) if presenter.rendered else None
            presenter.context_menu(node=node)
            if NODE_ACTIONS[action] not in context_menu_keys(node):
                return
        getattr(presenter, action)()

    #
    # What the workspace, plugins and the Qt view's callers use
    #

    @property
    def function(self):
        return self.presenter.function

    @function.setter
    def function(self, func) -> None:
        self.presenter.function.am_obj = func
        self.presenter.function.am_event()

    @property
    def _function(self):
        return self.presenter.function

    @property
    def codegen(self):
        return self.presenter.codegen

    @property
    def addr(self):
        return self.presenter.addr

    @property
    def current_node(self):
        return self.presenter.current_node

    @property
    def jump_history(self):
        return self.presenter.jump_history

    @property
    def vars_must_struct(self):
        return self.presenter.vars_must_struct

    @property
    def flavor(self):
        return self.presenter.flavor

    def decompile(self, *args, **kwargs) -> None:
        self.presenter.decompile(*args, **kwargs)

    def jump_to(self, addr: int, src_ins_addr=None, **_kwargs) -> bool:
        return self.presenter.jump_to(addr, src_ins_addr)

    def variable_manager(self, func_addr=None):
        return self.presenter.variable_manager(func_addr)

    @property
    def has_pattern_highlight(self) -> bool:
        return self.presenter.has_pattern_highlight

    def highlight_pattern(self, func_addr: int, copies, layer: str = "discover") -> None:
        self.presenter.highlight_pattern(func_addr, copies, layer)

    def set_pattern_highlight(self, name: str, on: bool) -> None:
        self.presenter.set_pattern_highlight(name, on)

    def is_pattern_highlighted(self, name: str) -> bool:
        return self.presenter.is_pattern_highlighted(name)

    def clear_pattern_highlight(self) -> bool:
        return self.presenter.clear_pattern_highlight()

    def pattern_call_count(self, name: str) -> int:
        return self.presenter.pattern_call_count(name)

    def line_texts(self) -> list[str]:
        """The text of every line as the widget draws it (without the line numbers)."""
        doc = self.presenter.doc
        if doc is None:
            return []
        return [self.code.text_strip(row).text for row in range(len(doc.lines))]


__all__ = ["CodeHeader", "CodeSidePanel", "CodeTuiView", "CodeWidget", "OptionsSheetWidget", "PatternsPane"]
