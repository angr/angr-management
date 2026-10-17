"""
Tables over angrmanagement.present.tables models.

:class:`TableWidget` is a ``DataTable`` that shows a ``TableModel``: its columns, its cells with their style keys
drawn through the current theme, sorting when a header is clicked, Enter or a click on the highlighted row to activate,
and the model's context menu on Shift+F10 or a right click. :class:`FilterableTable` puts a filter box above it; typing
a printable character in the table starts filtering and Escape clears the filter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import DataTable, Input, Static

from angrmanagement.present.tables import APPENDED, DATA
from angrmanagement.tui.theme import rich_style
from angrmanagement.tui.widgets.styles import current_theme

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events
    from textual.app import ComposeResult

    from angrmanagement.present.tables import Cell, Column, TableModel
    from angrmanagement.present.theme import Theme


class TableWidget(DataTable):
    """A DataTable showing a TableModel."""

    BINDINGS: ClassVar = [
        Binding("shift+f10", "context_menu", "Menu", show=False),
        Binding("space", "toggle_check", "Toggle", show=False),
    ]

    DEFAULT_CSS = """
    TableWidget {
        height: 1fr;
    }
    """

    class FilterRequested(Message):
        """A printable key was typed in the table: start filtering with it."""

        def __init__(self, table: TableWidget, text: str) -> None:
            super().__init__()
            self.table = table
            self.text = text

    class ClearFilterRequested(Message):
        """Escape was pressed in the table."""

        def __init__(self, table: TableWidget) -> None:
            super().__init__()
            self.table = table

    class SelectionChanged(Message):
        """The highlighted row changed."""

        def __init__(self, table: TableWidget, row: int) -> None:
            super().__init__()
            self.table = table
            self.row = row

    def __init__(self, model: TableModel, *, id: str | None = None, classes: str | None = None) -> None:  # pylint:disable=redefined-builtin
        super().__init__(cursor_type="row", zebra_stripes=False, id=id, classes=classes)
        self.model = model
        #: whether printable keys start filtering (a filter box is there to take them)
        self.filter_keys = False
        self._sort_column: int | None = None
        self._sort_descending = False
        self._column_count = -1

    #
    # Building
    #

    def on_mount(self) -> None:
        self.model.changed.connect(self._on_model_changed)
        self.rebuild()

    def on_unmount(self) -> None:
        self.model.changed.disconnect(self._on_model_changed)

    def _header_label(self, idx: int, column: Column) -> Text:
        label = column.name
        if idx == self._sort_column:
            label += " ▼" if self._sort_descending else " ▲"
        justify: Any = column.align
        return Text(label, justify=justify)

    @staticmethod
    def _cell_text(cell: Cell, column: Column, theme: Theme) -> Text:
        text = cell.text
        if column.checkable:
            text = "[x]" if cell.checked else "[ ]"
        justify: Any = column.align
        return Text(text, style=rich_style(theme.style_of(cell)), justify=justify, no_wrap=True)

    def cells_of_row(self, row: int, columns: list[Column] | None = None, theme: Theme | None = None) -> list[Text]:
        columns = columns if columns is not None else self.model.columns
        theme = theme if theme is not None else current_theme(self)
        return [self._cell_text(self.model.cell(row, col), column, theme) for col, column in enumerate(columns)]

    def rebuild(self) -> None:
        """Show the model's columns and rows again."""
        columns = self.model.columns
        cursor = self.cursor_row
        if len(columns) != self._column_count:
            self.clear(columns=True)
            for idx, column in enumerate(columns):
                width = column.width_hint or None
                if column.stretch:
                    width = None
                self.add_column(self._header_label(idx, column), width=width, key=str(idx))
            self._column_count = len(columns)
        else:
            self.clear()
            for idx, column in enumerate(columns):
                self.columns[str(idx)].label = self._header_label(idx, column)  # type: ignore[index]
        theme = current_theme(self)
        self.add_rows(self.cells_of_row(row, columns, theme) for row in range(self.model.row_count))
        if self.row_count:
            self.move_cursor(row=min(max(cursor, 0), self.row_count - 1), animate=False)

    def _on_model_changed(self, kind: str, first: int, last: int) -> None:
        if kind == APPENDED and len(self.model.columns) == self._column_count and first == self.row_count:
            theme = current_theme(self)
            columns = self.model.columns
            self.add_rows(self.cells_of_row(row, columns, theme) for row in range(first, last + 1))
            return
        if kind == DATA and last < self.row_count and last - first < 64:
            # a few rows: update their cells; many: building the rows again is cheaper
            theme = current_theme(self)
            columns = self.model.columns
            for row in range(first, last + 1):
                for col, cell in enumerate(self.cells_of_row(row, columns, theme)):
                    self.update_cell_at((row, col), cell)  # type: ignore[arg-type]
            return
        self.rebuild()

    #
    # Rows
    #

    @property
    def selected_rows(self) -> list[int]:
        """The rows the user has selected: the highlighted one."""
        if self.row_count == 0:
            return []
        return [self.cursor_row]

    #
    # Events and actions
    #

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        event.stop()
        col = event.column_index
        if self._sort_column == col:
            self._sort_descending = not self._sort_descending
        else:
            self._sort_column, self._sort_descending = col, False
        self.model.sort(col, self._sort_descending)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        self.model.activate(event.cursor_row)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.post_message(self.SelectionChanged(self, event.cursor_row))

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape" and self.filter_keys:
            self.post_message(self.ClearFilterRequested(self))
            event.stop()
            return
        if self.filter_keys and event.is_printable and event.character and event.character != " ":
            self.post_message(self.FilterRequested(self, event.character))
            event.stop()

    def action_toggle_check(self) -> None:
        columns = self.model.columns
        for col, column in enumerate(columns):
            if column.checkable and self.row_count:
                row = self.cursor_row
                cell = self.model.cell(row, col)
                self.model.set_checked(row, col, not cell.checked)
                return

    def action_context_menu(self) -> None:
        self.open_context_menu()

    def open_context_menu(self, offset: tuple[int, int] | None = None) -> None:
        menu = self.model.context_menu(self.selected_rows)
        if menu is None:
            return
        if offset is None:
            region = self.region
            offset = (region.x + 2, region.y + 1 + min(self.cursor_row - self.scroll_offset.y + 1, region.height - 1))
        open_menu = getattr(self.app, "open_context_menu", None)
        if open_menu is not None:
            open_menu(menu, offset)

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button == 3:
            meta = event.style.meta if event.style else {}
            row = meta.get("row")
            if isinstance(row, int) and row >= 0:
                self.move_cursor(row=row)
            event.stop()
            self.open_context_menu((event.screen_x, event.screen_y))


class FilterableTable(Vertical):
    """
    A table with a filter box above it and a status label beside the box.

    :param on_filter:   Called with the filter text; ``model.filter`` by default.
    :param on_submit:   Called when Enter is pressed in the filter box.
    :param status:      Returns the text of the status label, such as a row count; refreshed on every model change.
    """

    DEFAULT_CSS = """
    FilterableTable {
        height: 1fr;
    }
    FilterableTable > Horizontal {
        height: auto;
    }
    FilterableTable > Horizontal > Input {
        width: 1fr;
    }
    FilterableTable > Horizontal > .status {
        width: auto;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        model: TableModel,
        placeholder: str = "Filter...",
        on_filter: Callable[[str], Any] | None = None,
        on_submit: Callable[[str], Any] | None = None,
        status: Callable[[], str] | None = None,
        show_filter: bool = True,
        id: str | None = None,  # pylint:disable=redefined-builtin
    ) -> None:
        super().__init__(id=id)
        self.model = model
        self.placeholder = placeholder
        self.on_filter = on_filter if on_filter is not None else model.filter
        self.on_submit = on_submit
        self.status = status
        self.show_filter = show_filter
        self.table = TableWidget(model)
        self.table.filter_keys = show_filter
        # not select_on_focus: the key that started filtering must not be replaced by the next one
        self.filter_box = Input(placeholder=placeholder, classes="filter", compact=True, select_on_focus=False)
        self.status_label = Static("", classes="status")

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield self.filter_box
            yield self.status_label
        yield self.table

    def on_mount(self) -> None:
        if not self.show_filter:
            self.filter_box.display = False
        self.model.changed.connect(self._update_status)
        self._update_status()

    def on_unmount(self) -> None:
        self.model.changed.disconnect(self._update_status)

    def _update_status(self, *_args) -> None:
        if self.status is not None and self.is_mounted:
            self.status_label.update(Text(self.status()))

    def refresh_status(self) -> None:
        """Show the status text again, after something other than the model changed it."""
        self._update_status()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input is self.filter_box:
            event.stop()
            self.on_filter(event.value)
            self._update_status()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input is self.filter_box:
            event.stop()
            if self.on_submit is not None:
                self.on_submit(event.value)
            self.table.focus()

    def on_table_widget_filter_requested(self, event: TableWidget.FilterRequested) -> None:
        if not self.show_filter:
            return
        event.stop()
        self.filter_box.focus()
        self.filter_box.value += event.text
        self.filter_box.cursor_position = len(self.filter_box.value)

    def on_table_widget_clear_filter_requested(self, event: TableWidget.ClearFilterRequested) -> None:
        event.stop()
        self.filter_box.value = ""

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape" and self.filter_box.has_focus:
            event.stop()
            if self.filter_box.value:
                self.filter_box.value = ""
            else:
                self.table.focus()

    def set_filter(self, text: str) -> None:
        self.filter_box.value = text
