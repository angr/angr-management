from __future__ import annotations

import string
from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QPoint, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QPalette, QPen
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsItem,
    QGraphicsScene,
    QGraphicsView,
    QHeaderView,
    QStyle,
    QStyleOptionButton,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from PySide6.QtCore import QAbstractItemModel
    from PySide6.QtGui import QContextMenuEvent, QKeyEvent, QMouseEvent


class QFastTableContentItem(QGraphicsItem):
    """
    A single graphics item that spans the entire virtual table and paints only the rows
    and columns intersecting the exposed viewport rectangle.

    Keeping a single item (instead of one item per cell) and painting only the exposed
    region makes the paint cost proportional to the number of *visible* rows rather than
    the total number of rows in the model. This is what makes the view fast for tables
    with thousands of entries.
    """

    def __init__(self, table: QFastTableView) -> None:
        super().__init__()
        self._table = table
        # Without this flag, option.exposedRect is widened to the full boundingRect and we
        # would end up painting every row on every update, defeating the whole purpose.
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemUsesExtendedStyleOption, True)

    def boundingRect(self) -> QRectF:  # type: ignore[override]
        return QRectF(0, 0, self._table.content_width(), self._table.content_height())

    def paint(self, painter, option, widget=None) -> None:  # type: ignore[override] # pylint:disable=unused-argument
        self._table._paint_cells(painter, option.exposedRect)


class QFastTableGraphicsView(QGraphicsView):
    """
    The scrolling area that hosts the table content item and forwards user interaction to
    the owning :class:`QFastTableView`. The horizontal header is parented here and placed
    in the reserved top viewport margin so its width always matches the content viewport
    (i.e. it excludes the vertical scrollbar), keeping columns aligned with their headers.
    """

    def __init__(self, table: QFastTableView, header: QHeaderView) -> None:
        super().__init__(table)
        self._table = table
        self._header = header
        self._header_height = 20

        header.setParent(self)
        header.show()
        header.raise_()

        self.setFrameShape(QGraphicsView.Shape.NoFrame)
        # Scene coordinates map 1:1 to content pixels (no transform), and the top-left of
        # the scene must anchor to the top-left of the viewport for the header offset sync
        # to line up.
        self.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setDragMode(QGraphicsView.DragMode.NoDrag)

    def refresh_header_layout(self) -> None:
        self._header_height = max(self._header.sizeHint().height(), 16)
        self.setViewportMargins(0, self._header_height, 0, 0)
        self._reposition_header()

    def _reposition_header(self) -> None:
        vp = self.viewport().geometry()
        self._header.setGeometry(vp.x(), vp.y() - self._header_height, vp.width(), self._header_height)

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._reposition_header()

    def mousePressEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        self.setFocus()
        self._table._handle_mouse_press(self.mapToScene(event.position().toPoint()), event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        self._table._handle_mouse_double_click(self.mapToScene(event.position().toPoint()), event)

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:  # type: ignore[override]
        self._table._handle_context_menu(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:  # type: ignore[override]
        if not self._table._handle_key_press(event):
            super().keyPressEvent(event)


class QFastTableView(QWidget):
    """
    A fast, virtualized table view backed by a :class:`QGraphicsScene`.

    It renders any standard ``QAbstractItemModel`` (typically a ``QAbstractTableModel``),
    honoring the ``Display``, ``Foreground``, ``Background``, ``Font``, ``TextAlignment``
    and ``CheckState`` roles, and only paints the rows currently visible in the viewport.
    Painting cost is therefore ``O(visible rows)`` regardless of the total row count, which
    is the key difference from ``QTableView`` for large models.

    A standard ``QHeaderView`` is used for the columns, providing clickable sorting,
    interactive resizing, stretch-last-section and column show/hide behavior. Callers may
    inject a custom header (e.g. one with a column-visibility context menu) via the
    constructor.

    Signals:
        row_double_clicked(int): a row was double-clicked or activated with Enter.
        selection_changed(): the set of selected rows changed.
        context_menu_requested(QPoint): a context menu was requested (global position).
        key_pressed(str): a printable key was pressed while the view had focus.
    """

    row_double_clicked = Signal(int)
    selection_changed = Signal()
    context_menu_requested = Signal(QPoint)
    key_pressed = Signal(str)

    DEFAULT_ROW_HEIGHT = 24
    CELL_PADDING = 4

    def __init__(self, parent: QWidget | None = None, header: QHeaderView | None = None) -> None:
        super().__init__(parent)

        self._model: QAbstractItemModel | None = None
        self._row_height: int = self.DEFAULT_ROW_HEIGHT
        self._sorting_enabled: bool = True
        self._grid_enabled: bool = True

        # selection state (row indices)
        self._selected_rows: set[int] = set()
        self._current_row: int | None = None
        self._anchor_row: int | None = None

        self._header = header if header is not None else QHeaderView(Qt.Orientation.Horizontal, self)
        self._header.setSectionsClickable(True)

        self._scene = QGraphicsScene(self)
        self._scene.setItemIndexMethod(QGraphicsScene.ItemIndexMethod.NoIndex)
        self._content = QFastTableContentItem(self)
        self._scene.addItem(self._content)

        self._gview = QFastTableGraphicsView(self, self._header)
        self._gview.setScene(self._scene)
        self.setFocusProxy(self._gview)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._gview)

        self._gview.setBackgroundBrush(QBrush(self.palette().color(QPalette.ColorRole.Base)))

        # keep the header horizontally aligned with the content while scrolling
        self._gview.horizontalScrollBar().valueChanged.connect(self._on_hscroll)

        # header interactions
        self._header.sectionResized.connect(self._on_header_geometry_changed)
        self._header.sectionMoved.connect(self._on_header_geometry_changed)
        self._header.geometriesChanged.connect(self._on_header_geometry_changed)
        self._header.sectionClicked.connect(self._on_section_clicked)
        self._header.sortIndicatorChanged.connect(self._on_sort_indicator_changed)

        self._gview.refresh_header_layout()

    #
    # Public API
    #

    def setModel(self, model: QAbstractItemModel | None) -> None:
        self._model = model
        self._header.setModel(model)

        if model is not None:
            model.modelReset.connect(self._on_model_reset)
            model.layoutChanged.connect(self._on_layout_changed)
            model.dataChanged.connect(self._on_data_changed)
            model.rowsInserted.connect(self._on_layout_changed)
            model.rowsRemoved.connect(self._on_layout_changed)
            model.columnsInserted.connect(self._on_layout_changed)
            model.columnsRemoved.connect(self._on_layout_changed)

        self._selected_rows.clear()
        self._current_row = None
        self._anchor_row = None
        self._update_scene_geometry()
        self._gview.refresh_header_layout()
        self._request_repaint()

    def model(self) -> QAbstractItemModel | None:
        return self._model

    def header(self) -> QHeaderView:
        return self._header

    def set_row_height(self, height: int) -> None:
        self._row_height = max(1, height)
        self._update_scene_geometry()
        self._request_repaint()

    def set_grid_visible(self, visible: bool) -> None:
        self._grid_enabled = visible
        self._request_repaint()

    def set_sorting_enabled(self, enabled: bool) -> None:
        self._sorting_enabled = enabled
        self._header.setSortIndicatorShown(enabled)

    def viewport_update(self) -> None:
        self._request_repaint()

    def selected_rows(self) -> list[int]:
        return sorted(self._selected_rows)

    @property
    def current_row(self) -> int | None:
        return self._current_row

    def clear_selection(self) -> None:
        if not self._selected_rows and self._current_row is None:
            return
        self._selected_rows.clear()
        self._current_row = None
        self._anchor_row = None
        self.selection_changed.emit()
        self._request_repaint()

    def select_row(self, row: int, *, ensure_visible: bool = True) -> None:
        if not 0 <= row < self.row_count():
            return
        self._selected_rows = {row}
        self._current_row = row
        self._anchor_row = row
        if ensure_visible:
            self._ensure_row_visible(row)
        self.selection_changed.emit()
        self._request_repaint()

    #
    # Geometry helpers
    #

    def row_count(self) -> int:
        return self._model.rowCount() if self._model is not None else 0

    def column_count(self) -> int:
        return self._model.columnCount() if self._model is not None else 0

    def content_width(self) -> float:
        if self._model is None:
            return 0.0
        return float(self._header.length())

    def content_height(self) -> float:
        return float(self.row_count() * self._row_height)

    def _update_scene_geometry(self) -> None:
        self._content.prepareGeometryChange()
        self._scene.setSceneRect(0, 0, self.content_width(), self.content_height())
        self._header.setOffset(self._gview.horizontalScrollBar().value())

    def _request_repaint(self) -> None:
        self._content.update()

    #
    # Painting
    #

    def _paint_cells(self, painter: QPainter, exposed: QRectF) -> None:
        model = self._model
        if model is None:
            return
        row_count = self.row_count()
        col_count = self.column_count()
        if row_count == 0 or col_count == 0:
            return

        row_h = self._row_height
        first_row = max(0, int(exposed.top() // row_h))
        last_row = min(row_count - 1, int(exposed.bottom() // row_h))
        if last_row < first_row:
            return

        # figure out which columns are (at least partially) visible
        visible_cols: list[tuple[int, float, float]] = []
        for logical in range(col_count):
            if self._header.isSectionHidden(logical):
                continue
            x = self._header.sectionPosition(logical)
            w = self._header.sectionSize(logical)
            if w <= 0 or x + w < exposed.left() or x > exposed.right():
                continue
            visible_cols.append((logical, float(x), float(w)))
        if not visible_cols:
            return

        palette = self.palette()
        highlight = palette.color(QPalette.ColorRole.Highlight)
        highlight_text = palette.color(QPalette.ColorRole.HighlightedText)
        default_text = palette.color(QPalette.ColorRole.Text)
        grid_color = QColor(palette.color(QPalette.ColorRole.Mid))
        grid_color.setAlpha(90)
        style = QApplication.style()

        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        for row in range(first_row, last_row + 1):
            y = row * row_h
            selected = row in self._selected_rows

            if selected:
                painter.fillRect(QRectF(exposed.left(), y, exposed.width(), row_h), highlight)

            for logical, x, w in visible_cols:
                index = model.index(row, logical)
                cell_rect = QRectF(x, y, w, row_h)

                text = model.data(index, Qt.ItemDataRole.DisplayRole)
                has_text = text is not None and text != ""
                check_state = model.data(index, Qt.ItemDataRole.CheckStateRole)

                if not selected:
                    bg = model.data(index, Qt.ItemDataRole.BackgroundRole)
                    if bg is not None:
                        brush = bg if isinstance(bg, QBrush) else QBrush(QColor(bg))
                        if brush.style() != Qt.BrushStyle.NoBrush:
                            painter.fillRect(cell_rect, brush)

                text_left = x + self.CELL_PADDING
                if check_state is not None:
                    box = self._checkbox_rect(cell_rect, centered=not has_text)
                    self._draw_checkbox(painter, style, box, check_state, palette)
                    if has_text:
                        text_left = box.right() + self.CELL_PADDING

                if has_text:
                    font = model.data(index, Qt.ItemDataRole.FontRole)
                    painter.setFont(font if font is not None else self.font())

                    if selected:
                        pen_color = highlight_text
                    else:
                        fg = model.data(index, Qt.ItemDataRole.ForegroundRole)
                        if fg is None:
                            pen_color = default_text
                        elif isinstance(fg, QBrush):
                            pen_color = fg.color()
                        else:
                            pen_color = QColor(fg)
                    painter.setPen(QPen(pen_color))

                    align = model.data(index, Qt.ItemDataRole.TextAlignmentRole)
                    alignment = (
                        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
                        if align is None
                        else Qt.AlignmentFlag(align)
                    )

                    text_width = x + w - text_left - self.CELL_PADDING
                    if text_width > 0:
                        fm = painter.fontMetrics()
                        elided = fm.elidedText(str(text), Qt.TextElideMode.ElideRight, int(text_width))
                        painter.drawText(QRectF(text_left, y, text_width, row_h), int(alignment), elided)

            if self._grid_enabled:
                painter.setPen(QPen(grid_color))
                line_y = y + row_h - 1
                painter.drawLine(QPointF(exposed.left(), line_y), QPointF(exposed.right(), line_y))

    def _checkbox_rect(self, cell_rect: QRectF, *, centered: bool) -> QRectF:
        style = QApplication.style()
        w = style.pixelMetric(QStyle.PixelMetric.PM_IndicatorWidth)
        h = style.pixelMetric(QStyle.PixelMetric.PM_IndicatorHeight)
        cy = cell_rect.center().y() - h / 2
        cx = cell_rect.center().x() - w / 2 if centered else cell_rect.left() + self.CELL_PADDING
        return QRectF(cx, cy, w, h)

    @staticmethod
    def _draw_checkbox(painter: QPainter, style, box: QRectF, check_state, palette) -> None:
        opt = QStyleOptionButton()
        opt.rect = box.toRect()
        opt.palette = palette
        opt.state = QStyle.StateFlag.State_Enabled
        if Qt.CheckState(check_state) == Qt.CheckState.Checked:
            opt.state |= QStyle.StateFlag.State_On
        else:
            opt.state |= QStyle.StateFlag.State_Off
        style.drawPrimitive(QStyle.PrimitiveElement.PE_IndicatorCheckBox, opt, painter)

    #
    # Coordinate helpers
    #

    def _row_at(self, scene_y: float) -> int | None:
        if scene_y < 0:
            return None
        row = int(scene_y // self._row_height)
        return row if 0 <= row < self.row_count() else None

    def _col_at(self, scene_x: float) -> int | None:
        for logical in range(self.column_count()):
            if self._header.isSectionHidden(logical):
                continue
            pos = self._header.sectionPosition(logical)
            size = self._header.sectionSize(logical)
            if pos <= scene_x < pos + size:
                return logical
        return None

    def _cell_rect(self, row: int, logical: int) -> QRectF:
        x = self._header.sectionPosition(logical)
        w = self._header.sectionSize(logical)
        return QRectF(x, row * self._row_height, w, self._row_height)

    def _visible_row_count(self) -> int:
        return max(1, self._gview.viewport().height() // self._row_height)

    def _ensure_row_visible(self, row: int) -> None:
        self._gview.ensureVisible(QRectF(0, row * self._row_height, 1, self._row_height), 0, 0)

    #
    # Interaction handlers
    #

    def _handle_mouse_press(self, scene_pos: QPointF, event: QMouseEvent) -> None:
        if self._model is None:
            return
        row = self._row_at(scene_pos.y())
        if row is None:
            return

        if event.button() == Qt.MouseButton.LeftButton:
            col = self._col_at(scene_pos.x())
            if col is not None and self._toggle_checkbox(row, col, scene_pos):
                # a checkbox toggle also selects the row below
                pass

            mods = event.modifiers()
            if mods & Qt.KeyboardModifier.ShiftModifier and self._anchor_row is not None:
                self._select_range(self._anchor_row, row)
            elif mods & Qt.KeyboardModifier.ControlModifier:
                if row in self._selected_rows:
                    self._selected_rows.discard(row)
                else:
                    self._selected_rows.add(row)
                self._anchor_row = row
            else:
                self._selected_rows = {row}
                self._anchor_row = row
            self._current_row = row
            self.selection_changed.emit()
            self._request_repaint()

    def _toggle_checkbox(self, row: int, logical: int, scene_pos: QPointF) -> bool:
        model = self._model
        assert model is not None
        index = model.index(row, logical)
        if not model.flags(index) & Qt.ItemFlag.ItemIsUserCheckable:
            return False
        check_state = model.data(index, Qt.ItemDataRole.CheckStateRole)
        if check_state is None:
            return False
        text = model.data(index, Qt.ItemDataRole.DisplayRole)
        has_text = text is not None and text != ""
        if not self._checkbox_rect(self._cell_rect(row, logical), centered=not has_text).contains(scene_pos):
            return False
        new_state = (
            Qt.CheckState.Unchecked if Qt.CheckState(check_state) == Qt.CheckState.Checked else Qt.CheckState.Checked
        )
        model.setData(index, new_state, Qt.ItemDataRole.CheckStateRole)
        self._request_repaint()
        return True

    def _handle_mouse_double_click(self, scene_pos: QPointF, event: QMouseEvent) -> None:  # pylint:disable=unused-argument
        row = self._row_at(scene_pos.y())
        if row is not None:
            self._current_row = row
            self.row_double_clicked.emit(row)

    def _handle_context_menu(self, event: QContextMenuEvent) -> None:
        if self._model is not None:
            row = self._row_at(self._gview.mapToScene(event.pos()).y())
            if row is not None and row not in self._selected_rows:
                self._selected_rows = {row}
                self._anchor_row = row
                self._current_row = row
                self.selection_changed.emit()
                self._request_repaint()
        self.context_menu_requested.emit(event.globalPos())

    def _handle_key_press(self, event: QKeyEvent) -> bool:
        if self._model is None:
            return False

        row_count = self.row_count()
        key = event.key()
        cur = self._current_row if self._current_row is not None else -1

        if key == Qt.Key.Key_Up:
            new = max(0, cur - 1) if cur > 0 else 0
        elif key == Qt.Key.Key_Down:
            new = min(row_count - 1, cur + 1) if cur >= 0 else 0
        elif key == Qt.Key.Key_PageUp:
            new = max(0, cur - self._visible_row_count())
        elif key == Qt.Key.Key_PageDown:
            new = min(row_count - 1, (cur if cur >= 0 else 0) + self._visible_row_count())
        elif key == Qt.Key.Key_Home:
            new = 0
        elif key == Qt.Key.Key_End:
            new = row_count - 1
        elif key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if self._current_row is not None:
                self.row_double_clicked.emit(self._current_row)
            return True
        else:
            text = event.text()
            if text and text in string.printable and text not in string.whitespace:
                self.key_pressed.emit(text)
                return True
            return False

        if row_count == 0:
            return True

        if event.modifiers() & Qt.KeyboardModifier.ShiftModifier and self._anchor_row is not None:
            self._select_range(self._anchor_row, new)
        else:
            self._selected_rows = {new}
            self._anchor_row = new
        self._current_row = new
        self._ensure_row_visible(new)
        self.selection_changed.emit()
        self._request_repaint()
        return True

    def _select_range(self, a: int, b: int) -> None:
        lo, hi = (a, b) if a <= b else (b, a)
        self._selected_rows = set(range(lo, hi + 1))

    #
    # Signal slots
    #

    def _on_hscroll(self, value: int) -> None:
        self._header.setOffset(value)

    def _on_header_geometry_changed(self, *args) -> None:  # pylint:disable=unused-argument
        self._update_scene_geometry()
        self._request_repaint()

    def _on_section_clicked(self, logical: int) -> None:
        if not self._sorting_enabled or self._model is None:
            return
        header = self._header
        if header.sortIndicatorSection() == logical:
            order = (
                Qt.SortOrder.DescendingOrder
                if header.sortIndicatorOrder() == Qt.SortOrder.AscendingOrder
                else Qt.SortOrder.AscendingOrder
            )
        else:
            order = Qt.SortOrder.AscendingOrder
        # this emits sortIndicatorChanged, which performs the actual sort
        header.setSortIndicator(logical, order)

    def _on_sort_indicator_changed(self, logical: int, order) -> None:
        if not self._sorting_enabled or self._model is None:
            return
        self._model.sort(logical, order)

    def _on_layout_changed(self, *args) -> None:  # pylint:disable=unused-argument
        rc = self.row_count()
        self._selected_rows = {r for r in self._selected_rows if r < rc}
        if self._current_row is not None and self._current_row >= rc:
            self._current_row = rc - 1 if rc > 0 else None
        if self._anchor_row is not None and self._anchor_row >= rc:
            self._anchor_row = None
        self._update_scene_geometry()
        self._request_repaint()

    def _on_model_reset(self, *args) -> None:  # pylint:disable=unused-argument
        self._selected_rows.clear()
        self._current_row = None
        self._anchor_row = None
        self._update_scene_geometry()
        self._request_repaint()

    def _on_data_changed(self, *args) -> None:  # pylint:disable=unused-argument
        self._request_repaint()

    #
    # Events
    #

    def changeEvent(self, event) -> None:  # type: ignore[override]
        if event.type() == QEvent.Type.PaletteChange:
            self._gview.setBackgroundBrush(QBrush(self.palette().color(QPalette.ColorRole.Base)))
            self._request_repaint()
        super().changeEvent(event)
