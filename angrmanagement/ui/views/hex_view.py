"""
The Qt hex view: the neutral hex editor of :mod:`angrmanagement.present.hexdump` drawn on a QGraphicsScene.

:class:`HexGraphicsObject` is a :class:`~angrmanagement.present.hexdump.HexGrid` that paints itself and takes the mouse
and the keys; :class:`HexView` is a :class:`~angrmanagement.present.hexdump.HexViewMixin` with the tool bar, the find
bar and Qt's dialogs.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import PySide6
from PySide6.QtCore import QEvent, QMarginsF, QPointF, QRectF, QSizeF, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QCursor, QFont, QKeySequence, QPainterPath, QPen, QShortcut, QWheelEvent
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
from angrmanagement.present import hexdump
from angrmanagement.present.hexdump import (
    HexAddress,
    HexByteValue,
    HexDataBuffer,
    HexDataSource,
    HexGrid,
    HexViewMixin,
    RowCol,
    register_hex_commands,
)
from angrmanagement.ui.dialogs.input_prompt import InputPromptDialog
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.menus.menu import to_qmenu
from angrmanagement.ui.widgets.qfind_bar import QFindBar
from angrmanagement.utils import is_printable

from .view import SynchronizedInstanceView

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angr.knowledge_plugins.patches import Patch
    from PySide6.QtGui import QPainter
    from PySide6.QtWidgets import QStyleOptionGraphicsItem, QWidget

    from angrmanagement.data.breakpoint import Breakpoint
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

log = logging.getLogger(__name__)

#: The cursor keys of HexGraphicsObject.keyPressEvent, by the names HexGrid.move_cursor takes.
_MOVEMENT_KEYS = {
    Qt.Key.Key_Up: "up",
    Qt.Key.Key_Down: "down",
    Qt.Key.Key_Right: "right",
    Qt.Key.Key_Left: "left",
    Qt.Key.Key_PageUp: "pageup",
    Qt.Key.Key_PageDown: "pagedown",
    Qt.Key.Key_Home: "home",
    Qt.Key.Key_End: "end",
}


class HexHighlightRegion(hexdump.HexHighlightRegion):
    """
    Defines a highlighted region.
    """

    def gen_context_menu_actions(self) -> QMenu | None:
        """
        Get submenu for this highlight region.
        """
        menu = self.context_menu()  # pylint: disable=assignment-from-none
        return None if menu is None else to_qmenu(menu)


class BreakpointHighlightRegion(hexdump.BreakpointHighlightRegion, HexHighlightRegion):
    """
    Defines a highlighted region indicating a breakpoint.
    """

    def __init__(self, bp: Breakpoint, view: HexView) -> None:
        super().__init__(bp, view, Qt.GlobalColor.cyan)


class PatchHighlightRegion(hexdump.PatchHighlightRegion, HexHighlightRegion):
    """
    Defines a highlighted region indicating a patch.
    """

    def __init__(self, patch: Patch, view: HexView) -> None:
        super().__init__(patch, view, Qt.GlobalColor.yellow)

    def cursor(self) -> HexAddress:
        return self.view.inner_widget.hex.cursor

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

    def comment(self) -> None:
        """
        Set the comment for this patch.
        """
        dlg = InputPromptDialog("Set Patch Comment", "Patch comment:", self.patch.comment, parent=self.view)
        dlg.exec_()
        self.set_comment(dlg.result)


class HexGraphicsObject(QGraphicsObject, HexGrid):
    """
    A graphics item providing a conventional hex-editor interface for a contiguous region of memory.
    """

    cursor_changed = Signal()
    viewport_changed = Signal()

    def __init__(self) -> None:
        QGraphicsObject.__init__(self)
        HexGrid.__init__(self)
        self.setFlag(
            QGraphicsItem.GraphicsItemFlag.ItemUsesExtendedStyleOption, True
        )  # Give me more specific paint update rect info
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsFocusable, True)  # Give me focus/key events
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemClipsToShape, True)
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
        self.font: QFont = QFont(Conf.disasm_font)
        self.font.setPointSizeF(12)

        self.cursor_blink_timer: QTimer = QTimer(self)
        self.cursor_blink_timer.timeout.connect(self.toggle_cursor_blink)

        self._update_layout()

    #
    # HexGrid's hooks
    #

    def notify_cursor_changed(self) -> None:
        self.cursor_changed.emit()

    def notify_viewport_changed(self) -> None:
        self.viewport_changed.emit()

    def _cursor_set(self) -> None:
        if self.hasFocus():
            self.restart_cursor_blink_timer()

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

    def restart_cursor_blink_timer(self) -> None:
        """
        Restart the cursor blink timer.
        """
        self.cursor_blink_timer.stop()
        self.cursor_blink_state = True
        self.cursor_blink_timer.start(750)

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
            self.click(addr, ascii_column, QApplication.keyboardModifiers() in (Qt.KeyboardModifier.ShiftModifier,))
            event.accept()

    def mouseDoubleClickEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        """
        Handle mouse double-click events (e.g. update selection)
        """
        if event.button() == Qt.MouseButton.LeftButton:
            self.select_region_under_cursor()

    def mouseMoveEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        """
        Handle mouse move events (e.g. updating selection).
        """
        if self.mouse_pressed:
            addr = self.point_to_addr(event.pos())
            if addr is None:
                return
            addr, ascii_column = addr
            self.drag_to(addr, ascii_column)

    def mouseReleaseEvent(self, event: QGraphicsSceneMouseEvent) -> None:
        """
        Handle mouse release events.
        """
        if event.button() == Qt.MouseButton.LeftButton:
            self.mouse_pressed = False

    def keyPressEvent(self, event: PySide6.QtGui.QKeyEvent) -> None:
        """
        Handle key press events (e.g. moving cursor around).
        """
        movement = _MOVEMENT_KEYS.get(event.key())
        if movement is not None:
            extend = bool(QApplication.keyboardModifiers() & Qt.KeyboardModifier.ShiftModifier)
            self.move_cursor(movement, extend)
            event.accept()
            return
        elif QApplication.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier:
            if event.key() == Qt.Key.Key_Space:
                self.toggle_column()
                event.accept()
                return
        elif self.type_text(event.text()):
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

    def toggle_cursor_blink(self) -> None:
        """
        Simply toggles cursor blink status.
        """
        self.cursor_blink_state = not self.cursor_blink_state
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

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget | None = None) -> None:  # pylint: disable=unused-argument
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
        text = self.tooltip_at(addr)
        if text:
            self.setToolTip(text)


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


class HexView(SynchronizedInstanceView, HexViewMixin):
    """
    View and edit memory/object code in classic hex editor format.
    """

    REGION_CLASS = HexHighlightRegion
    PATCH_REGION_CLASS = PatchHighlightRegion
    BREAKPOINT_REGION_CLASS = BreakpointHighlightRegion
    SYNCHRONIZED_REGION_COLOR = Qt.GlobalColor.green
    CHANGED_REGION_COLOR = Qt.GlobalColor.red

    _widgets_initialized: bool = False

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("hex", workspace, default_docking_position, instance)
        self.base_caption: str = "Hex"
        self._init_hex_state()
        self._find_bar: QFindBar | None = None
        self._init_widgets()
        self._start_hex()

    @classmethod
    def register_commands(cls, workspace: Workspace) -> None:
        register_hex_commands(workspace)

    def closeEvent(self, event) -> None:
        self._dbg_watcher.shutdown()
        super().closeEvent(event)

    #
    # HexViewMixin's hooks
    #

    @property
    def grid(self) -> HexGraphicsObject:
        return self.inner_widget.hex

    def _grid_if_ready(self) -> HexGraphicsObject | None:
        return self.inner_widget.hex if self._widgets_initialized else None

    @property
    def data_source(self) -> HexDataSource:
        return self._data_source_combo.currentData()

    def _set_region_callback(self, write, read, addr: int, size: int) -> None:
        self.inner_widget.set_region_callback(write, read, addr, size)

    def _clear_grid(self) -> None:
        self.inner_widget.clear()

    def _display_start_addr(self) -> HexAddress:
        return self.inner_widget.get_display_start_addr()

    def _set_display_start_addr(self, start: HexAddress) -> None:
        self.inner_widget.set_display_start_addr(start)

    def update_status_text(self) -> None:
        """
        Update status text with current cursor info.
        """
        self._status_lbl.setText(self.status_text())

    def _focus_grid(self) -> None:
        self.inner_widget.setFocus()

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

        self._find_bar = QFindBar(self, modes=["Hex", "Text"])
        self._find_bar.set_text_options_visible(False)  # the default mode is Hex
        self._find_bar.query_changed.connect(self._update_find_matches)
        self._find_bar.find_next.connect(self.find_next)
        self._find_bar.find_previous.connect(self.find_previous)
        self._find_bar.closed.connect(self._on_find_bar_closed)

        self.inner_widget = HexGraphicsView(parent=self)
        lyt = QVBoxLayout()
        lyt.addWidget(status_bar)
        lyt.addWidget(self._find_bar)
        lyt.addWidget(self.inner_widget)
        lyt.setContentsMargins(0, 0, 0, 0)
        lyt.setSpacing(0)
        self.setLayout(lyt)
        self.inner_widget.cursor_changed.connect(self.on_cursor_changed)
        self.inner_widget.hex.viewport_changed.connect(self.on_cursor_changed)

        for sequence, handler in [
            (QKeySequence.StandardKey.Find, self.show_find_bar),
            (QKeySequence(Qt.Key.Key_F3), self.find_next),
            (QKeySequence("Shift+F3"), self.find_previous),
        ]:
            shortcut = QShortcut(sequence, self, handler)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)

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
        self._revert_selected_patches()

    def _get_breakpoint_submenu(self) -> QMenu:
        """
        Get context menu to add new breakpoints.
        """
        return to_qmenu(self.breakpoint_menu(), self)

    def contextMenuEvent(self, event: PySide6.QtGui.QContextMenuEvent) -> None:  # pylint: disable=unused-argument
        """
        Display view context menu.
        """
        menu = self.context_menu()
        menu.parent = self
        mnu = to_qmenu(menu, self)
        mnu.exec_(QCursor.pos())

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
        JumpTo(self, parent=self).show()


__all__ = [
    "BreakpointHighlightRegion",
    "HexAddress",
    "HexByteValue",
    "HexDataBuffer",
    "HexDataSource",
    "HexGraphicsObject",
    "HexGraphicsSubView",
    "HexGraphicsView",
    "HexHighlightRegion",
    "HexView",
    "PatchHighlightRegion",
    "RowCol",
]
