from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QPoint, QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QLinearGradient, QPen, QPolygonF
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsPolygonItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf
from angrmanagement.logic.debugger import DebuggerWatcher
from angrmanagement.logic.debugger.bintrace import BintraceDebugger

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.instance import Instance


class TraceMapItem(QGraphicsItem):
    """
    Trace map item to be rendered in graphics scene.
    """

    ZVALUE_CHECKPOINT = 1
    ZVALUE_ADDR = 2
    ZVALUE_HOVER = 3

    def __init__(self, instance: Instance) -> None:
        super().__init__()
        self.instance = instance

        self._width: int = 1
        self._height: int = 1

        self._addr: int = 0
        self._indicator_items: Sequence[QGraphicsItem] = []

        self._hover_addr: int | None = None
        self._hover_items: Sequence[QGraphicsItem] = []

        self._checkpoints = []
        self._checkpoint_items: Sequence[QGraphicsItem] = []

        self._total_size: int = 0
        self._pressed: bool = False

        self.setAcceptHoverEvents(True)
        self._register_events()

    def refresh(self) -> None:
        self._gen_current_indicator()
        self._gen_checkpoint_indicators()
        self._gen_hover_indicator()

    def _register_events(self) -> None:
        self._dbg_watcher = DebuggerWatcher(self.on_debugger_state_updated, self.instance.debugger_mgr.debugger)
        self.on_debugger_state_updated()

    def on_debugger_state_updated(self) -> None:
        self._addr = 0
        self._total_size = 0
        self._checkpoints = []

        if isinstance(self._dbg_watcher.debugger.am_obj, BintraceDebugger):
            # FIXME: Expose trace info as TraceDebugger abstraction between Debugger<>BintraceDebugger
            dbg = self._dbg_watcher.debugger.am_obj
            t = dbg._trace.trace
            s = dbg._trace_dbg.state
            if s and s.event_count >= 0:
                self._addr = s.event_count
                self._total_size = t.get_num_events()
                self._checkpoints = [s.event_count for s in t.checkpoints]

        self.refresh()

    @property
    def width(self) -> int:
        return self._width

    def set_width(self, width: int) -> None:
        """
        Set the desired width of the trace map in scene units.
        """
        self.prepareGeometryChange()
        self._width = width

    @property
    def height(self) -> int:
        return self._height

    def set_height(self, height: int) -> None:
        """
        Set the desired height of the trace map in scene units.
        """
        self.prepareGeometryChange()
        self._height = height

    def paint(self, painter, option, widget) -> None:
        """
        Paint the trace map.
        """
        # Drawn by child items

    def boundingRect(self) -> QRectF:
        """
        Return the bounding dimensions of this item.
        """
        return QRectF(0, 0, self._width, self._height)

    def _get_pos_from_addr(self, addr: int) -> int | None:
        """
        Get scene X coordinate from address, or None if it could not be mapped.
        """
        if self._total_size == 0 or addr > self._total_size:
            return None
        return int(addr / self._total_size * self._width)

    def _get_addr_from_pos(self, pos: int) -> int | None:
        """
        Get address from scene X coordinate, or None if it could not be mapped.
        """
        offset = int(pos * self._total_size // self._width)
        return offset

    def _get_offset_size_rect(self, offset: int, size: int) -> QRectF:
        """
        Given a byte offset `offset` and number of bytes `size`, get a rect to draw.
        """
        if self._total_size == 0:
            return None
        x = offset / self._total_size * self._width
        width = size / self._total_size * self._width
        return QRectF(x, 0, width, self._height)

    def _create_line_indicator(
        self, addr: int, item_map, color=Qt.GlobalColor.yellow, show_frontier: bool = False, z=None, z_frontier=None
    ) -> None:
        """
        Generate a cursor at a given address.
        """
        pos_x = self._get_pos_from_addr(addr)
        if pos_x is None:
            return

        pen = QPen(color)
        brush = QBrush(color)
        height = self.height

        tri_width = 7
        tri_height = 4

        pos_x = int(pos_x - tri_width / 2)  # Center drawing
        center = pos_x + int(tri_width / 2)
        pos_y = 0
        frontier_width = int(0.15 * max(self.width, self.height))

        if show_frontier:
            # Draw frontier gradients
            r = QRectF(center - frontier_width, pos_y, frontier_width, height)
            bg = QLinearGradient(r.topLeft(), r.topRight())
            color = Qt.GlobalColor.red
            top_color = QColor(color)
            top_color.setAlpha(0)
            bg.setColorAt(0, top_color)
            bottom_color = QColor(color)
            bottom_color.setAlpha(180)
            bg.setColorAt(1, bottom_color)

            i = QGraphicsRectItem(r, parent=self)
            i.setPen(Qt.PenStyle.NoPen)
            i.setBrush(bg)
            if z_frontier is not None:
                i.setZValue(z_frontier)
            item_map.append(i)

            r = QRectF(center, pos_y, frontier_width, height)
            bg = QLinearGradient(r.topLeft(), r.topRight())
            color = Qt.GlobalColor.blue
            top_color = QColor(color)
            bg.setColorAt(0, top_color)
            bottom_color = QColor(color)
            bottom_color.setAlpha(0)
            bg.setColorAt(1, bottom_color)

            i = QGraphicsRectItem(r, parent=self)
            i.setPen(Qt.PenStyle.NoPen)
            i.setBrush(bg)
            if z_frontier is not None:
                i.setZValue(z_frontier)
            item_map.append(i)

        # Draw line
        i = QGraphicsLineItem(center, 0, center, height, parent=self)
        i.setPen(pen)
        if z is not None:
            i.setZValue(z)
        item_map.append(i)

        # Draw top and bottom triangles
        t = QPolygonF()
        t.append(QPointF(pos_x, pos_y))
        t.append(QPointF(pos_x + tri_width - 1, pos_y))
        t.append(QPointF(center, pos_y + tri_height - 1))
        t.append(QPointF(pos_x, pos_y))

        pos_y += height - 1
        b = QPolygonF()
        b.append(QPointF(pos_x, pos_y))
        b.append(QPointF(center, pos_y - tri_height + 1))
        b.append(QPointF(pos_x + tri_width - 1, pos_y))
        b.append(QPointF(pos_x, pos_y))

        for i in [QGraphicsPolygonItem(t, parent=self), QGraphicsPolygonItem(b, parent=self)]:
            i.setPen(pen)
            i.setBrush(brush)
            if z is not None:
                i.setZValue(z)
            item_map.append(i)

    def _gen_checkpoint_indicators(self) -> None:
        """
        Create checkpoint indicators.
        """
        scene = self.scene()
        for item in self._checkpoint_items:
            scene.removeItem(item)
        self._checkpoint_items.clear()

        color = QColor(Qt.GlobalColor.green)

        for checkpoint_addr in self._checkpoints:
            self._create_line_indicator(checkpoint_addr, self._checkpoint_items, color=color, z=self.ZVALUE_CHECKPOINT)

    def _gen_current_indicator(self) -> None:  # pylint: disable=unused-argument
        """
        Create current address indicator.
        """
        scene = self.scene()
        for item in self._indicator_items:
            scene.removeItem(item)
        self._indicator_items.clear()

        self._create_line_indicator(self._addr, self._indicator_items, show_frontier=True, z=self.ZVALUE_ADDR)

    def _gen_hover_indicator(self) -> None:
        """
        Create the hovered address indicator.
        """
        scene = self.scene()
        for item in self._hover_items:
            scene.removeItem(item)
        self._hover_items.clear()

        if self._hover_addr is not None:
            self._create_line_indicator(
                self._hover_addr, self._hover_items, color=Qt.GlobalColor.gray, z=self.ZVALUE_HOVER
            )

    def _remove_hover_indicators(self) -> None:
        """
        Remove active hover items, if set.
        """
        if self._hover_addr is not None:
            self._hover_addr = None
            self._gen_hover_indicator()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            pos = event.pos()
            offset = pos.x()
            self.select_offset(offset)
            self._pressed = True

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._pressed = False

    def mouseMoveEvent(self, event) -> None:
        if self._pressed:
            pos = event.pos()
            offset = pos.x()
            self.select_offset(offset)
        else:
            super().mouseMoveEvent(event)

    def on_mouse_move_event_from_view(self, point: QPointF) -> None:
        """
        Add hover items.
        """
        self._remove_hover_indicators()
        self._hover_addr = self._get_addr_from_pos(point.x())
        self._gen_hover_indicator()

    def hoverLeaveEvent(self, event) -> None:  # pylint: disable=unused-argument
        self._remove_hover_indicators()

    def select_offset(self, offset: int) -> None:
        """
        Update listeners with new desired location.
        """
        if not isinstance(self._dbg_watcher.debugger.am_obj, BintraceDebugger):
            return

        addr = self._get_addr_from_pos(offset)
        if addr is None:
            return

        dbg = self._dbg_watcher.debugger.am_obj
        dbg.replay_to_nth_event(addr)


class QTraceMapView(QGraphicsView):
    """
    Graphics view for trace map scene. The scene will rotate based on dimensions of the viewport to support horizontal
    and vertical orientations.
    """

    def __init__(self, instance: Instance, parent=None) -> None:
        super().__init__(parent)
        self.instance = instance
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setMouseTracking(True)
        self._scene = QGraphicsScene(parent=self)
        self.setScene(self._scene)
        self.fm: TraceMapItem = TraceMapItem(self.instance)
        self._scale: float = 1.0
        self._scene.addItem(self.fm)
        self._orientation: str = "horizontal"
        self._base_width: int = 0

        self.setBackgroundBrush(Conf.palette_base)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.NoAnchor)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.NoAnchor)
        self.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.update_size()

    def mouseMoveEvent(self, event) -> None:
        """
        Handle mouse move events.

        Mouse move events whilst not holding a mouse button will not be propagated down to QGraphicsItems, so we catch
        the movement events here in the view and forward them to the trace map item.
        """
        scene_pt = self.mapToScene(event.pos().x(), event.pos().y())
        item_pt = self.fm.mapFromScene(scene_pt)
        self.fm.on_mouse_move_event_from_view(item_pt)
        super().mouseMoveEvent(event)

    def wheelEvent(self, event) -> None:
        """
        Handle wheel events to scale and translate the trace map.
        """
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier == Qt.KeyboardModifier.ControlModifier:
            self.adjust_viewport_scale(
                1.25 if event.angleDelta().y() > 0 else 1 / 1.25, QPoint(event.position().x(), event.position().y())
            )
        else:
            self.translate(100 * (-1 if event.angleDelta().y() < 0 else 1), 0)
            super().wheelEvent(event)

    def resizeEvent(self, event) -> None:  # pylint: disable=unused-argument
        """
        Handle view resize events, updating the trace map size accordingly.
        """
        self.update_size()

    def adjust_viewport_scale(self, scale: float | None = None, point: QPoint | None = None) -> None:
        """
        Adjust viewport scale factor.
        """
        if point is None:
            point = QPoint(0, 0)
        point_rel = self.mapToScene(point).x() / self.fm.width

        if scale is None:
            self._scale = 1.0
        else:
            self._scale = max(self._scale * scale, 1.0)

        self.update_size()
        self.translate(int(self.mapToScene(point).x() - point_rel * self.fm.width), 0)

    def keyPressEvent(self, event) -> None:
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

    def changeEvent(self, event: QEvent) -> None:
        """
        Redraw on color scheme update.
        """
        if event.type() == QEvent.Type.StyleChange:
            self.setBackgroundBrush(Conf.palette_base)
            self.fm.refresh()

    def update_size(self) -> None:
        """
        Resize map.
        """
        rotation = 0
        vg = self.viewport().geometry()
        if vg.width() > vg.height():
            if self._orientation != "horizontal":
                rotation = -90
            self._orientation = "horizontal"
            w, h = vg.width(), vg.height()
        else:
            if self._orientation != "vertical":
                rotation = 90
            self._orientation = "vertical"
            w, h = vg.height(), vg.width()

        if rotation:
            self._scale = 1.0

        if self._scale <= 1.0:
            # Only resize to map to viewport width if scale is at base level to not disturb preferred size
            self._base_width = w

        self.fm.set_width(int(self._base_width * self._scale))
        self.fm.set_height(h)
        self.fm.refresh()
        self.setSceneRect(QRectF(0, 0, self.fm.width, self.fm.height))
        if rotation:
            self.rotate(rotation)


class QTraceMap(QWidget):
    """
    Map of the current trace, with debugger playback position and checkpoint indicators.
    """

    def __init__(self, instance: Instance, parent=None) -> None:
        super().__init__(parent)
        self.instance = instance
        self.view: QTraceMapView = None
        self._init_widgets()

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(25, 25)

    def minimumSizeHint(self):  # pylint:disable=no-self-use
        return QSize(25, 25)

    #
    # Public methods
    #

    def refresh(self) -> None:
        if self.view is not None:
            self.view.fm.refresh()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self.view = QTraceMapView(self.instance, self)
        layout = QHBoxLayout()
        layout.addWidget(self.view)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
