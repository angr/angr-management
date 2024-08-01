from __future__ import annotations

import math
from typing import TYPE_CHECKING

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QBrush, QColor, QKeyEvent, QPainterPath, QPainterPathStroker, QPen
from PySide6.QtWidgets import QApplication, QGraphicsItem

from angrmanagement.config import Conf
from angrmanagement.utils.edge import EdgeSort

if TYPE_CHECKING:
    from angrmanagement.ui.views.data_dep_view import DataDepView
    from angrmanagement.ui.views.dep_view import DependencyView
    from angrmanagement.ui.views.proximity_view import ProximityView

EDGE_COLORS = {
    EdgeSort.BACK_EDGE: "disasm_view_back_edge_color",
    EdgeSort.TRUE_BRANCH: "disasm_view_true_edge_color",
    EdgeSort.FALSE_BRANCH: "disasm_view_false_edge_color",
    EdgeSort.DIRECT_JUMP: "disasm_view_direct_jump_edge_color",
    EdgeSort.EXCEPTION_EDGE: "disasm_view_exception_edge_color",
}

EDGE_STYLES = {EdgeSort.DIRECT_JUMP: Qt.PenStyle.SolidLine, EdgeSort.EXCEPTION_EDGE: Qt.PenStyle.DashLine}


class QGraphArrow(QGraphicsItem):
    def __init__(self, edge, arrow_location: str = "end", arrow_direction: str = "down", parent=None) -> None:
        super().__init__(parent)

        self.edge = edge
        self.rect = None
        self._start = QPointF(*self.edge.coordinates[0])
        self.coords = [self.create_point(c) for c in self.edge.coordinates]
        self.end = self.coords[-1]
        self.start = self.coords[0]

        self.color = getattr(Conf, EDGE_COLORS.get(self.edge.sort, EDGE_COLORS[EdgeSort.DIRECT_JUMP]))
        self.arrow = self._make_arrow(arrow_location, arrow_direction)
        self.style = EDGE_STYLES.get(self.edge.sort, EDGE_STYLES[EdgeSort.DIRECT_JUMP])
        self.path = self._make_path()

        self._hovered = False

        self.setAcceptHoverEvents(True)

    @staticmethod
    def _get_distance(pt0: QPointF, pt1: QPointF) -> float:
        d = (pt1.x() - pt0.x()) ** 2 + (pt1.y() - pt0.y()) ** 2
        return math.sqrt(d)

    def _make_path(self):
        path = QPainterPath(self.coords[0])
        for c in self.coords[1:]:
            path.lineTo(c)
        return path

    def _make_arrow(self, location, direction):
        coord = self.start if location == "start" else self.end

        if direction == "down":
            return [
                QPointF(coord.x() - 3, coord.y()),
                QPointF(coord.x() + 3, coord.y()),
                QPointF(coord.x(), coord.y() + 6),
            ]
        elif direction == "right":
            return [
                QPointF(coord.x(), coord.y() - 3),
                QPointF(coord.x(), coord.y() + 3),
                QPointF(coord.x() + 6, coord.y()),
            ]
        elif direction == "left":
            return [
                QPointF(coord.x(), coord.y() - 3),
                QPointF(coord.x(), coord.y() + 3),
                QPointF(coord.x() - 6, coord.y()),
            ]
        else:
            raise NotImplementedError(f"Direction {direction} is not supported yet.")

    def _should_highlight(self) -> bool:
        return False

    def create_point(self, stuff):
        return QPointF(*stuff) - self._start

    def paint(self, painter, option, widget) -> None:
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        should_highlight = self._should_highlight()

        pen = QPen(QColor(0, 254, 254), 2, self.style) if should_highlight else QPen(self.color, 2, self.style)

        painter.setPen(pen)

        painter.drawPath(self.path)

        # arrow
        if lod < 0.3:
            return

        # arrow
        brush = QBrush(QColor(0, 254, 254)) if should_highlight else QBrush(self.color)
        painter.setBrush(brush)
        painter.drawPolygon(self.arrow)

    def boundingRect(self):
        if self.rect is None:
            self.rect = self.path.boundingRect()
        return self.rect

    def shape(self):
        stroker = QPainterPathStroker()
        stroker.setWidth(4)
        stroker.setCapStyle(Qt.RoundCap)
        return stroker.createStroke(self.path)

    #
    # Event handlers
    #

    def hoverEnterEvent(self, event) -> None:
        pass

    def hoverLeaveEvent(self, event) -> None:
        pass

    def mouseDoubleClickEvent(self, event) -> None:
        pass


class QDisasmGraphArrow(QGraphArrow):
    def __init__(self, edge, disasm_view, infodock, parent=None) -> None:
        super().__init__(edge, arrow_direction="down", parent=parent)
        self.disasm_view = disasm_view
        self.infodock = infodock

    def _should_highlight(self) -> bool:
        return (
            self.infodock.is_edge_hovered(self.edge.src.addr, self.edge.dst.addr)
            or self.infodock.is_block_hovered(self.edge.src.addr)
            or self.infodock.is_block_hovered(self.edge.dst.addr)
        )

    #
    # Event handlers
    #

    def hoverEnterEvent(self, event) -> None:
        self.infodock.hover_edge(self.edge.src.addr, self.edge.dst.addr)

    def hoverLeaveEvent(self, event) -> None:
        self.infodock.unhover_edge(self.edge.src.addr, self.edge.dst.addr)

    def mouseDoubleClickEvent(self, event) -> None:
        if QApplication.keyboardModifiers() == Qt.KeyboardModifier.ShiftModifier:
            # go to the source
            self.disasm_view.jump_to(self.edge.src.addr, src_ins_addr=self.edge.dst.addr, use_animation=True)
            event.accept()
        else:
            # go to the destination
            self.disasm_view.jump_to(self.edge.dst.addr, src_ins_addr=self.edge.src.addr, use_animation=True)
            event.accept()
        super().mouseDoubleClickEvent(event)


class QGraphArrowBezier(QGraphArrow):
    def __init__(
        self, edge, arrow_location: str = "end", arrow_direction: str = "down", radius: int = 18, parent=None
    ) -> None:
        self._radius = radius
        super().__init__(edge, arrow_location=arrow_location, arrow_direction=arrow_direction, parent=parent)

    def _get_line_start(self, i: int) -> QPointF:
        pt0 = self.coords[i]
        pt1 = self.coords[i + 1] if i + 1 < len(self.coords) else self.coords[0]
        rat = self._radius / self._get_distance(pt0, pt1)
        if rat > 0.5:
            rat = 0.5
        return QPointF((1.0 - rat) * pt0.x() + rat * pt1.x(), (1.0 - rat) * pt0.y() + rat * pt1.y())

    def _get_line_end(self, i: int) -> QPointF:
        pt0 = self.coords[i]
        pt1 = self.coords[i + 1] if i + 1 < len(self.coords) else self.coords[0]
        rat = self._radius / self._get_distance(pt0, pt1)
        if rat > 0.5:
            rat = 0.5
        return QPointF(rat * pt0.x() + (1.0 - rat) * pt1.x(), rat * pt0.y() + (1.0 - rat) * pt1.y())

    def _make_path(self):
        if len(self.coords) < 3:
            return super()._make_path()
            # programming error - don't use this class for a simple segment!
            # raise ValueError("At least 3 coordinates are required.")

        path = QPainterPath(self.coords[0])

        for i in range(len(self.coords) - 1):
            pt0 = self._get_line_start(i)
            if i == 0:
                path.lineTo(pt0)
            else:
                path.quadTo(self.coords[i], pt0)
            pt1 = self._get_line_end(i)
            path.lineTo(pt1)

        path.lineTo(self.coords[-1])

        return path


class QDepGraphArrow(QGraphArrowBezier):
    def __init__(self, dep_view: DependencyView, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._dep_view = dep_view

    def _should_highlight(self) -> bool:
        if self._dep_view.hovered_block is None:
            return False
        return self._dep_view.hovered_block is self.edge.src or self._dep_view.hovered_block is self.edge.dst


class QProximityGraphArrow(QGraphArrow):
    def __init__(self, proximity_view: ProximityView, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._proximity_view = proximity_view

    def _should_highlight(self) -> bool:
        if self._proximity_view.hovered_block is None:
            return False
        return (
            self._proximity_view.hovered_block is self.edge.src or self._proximity_view.hovered_block is self.edge.dst
        )


class QDataDepGraphArrow(QGraphArrow):
    """Used to represent an edge between two QDataDepGraphBlocks"""

    def __init__(self, data_dep_view: DataDepView, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemIsFocusable)
        self._data_dep_view = data_dep_view
        self.is_hovered = False

    def _should_highlight(self) -> bool:
        # Should be highlighted if in trace path
        return (
            self.is_hovered
            or self.edge.dst in self._data_dep_view.traced_ancestors
            or self.edge.src in self._data_dep_view.traced_descendants
        )

    def hoverEnterEvent(self, event) -> None:
        self.is_hovered = True
        self.update()  # Must trigger repaint to highlight
        self.setFocus(Qt.FocusReason.MouseFocusReason)
        self.grabKeyboard()
        self._data_dep_view.graph_widget.handle_preview_request(
            self, event.modifiers() & Qt.KeyboardModifier.ControlModifier
        )

    def hoverLeaveEvent(self, event) -> None:
        self.is_hovered = False
        self.update()  # Must trigger repaint to unhighlight
        self.ungrabKeyboard()
        self.clearFocus()
        self._data_dep_view.graph_widget.hide_preview()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if self.is_hovered and event.key() == Qt.Key.Key_Control:
            self._data_dep_view.graph_widget.handle_preview_request(self, True)
        else:
            super().keyPressEvent(event)

    def keyReleaseEvent(self, event: QKeyEvent) -> None:
        if self.is_hovered and event.key() == Qt.Key.Key_Control:
            self._data_dep_view.graph_widget.handle_preview_request(self, False)
        else:
            super().keyPressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        """
        A double click on an arrow should center the data-dep view on the arrow's destination or source node
        If the control modifier is held, then the jump will be made to the destination. Otherwise, the source.
        """
        jump_to_dst = event.modifiers() & Qt.KeyboardModifier.ControlModifier
        self._data_dep_view.graph_widget.jump_to_neighbor(self, jump_to_dst, self.mapToParent(event.pos().toPoint()))


class QDataDepGraphAncestorLine(QDataDepGraphArrow):
    """
    Dashed line to differentiate between value dependencies and ancestor linking
    """

    dash_len = 5.0

    def _calculate_dash_pattern(self) -> list[float]:
        """
        Builds dash pattern list dynamically, ensuring the correct number of dashes and spacing per each distance that
        must be covered
        """
        dash_len = self.dash_len
        distance = self._get_distance(self.start, self.end)
        dash_count = distance // dash_len

        dash_count = 19 if dash_count < 20 else dash_count - 1
        dash_len = (distance - dash_len) / dash_count

        # Must have an even amount of dashes
        if dash_count % 2 != 0:
            dash_count -= 1
            dash_len = distance / dash_count

        pattern = [dash_len] * int(dash_count)
        pattern.append(distance - (dash_len * dash_count))  # Remaining width is last tick
        pattern.append(0.0)
        return pattern

    def paint(self, painter, option, widget) -> None:
        should_highlight = self._should_highlight()

        pen = QPen(QColor(0, 254, 254), 2, self.style) if should_highlight else QPen(self.color, 2, self.style)

        pen.setDashPattern(self._calculate_dash_pattern())

        painter.setPen(pen)
        painter.drawPath(self.path)
