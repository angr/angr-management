import math
from typing import TYPE_CHECKING

from PySide2.QtWidgets import QGraphicsItem, QApplication
from PySide2.QtGui import QPen, QBrush, QColor, QPainterPath, QPainterPathStroker
from PySide2.QtCore import QPointF, Qt

from ...utils.edge import EdgeSort
from ...config import Conf

if TYPE_CHECKING:
    from ..views.dep_view import DependencyView


EDGE_COLORS = {
    EdgeSort.BACK_EDGE: 'disasm_view_back_edge_color',
    EdgeSort.TRUE_BRANCH: 'disasm_view_true_edge_color',
    EdgeSort.FALSE_BRANCH: 'disasm_view_false_edge_color',
    EdgeSort.DIRECT_JUMP: 'disasm_view_direct_jump_edge_color',
    EdgeSort.EXCEPTION_EDGE: 'disasm_view_exception_edge_color',
}

EDGE_STYLES = {
    EdgeSort.DIRECT_JUMP: Qt.SolidLine,
    EdgeSort.EXCEPTION_EDGE: Qt.DashLine
}


class QGraphArrow(QGraphicsItem):

    def __init__(self, edge, arrow_location="end", arrow_direction='down', parent=None):
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

    def _make_path(self):
        path = QPainterPath(self.coords[0])
        for c in self.coords[1:]:
            path.lineTo(c)
        return path

    def _make_arrow(self, location, direction):
        if location == "start":
            coord = self.start
        else:
            coord = self.end

        if direction == "down":
            return [QPointF(coord.x() - 3, coord.y()), QPointF(coord.x() + 3, coord.y()),
                     QPointF(coord.x(), coord.y() + 6)]
        elif direction == "right":
            return [QPointF(coord.x(), coord.y() - 3), QPointF(coord.x(), coord.y() + 3),
                 QPointF(coord.x() + 6, coord.y())]
        elif direction == "left":
            return [QPointF(coord.x(), coord.y() - 3), QPointF(coord.x(), coord.y() + 3),
                    QPointF(coord.x() - 6, coord.y())]
        else:
            raise NotImplementedError("Direction %s is not supported yet." % direction)

    def _should_highlight(self) -> bool:
        return False

    def create_point(self, stuff):
        return QPointF(*stuff) - self._start

    def paint(self, painter, option, widget):
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        should_highlight = self._should_highlight()

        if should_highlight:
            pen = QPen(QColor(0, 0xfe, 0xfe), 2, self.style)
        else:
            pen = QPen(self.color, 2, self.style)
        painter.setPen(pen)

        painter.drawPath(self.path)

        # arrow
        if lod < 0.3:
            return

        # arrow
        if should_highlight:
            brush = QBrush(QColor(0, 0xfe, 0xfe))
        else:
            brush = QBrush(self.color)
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

    def hoverEnterEvent(self, event):
        pass

    def hoverLeaveEvent(self, event):
        pass

    def mouseDoubleClickEvent(self, event):
        pass


class QDisasmGraphArrow(QGraphArrow):
    def __init__(self, edge, disasm_view, infodock, parent=None):
        super().__init__(edge, arrow_direction='down', parent=parent)
        self.disasm_view = disasm_view
        self.infodock = infodock

    def _should_highlight(self) -> bool:
        return self.infodock.is_edge_hovered(self.edge.src.addr, self.edge.dst.addr) or \
                self.infodock.is_block_hovered(self.edge.src.addr) or \
                self.infodock.is_block_hovered(self.edge.dst.addr)

    #
    # Event handlers
    #

    def hoverEnterEvent(self, event):
        self.infodock.hover_edge(self.edge.src.addr, self.edge.dst.addr)

    def hoverLeaveEvent(self, event):
        self.infodock.unhover_edge(self.edge.src.addr, self.edge.dst.addr)

    def mouseDoubleClickEvent(self, event):
        if QApplication.keyboardModifiers() == Qt.ShiftModifier:
            # go to the source
            self.disasm_view.jump_to(self.edge.src.addr, src_ins_addr=self.edge.dst.addr, use_animation=True)
            event.accept()
        else:
            # go to the destination
            self.disasm_view.jump_to(self.edge.dst.addr, src_ins_addr=self.edge.src.addr, use_animation=True)
            event.accept()
        super().mouseDoubleClickEvent(event)


class QGraphArrowBezier(QGraphArrow):
    def __init__(self, edge, arrow_location="end", arrow_direction='down', radius=18, parent=None):
        self._radius = radius
        super().__init__(edge, arrow_location=arrow_location, arrow_direction=arrow_direction, parent=parent)

    @staticmethod
    def _get_distance(pt0: QPointF, pt1: QPointF) -> float:
        d = (pt1.x() - pt0.x()) ** 2 + (pt1.y() - pt0.y()) ** 2
        return math.sqrt(d)

    def _get_line_start(self, i: int) -> QPointF:
        pt0 = self.coords[i]
        pt1 = self.coords[i+1] if i+1<len(self.coords) else self.coords[0]
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
            # raise ValueError("At least 3 coordinates are required.")  # programming error - don't use this class for a simple segment!

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
    def __init__(self, dep_view: 'DependencyView', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dep_view = dep_view

    def _should_highlight(self) -> bool:
        if self._dep_view.hovered_block is None:
            return False
        return self._dep_view.hovered_block is self.edge.src or self._dep_view.hovered_block is self.edge.dst


class QProximityGraphArrow(QGraphArrow):
    def __init__(self, proximity_view: 'QProximityView', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._proximity_view = proximity_view

    def _should_highlight(self) -> bool:
        if self._proximity_view.hovered_block is None:
            return False
        return self._proximity_view.hovered_block is self.edge.src or \
               self._proximity_view.hovered_block is self.edge.dst

