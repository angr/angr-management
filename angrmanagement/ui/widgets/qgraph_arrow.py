
from PySide2.QtWidgets import QGraphicsItem, QApplication
from PySide2.QtGui import QPen, QBrush, QColor, QPainterPath, QPainterPathStroker
from PySide2.QtCore import QPointF, Qt

from ...utils.edge import EdgeSort

EDGE_COLORS = {
    EdgeSort.BACK_EDGE: QColor(0xf9, 0xd5, 0x77),  # Honey
    EdgeSort.TRUE_BRANCH: QColor(0x79, 0xcc, 0xcd),  # Agar
    EdgeSort.FALSE_BRANCH: QColor(0xf1, 0x66, 0x64),  # Tomato
    EdgeSort.DIRECT_JUMP: QColor(0x56, 0x5a, 0x5c),  # Dark gray
    EdgeSort.EXCEPTION_EDGE: QColor(0xf9, 0x91, 0x0a),  # Dark orange
}

EDGE_STYLES = {
    EdgeSort.DIRECT_JUMP: Qt.SolidLine,
    EdgeSort.EXCEPTION_EDGE: Qt.DashLine
}


class QGraphArrow(QGraphicsItem):

    def __init__(self, edge, disasm_view, infodock, parent=None):
        super().__init__(parent)

        self.edge = edge
        self.disasm_view = disasm_view
        self.infodock = infodock
        self.rect = None
        self._start = QPointF(*self.edge.coordinates[0])
        self.coords = [self.create_point(c) for c in self.edge.coordinates]
        self.end = self.coords[-1]

        self.color = EDGE_COLORS.get(self.edge.sort, EDGE_COLORS[EdgeSort.DIRECT_JUMP])
        self.arrow = [QPointF(self.end.x() - 3, self.end.y()), QPointF(self.end.x() + 3, self.end.y()),
                 QPointF(self.end.x(), self.end.y() + 6)]
        self.style = EDGE_STYLES.get(self.edge.sort, EDGE_STYLES[EdgeSort.DIRECT_JUMP])
        #self.setCacheMode(QGraphicsItem.DeviceCoordinateCache)
        path = QPainterPath(self.coords[0])
        for c in self.coords[1:] + self.arrow:
            path.lineTo(c)
        self.path = path

        self._hovered = False

        self.setAcceptHoverEvents(True)

    def create_point(self, stuff):
        return QPointF(*stuff) - self._start

    def paint(self, painter, option, widget):
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        should_highlight = self.infodock.is_edge_hovered(self.edge.src.addr, self.edge.dst.addr) or \
                self.infodock.is_block_hovered(self.edge.src.addr) or \
                self.infodock.is_block_hovered(self.edge.dst.addr)

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
        self.infodock.hover_edge(self.edge.src.addr, self.edge.dst.addr)

    def hoverLeaveEvent(self, event):
        self.infodock.unhover_edge(self.edge.src.addr, self.edge.dst.addr)

    def mouseDoubleClickEvent(self, event):
        if QApplication.keyboardModifiers() == Qt.ShiftModifier:
            # go to the source
            self.disasm_view.jump_to(self.edge.src.addr, src_ins_addr=self.edge.dst.addr)
            event.accept()
        else:
            # go to the destination
            self.disasm_view.jump_to(self.edge.dst.addr, src_ins_addr=self.edge.src.addr)
            event.accept()
        super().mouseDoubleClickEvent(event)
