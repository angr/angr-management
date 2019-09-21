
from sortedcontainers import SortedDict

from PySide2.QtWidgets import QWidget, QHBoxLayout, QGraphicsScene, QSizePolicy
from PySide2.QtGui import QPaintEvent, QPainter, QBrush, QPen, QPolygonF
from PySide2.QtCore import Qt, QRectF, QSize, QPointF

from angr.block import Block
from angr.analyses.cfg.cfb import Unknown

from ...config import Conf
from .qgraph import QZoomableDraggableGraphicsView


class Orientation:
    Vertical = 0
    Horizontal = 1


class QFeatureMapView(QZoomableDraggableGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._scene = QGraphicsScene()
        self.setScene(self._scene)


class QFeatureMap(QWidget):
    """
    Byte-level map of the memory space.
    """
    def __init__(self, disasm_view, parent=None):
        super().__init__(parent)

        self.disasm_view = disasm_view
        self.workspace = disasm_view.workspace
        self.instance = self.workspace.instance

        self.orientation = Orientation.Vertical

        # widgets
        self.view = None  # type: QFeatureMapView

        # items
        self._insn_indicators = [ ]

        # cached values
        self._addr_to_region = SortedDict()
        self._regionaddr_to_offset = SortedDict()
        self._total_size = None
        self._regions_painted = False

        self._init_widgets()
        self._register_events()

    def sizeHint(self):
        return QSize(25, 25)

    #
    # Public methods
    #

    def refresh(self):

        if self.view is None:
            return

        if not self._regions_painted:
            self._regions_painted = True
            self._paint_regions()

    #
    # Private methods
    #

    def _init_widgets(self):
        self.view = QFeatureMapView(self)

        layout = QHBoxLayout()
        layout.addWidget(self.view)

        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _register_events(self):
        self.disasm_view.infodock.selected_insns.am_subscribe(self._paint_insn_indicators)

    def _paint_regions(self):

        cfb = self.instance.cfb_container.am_obj

        if cfb is None:
            return

        # colors
        func_color = Conf.feature_map_color_regular_function
        data_color = Conf.feature_map_color_data
        unknown_color = Conf.feature_map_color_unknown

        if self._total_size is None:
            # calculate the total number of bytes
            b = 0
            self._addr_to_region.clear()
            self._regionaddr_to_offset.clear()
            for mr in cfb.regions:
                self._addr_to_region[mr.addr] = mr
                self._regionaddr_to_offset[mr.addr] = b
                b += mr.size
            self._total_size = b

        # iterate through all items and draw the image
        offset = 0
        total_width = self.width()
        for _, obj in cfb.ceiling_items():
            pos = offset * total_width // self._total_size
            length = obj.size * total_width // self._total_size
            offset += obj.size

            # draw a rectangle
            if isinstance(obj, Unknown):
                pen = QPen(data_color)
                brush = QBrush(data_color)
            elif isinstance(obj, Block):
                # TODO: Check if it belongs to a function or not
                pen = QPen(func_color)
                brush = QBrush(func_color)
            else:
                pen = QPen(unknown_color)
                brush = QBrush(unknown_color)
            rect = QRectF(pos, 0, length, self.height())
            self.view._scene.addRect(rect, pen, brush)

    def _get_pos_from_addr(self, addr):

        # find the region it belongs to
        try:
            mr_base = next(self._addr_to_region.irange(maximum=addr, reverse=True))
        except StopIteration:
            return None

        # get the base offset of that region
        base_offset = self._regionaddr_to_offset[mr_base]

        offset = base_offset + addr - mr_base
        return offset * self.width() // self._total_size

    def _paint_insn_indicators(self):

        scene = self.view.scene()  # type: QGraphicsScene
        for item in self._insn_indicators:
            scene.removeItem(item)
        self._insn_indicators.clear()

        for selected_insn_addr in self.disasm_view.infodock.selected_insns:
            pos = self._get_pos_from_addr(selected_insn_addr)
            if pos is None:
                continue
            pen = QPen(Qt.yellow)
            brush = QBrush(Qt.yellow)
            rect = QRectF(pos, 0, 2, 5)
            # rectangle
            item = scene.addRect(rect, pen, brush)
            self._insn_indicators.append(item)
            # triangle
            triangle = QPolygonF()
            triangle.append(QPointF(pos - 1, 5))
            triangle.append(QPointF(pos + 3, 5))
            triangle.append(QPointF(pos + 1, 7))
            triangle.append(QPointF(pos - 1, 5))
            item = scene.addPolygon(triangle, pen, brush)
            self._insn_indicators.append(item)
