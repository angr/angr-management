
from sortedcontainers import SortedDict

from PySide2.QtWidgets import QWidget, QHBoxLayout, QGraphicsScene, QSizePolicy, QGraphicsSceneMouseEvent
from PySide2.QtGui import QPaintEvent, QPainter, QBrush, QPen, QPolygonF
from PySide2.QtCore import Qt, QRectF, QSize, QPointF

import cle
from angr.block import Block
from angr.analyses.cfg.cfb import Unknown

from ...config import Conf
from ...data.object_container import ObjectContainer
from .qgraph import QZoomableDraggableGraphicsView

import logging
l = logging.getLogger(name=__name__)

class Orientation:
    Vertical = 0
    Horizontal = 1


class QClickableGraphicsScene(QGraphicsScene):

    def __init__(self, feature_map):
        """

        :param QFeatureMap feature_map:
        """
        super().__init__()

        self._feature_map = feature_map

    def mousePressEvent(self, mouseEvent):
        """

        :param QGraphicsSceneMouseEvent mouseEvent:
        :return:
        """

        if mouseEvent.button() == Qt.LeftButton:
            pos = mouseEvent.scenePos()
            offset = pos.x()
            self._feature_map.select_offset(offset)


class QFeatureMapView(QZoomableDraggableGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._scene = QClickableGraphicsScene(parent)
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

        # data instance
        self.addr = ObjectContainer(None, name='The current address of the Feature Map.')

        # cached values
        self._addr_to_region = SortedDict()
        self._regionaddr_to_offset = SortedDict()
        self._offset_to_regionaddr = SortedDict()
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
            self._regions_painted = self._paint_regions()

    def select_offset(self, offset):

        addr = self._get_addr_from_pos(offset)
        if addr is None:
            return
        self.addr.am_obj = addr
        self.addr.am_event()

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
            return False

        # colors
        func_color = Conf.feature_map_color_regular_function
        data_color = Conf.feature_map_color_data
        unknown_color = Conf.feature_map_color_unknown
        delimiter_color = Conf.feature_map_color_delimiter
        if self._total_size is None:
            # calculate the total number of bytes
            b = 0
            self._addr_to_region.clear()
            self._regionaddr_to_offset.clear()
            for mr in cfb.regions:
                self._addr_to_region[mr.addr] = mr
                self._regionaddr_to_offset[mr.addr] = b
                self._offset_to_regionaddr[b] = mr.addr
                b += self._adjust_region_size(mr)
            self._total_size = b

        # iterate through all items and draw the image
        offset = 0
        total_width = self.width()
        current_region = None
        height = self.height()
        l.debug("total width %d", total_width)
        for addr, obj in cfb.ceiling_items():

            # are we in a new region?
            new_region = False
            if current_region is None or not (current_region.addr <= addr < current_region.addr + current_region.size):
                try:
                    current_region_addr = next(self._addr_to_region.irange(maximum=addr, reverse=True))
                except StopIteration:
                    # FIXME: it's not within any of the known regions
                    # we should fix this in the future. for now, let's make sure it does not crash
                    continue
                current_region = self._addr_to_region[current_region_addr]
                new_region = True

            # adjust size
            adjusted_region_size = self._adjust_region_size(current_region)
            adjusted_size = min(obj.size, current_region.addr + adjusted_region_size - addr)
            if adjusted_size <= 0:
                continue

            pos = offset * total_width // self._total_size
            length = adjusted_size * total_width // self._total_size
            offset += adjusted_size

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
            rect = QRectF(pos, 0, length, height)
            self.view._scene.addRect(rect, pen, brush)

            # if at the beginning of a new region, draw a line
            if new_region:
                pen = QPen(delimiter_color)
                self.view._scene.addLine(pos, 0, pos, height, pen)

        return True

    def _adjust_region_size(self, memory_region):

        if isinstance(memory_region.object, (cle.ExternObject, cle.TLSObject, cle.KernelObject)):
            # Draw unnecessary objects smaller
            return 80
        else:
            l.debug("memory_region.size: %x memory_region.object: %s", memory_region.size, memory_region.object)
            return memory_region.size

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

    def _get_addr_from_pos(self, pos):

        offset = int(pos * self._total_size // self.width())

        try:
            base_offset = next(self._offset_to_regionaddr.irange(maximum=offset, reverse=True))
        except StopIteration:
            return None

        region_addr = self._offset_to_regionaddr[base_offset]
        return region_addr + offset - base_offset

    def _paint_insn_indicators(self, **kwargs):

        scene = self.view.scene()  # type: QGraphicsScene
        for item in self._insn_indicators:
            scene.removeItem(item)
        self._insn_indicators.clear()

        for selected_insn_addr in self.disasm_view.infodock.selected_insns:
            pos = self._get_pos_from_addr(selected_insn_addr)
            if pos is None:
                continue

            pos -= 1  # this is the top-left x coordinate of our arrow body (the rectangle)

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
