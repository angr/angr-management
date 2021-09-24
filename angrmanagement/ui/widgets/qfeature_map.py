from typing import Optional, Sequence, Mapping
import logging
from sortedcontainers import SortedDict

from PySide2.QtWidgets import QWidget, QHBoxLayout, QGraphicsScene, QGraphicsView, QGraphicsItem, QGraphicsRectItem, \
    QGraphicsPolygonItem, QGraphicsLineItem
from PySide2.QtGui import QBrush, QPen, QPolygonF
from PySide2.QtCore import Qt, QRectF, QSize, QPointF, QPoint, QEvent

import cle
from angr.block import Block
from angr.analyses.cfg.cfb import Unknown, MemoryRegion

from ...config import Conf
from ...data.object_container import ObjectContainer


l = logging.getLogger(name=__name__)


class FeatureMapItem(QGraphicsItem):
    """
    Feature map item to be rendered in graphics scene.

    The feature map will be rendered horizontally, with addresses increasing from left to right.
    """

    def __init__(self, disasm_view, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._width: int = 1
        self._height: int = 1

        self.disasm_view = disasm_view
        self.workspace = disasm_view.workspace
        self.instance = self.workspace.instance

        self.addr = ObjectContainer(None, name='The current address of the Feature Map.')

        self._map_items: Sequence[QGraphicsItem] = []
        self._map_indicator_items: Sequence[QGraphicsItem] = []
        self._addr_to_region: Mapping[int, MemoryRegion] = SortedDict()
        self._regionaddr_to_offset: Mapping[int, int] = SortedDict()
        self._offset_to_regionaddr: Mapping[int, int] = SortedDict()
        self._total_size: int = 0
        self._pressed: bool = False

        self._register_events()
        self.refresh()

    def refresh(self):
        self._generate_map_items()
        self._generate_indicators()

    def _register_events(self):
        self.instance.cfb.am_subscribe(self._generate_map_items)
        self.disasm_view.infodock.selected_insns.am_subscribe(self._generate_indicators)
        self.disasm_view.infodock.selected_labels.am_subscribe(self._generate_indicators)

    @property
    def width(self) -> int:
        return self._width

    def set_width(self, width: int):
        """
        Set the desired width of the feature map in scene units.
        """
        self.prepareGeometryChange()
        self._width = width

    @property
    def height(self) -> int:
        return self._height

    def set_height(self, height: int):
        """
        Set the desired height of the feature map in scene units.
        """
        self.prepareGeometryChange()
        self._height = height

    def paint(self, painter, option, widget):
        """
        Paint the feature map.
        """
        # Handled by subitems

    def boundingRect(self) -> QRectF:
        """
        Return the bounding dimensions of this item.
        """
        return QRectF(0, 0, self._width, self._height)

    def _generate_map_items(self, **kwargs):  # pylint: disable=unused-argument
        """
        Generate the feature map items (memory region blocks, separating lines, etc).
        """
        cfb = self.instance.cfb.am_obj
        if cfb is None:
            return

        for item in self._map_items:
            self.scene().removeItem(item)
        self._map_items.clear()

        func_color = Conf.feature_map_color_regular_function
        data_color = Conf.feature_map_color_data
        unknown_color = Conf.feature_map_color_unknown
        delimiter_color = Conf.feature_map_color_delimiter

        self._total_size = 0
        self._addr_to_region.clear()
        self._regionaddr_to_offset.clear()
        for mr in cfb.regions:
            self._addr_to_region[mr.addr] = mr
            self._regionaddr_to_offset[mr.addr] = self._total_size
            self._offset_to_regionaddr[self._total_size] = mr.addr
            self._total_size += self._adjust_region_size(mr)

        offset = 0
        current_region = None
        for addr, obj in cfb.ceiling_items():
            if obj.size is None:
                continue

            # are we in a new region?
            new_region = False
            if current_region is None or not current_region.addr <= addr < current_region.addr + current_region.size:
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

            pos = offset * self._width // self._total_size
            length = adjusted_size * self._width // self._total_size
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

            pen.setWidth(0)
            item = QGraphicsRectItem(QRectF(pos, 0, length, self._height), parent=self)
            item.setPen(pen)
            item.setBrush(brush)
            self._map_items.append(item)

            # if at the beginning of a new region, draw a line
            if new_region:
                pen = QPen(delimiter_color)
                pw = pen.width()
                item = QGraphicsLineItem(pos, pw/2, pos, self._height - pw/2, parent=self)
                item.setPen(pen)
                self._map_items.append(item)

        self.update()

    def _generate_indicators(self, **kwargs):  # pylint: disable=unused-argument
        """
        Paint arrow indicators of selected instructions and labels.
        """
        scene = self.scene()
        for item in self._map_indicator_items:
            scene.removeItem(item)
        self._map_indicator_items.clear()

        for addr in list(self.disasm_view.infodock.selected_insns) + list(self.disasm_view.infodock.selected_labels):
            pos = self._get_pos_from_addr(addr)
            if pos is None:
                continue

            pos -= 1  # this is the top-left x coordinate of our arrow body (the rectangle)

            pen = QPen(Qt.yellow)
            brush = QBrush(Qt.yellow)
            item = QGraphicsRectItem(QRectF(pos, 0, 2, 5), parent=self)
            item.setPen(pen)
            item.setBrush(brush)
            self._map_indicator_items.append(item)

            triangle = QPolygonF()
            triangle.append(QPointF(pos - 1, 5))
            triangle.append(QPointF(pos + 3, 5))
            triangle.append(QPointF(pos + 1, 7))
            triangle.append(QPointF(pos - 1, 5))
            item = QGraphicsPolygonItem(triangle, parent=self)
            item.setPen(pen)
            item.setBrush(brush)
            self._map_indicator_items.append(item)

        self.update()

    @staticmethod
    def _adjust_region_size(memory_region):
        if isinstance(memory_region.object, (cle.ExternObject, cle.TLSObject, cle.KernelObject)):
            return 80 # Draw unnecessary objects smaller
        else:
            l.debug("memory_region.size: %x memory_region.object: %s", memory_region.size, memory_region.object)
            return memory_region.size

    def _get_pos_from_addr(self, addr: int) -> Optional[int]:
        """
        Get scene X coordinate from address, or None if it could not be mapped.
        """
        try:
            mr_base = next(self._addr_to_region.irange(maximum=addr, reverse=True))
        except StopIteration:
            return None

        base_offset = self._regionaddr_to_offset[mr_base]
        offset = base_offset + addr - mr_base
        return offset * self._width // self._total_size

    def _get_addr_from_pos(self, pos: int) -> Optional[int]:
        """
        Get address from scene X coordinate, or None if it could not be mapped.
        """
        offset = int(pos * self._total_size // self._width)

        try:
            base_offset = next(self._offset_to_regionaddr.irange(maximum=offset, reverse=True))
        except StopIteration:
            return None

        region_addr = self._offset_to_regionaddr[base_offset]
        return region_addr + offset - base_offset

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            pos = event.pos()
            offset = pos.x()
            self.select_offset(offset)
            self._pressed = True

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._pressed = False

    def mouseMoveEvent(self, event):
        if self._pressed:
            pos = event.pos()
            offset = pos.x()
            self.select_offset(offset)

    def select_offset(self, offset):
        addr = self._get_addr_from_pos(offset)
        if addr is None:
            return
        self.addr.am_obj = addr
        self.addr.am_event()


class QFeatureMapView(QGraphicsView):
    """
    Main view for feature map scene.
    """

    def __init__(self, disasm_view, parent=None):
        super().__init__(parent)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scene = QGraphicsScene(parent=self)
        self.setScene(self._scene)
        self.fm: FeatureMapItem = FeatureMapItem(disasm_view)
        self._scale: float = 1.0
        self._scene.addItem(self.fm)

        self.setBackgroundBrush(Conf.palette_base)
        self.setResizeAnchor(QGraphicsView.NoAnchor)
        self.setTransformationAnchor(QGraphicsView.NoAnchor)
        self.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.update_size()

        self._base_width: int = 0

    def wheelEvent(self, event):
        """
        Handle wheel events to scale and translate the feature map.
        """
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            self.adjust_viewport_scale(1.25 if event.delta() > 0 else 1/1.25,
                                       QPoint(event.pos().x(), event.pos().y()))
        else:
            self.translate(100 * (-1 if event.delta() < 0 else 1), 0)
            super().wheelEvent(event)

    def resizeEvent(self, event):  # pylint: disable=unused-argument
        self.update_size()

    def adjust_viewport_scale(self, scale: Optional[float] = None, point: Optional[QPoint] = None):
        """
        Adjust viewport scale factor.
        """
        if point is None:
            point = QPoint(0, 0)
        point_rel = self.mapToScene(point).x() / self.fm.width

        if scale is None:
            self._scale = 1.0
        else:
            self._scale *= scale
            if self._scale < 1.0:
                self._scale = 1.0

        self.update_size()
        self.translate(self.mapToScene(point).x() - point_rel * self.fm.width, 0)

    def keyPressEvent(self, event):
        """
        Handle key events.
        """
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            if event.key() == Qt.Key_0:
                self.adjust_viewport_scale()
                event.accept()
                return
            elif event.key() == Qt.Key_Equal:
                self.adjust_viewport_scale(1.25)
                event.accept()
                return
            elif event.key() == Qt.Key_Minus:
                self.adjust_viewport_scale(1/1.25)
                event.accept()
                return
        super().keyPressEvent(event)

    def changeEvent(self, event: QEvent):
        """
        Redraw on color scheme update.
        """
        if event.type() == QEvent.StyleChange:
            self.setBackgroundBrush(Conf.palette_base)
            self.fm.refresh()

    def update_size(self):
        """
        Resize feature map.
        """
        vg = self.viewport().geometry()
        if self._scale <= 1.0:
            # Only resize to feature map to viewport width if scale is at base level to not disturb preferred size
            self._base_width = vg.width()
        self.fm.set_width(self._base_width * self._scale)
        self.fm.set_height(vg.height())
        self.fm.refresh()
        self.setSceneRect(self._scene.itemsBoundingRect())


class QFeatureMap(QWidget):
    """
    Byte-level map of the memory space.
    """

    def __init__(self, disasm_view, parent=None):
        super().__init__(parent)
        self.disasm_view = disasm_view
        self.view: QFeatureMapView = None
        self.addr = None
        self._init_widgets()

    @staticmethod
    def sizeHint():
        return QSize(25, 25)

    #
    # Public methods
    #

    def refresh(self):
        if self.view is not None:
            self.view.fm.refresh()

    #
    # Private methods
    #

    def _init_widgets(self):
        self.view = QFeatureMapView(self.disasm_view, self)
        layout = QHBoxLayout()
        layout.addWidget(self.view)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
        self.addr = self.view.fm.addr
