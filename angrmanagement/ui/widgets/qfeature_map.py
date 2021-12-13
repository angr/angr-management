from typing import Optional, Sequence, Mapping
import logging
from sortedcontainers import SortedDict

from PySide2.QtWidgets import QWidget, QHBoxLayout, QGraphicsScene, QGraphicsView, QGraphicsItem, QGraphicsRectItem, \
    QGraphicsPolygonItem, QGraphicsLineItem
from PySide2.QtGui import QBrush, QPen, QPolygonF
from PySide2.QtCore import Qt, QRectF, QSize, QPointF, QPoint, QEvent, QMarginsF

import cle
from angr.block import Block
from angr.analyses.cfg.cfb import MemoryRegion
from angr.knowledge_plugins.cfg import MemoryData

from ...config import Conf
from ...data.object_container import ObjectContainer


l = logging.getLogger(name=__name__)


class FeatureMapItem(QGraphicsItem):
    """
    Feature map item to be rendered in graphics scene.

    The feature map will be rendered horizontally, with addresses increasing from left to right.
    """
    ZVALUE_SEPARATOR = 1
    ZVALUE_HOVER     = 2
    ZVALUE_INDICATOR = 3

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
        self._map_hover_region_item: Optional[QGraphicsItem] = None
        self._map_hover_region: Optional[MemoryRegion] = None
        self._addr_to_region: Mapping[int, MemoryRegion] = SortedDict()
        self._regionaddr_to_offset: Mapping[int, int] = SortedDict()
        self._offset_to_regionaddr: Mapping[int, int] = SortedDict()
        self._total_size: int = 0
        self._pressed: bool = False

        self.setAcceptHoverEvents(True)
        self._register_events()
        self.refresh()

    def refresh(self):
        # temporarily disable the auto-refresh of QFeatureMap until we have a more performant solution
        return
        self._generate_map_items()
        self._generate_hover_region()
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
        # Drawn by child items

    def boundingRect(self) -> QRectF:
        """
        Return the bounding dimensions of this item.
        """
        return QRectF(0, 0, self._width, self._height)

    def _calculate_memory_region_offsets(self):
        """
        Calculate all memory region offsets and lengths.
        """
        self._total_size = 0
        self._addr_to_region.clear()
        self._regionaddr_to_offset.clear()

        if self.instance.cfb.am_none:
            return

        for mr in self.instance.cfb.regions:
            self._addr_to_region[mr.addr] = mr
            self._regionaddr_to_offset[mr.addr] = self._total_size
            self._offset_to_regionaddr[self._total_size] = mr.addr
            self._total_size += self._get_adjusted_region_size(mr)

    @staticmethod
    def _get_adjusted_region_size(mr: MemoryRegion):
        if isinstance(mr.object, (cle.ExternObject, cle.TLSObject, cle.KernelObject)):
            return 80 # Draw unnecessary objects smaller
        else:
            l.debug("memory_region.size: %x memory_region.object: %s", mr.size, mr.object)
            return mr.size

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

    def _get_region_from_point(self, point: QPoint) -> Optional[MemoryRegion]:
        """
        Get the memory region from X coordinate, or None if it could not be mapped.
        """
        offset = int(point.x() * self._total_size // self._width)
        try:
            base_offset = next(self._offset_to_regionaddr.irange(maximum=offset, reverse=True))
        except StopIteration:
            return None

        return self._addr_to_region[self._offset_to_regionaddr[base_offset]]

    def _get_offset_size_rect(self, offset: int, size: int) -> QRectF:
        """
        Given a byte offset `offset` and number of bytes `size`, get a rect to draw.
        """
        x = offset / self._total_size * self._width
        width = size / self._total_size * self._width
        return QRectF(x, 0, width, self._height)

    def _get_region_rect(self, mr: MemoryRegion) -> QRectF:
        """
        Get the rect to draw this memory region.
        """
        return self._get_offset_size_rect(self._regionaddr_to_offset[mr.addr], self._get_adjusted_region_size(mr))

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
        self._calculate_memory_region_offsets()

        func_color = Conf.feature_map_color_regular_function
        data_color = Conf.feature_map_color_data
        unknown_color = Conf.feature_map_color_unknown
        delimiter_color = Conf.feature_map_color_delimiter
        offset = 0
        current_region = None

        for addr, obj in cfb.ceiling_items():
            if obj.size is None:
                continue

            # Are we in a new region?
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

            if new_region:
                r = self._get_region_rect(current_region)
                pos = r.topLeft().x()
                pen = QPen(delimiter_color)
                hpw = pen.width() / 2
                item = QGraphicsLineItem(pos, hpw, pos, self._height - hpw, parent=self)
                item.setPen(pen)
                item.setZValue(self.ZVALUE_SEPARATOR)
                self._map_items.append(item)

            # Clip item to possibly truncated region size
            adjusted_region_size = self._get_adjusted_region_size(current_region)
            adjusted_size = min(obj.size, current_region.addr + adjusted_region_size - addr)
            if adjusted_size <= 0:
                # Item falls outside truncated region. Drop the item.
                continue

            r = self._get_offset_size_rect(offset, adjusted_size)
            offset += adjusted_size

            if isinstance(obj, MemoryData):
                brush = QBrush(data_color)
            elif isinstance(obj, Block):
                # TODO: Check if it belongs to a function or not
                brush = QBrush(func_color)
            else:
                brush = QBrush(unknown_color)

            item = QGraphicsRectItem(r, parent=self)
            item.setPen(Qt.NoPen)
            item.setBrush(brush)
            self._map_items.append(item)

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
            item = QGraphicsRectItem(QRectF(pos, 0, 2, 10), parent=self)
            item.setPen(pen)
            item.setBrush(brush)
            item.setZValue(self.ZVALUE_INDICATOR)
            self._map_indicator_items.append(item)

            triangle = QPolygonF()
            triangle.append(QPointF(pos - 1, 10))
            triangle.append(QPointF(pos + 3, 10))
            triangle.append(QPointF(pos + 1, 12))
            triangle.append(QPointF(pos - 1, 10))
            item = QGraphicsPolygonItem(triangle, parent=self)
            item.setPen(pen)
            item.setBrush(brush)
            item.setZValue(self.ZVALUE_INDICATOR)
            self._map_indicator_items.append(item)

    def _generate_hover_region(self):
        """
        Paint the memory region indicator.
        """
        if self._map_hover_region_item:
            self.scene().removeItem(self._map_hover_region_item)
            self._map_hover_region_item = None

        mr = self._map_hover_region
        if mr is None:
            return

        pw = 1.0
        hpw = pw / 2
        pen = QPen(Qt.red)
        pen.setWidth(pw)
        r = self._get_region_rect(mr)
        r = r.marginsRemoved(QMarginsF(hpw, hpw, hpw, hpw))
        item = QGraphicsRectItem(r, parent=self)
        item.setPen(pen)
        item.setZValue(self.ZVALUE_HOVER)
        self._map_hover_region_item = item

    def _remove_hover_region(self):
        """
        Remove active hover region, if set.
        """
        if self._map_hover_region_item is not None:
            self._map_hover_region = None
            self._generate_hover_region()
            self.setToolTip('')

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
        else:
            super().mouseMoveEvent(event)

    def on_mouse_move_event_from_view(self, point: QPointF):
        """
        Highlight memory region under cursor.
        """
        self.setToolTip('')
        mr = self._get_region_from_point(point)
        if mr is None:
            self._remove_hover_region()
            return

        try:
            addr = self._get_addr_from_pos(point.x())
            item = self.workspace.instance.cfb.floor_item(addr)
            if item is not None:
                _, item = item
                self.setToolTip(f'{str(item)} in {str(mr)}')
        except KeyError:
            pass

        if mr is self._map_hover_region:
            return

        self._remove_hover_region()
        self._map_hover_region = mr
        self._generate_hover_region()

    def hoverLeaveEvent(self, event):  # pylint: disable=unused-argument
        self._remove_hover_region()

    def select_offset(self, offset):
        """
        Update listeners with new desired location.
        """
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
        self.setMouseTracking(True)
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

    def mouseMoveEvent(self, event):
        """
        Handle mouse move events.

        Mouse move events whilst not holding a mouse button will not be propagated down to QGraphicsItems, so we catch
        the movement events here in the view and forward them to the feature map item.
        """
        scene_pt = self.mapToScene(event.pos().x(), event.pos().y())
        item_pt = self.fm.mapFromScene(scene_pt)
        self.fm.on_mouse_move_event_from_view(item_pt)
        super().mouseMoveEvent(event)

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
        """
        Handle view resize events, updating the feature map size accordingly.
        """
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
