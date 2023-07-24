import logging
import time
from threading import Lock
from typing import TYPE_CHECKING, List, Mapping, Optional

import cle
from angr.block import Block
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort
from PySide6.QtCore import QEvent, QMarginsF, QPoint, QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QPen, QPolygonF
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsPolygonItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QWidget,
)
from sortedcontainers import SortedDict

from angrmanagement.config import Conf
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.data.tagged_interval_map import TaggedIntervalMap
from angrmanagement.logic.threads import gui_thread_schedule_async

if TYPE_CHECKING:
    from angr.analyses.cfg.cfb import MemoryRegion


log = logging.getLogger(name=__name__)


def _get_tags_for_item(item) -> Optional[int]:
    """
    Generate bit mask based for the type of item provided, or None if it could not be mapped.
    """
    if isinstance(item, Block):
        b = 0
    elif isinstance(item, MemoryData):
        b = {
            MemoryDataSort.String: 2,
            MemoryDataSort.UnicodeString: 2,
        }.get(item.sort, 1)
    else:
        return None
    return 1 << b


def _get_feature_tag_colors() -> List[QColor]:
    """
    Generate list of colors corresponding to each tag bit.
    """
    return [
        Conf.feature_map_regular_function_color,
        Conf.feature_map_data_color,
        Conf.feature_map_string_color,
    ]


class FeatureMapPalette:
    """
    Generates QBrushes based on feature tag bit mask.
    """

    def __init__(self):
        self._feature_colors = _get_feature_tag_colors()
        self._brush_cache = {}

    def __getitem__(self, tags):
        return self._get_brush_for_tags_cached(tags)

    def _get_brush_for_tags_cached(self, tags: int) -> QBrush:
        brush = self._brush_cache.get(tags, None)
        if brush is None:
            brush = self._get_brush_for_tags(tags)
        return brush

    def _get_brush_for_tags(self, tags: int) -> QBrush:
        return QBrush(self._blend_colors(self._get_colors_for_tags(tags)))

    def _get_colors_for_tags(self, tags: int) -> List[QColor]:
        return [self._feature_colors[i] for i in range(len(self._feature_colors)) if tags & (1 << i)]

    @staticmethod
    def _blend_colors(colors):
        nc = len(colors)
        return QColor(
            round(sum(c.red() for c in colors) / nc),
            round(sum(c.green() for c in colors) / nc),
            round(sum(c.blue() for c in colors) / nc),
            255,
        )


class FeatureMapItem(QGraphicsItem):
    """
    Feature map item to be rendered in graphics scene.

    The feature map will be rendered horizontally, with addresses increasing from left to right.
    """

    ZVALUE_HOVER = 1
    ZVALUE_CURSOR = 2

    def __init__(self, instance, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance = instance

        self.setFlag(QGraphicsItem.ItemUsesExtendedStyleOption, True)  # Give me more specific paint update rect info
        self.setFlag(QGraphicsItem.ItemClipsToShape, True)
        self.setAcceptHoverEvents(True)

        self.addr = ObjectContainer(None, name="The current address of the Feature Map.")

        self._width: int = 1
        self._height: int = 1
        self._pressed: bool = False

        self._last_refresh_timestamp: float = 0
        self._refresh_pending: bool = False
        self._min_cfb_time_between_refresh: float = 1 / 30

        self._addr_to_region: SortedDict = SortedDict()  # SortedDict[int, "MemoryRegion"]
        self._region_to_position: Mapping[MemoryRegion, float] = {}
        self._region_to_width: Mapping[MemoryRegion, float] = {}
        self._position_to_region: SortedDict = SortedDict()  # SortedDict[int, "MemoryRegion"]

        self._cursor_addrs: List[int] = []
        self._cursor_items: List[QGraphicsItem] = []
        self._hover_region: Optional[MemoryRegion] = None
        self._hover_region_item: Optional[QGraphicsItem] = None

        self._feature_palette: FeatureMapPalette
        self._refresh_palette()

        self._nbits_per_lod: List[int] = [13, 12, 8, 6, 4, 0]
        self._cfb_feature_maps: List[TaggedIntervalMap]
        self._cfb_feature_maps_lock: Lock = Lock()
        self._clear_cfb_feature_maps()

        self._register_events()
        self.reload()

    def _register_events(self):
        self.instance.cfb.am_subscribe(self._on_cfb_event)

    def reload(self):
        self._clear_hover_region()
        with self._cfb_feature_maps_lock:
            self._build_cfb_feature_maps()
        self.refresh()

    def set_cursor_addrs(self, cursor_addrs):
        self._cursor_addrs = cursor_addrs
        self._create_cursor_items()
        self.update()

    def refresh(self):
        self._layout_regions()
        self._create_hover_item()
        self._create_cursor_items()
        self.update()

        self._last_refresh_timestamp = time.time()
        self._refresh_pending = False

    def _refresh_palette(self):
        self._feature_palette = FeatureMapPalette()

    @property
    def width(self) -> int:
        return self._width

    @width.setter
    def width(self, value: int):
        self.prepareGeometryChange()
        self._width = value

    @property
    def height(self) -> int:
        return self._height

    @height.setter
    def height(self, value: int):
        self.prepareGeometryChange()
        self._height = value

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, self._width, self._height)

    def _on_cfb_event(self, **kwargs):
        if "object_added" in kwargs:  # Called by task thread
            addr, item = kwargs["object_added"]
            tags = _get_tags_for_item(item)
            if tags is None or item.size is None:
                return
            with self._cfb_feature_maps_lock:
                for fm in self._cfb_feature_maps:
                    fm.add(addr, item.size, tags)

            if (
                not self._refresh_pending
                and time.time() - self._last_refresh_timestamp > self._min_cfb_time_between_refresh
            ):
                self._refresh_pending = True
                gui_thread_schedule_async(self.refresh)
        elif not kwargs:
            self.reload()

    def _clear_cfb_feature_maps(self):
        self._cfb_feature_maps = [TaggedIntervalMap(nbits) for nbits in self._nbits_per_lod]

    def _build_cfb_feature_maps(self):
        if self.instance.cfb.am_none:
            return

        self._clear_cfb_feature_maps()

        num_items = 0
        time_start = time.time()
        for addr, item in self.instance.cfb._blanket.items():  # FIXME: Don't access protected member of CFB
            if not item.size:
                continue
            tags = _get_tags_for_item(item)
            if tags is None:
                continue
            self._cfb_feature_maps[-1].add(addr, item.size, tags)
            num_items += 1
        time_end = time.time()
        log.debug(
            "Reduced %d items in CFB to %d in %.4f s",
            num_items,
            len(self._cfb_feature_maps[-1]._map),
            time_end - time_start,
        )

        for i in range(len(self._cfb_feature_maps) - 2, -1, -1):
            time_start = time.time()
            fm_in = self._cfb_feature_maps[i + 1]
            fm_out = self._cfb_feature_maps[i]
            for addr, size, tags in fm_in.irange():
                if tags != 0:
                    fm_out.add(addr, size, tags)
            time_end = time.time()
            log.debug(
                "%d bit fm: Reduced %d items to %d in %.4f s",
                fm_out.nbits,
                len(fm_in._map),
                len(fm_out._map),
                time_end - time_start,
            )

    def _find_first_overlapping_region(self, mr: "MemoryRegion") -> Optional["MemoryRegion"]:
        """
        Find the first region in self._addr_to_region that `mr` overlaps, if any.
        """
        start_idx = max(0, self._addr_to_region.bisect_left(mr.addr) - 1)
        for e_addr in self._addr_to_region.islice(start_idx):
            e_mr = self._addr_to_region[e_addr]
            if (e_mr.addr + e_mr.size) <= mr.addr:
                continue
            if e_mr.addr < (mr.addr + mr.size):
                return e_mr
        return None

    def _layout_regions(self):
        """
        Calculate displayed memory region positions and sizes.
        """
        self._addr_to_region.clear()
        self._position_to_region.clear()
        self._region_to_position.clear()
        self._region_to_width.clear()

        if self.instance.cfb.am_none:
            return

        # Add regions from largest to smallest
        for new_mr in sorted(self.instance.cfb.regions, key=lambda mr: mr.size, reverse=True):
            mr = self._find_first_overlapping_region(new_mr)
            if mr is not None:
                log.debug("Skipping CFB region %s, which overlaps %s", new_mr, mr)
                continue
            self._addr_to_region[new_mr.addr] = new_mr

        # Determine total displayed byte count
        rem_bytes = 0
        region_to_size = {}
        for mr in self._addr_to_region.values():
            size = mr.size if self._should_show_region_to_scale(mr) else 80
            region_to_size[mr] = size
            rem_bytes += size

        # Determine region widths in scene units
        rem_width = self.width
        for mr in self._addr_to_region.values():
            width = max(round(region_to_size[mr] * rem_width / rem_bytes), 1)
            self._region_to_width[mr] = width
            rem_bytes -= region_to_size[mr]
            rem_width -= width

        # Determine region position in scene units
        position = 0
        for mr in self._addr_to_region.values():
            self._region_to_position[mr] = position
            self._position_to_region[position] = mr
            position += self._region_to_width[mr]

    @staticmethod
    def _should_show_region_to_scale(mr: "MemoryRegion"):
        return not isinstance(mr.object, (cle.ExternObject, cle.TLSObject, cle.KernelObject))

    def _get_region_at_addr(self, addr: int) -> Optional["MemoryRegion"]:
        start_idx = max(0, self._addr_to_region.bisect_left(addr) - 1)
        for mr_addr in self._addr_to_region.islice(start_idx):
            mr = self._addr_to_region[mr_addr]
            if mr.addr + mr.size < addr:
                continue
            if mr.addr > addr:
                break
            return mr
        return None

    def _get_position_at_addr(self, addr: int) -> Optional[float]:
        mr = self._get_region_at_addr(addr)
        if mr is None or mr.size == 0:
            return None
        mr_pos = self._region_to_position[mr]
        mr_width = self._region_to_width[mr]
        offset = addr - mr.addr
        assert offset >= 0
        return mr_pos + mr_width * offset / mr.size

    def _floor_position_to_nearest_region(self, pos: float) -> Optional["MemoryRegion"]:
        try:
            pos = next(self._position_to_region.irange(maximum=pos, reverse=True))
            return self._position_to_region[pos]
        except StopIteration:
            return None

    def _get_addr_at_position(self, pos: float) -> Optional[int]:
        mr = self._floor_position_to_nearest_region(pos)
        if mr is None:
            return None
        pos -= self._region_to_position[mr]
        width = self._region_to_width[mr]
        if width < 1:
            return mr.addr
        return mr.addr + int(pos / width * mr.size)

    def _get_region_display_rect(self, mr: "MemoryRegion") -> QRectF:
        x = self._region_to_position[mr]
        width = self._region_to_width[mr]
        return QRectF(x, 0, width, self._height)

    def paint(self, painter, option, _):
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(Qt.green if log.level == logging.DEBUG else Conf.feature_map_unknown_color)
        painter.drawRect(option.exposedRect)

        if not len(self._position_to_region):
            return  # Nothing to draw

        pos_l = max(0, option.exposedRect.left())
        min_visible_addr = self._get_addr_at_position(pos_l)
        if min_visible_addr is None:
            min_visible_addr = 0

        pos_r = max(0, option.exposedRect.right())
        max_visible_addr = self._get_addr_at_position(pos_r)
        if max_visible_addr is None:
            return

        log.debug(
            "paint event: %dpx-%dpx of %dpx [%#x - %#x]",
            option.exposedRect.left(),
            option.exposedRect.right(),
            self._width,
            min_visible_addr,
            max_visible_addr,
        )

        item_count = 0
        skipped_item_count = 0
        prev_tags = None
        region_delim_xcoords = []

        # Iterate over visible regions
        start_idx = max(0, self._position_to_region.bisect_left(pos_l) - 1)
        for pos in self._position_to_region.islice(start_idx):
            mr = self._position_to_region[pos]
            if (mr.addr + mr.size) < min_visible_addr:
                continue
            if mr.addr > max_visible_addr:
                break

            # Clip region to visible addresses
            min_obj_addr = max(min_visible_addr, mr.addr)
            max_obj_addr = min(max_visible_addr, mr.addr + mr.size - 1)
            log.debug("Painting region %s clipped to %#x-%#x", mr, min_obj_addr, max_obj_addr)

            mr_rect = self._get_region_display_rect(mr)
            region_delim_xcoords.append(mr_rect.left())

            # Pick appropriate level of detail for the region
            lod = -1  # Max LOD
            bytes_per_pixel = int(mr.size / mr_rect.width())
            for idx, bits_per_bin in enumerate(self._nbits_per_lod):
                bytes_per_bin = 1 << bits_per_bin
                if bytes_per_pixel * 3 >= bytes_per_bin:
                    lod = idx
                    break

            # Iterate over visible items in the region
            item_count_in_region = 0

            with self._cfb_feature_maps_lock:
                to_draw = list(self._cfb_feature_maps[lod].irange(min_obj_addr, max_obj_addr))

            for addr, size, tags in to_draw:
                if not size or not tags:
                    continue

                log.debug("Painting item at %#x, size %#x", addr, size)

                # Clip to memory region bounds
                if addr < min_obj_addr:
                    delta = min_obj_addr - addr
                    addr += delta
                    size -= delta

                end_addr = addr + size - 1
                if end_addr > max_obj_addr:
                    delta = end_addr - max_obj_addr
                    size -= delta

                if prev_tags != tags:
                    painter.setBrush(self._feature_palette[tags])
                    prev_tags = tags

                x = mr_rect.x() + (addr - mr.addr) / mr.size * mr_rect.width()
                width = size / mr.size * mr_rect.width()

                r = QRectF(x, 0, width, mr_rect.height())
                painter.drawRect(r)

                log.debug("Painted %#x, %x, %d at %s", addr, size, tags, r)
                item_count_in_region += 1
                item_count += 1

            log.debug(
                "Painted %d items in region %s at position %f width %f BPP = %d at LOD = %s",
                item_count_in_region,
                mr,
                mr_rect.x(),
                mr_rect.width(),
                bytes_per_pixel,
                lod,
            )
        log.debug("Painted %d items in total, skipped %d", item_count, skipped_item_count)

        pen = QPen(Conf.feature_map_delimiter_color)
        pen.setWidthF(1.0)
        painter.setPen(pen)
        for x in region_delim_xcoords:
            log.debug("Drawing delimiter at %f", x)
            painter.drawLine(x, 0, x, self._height)

    def _create_cursor_items(self, **_):
        self._remove_cursor_items()

        line_width = 3
        half_line_width = line_width / 2
        line_height = self._height // 2
        head_width = 4
        half_head_width = head_width / 2
        head_height = 4
        half_width = half_line_width + half_head_width

        #   6 0
        #   | |
        # 4-5 1-2
        #  -   -
        #    3
        arrow = QPolygonF()
        arrow.append(QPointF(0 + half_line_width, 0))
        arrow.append(QPointF(0 + half_line_width, line_height))
        arrow.append(QPointF(0 + half_line_width + half_head_width, line_height))
        arrow.append(QPointF(0, line_height + head_height))
        arrow.append(QPointF(0 - half_line_width - half_head_width, line_height))
        arrow.append(QPointF(0 - half_line_width, line_height))
        arrow.append(QPointF(0 - half_line_width, 0))
        arrow.translate(half_width, 0)

        pen = Qt.NoPen
        brush = QBrush(Qt.GlobalColor.yellow)

        for addr in self._cursor_addrs:
            pos = self._get_position_at_addr(addr)
            if pos is None:
                continue

            item = QGraphicsPolygonItem(arrow, parent=self)
            item.setCacheMode(QGraphicsItem.ItemCoordinateCache)
            item.setPen(pen)
            item.setBrush(brush)
            item.setZValue(self.ZVALUE_CURSOR)
            item.setX(pos - half_width)
            self._cursor_items.append(item)

    def _remove_cursor_items(self):
        scene = self.scene()
        for item in self._cursor_items:
            scene.removeItem(item)
        self._cursor_items.clear()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.select_at_position(event.pos().x())
            self._pressed = True

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._pressed = False

    def mouseMoveEvent(self, event):
        x = event.pos().x()
        if self._pressed:
            self.select_at_position(x)
        self._handle_hover_at_position(x)

    def select_at_position(self, pos: float):
        addr = self._get_addr_at_position(pos)
        if addr is not None:
            self.addr.am_obj = addr
            self.addr.am_event()

    def hoverEnterEvent(self, event):
        self._handle_hover_at_position(event.pos().x())

    def hoverMoveEvent(self, event):
        self._handle_hover_at_position(event.pos().x())

    def hoverLeaveEvent(self, _):
        self._clear_hover_region()

    def _clear_hover_region(self):
        self._remove_hover_item()
        self._hover_region = None

    def _handle_hover_at_position(self, pos: float):
        hovered_region = self._floor_position_to_nearest_region(pos)

        if hovered_region is None:
            self._remove_hover_item()
            self.setToolTip("")
            return

        # Generate tooltip text for item under cursor
        new_tooltip = ""
        try:
            addr = self._get_addr_at_position(pos)
            if addr is None:
                return
            item = self.instance.cfb.floor_item(addr)
            if item is not None:
                _, item = item
                new_tooltip = f"{str(item)} in {str(hovered_region)}"
        except KeyError:
            pass
        self.setToolTip(new_tooltip)

        # Update hover region indicator
        if hovered_region is not self._hover_region:
            self._remove_hover_item()
            self._hover_region = hovered_region
            self._create_hover_item()

    def _create_hover_item(self):
        self._remove_hover_item()
        hovered_region = self._hover_region
        if hovered_region is None:
            return

        pw = 1.0
        hpw = pw / 2
        pen = QPen(Qt.GlobalColor.red)
        pen.setWidthF(pw)
        r = self._get_region_display_rect(hovered_region)
        r = r.marginsRemoved(QMarginsF(pw, hpw, pw, hpw))
        item = QGraphicsRectItem(r, parent=self)
        item.setPen(pen)
        item.setZValue(self.ZVALUE_HOVER)
        self._hover_region_item = item
        log.debug("Created hover item")

    def _remove_hover_item(self):
        if self._hover_region_item:
            self.scene().removeItem(self._hover_region_item)
            self._hover_region_item = None
            log.debug("Removed hover item")


class QFeatureMapView(QGraphicsView):
    """
    Main view for feature map scene.
    """

    def __init__(self, instance, parent=None):
        super().__init__(parent)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._scene = QGraphicsScene(parent=self)
        self.setScene(self._scene)

        self._feature_map_item: FeatureMapItem = FeatureMapItem(instance)
        self._scale: float = 1.0
        self._base_width: int = 0
        self._scene.addItem(self._feature_map_item)
        self._orientation: str = "horizontal"

        self.setBackgroundBrush(Conf.palette_base)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.NoAnchor)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.NoAnchor)
        self.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self._update_feature_map_item_size()

    def minimumSize(self):  # pylint:disable=no-self-use
        return QSize(10, 10)

    def minimumSizeHint(self):  # pylint:disable=no-self-use
        return QSize(10, 10)

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(10, 10)

    def wheelEvent(self, event):
        """
        Handle wheel events to scale and translate the feature map.
        """
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier == Qt.KeyboardModifier.ControlModifier:
            self.adjust_viewport_scale(
                1.25 if event.angleDelta().y() > 0 else 1 / 1.25,
                QPoint(int(event.position().x()), int(event.position().y())),
            )
        else:
            if self._scale > 1.0:
                self.translate(100 * (-1 if event.angleDelta().y() < 0 else 1), 0)
            super().wheelEvent(event)

    def resizeEvent(self, event):
        """
        Handle view resize events, updating the feature map size accordingly.
        """
        self._update_feature_map_item_size()
        return super().resizeEvent(event)

    def adjust_viewport_scale(self, scale: Optional[float] = None, point: Optional[QPoint] = None):
        """
        Adjust viewport scale factor.
        """
        if point is None:
            point = QPoint(0, 0)
        point_rel = self.mapToScene(point).x() / self._feature_map_item.width

        if scale is None:
            self._scale = 1.0
        else:
            self._scale *= scale
            self._scale = min(max(1.0, self._scale), 1000.0)
            if self._scale < 1.25:
                self._scale = 1.0

        self._update_feature_map_item_size()
        self.translate(self.mapToScene(point).x() - point_rel * self._feature_map_item.width, 0)

    def keyPressEvent(self, event):
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

    def changeEvent(self, event: QEvent):
        """
        Redraw on color scheme update.
        """
        if event.type() == QEvent.Type.StyleChange:
            self.setBackgroundBrush(Conf.palette_base)
            self._feature_map_item._refresh_palette()
            self._feature_map_item.refresh()

    def _update_feature_map_item_size(self):
        """
        Resize feature map.
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

        changed = False
        new_width = int(self._base_width * self._scale)
        point_rel = self.mapToScene(QPoint(0, 0)).x() / self._feature_map_item.width

        if self._scale <= 1.0 or new_width < w:
            self._base_width = w
            self._scale = 1.0
            new_width = w

        if new_width != self._feature_map_item.width:
            self._feature_map_item.width = max(new_width, 1)
            changed = True

        new_height = h
        if new_height != self._feature_map_item.height:
            self._feature_map_item.height = max(new_height, 1)
            changed = True

        if changed:
            self._feature_map_item.refresh()
            self.setSceneRect(self._scene.itemsBoundingRect())

        if rotation:
            self.rotate(rotation)
            self.translate(self.mapToScene(QPoint(0, 0)).x() - point_rel * self._feature_map_item.width, 0)


class QFeatureMap(QWidget):
    """
    Byte-level map of the memory space.
    """

    def __init__(self, instance, parent=None):
        super().__init__(parent)
        self.instance = instance
        self._init_widgets()

    @staticmethod
    def sizeHint():
        return QSize(10, 10)

    @staticmethod
    def minimumSizeHint():
        return QSize(10, 10)

    #
    # Private methods
    #

    def _init_widgets(self):
        self.view = QFeatureMapView(self.instance, self)
        self.view.setContentsMargins(0, 0, 0, 0)
        layout = QHBoxLayout()
        layout.addWidget(self.view)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setLayout(layout)
        self.addr = self.view._feature_map_item.addr

    def set_cursor_addrs(self, cursor_addrs):
        self.view._feature_map_item.set_cursor_addrs(cursor_addrs)
