from __future__ import annotations

import logging
from typing import TYPE_CHECKING

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

from angrmanagement.config import Conf
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.present.feature_map import FeatureMapPresenter

if TYPE_CHECKING:
    from angr.analyses.cfg.cfb import MemoryRegion

    from angrmanagement.data.instance import Instance


log = logging.getLogger(name=__name__)


def _get_feature_tag_colors() -> list[QColor]:
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

    def __init__(self) -> None:
        self._feature_colors = _get_feature_tag_colors()
        self._brush_cache = {}

    def __getitem__(self, tags):
        return self._get_brush_for_tags_cached(tags)

    def _get_brush_for_tags_cached(self, tags: int) -> QBrush:
        brush = self._brush_cache.get(tags, None)
        if brush is None:
            brush = self._get_brush_for_tags(tags)
            self._brush_cache[tags] = brush
        return brush

    def _get_brush_for_tags(self, tags: int) -> QBrush:
        return QBrush(self._blend_colors(self._get_colors_for_tags(tags)))

    def _get_colors_for_tags(self, tags: int) -> list[QColor]:
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

    def __init__(self, instance: Instance, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.instance = instance

        self.setFlag(
            QGraphicsItem.GraphicsItemFlag.ItemUsesExtendedStyleOption, True
        )  # Give me more specific paint update rect info
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemClipsToShape, True)
        self.setAcceptHoverEvents(True)

        self.addr = ObjectContainer(None, name="The current address of the Feature Map.")

        self._width: int = 1
        self._height: int = 1
        self._pressed: bool = False

        self._cursor_addrs: list[int] = []
        self._cursor_items: list[QGraphicsItem] = []
        self._hover_region: MemoryRegion | None = None
        self._hover_region_item: QGraphicsItem | None = None

        self._feature_palette: FeatureMapPalette
        self._refresh_palette()

        #: follows the CFB and keeps the maps and the layout of the regions, shared with the terminal's feature map;
        #: the toolbar gives the cursors and does the jump
        self._presenter = FeatureMapPresenter(None, instance)
        self.model = self._presenter.model
        self._presenter.on_reloading = self._clear_hover_region
        self._presenter.on_changed = self._redraw
        self.refresh()

    def shutdown(self) -> None:
        """Stop following the CFB."""
        self._presenter.close()

    def set_cursor_addrs(self, cursor_addrs) -> None:
        self._cursor_addrs = cursor_addrs
        self._create_cursor_items()
        self.update()

    def refresh(self) -> None:
        self._presenter.refresh()

    def _redraw(self) -> None:
        self._layout_regions()
        self._create_hover_item()
        self._create_cursor_items()
        self.update()

    def _refresh_palette(self) -> None:
        self._feature_palette = FeatureMapPalette()

    @property
    def width(self) -> int:
        return self._width

    @width.setter
    def width(self, value: int) -> None:
        self.prepareGeometryChange()
        self._width = value

    @property
    def height(self) -> int:
        return self._height

    @height.setter
    def height(self, value: int) -> None:
        self.prepareGeometryChange()
        self._height = value

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, self._width, self._height)

    def _layout_regions(self) -> None:
        """
        Calculate displayed memory region positions and sizes.
        """
        self.model.layout(self.width)

    def _get_position_at_addr(self, addr: int) -> float | None:
        return self.model.position_at_addr(addr)

    def _floor_position_to_nearest_region(self, pos: float) -> MemoryRegion | None:
        return self.model.region_at_position(pos)

    def _get_addr_at_position(self, pos: float) -> int | None:
        return self.model.addr_at_position(pos)

    def _get_region_display_rect(self, mr: MemoryRegion) -> QRectF:
        x, width = self.model.region_span(mr)
        return QRectF(x, 0, width, self._height)

    def paint(self, painter, option, _) -> None:
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(Qt.GlobalColor.green if log.level == logging.DEBUG else Conf.feature_map_unknown_color)
        painter.drawRect(option.exposedRect)

        position_to_region = self.model.position_to_region
        if not len(position_to_region):
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
        start_idx = max(0, position_to_region.bisect_left(pos_l) - 1)
        for pos in position_to_region.islice(start_idx):
            mr = position_to_region[pos]
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
            bytes_per_pixel = int(mr.size / mr_rect.width())
            lod = self.model.lod_for(mr)

            # Iterate over visible items in the region
            item_count_in_region = 0

            to_draw = self.model.items(lod, min_obj_addr, max_obj_addr)

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

    def _create_cursor_items(self, **_) -> None:
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

        pen = Qt.PenStyle.NoPen
        brush = QBrush(Qt.GlobalColor.yellow)

        for addr in self._cursor_addrs:
            pos = self._get_position_at_addr(addr)
            if pos is None:
                continue

            item = QGraphicsPolygonItem(arrow, parent=self)
            item.setCacheMode(QGraphicsItem.CacheMode.ItemCoordinateCache)
            item.setPen(pen)
            item.setBrush(brush)
            item.setZValue(self.ZVALUE_CURSOR)
            item.setX(pos - half_width)
            self._cursor_items.append(item)

    def _remove_cursor_items(self) -> None:
        scene = self.scene()
        for item in self._cursor_items:
            scene.removeItem(item)
        self._cursor_items.clear()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.select_at_position(event.pos().x())
            self._pressed = True

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._pressed = False

    def mouseMoveEvent(self, event) -> None:
        x = event.pos().x()
        if self._pressed:
            self.select_at_position(x)
        self._handle_hover_at_position(x)

    def select_at_position(self, pos: float) -> None:
        addr = self._get_addr_at_position(pos)
        if addr is not None:
            self.addr.am_obj = addr
            self.addr.am_event()

    def hoverEnterEvent(self, event) -> None:
        self._handle_hover_at_position(event.pos().x())

    def hoverMoveEvent(self, event) -> None:
        self._handle_hover_at_position(event.pos().x())

    def hoverLeaveEvent(self, _) -> None:
        self._clear_hover_region()

    def _clear_hover_region(self) -> None:
        self._remove_hover_item()
        self._hover_region = None

    def _handle_hover_at_position(self, pos: float) -> None:
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

    def _create_hover_item(self) -> None:
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

    def _remove_hover_item(self) -> None:
        if self._hover_region_item:
            self.scene().removeItem(self._hover_region_item)
            self._hover_region_item = None
            log.debug("Removed hover item")


class QFeatureMapView(QGraphicsView):
    """
    Main view for feature map scene.
    """

    def __init__(self, instance: Instance, parent=None) -> None:
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

    def wheelEvent(self, event) -> None:
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

    def adjust_viewport_scale(self, scale: float | None = None, point: QPoint | None = None) -> None:
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
            self._feature_map_item._refresh_palette()
            self._feature_map_item.refresh()

    def _update_feature_map_item_size(self) -> None:
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

    def __init__(self, instance: Instance, parent=None) -> None:
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

    def _init_widgets(self) -> None:
        self.view = QFeatureMapView(self.instance, self)
        self.view.setContentsMargins(0, 0, 0, 0)
        layout = QHBoxLayout()
        layout.addWidget(self.view)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setLayout(layout)
        self.addr = self.view._feature_map_item.addr

    def set_cursor_addrs(self, cursor_addrs) -> None:
        self.view._feature_map_item.set_cursor_addrs(cursor_addrs)

    def shutdown(self) -> None:
        """Stop following the CFB."""
        self.view._feature_map_item.shutdown()
