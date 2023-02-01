from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QMarginsF, QPoint, QPointF, QRectF, Qt
from PySide6.QtGui import QImage, QMouseEvent, QPainter, QPainterPath, QPen, QWheelEvent
from PySide6.QtWidgets import QFrame, QGraphicsItem, QGraphicsScene, QGraphicsView

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from .qgraph import QBaseGraphicsView


def clamp(v, min_, max_):
    return min(max(v, min_), max_)


class QMiniMapViewportBox(QGraphicsItem):
    """
    Widget to indicate target viewport position/size on the minimap.
    """

    PEN_WIDTH: float = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._scene_rect: QRectF = QRectF()
        self._viewport_rect: QRectF = QRectF()

    def set_scene_rect(self, rect: QRectF):
        """
        Define the dimensions of the total minimap scene, to render the outer border.
        """
        self.prepareGeometryChange()
        self._scene_rect = rect
        self.update()

    def set_viewport_rect(self, rect: QRectF):
        """
        Define the offset and dimensions of the displayed viewport indicator in the minimap scene.
        """
        self._viewport_rect = rect
        self.update()

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        """
        Draw the minimap outline and viewport box.
        """
        # Minimap outline
        painter.setPen(QPen(Conf.palette_mid, self.PEN_WIDTH))
        path = QPainterPath()
        path.addRect(self._scene_rect)
        painter.drawPath(path)

        # Viewport box
        painter.setPen(QPen(Conf.disasm_view_minimap_viewport_color, self.PEN_WIDTH))
        path = QPainterPath()
        path.addRect(self._viewport_rect)
        painter.drawPath(path)

    def boundingRect(self):
        half_pen_width = self.PEN_WIDTH / 2
        margins = QMarginsF(half_pen_width, half_pen_width, half_pen_width, half_pen_width)
        return self._scene_rect.marginsAdded(margins)


class QMiniMapTargetSceneViewer(QGraphicsItem):
    """
    Widget to render minimized version of the target view's scene on the minimap.

    For performance, the scene is cached in a QImage and only updated when update_scene_drawing is called.
    """

    def __init__(self, target_view: QGraphicsView, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._view: QGraphicsView = target_view
        self._minimap_scene_rect: QRectF = QRectF()
        self._scene_img: QImage = QImage()

    def set_scene_rect(self, rect: QRectF):
        """
        Define the dimensions of the total minimap scene.
        """
        self.prepareGeometryChange()
        self._minimap_scene_rect = rect
        self.update_scene_drawing()
        self.update()

    def update_scene_drawing(self):
        """
        Render the target scene in an image to be used for minimap painting.
        """
        scene = self._view.scene()
        if scene is None:
            return

        dpr = self._view.devicePixelRatioF()
        self._scene_img = QImage(
            dpr * self._minimap_scene_rect.width(), dpr * self._minimap_scene_rect.height(), QImage.Format_ARGB32
        )
        self._scene_img.setDevicePixelRatio(dpr)
        self._scene_img.fill(Conf.palette_base)
        self._view.set_extra_render_pass(True)
        painter = QPainter(self._scene_img)
        painter.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        scene.render(painter, target=self._minimap_scene_rect)
        self._view.set_extra_render_pass(False)
        self.update()

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        """
        Paint the minimized scene image.
        """
        painter.drawImage(0, 0, self._scene_img)

    def boundingRect(self):
        return self._minimap_scene_rect


class QMiniMapView(QGraphicsView):
    """
    Renders a minimized version of a QBaseGraphicsView, indicating current viewport and handling mouse events to
    support viewport control.
    """

    def __init__(self, target_view: "QBaseGraphicsView", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._target_view: QBaseGraphicsView = target_view
        self._is_mouse_pressed: bool = False
        self._scale: float = 1.0
        self._minimap_scene: QGraphicsScene = QGraphicsScene()
        self.setScene(self._minimap_scene)
        self._minimap_target_viewport_box: QMiniMapViewportBox = QMiniMapViewportBox()
        self._minimap_scene.addItem(self._minimap_target_viewport_box)
        self._minimap_target_viewport_box.setZValue(1.0)
        self._minimap_target_scene_viewer: QMiniMapTargetSceneViewer = QMiniMapTargetSceneViewer(self._target_view)
        self._minimap_scene.addItem(self._minimap_target_scene_viewer)
        self._target_view.visible_scene_rect_changed.connect(self.on_target_viewport_visible_scene_rect_changed)
        self.setFrameStyle(QFrame.NoFrame)

    def on_target_viewport_visible_scene_rect_changed(self, visible: QRectF):
        scene = self._target_view.scene()
        if scene is None:
            return

        x = (visible.x() - scene.sceneRect().x()) * self._scale
        y = (visible.y() - scene.sceneRect().y()) * self._scale
        width = visible.width() * self._scale
        height = visible.height() * self._scale
        mm_scene_w = self.sceneRect().width()
        mm_scene_h = self.sceneRect().height()

        minimap_vp_rect = QRectF()
        minimap_vp_rect.setTopLeft(QPoint(int(clamp(x, 0, mm_scene_w)), int(clamp(y, 0, mm_scene_h))))
        minimap_vp_rect.setBottomRight(
            QPoint(int(clamp(x + width, 0, mm_scene_w)), int(clamp(y + height, 0, mm_scene_h)))
        )

        self._minimap_target_viewport_box.set_viewport_rect(minimap_vp_rect)
        self._minimap_target_viewport_box.update()

    def reload_target_scene(self):
        """
        Reload scene from target view, scaling the minimap view to properly fit the scene into view while preserving
        scene aspect ratio.
        """
        scene = self._target_view.scene()
        if scene is None:
            return

        # Scale target scene dimensions to fit within widget bounds, preserving scene aspect ratio
        mm_max_w = self.maximumWidth()
        mm_max_h = self.maximumHeight()
        scene_rect = scene.sceneRect()
        scene_w = scene_rect.width()
        scene_h = scene_rect.height()

        if mm_max_w == 0 or mm_max_h == 0 or scene_w == 0 or scene_h == 0:
            return

        minimap_aspect_ratio = mm_max_w / mm_max_h
        scene_aspect_ratio = scene_w / scene_h

        if minimap_aspect_ratio < scene_aspect_ratio:
            self._scale = mm_max_w / scene_w
        else:
            self._scale = mm_max_h / scene_h

        scaled_scene_rect = QRectF(0, 0, int(scene_w * self._scale), int(scene_h * self._scale))
        self.resize(scaled_scene_rect.width(), scaled_scene_rect.height())
        self._minimap_scene.setSceneRect(scaled_scene_rect)
        self.setSceneRect(scaled_scene_rect)
        self._minimap_target_scene_viewer.set_scene_rect(scaled_scene_rect)
        self._minimap_target_viewport_box.set_scene_rect(scaled_scene_rect)

        self._minimap_target_scene_viewer.update_scene_drawing()
        self.on_target_viewport_visible_scene_rect_changed(self._target_view.visible_scene_rect)

    def map_event_pos_to_target_scene_pos(self, pos: QPoint) -> QPointF:
        """
        Map a point `pos` from view (e.g. mouse event) to target scene.
        """
        scene_rect = self._target_view.scene().sceneRect()
        pos = self.mapToScene(pos)
        x, y = pos.x(), pos.y()
        x = x / self._scale + scene_rect.x()
        y = y / self._scale + scene_rect.y()
        return QPointF(x, y)

    def mousePressEvent(self, event: QMouseEvent):
        """
        Handle mouse press, moving the target view port to cursor position in target scene.
        """
        if event.button() == Qt.LeftButton:
            self._is_mouse_pressed = True
            self.setCursor(Qt.ClosedHandCursor)
            self._target_view.centerOn(self.map_event_pos_to_target_scene_pos(event.pos()))
            event.accept()

    def mouseMoveEvent(self, event: QMouseEvent):
        """
        Handle mouse move, moving the target view port to cursor position in target scene when mouse is pressed.
        """
        if self._is_mouse_pressed:
            self._target_view.centerOn(self.map_event_pos_to_target_scene_pos(event.pos()))
            event.accept()

    def mouseReleaseEvent(self, event: QMouseEvent):
        """
        Handle mouse release, ending viewport drag.
        """
        if event.button() == Qt.LeftButton:
            self.setCursor(Qt.ArrowCursor)
            event.accept()
        self._is_mouse_pressed = False

    def wheelEvent(self, event: QWheelEvent):
        """
        Forward the wheel event to target view to handle zoom events.
        """
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            pos = event.position()
            self._target_view.centerOn(self.map_event_pos_to_target_scene_pos(QPoint(pos.x(), pos.y())))

        self._target_view.wheelEvent(event)

    def changeEvent(self, event: QEvent):
        """
        Redraw on color scheme update.
        """
        if event.type() == QEvent.PaletteChange:
            self.reload_target_scene()
