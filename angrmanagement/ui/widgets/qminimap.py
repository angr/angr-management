from PySide2.QtCore import QRect, QPoint, QPointF, Qt, QRectF
from PySide2.QtGui import QPainter, QPainterPath, QPen, QPaintEvent, QMouseEvent, QWheelEvent
from PySide2.QtWidgets import QWidget, QGraphicsView

from ...config import Conf


def clamp(v, min_, max_):
    return min(max(v, min_), max_)


class QMiniMap(QWidget):
    """
    Renders a minimized version of a QGraphicsScene, indicating current viewport
    and handling mouse events to support viewport translation.
    """

    def __init__(self, view:QGraphicsView, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._view:QGraphicsView = view
        self._is_mouse_pressed:bool = False
        self._full_scene_rect:QRectF = QRectF()
        self._scale:float = 1.0

    def paintEvent(self, event:QPaintEvent): # pylint: disable=unused-argument
        scene = self._view.scene()
        if scene is None:
            return

        # Scale based on scene and minimap widget dimensions
        self._full_scene_rect = self._view.scene().sceneRect()
        scene_width = self._full_scene_rect.width()
        scene_height = self._full_scene_rect.height()
        if scene_width == 0 or scene_height == 0:
            return

        mm_max_w, mm_max_h = self.geometry().width(), self.geometry().height()
        if mm_max_w == 0 or mm_max_h == 0:
            return

        if mm_max_w/mm_max_h < scene_width/scene_height:
            self._scale = mm_max_w/scene_width
        else:
            self._scale = mm_max_h/scene_height

        painter = QPainter(self)
        painter.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)

        # Draw minimap border and background color
        path = QPainterPath()
        mm_scene_w = self._full_scene_rect.width()*self._scale
        mm_scene_h = self._full_scene_rect.height()*self._scale
        path.addRect(QRect(0, 0, mm_scene_w, mm_scene_h))
        painter.setPen(QPen(Conf.palette_mid, 2.5))
        painter.setBrush(Conf.palette_base)
        painter.drawPath(path)

        # Draw scene
        painter.setBrush(Qt.transparent)
        self._view.set_extra_render_pass(True)
        scene.render(painter)
        self._view.set_extra_render_pass(False)

        # Draw viewport box
        vp = self._view.mapToScene(self._view.viewport().geometry()).boundingRect()
        x = (vp.x() - self._full_scene_rect.x())*self._scale
        y = (vp.y() - self._full_scene_rect.y())*self._scale
        width = vp.width()*self._scale
        height = vp.height()*self._scale
        path = QPainterPath()
        mini_vp = QRectF()
        mini_vp.setTopLeft(QPointF(clamp(x, 0, mm_scene_w), clamp(y, 0, mm_scene_h)))
        mini_vp.setBottomRight(QPointF(clamp(x+width, 0, mm_scene_w), clamp(y+height, 0, mm_scene_h)))
        path.addRect(mini_vp)
        painter.setPen(QPen(Conf.disasm_view_minimap_viewport_color, 2.5))
        painter.setBrush(Qt.transparent)
        painter.drawPath(path)

        painter.end()

    def move_viewport_to(self, pos:QPoint):
        x, y = pos.x(), pos.y()
        x = x/self._scale + self._full_scene_rect.x()
        y = y/self._scale + self._full_scene_rect.y()
        self._view.centerOn(QPointF(x, y))

    def mousePressEvent(self, event:QMouseEvent):
        if event.button() == Qt.LeftButton:
            self._is_mouse_pressed = True
            self.setCursor(Qt.ClosedHandCursor)
            self.move_viewport_to(event.pos())
            event.accept()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event:QMouseEvent):
        if self._is_mouse_pressed:
            self.move_viewport_to(event.pos())
            event.accept()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event:QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.setCursor(Qt.ArrowCursor)
            event.accept()
        self._is_mouse_pressed = False
        super().mouseReleaseEvent(event)

    def wheelEvent(self, event:QWheelEvent):
        # Pass the wheel event to target view to handle zoom events
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            self.move_viewport_to(event.pos())
        self._view.wheelEvent(event)
