import logging

from PySide6.QtCore import QEvent, QMarginsF, QPoint, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QImage, QMouseEvent, QPainter, QVector2D
from PySide6.QtWidgets import (
    QApplication,
    QGestureEvent,
    QGraphicsScene,
    QGraphicsSceneMouseEvent,
    QGraphicsView,
    QPinchGesture,
    QStyleOptionGraphicsItem,
)

_l = logging.getLogger(__name__)


class QBaseGraphicsView(QGraphicsView):
    visible_scene_rect_changed = Signal(QRectF)

    #
    # Public methods
    #

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._visibile_scene_rect: QRectF = QRectF()

    @property
    def visible_scene_rect(self):
        return self._visibile_scene_rect

    def redraw(self):
        """
        Redraw the scene. Do not recompute any items in the view.

        :return:    None
        """
        scene = self.scene()
        if scene is not None:
            scene.update(self.sceneRect())

    def viewportEvent(self, event: QEvent) -> bool:
        visible_scene_rect = self.mapToScene(self.viewport().geometry()).boundingRect()
        if visible_scene_rect != self._visibile_scene_rect:
            self._visibile_scene_rect = visible_scene_rect
            self.visible_scene_rect_changed.emit(visible_scene_rect)

        return super().viewportEvent(event)


class QSaveableGraphicsView(QBaseGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self._is_extra_render_pass: bool = False

    @property
    def is_extra_render_pass(self):
        return self._is_extra_render_pass

    def set_extra_render_pass(self, is_extra_pass: bool):
        """
        Trigger any post-render callbacks
        """
        self._is_extra_render_pass = is_extra_pass

    def save_image_to(self, path, top_margin=50, bottom_margin=50, left_margin=50, right_margin=50):
        margins = QMarginsF(left_margin, top_margin, right_margin, bottom_margin)

        oldRect = self.scene().sceneRect()
        minRect = self.scene().itemsBoundingRect()
        imgRect = minRect.marginsAdded(margins)

        image = QImage(imgRect.size().toSize(), QImage.Format_ARGB32)
        image.fill(Qt.white)
        painter = QPainter(image)

        painter.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)

        # draw the image
        self.scene().setSceneRect(imgRect)
        self.scene().render(painter)
        image.save(path)

        # cleanup
        painter.end()

        # restore the old scene rect
        self.scene().setSceneRect(oldRect)


class QZoomableDraggableGraphicsView(QSaveableGraphicsView):
    ZOOM_X = True
    ZOOM_Y = True

    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self._is_dragging = False
        self._is_mouse_pressed = False

        self._last_coords = None
        self._last_screen_pos = None

        self.setTransformationAnchor(QGraphicsView.NoAnchor)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)

        # scroll bars are useless when the scene is near-infinite
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # the zoom factor, for preserving the zoom
        self.zoom_factor = None

        # self.setRenderHints(
        # QPainter.Antialiasing | QPainter.SmoothPixmapTransform)

        self.grabGesture(Qt.PinchGesture)
        self._gesture_last_scale = 1.0

    def _initial_position(self):
        raise NotImplementedError

    def _reset_view(self):
        self.resetTransform()
        self.centerOn(self._initial_position())
        self.zoom(restore=True)

    def _reset_scene(self):
        if self.scene() is None:
            scene = QGraphicsScene(self)
            self.setScene(scene)
        else:
            self.scene().clear()

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(300, 300)

    def zoom(self, out=False, at=None, reset=False, restore=False, factor=1.25):
        if at is None:
            at = self.scene().sceneRect().center().toPoint()
        lod = QStyleOptionGraphicsItem.levelOfDetailFromTransform(self.transform())
        zoomInFactor = factor
        zoomOutFactor = 1 / zoomInFactor

        if reset:
            zoomFactor = 1 / lod
        elif restore:
            zoomFactor = self.zoom_factor if self.zoom_factor else 1 / lod
        elif not out:
            zoomFactor = zoomInFactor
        else:
            zoomFactor = zoomOutFactor
            # limit the scroll out limit for usability
            if lod < 0.015:
                return

        # Save the scene pos
        oldPos = self.mapToScene(at)

        # Zoom
        self.scale(zoomFactor if self.ZOOM_X else 1, zoomFactor if self.ZOOM_Y else 1)
        self.zoom_factor = QStyleOptionGraphicsItem.levelOfDetailFromTransform(self.transform())

        # Get the new position
        newPos = self.mapToScene(at)

        # Move scene to old position
        delta = newPos - oldPos
        self.translate(delta.x(), delta.y())

    def wheelEvent(self, event):
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            self.zoom(
                event.angleDelta().y() < 0,
                QPoint(event.position().x(), event.position().y()),
                factor=1 + 0.25 * abs(event.angleDelta().y()) / 120,
            )
        elif event.angleDelta().x() != 0:
            # if this is an angled zoom (e.g. touchpad) then just let the default handler take care of it
            super().wheelEvent(event)
        else:
            # if it is not an angled zoom (e.g. mouse wheel) parse the shift key specially to mean horizontal movement
            if event.modifiers() & Qt.ShiftModifier == Qt.ShiftModifier:
                event.setModifiers(event.modifiers() & ~Qt.ShiftModifier)
                self.horizontalScrollBar().wheelEvent(event)
            else:
                self.verticalScrollBar().wheelEvent(event)

    def _save_last_coords(self, event):
        pos = self.mapToScene(event.pos())
        self._last_coords = (pos.x(), pos.y())
        self._last_screen_pos = event.pos()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Equal and (event.modifiers() & Qt.ControlModifier == Qt.ControlModifier):
            self.zoom(out=False)
        elif event.key() == Qt.Key_Minus and (event.modifiers() & Qt.ControlModifier == Qt.ControlModifier):
            self.zoom(out=True)
        elif event.key() == Qt.Key_0 and (event.modifiers() & Qt.ControlModifier == Qt.ControlModifier):
            self.zoom(reset=True)
        else:
            super().keyPressEvent(event)

    def mousePressEvent(self, event):
        # _l.debug('Received press')
        if event.button() == Qt.LeftButton:
            self._is_mouse_pressed = True
            self._is_dragging = False

            self._save_last_coords(event)
            event.accept()

        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        SENSITIVITY = 1.0
        if self._is_mouse_pressed:
            mouse_delta = QVector2D(event.pos() - self._last_screen_pos).length()
            if mouse_delta > SENSITIVITY:
                self._is_dragging = True
                pos = self.mapToScene(event.pos())

                self.viewport().setCursor(Qt.ClosedHandCursor)

                delta = (pos.x() - self._last_coords[0], pos.y() - self._last_coords[1])
                self.translate(*delta)

            self._save_last_coords(event)
            event.accept()

        super().mouseMoveEvent(event)

    def dispatchMouseEventToScene(self, event):
        if event.type() == QEvent.MouseButtonPress:
            newtype = QEvent.GraphicsSceneMousePress
        elif event.type() == QEvent.MouseButtonRelease:
            newtype = QEvent.GraphicsSceneMouseRelease
        else:
            raise ValueError(f"Unknown event type {event.type()}")

        # pulled from QGraphicsView::mousePressEvent in the qt codebase:
        mouseEvent = QGraphicsSceneMouseEvent(newtype)
        mousePressViewPoint = event.pos()
        mousePressScenePoint = self.mapToScene(mousePressViewPoint)
        mousePressScreenPoint = event.globalPos()
        lastMouseMoveScenePoint = mousePressScenePoint
        lastMouseMoveScreenPoint = mousePressScreenPoint
        mousePressButton = event.button()

        # mouseEvent.setWidget(self.viewport()) # TODO figure out how to do this in python, or if it's really necessary
        mouseEvent.setButtonDownScenePos(mousePressButton, mousePressScenePoint)
        mouseEvent.setButtonDownScreenPos(mousePressButton, mousePressScreenPoint)
        mouseEvent.setScenePos(mousePressScenePoint)
        mouseEvent.setScreenPos(mousePressScreenPoint)
        mouseEvent.setLastScenePos(lastMouseMoveScenePoint)
        mouseEvent.setLastScreenPos(lastMouseMoveScreenPoint)
        mouseEvent.setButtons(event.buttons())
        mouseEvent.setButton(event.button())
        mouseEvent.setModifiers(event.modifiers())
        mouseEvent.setSource(event.source())
        mouseEvent.setFlags(event.flags())
        mouseEvent.setAccepted(False)
        QApplication.sendEvent(self.scene(), mouseEvent)
        return mouseEvent

    def mouseReleaseEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton and self._is_dragging:
            self.viewport().setCursor(Qt.ArrowCursor)
            event.accept()

        if not event.isAccepted():
            # create a new event and dispatch it to the scene
            pressy = QMouseEvent(
                QEvent.MouseButtonPress,
                event.pos(),
                event.globalPos(),
                event.button(),
                event.buttons(),
                event.modifiers(),
            )

            _ = self.dispatchMouseEventToScene(pressy)

            releasy = QMouseEvent(
                QEvent.MouseButtonRelease,
                event.pos(),
                event.globalPos(),
                event.buton(),
                event.buttons(),
                event.modifiers(),
            )
            release_event = self.dispatchMouseEventToScene(releasy)

            if not release_event.isAccepted():
                self.on_background_click()
                release_event.accept()

        self._is_mouse_pressed = False
        self._is_dragging = False

        super().mouseReleaseEvent(event)

    def event(self, event):
        if event.type() == QEvent.Gesture and isinstance(event, QGestureEvent):
            return self._handle_pinch_gesture(event)
        return super().event(event)

    def _handle_pinch_gesture(self, event: QGestureEvent):
        for gesture in event.gestures():
            if isinstance(gesture, QPinchGesture):
                if gesture.state() == Qt.GestureState.GestureStarted:
                    self.pinchGestureStarted()
                elif gesture.state() == Qt.GestureState.GestureUpdated:
                    self.pinchGestureUpdated(gesture)

    def pinchGestureStarted(self):
        self._gesture_last_scale = 1.0

    def pinchGestureUpdated(self, gesture: QPinchGesture):
        newScale = gesture.scaleFactor() / self._gesture_last_scale
        self.zoom(at=gesture.centerPoint().toPoint(), factor=newScale)
