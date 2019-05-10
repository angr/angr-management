import logging

from PySide2.QtWidgets import QGraphicsScene, QGraphicsView, QStyleOptionGraphicsItem, QApplication, QGraphicsSceneMouseEvent
from PySide2.QtGui import QPainter, QMouseEvent, QImage, QVector2D
from PySide2.QtCore import Qt, QSize, QEvent, QMarginsF

_l = logging.getLogger(__name__)


class QSaveableGraphicsView(QGraphicsView):

    def save_image_to(self, path, top_margin=50, bottom_margin=50, left_margin=50, right_margin=50):

        margins = QMarginsF(left_margin, top_margin, right_margin, bottom_margin)

        oldRect = self.scene().sceneRect()
        minRect = self.scene().itemsBoundingRect()
        imgRect = minRect.marginsAdded(margins)


        image = QImage(imgRect.size().toSize(), QImage.Format_ARGB32)
        image.fill(Qt.white)
        painter = QPainter(image)

        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)

        # draw the image
        self.scene().setSceneRect(imgRect)
        self.scene().render(painter)
        image.save(path)

        # cleanup
        painter.end()

        # restore the old scene rect
        self.scene().setSceneRect(oldRect)


class CustomizableGraphicsScene(QGraphicsScene):
    def __init__(self, *args, **kwargs):
        self._onMousePress = kwargs.pop('onMousePress', None)
        super().__init__(*args, **kwargs)

    def mousePressEvent(self, event):
        if self._onMousePress is not None and not self._onMousePress(event):
            super().mousePressEvent(event)


class QZoomableDraggableGraphicsView(QSaveableGraphicsView):

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

        #self.setRenderHints(
                #QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)

    def _initial_position(self):
        raise NotImplementedError

    def _reset_view(self):
        self.resetMatrix()
        self.centerOn(self._initial_position())

    def _reset_scene(self):
        if self.scene() is None:
            width = 1000000 # a ludicrously large number, to emulate infinite panning
            scene = QGraphicsScene(- (width / 2), - (width / 2), width, width)
            self.setScene(scene)
        else:
            self.scene().clear()

    def sizeHint(self): #pylint: disable=no-self-use
        return QSize(300, 300)


    def wheelEvent(self, event):
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            lod = QStyleOptionGraphicsItem.levelOfDetailFromTransform(self.transform())
            zoomInFactor = 1.25
            zoomOutFactor = 1 / zoomInFactor

            # Save the scene pos
            oldPos = self.mapToScene(event.pos())

            # Zoom
            if event.delta() > 0:
                zoomFactor = zoomInFactor
            else:
                zoomFactor = zoomOutFactor
                # limit the scroll out limit for usability
                if lod < 0.015:
                    return
            self.scale(zoomFactor, zoomFactor)

            # Get the new position
            newPos = self.mapToScene(event.pos())

            # Move scene to old position
            delta = newPos - oldPos
            self.translate(delta.x(), delta.y())
        else:
            super().wheelEvent(event)

    def _save_last_coords(self, event):
        pos = self.mapToScene(event.pos())
        self._last_coords = (pos.x(), pos.y())
        self._last_screen_pos = event.pos()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Equal:
            try:
                self._reset_view()
            except NotImplementedError:
                _l.warning('%s does not implement _initial_position', type(self).__name__)
        else:
            super().keyPressEvent(event)

    def mousePressEvent(self, event):
        _l.debug('Received press')
        if event.button() == Qt.LeftButton:

            self._is_mouse_pressed = True
            self._is_dragging = False

            self._save_last_coords(event)
            event.accept()

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

    def dispatchMouseEventToScene(self, event):
        if event.type() == QEvent.MouseButtonPress:
            newtype = QEvent.GraphicsSceneMousePress
        elif event.type() == QEvent.MouseButtonRelease:
            newtype = QEvent.GraphicsSceneMouseRelease
        else:
            raise ValueError('Unknown event type {}'.format(event.type()))

        # pulled from QGraphicsView::mousePressEvent in the qt codebase:
        mouseEvent = QGraphicsSceneMouseEvent(newtype)
        mousePressViewPoint = event.pos()
        mousePressScenePoint = self.mapToScene(mousePressViewPoint)
        mousePressScreenPoint = event.globalPos()
        lastMouseMoveScenePoint = mousePressScenePoint
        lastMouseMoveScreenPoint = mousePressScreenPoint
        mousePressButton = event.button()

        #mouseEvent.setWidget(self.viewport()) # TODO figure out how to do this in python, or if it's really necessary
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

        if event.button() == Qt.LeftButton:
            if self._is_dragging:
                self.viewport().setCursor(Qt.ArrowCursor)
                event.accept()
            else:
                pressy = QMouseEvent(QEvent.MouseButtonPress,
                                     event.pos(),
                                     event.globalPos(),
                                     event.button(),
                                     event.buttons(),
                                     event.modifiers())

                pressEvent = self.dispatchMouseEventToScene(pressy)
                releaseEvent = self.dispatchMouseEventToScene(event)
                if not pressEvent.isAccepted():
                    self.on_background_click()
                    pressEvent.accept()
            self._is_mouse_pressed = False
            self._is_dragging = False
