
from atom.api import Typed
from enaml.qt.qt_container import QContainer, QtContainer, CONTAINER_POLICY
from enaml.qt.QtCore import Signal
from enaml.qt.QtGui import QMouseEvent, QKeyEvent

from ..widgets.rich_container import ProxyRichContainer

class QRichContainer(QContainer):
    clicked = Signal()
    right_clicked = Signal()
    key_pressed = Signal(int)

    def mouseReleaseEvent(self, mouse_event):
        """

        :param QMouseEvent mouse_event:
        :return:
        """

        if mouse_event.button() == 1:
            self.clicked.emit()
        elif mouse_event.button() == 2:
            self.right_clicked.emit()

    def keyPressEvent(self, key_event):
        """

        :param QKeyEvent key_event:
        :return:
        """

        key = key_event.key()
        self.key_pressed.emit(key)


class QtRichContainer(QtContainer, ProxyRichContainer):

    widget = Typed(QRichContainer)

    def create_widget(self):
        widget = QRichContainer(self.parent_widget())
        widget.setSizePolicy(CONTAINER_POLICY)
        self.widget = widget

    def init_widget(self):
        super(QtRichContainer, self).init_widget()
        widget = self.widget
        widget.clicked.connect(self.on_clicked)
        widget.right_clicked.connect(self.on_right_clicked)
        widget.key_pressed.connect(self.on_key_pressed)

    def on_clicked(self):
        self.declaration.clicked()

    def on_right_clicked(self):
        self.declaration.right_clicked()

    def on_key_pressed(self, key):
        self.declaration.key_pressed(key)
