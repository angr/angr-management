
from atom.api import Typed
from enaml.qt.qt_container import QContainer, QtContainer, CONTAINER_POLICY
from enaml.qt.QtCore import Signal
from enaml.qt.QtGui import QMouseEvent

class QRichContainer(QContainer):
    clicked = Signal()
    right_clicked = Signal()

    def mouseReleaseEvent(self, mouse_event):
        """

        :param QMouseEvent mouse_event:
        :return:
        """

        if mouse_event.button() == 1:
            self.clicked.emit()
        elif mouse_event.button() == 2:
            self.right_clicked.emit()


class QtRichContainer(QtContainer):

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

    def on_clicked(self):
        self.declaration.clicked()

    def on_right_clicked(self):
        self.declaration.right_clicked()
