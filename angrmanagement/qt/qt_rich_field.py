
from ..widgets.rich_field import ProxyRichField
from atom.api import Typed
from enaml.qt.qt_field import QtField, QFocusLineEdit
from enaml.qt.QtCore import Signal
from enaml.qt.QtGui import QKeyEvent


class QRichLineEdit(QFocusLineEdit):

    key_pressed = Signal(int)

    def keyPressEvent(self, key_event):
        """

        :param QKeyEvent key_event:
        :return:
        """

        # call parent handlers first to ensure text in textbox is fully committed
        super(QRichLineEdit, self).keyPressEvent(key_event)

        key = key_event.key()
        self.key_pressed.emit(key)


class QtRichField(QtField, ProxyRichField):

    widget = Typed(QRichLineEdit)

    def create_widget(self):
        self.widget = QRichLineEdit(self.parent_widget())

    def init_widget(self):
        super(QtRichField, self).init_widget()

        self.widget.key_pressed.connect(self.on_key_pressed)

    def on_key_pressed(self, key):
        self.declaration.key_pressed(key)
