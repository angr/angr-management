
from atom.api import Typed

from ..widgets.rich_label import ProxyRichLabel

from enaml.qt.QtCore import Qt, Signal
from enaml.qt.QtGui import QLabel, QMouseEvent

from enaml.qt.qt_control import QtControl


ALIGN_MAP = {
    'left': Qt.AlignLeft,
    'right': Qt.AlignRight,
    'center': Qt.AlignHCenter,
    'justify': Qt.AlignJustify,
}


VERTICAL_ALIGN_MAP = {
    'top': Qt.AlignTop,
    'bottom': Qt.AlignBottom,
    'center': Qt.AlignVCenter,
}


class QRichLabel(QLabel):
    mousePressed = Signal(QMouseEvent)

    def mousePressEvent(self, mouse_event):
        """
        Handle mouse press event.

        :param QMouseEvent mouse_event: The mouse event.
        """
        self.mousePressed.emit(mouse_event)


class QtRichLabel(QtControl, ProxyRichLabel):
    """
    A Qt implementation of an Enaml ProxyRichLabel.
    """

    #: A reference to the widget created by the proxy.
    widget = Typed(QRichLabel)

    #
    # Initialization APIs
    #

    def create_widget(self):
        """
        Create the underlying label widget.
        """
        self.widget = QRichLabel(self.parent_widget())

    def init_widget(self):
        """
        Initialize the underlying widget.
        """
        super(QtRichLabel, self).init_widget()
        d = self.declaration
        self.set_text(d.text)
        self.set_align(d.align)
        self.set_vertical_align(d.vertical_align)
        self.widget.linkActivated.connect(self.on_link_activated)
        self.widget.mousePressed.connect(self.on_mouse_pressed)

    #
    # Signal handlers
    #

    def on_link_activated(self, link):
        """
        Handle the link activated signal.
        """
        self.declaration.link_activated(link)

    def on_mouse_pressed(self, mouse_event):
        """
        Handle the mouse click signal.

        :param QMouseEvent mouse_event: The mouse event.
        """

        self.declaration.mouse_pressed(mouse_event)

    #
    # ProxyLabel API
    #

    def set_text(self, text):
        """
        Set the text in the widget.
        """
        with self.geometry_guard():
            self.widget.setText(text)

    def set_align(self, align):
        """
        Set the alignment of the text in the widget.
        """
        widget = self.widget
        alignment = widget.alignment()
        alignment &= ~Qt.AlignHorizontal_Mask
        alignment |= ALIGN_MAP[align]
        widget.setAlignment(alignment)

    def set_vertical_align(self, align):
        """
        Set the vertical alignment of the text in the widget.
        """
        widget = self.widget
        alignment = widget.alignment()
        alignment &= ~Qt.AlignVertical_Mask
        alignment |= VERTICAL_ALIGN_MAP[align]
        widget.setAlignment(alignment)
