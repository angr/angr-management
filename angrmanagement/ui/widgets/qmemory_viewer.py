
import logging

from PySide.QtGui import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea, QLineEdit,\
    QWidget, QPainter, QBrush, QPen
from PySide.QtCore import Qt, QSize

from ...config import Conf
from .qast_viewer import QASTViewer

l = logging.getLogger('ui.widgets.qregister_viewer')


class QMemoryView(QWidget):
    def __init__(self, parent=None):
        super(QMemoryView, self).__init__(parent)

        self.state = None
        self.cols = None
        self.rows = None
        self.address = None

    def paintEvent(self, event):

        if self.address is None:
            return

        MARGIN_LEFT = 5
        MARGIN_TOP = 5
        LINE_MARGIN = 3

        painter = QPainter(self)

        painter.setPen(QPen(Qt.black, 1))

        addr_base = self.address
        x = MARGIN_LEFT
        y = MARGIN_TOP

        for row in xrange(self.rows):

            x = MARGIN_LEFT  # carriage return

            # address
            addr = addr_base + row * self.cols
            addr_str = "%x" % addr
            painter.drawText(x, y + Conf.symexec_font_ascent, addr_str)

            y += Conf.symexec_font_height + LINE_MARGIN


class QMemoryViewer(QFrame):

    def __init__(self, parent):
        super(QMemoryViewer, self).__init__(parent)

        self._scrollarea = None  # type: QScrollArea
        self._txt_addr = None  # type: QLineEdit
        self._view = None  # type: QMemoryView

        self._addr = None  # the address to display
        self._state = None

        self._init_widgets()

    #
    # Properties
    #

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, v):
        self._state = v

        self.reload()

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, v):

        if self._addr != v:
            self._addr = v

            self.reload()

    #
    # Overridden methods
    #

    def sizeHint(self, *args, **kwargs):
        return QSize(100, 100)

    #
    # Public methods
    #

    def reload(self):

        if self._state is None:
            return

        if self.addr is None:
            return

        self._refresh_memory_view()

    #
    # Event handlers
    #

    def _on_address_entered(self):

        address_str = self._txt_addr.text()

        try:
            address = int(address_str, 16)
        except ValueError:
            return

        self.addr = address

    #
    # Private methods
    #

    def _init_widgets(self):

        layout = QVBoxLayout()

        # address

        lbl_addr = QLabel()
        lbl_addr.setText("Address")

        txt_addr = QLineEdit()
        txt_addr.returnPressed.connect(self._on_address_entered)
        self._txt_addr = txt_addr

        top_layout = QHBoxLayout()
        top_layout.addWidget(lbl_addr)
        top_layout.addWidget(txt_addr)

        self._view = QMemoryView()

        area = QScrollArea()
        self._scrollarea = area
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setWidgetResizable(True)

        area.setWidget(self._view)

        layout.addLayout(top_layout)
        layout.addWidget(area)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _refresh_memory_view(self):

        self._view.state = self._state
        self._view.cols = 16
        self._view.rows = 10
        self._view.address = self.addr

        self._view.repaint()
