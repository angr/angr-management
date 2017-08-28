
import logging

from PySide.QtGui import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea, QLineEdit,\
    QWidget, QPainter, QBrush, QPen
from PySide.QtCore import Qt, QSize

from ...config import Conf
from .qast_viewer import QASTViewer

l = logging.getLogger('ui.widgets.qregister_viewer')


class AddressPiece(object):
    __slots__ = ['address']

    def __init__(self, address):
        self.address = address


class NewLinePiece(object):
    pass


class QMemoryView(QWidget):
    def __init__(self, parent=None):
        super(QMemoryView, self).__init__(parent)

        self.state = None
        self.cols = None
        self.rows = None

        # The current address being displayed. Must be set through .address
        self._address = None

        self._objects = [ ]

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, v):
        if v != self._address:
            self._address = v
            self._reload_objects()

    def paintEvent(self, event):

        if self.address is None:
            return

        MARGIN_LEFT = 5
        MARGIN_TOP = 5
        LINE_MARGIN = 3

        painter = QPainter(self)

        painter.setPen(QPen(Qt.black, 1))
        painter.setFont(Conf.symexec_font)

        x = MARGIN_LEFT
        y = MARGIN_TOP

        for obj in self._objects:

            obj_type = type(obj)

            if obj_type is NewLinePiece:
                # carriage return
                x = MARGIN_LEFT
                y += Conf.symexec_font_height + LINE_MARGIN
            elif obj_type is AddressPiece:
                # address
                addr_str = "%08x" % obj.address
                painter.drawText(x, y + Conf.symexec_font_ascent, addr_str)
                x += Conf.symexec_font_width * len(addr_str)
                x += 7
            elif obj_type is QASTViewer:
                # AST viewer
                obj.x = x
                obj.y = y
                obj.paint(painter)

                x += obj.width + 2
            else:
                raise TypeError('paintEvent(): Unsupported object type %s.' % obj_type)

    def _reload_objects(self):
        """
        Reload addresses and text pieces to be displayed.

        :return: None
        """

        objects = [ ]

        addr_base = self.address
        for row in xrange(self.rows):

            addr = addr_base + row * self.cols

            # address
            addr_piece = AddressPiece(addr)
            objects.append(addr_piece)

            # QASTViewer objects
            for col in xrange(self.cols):
                data = self.state.memory.load(addr + col, 1, inspect=False, disable_actions=True)
                ast_viewer = QASTViewer(data, custom_painting=True, display_size=False)
                objects.append(ast_viewer)

            # end of the line
            newline_piece = NewLinePiece()
            objects.append(newline_piece)

        self._objects = objects


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
