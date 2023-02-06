from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QPainter, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QLineEdit, QScrollArea, QVBoxLayout, QWidget

from angrmanagement.config import Conf

from .qast_viewer import QASTViewer


class AddressPiece:
    __slots__ = ["address"]

    def __init__(self, address):
        self.address = address


class NewLinePiece:
    pass


class QMemoryView(QWidget):
    def __init__(self, state, instance, parent=None):
        super().__init__(parent)
        self.instance = instance

        self.state = state
        self.cols = None
        self.rows = None

        # The current address being displayed. Must be set through .address
        self._address = None

        self._objects = []

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
                raise TypeError("paintEvent(): Unsupported object type %s." % obj_type)

    def _reload_objects(self):
        """
        Reload addresses and text pieces to be displayed.

        :return: None
        """

        objects = []

        addr_base = self.address
        for row in range(self.rows):
            addr = addr_base + row * self.cols

            # address
            addr_piece = AddressPiece(addr)
            objects.append(addr_piece)

            # QASTViewer objects
            for col in range(self.cols):
                data = self.state.memory.load(addr + col, 1, inspect=False, disable_actions=True)
                ast_viewer = QASTViewer(
                    data, workspace=self.instance.workspace, custom_painting=True, display_size=False
                )
                objects.append(ast_viewer)

            # end of the line
            newline_piece = NewLinePiece()
            objects.append(newline_piece)

        self._objects = objects


class QMemoryViewer(QFrame):
    def __init__(self, state, parent, workspace):
        super().__init__(parent)
        self.workspace = workspace

        self._scrollarea: QScrollArea
        self._txt_addr: QLineEdit
        self._view: QMemoryView

        self._addr = None  # the address to display
        self.state = state

        self._init_widgets()

        self.state.am_subscribe(self._watch_state)

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
        if self.state.am_none:
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

        self._view = QMemoryView(self.state, self.workspace)

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
        self._view.cols = 16
        self._view.rows = 10
        self._view.address = self.addr

        self._view.repaint()

    def _watch_state(self, **kwargs):
        self.reload()
