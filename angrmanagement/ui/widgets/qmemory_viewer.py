
import logging

from PySide.QtGui import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea, QSizePolicy, QTextEdit, QLineEdit
from PySide.QtCore import Qt, QSize

from .qast_viewer import QASTViewer

l = logging.getLogger('ui.widgets.qregister_viewer')


class QMemoryViewer(QFrame):

    def __init__(self, parent):
        super(QMemoryViewer, self).__init__(parent)

        self._scrollarea = None  # type: QScrollArea
        self._txt_addr = None  # type: QLineEdit

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

        self._load_memory_widgets()

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

        area = QScrollArea()
        self._scrollarea = area
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setWidgetResizable(True)

        layout.addLayout(top_layout)
        layout.addWidget(area)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _load_memory_widgets(self):

        state = self._state

        COLUMNS = 16
        ROWS = 10

        layout = QVBoxLayout()

        addr_base = self.addr

        for row in xrange(ROWS):

            row_layout = QHBoxLayout()

            col = 0

            addr = addr_base + row * COLUMNS
            addr_label = QLabel("%x" % addr)
            addr_label.setProperty("class", "memory_viewer_address")
            row_layout.addWidget(addr_label)

            while col < COLUMNS:
                addr = addr_base + row * COLUMNS + col
                data = state.memory.load(addr, 1, inspect=False, disable_actions=True)

                ast_viewer = QASTViewer(data, display_size=False, byte_format="%02x", parent=self)

                row_layout.addWidget(ast_viewer)

                col += 1
            row_layout.addStretch(0)

            layout.addLayout(row_layout)

        container = QFrame()
        container.setLayout(layout)
        self._scrollarea.setWidget(container)
