
from PySide.QtGui import QColor, QPen
from PySide.QtCore import Qt

from .qgraph_object import QGraphObject


class QStateBlock(QGraphObject):
    def __init__(self, state, is_selected, symexec_view):
        super(QStateBlock, self).__init__()

        self.symexec_view = symexec_view
        self._workspace = self.symexec_view.workspace
        self._config = self.symexec_view.workspace

        self.state = state
        self.selected = is_selected

        # widgets
        self._label_str = None

        self._init_widgets()
        self._update_size()

    def _init_widgets(self):

        self._label_str = "%#x" % self.state.addr

        return

        # label
        label = QLabel()
        label.setText('%#x' % self.state.addr)

        # the select button

        path_button = QPushButton()
        path_button.setText('Select')
        path_button.released.connect(self._on_path_button_released)

        # the disasm button

        disasm_button = QPushButton()
        disasm_button.setText('Disasm')
        disasm_button.released.connect(self._on_disasm_button_released)

        sublayout = QHBoxLayout()
        sublayout.addWidget(path_button)
        sublayout.addWidget(disasm_button)

        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addLayout(sublayout)

        self.setLayout(layout)

    def paint(self, painter):
        """
        Paint a state block on the scene.

        :param painter:
        :return: None
        """

        # The node background
        painter.setBrush(QColor(0xfa, 0xfa, 0xfa))
        painter.setPen(QPen(QColor(0xf0, 0xf0, 0xf0), 1.5))
        painter.drawRect(self.x, self.y, self.width, self.height)

        x = self.x
        y = self.y

        # The label
        painter.setPen(Qt.black)
        painter.drawText(x, self.y + self._config.symexec_font_ascent, self._label_str)

    #
    # Events
    #

    def _on_path_button_released(self):
        self.selected = True
        self.symexec_view.view_path(self.state)

    def _on_disasm_button_released(self):
        disasm_view = self._workspace.views_by_category['disassembly'][0]
        disasm_view.jump_to(self.state.addr)

        self._workspace.raise_view(disasm_view)

    #
    # Private methods
    #

    def _update_size(self):
        self._width = 100
        self._height = 50
