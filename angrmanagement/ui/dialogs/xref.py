from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton
from PySide2.QtCore import QSize

from ..widgets.qxref_viewer import QXRefViewer


class XRef(QDialog):
    def __init__(self, variable_manager, variable, parent=None):
        super(XRef, self).__init__(parent)

        self._variable_manager = variable_manager
        self._variable = variable

        self.setWindowTitle('XRefs to %s(%s)' % (variable.name, variable.ident))

        self._init_widgets()

    def sizeHint(self, *args, **kwargs):
        return QSize(600, 200)

    def _init_widgets(self):

        # xref viewer
        xref_viewer = QXRefViewer(self._variable_manager, self._variable)

        # buttons
        btn_ok = QPushButton('OK')

        btn_close = QPushButton('Close')
        btn_close.clicked.connect(self._on_close_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(btn_ok)
        buttons_layout.addWidget(btn_close)

        layout = QVBoxLayout()
        layout.addWidget(xref_viewer)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

    #
    # Event handlers
    #

    def _on_close_clicked(self):
        self.close()
