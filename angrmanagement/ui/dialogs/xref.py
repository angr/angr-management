from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton
from PySide2.QtCore import QSize

from ..widgets.qxref_viewer import QXRefViewer, XRefMode


class XRef(QDialog):
    def __init__(self, variable_manager=None, variable=None, xrefs_manager=None, dst_addr=None, parent=None):
        super(XRef, self).__init__(parent)

        self._variable_manager = variable_manager
        self._variable = variable
        self._xrefs_manager = xrefs_manager
        self._dst_addr = dst_addr

        if variable is not None:
            self.setWindowTitle('XRefs to variable %s(%s)' % (variable.name, variable.ident))
        elif dst_addr is not None:
            self.setWindowTitle('XRefs to address %#x' % dst_addr)
        else:
            raise ValueError("Either variable or dst_addr must be specified.")

        self._init_widgets()

    def sizeHint(self, *args, **kwargs):
        return QSize(600, 200)

    def _init_widgets(self):

        # xref viewer
        xref_viewer = QXRefViewer(
            variable_manager=self._variable_manager, variable=self._variable,
            xrefs_manager=self._xrefs_manager, dst_addr=self._dst_addr,
        )

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
