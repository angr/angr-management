from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton
from PySide2.QtCore import QSize, Qt

from ..widgets.qxref_viewer import QXRefViewer, XRefMode


class XRef(QDialog):
    def __init__(self, addr=None, variable_manager=None, variable=None, xrefs_manager=None, dst_addr=None,
                 instance=None, parent=None):
        super(XRef, self).__init__(parent)

        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self._variable_manager = variable_manager
        self._variable = variable
        self._xrefs_manager = xrefs_manager
        self._addr = addr  # current address
        self._dst_addr = dst_addr
        self._instance = instance
        self._disassembly_view = parent

        if variable is not None:
            self.setWindowTitle('XRefs to variable %s(%s)' % (variable.name, variable.ident))
        elif dst_addr is not None:
            # is there a label for it?
            try:
                lbl = self._instance.kb.labels.get(dst_addr)
            except KeyError:
                lbl = None
            if lbl is not None:
                self.setWindowTitle('XRefs to %s' % lbl)
            else:
                self.setWindowTitle('XRefs to address %#x' % dst_addr)
        else:
            raise ValueError("Either variable or dst_addr must be specified.")

        self._init_widgets()

    def sizeHint(self, *args, **kwargs):
        return QSize(600, 400)

    def _init_widgets(self):

        # xref viewer
        xref_viewer = QXRefViewer(
            addr=self._addr, variable_manager=self._variable_manager, variable=self._variable,
            xrefs_manager=self._xrefs_manager, dst_addr=self._dst_addr,
            instance=self._instance, disassembly_view=self._disassembly_view, parent=self,
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

    def jump_to(self, addr):
        self._disassembly_view.jump_to(addr, src_ins_addr=self._addr)
        self.close()

    #
    # Event handlers
    #

    def _on_close_clicked(self):
        self.close()
