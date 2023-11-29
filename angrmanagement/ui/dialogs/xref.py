import logging

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QDialog, QVBoxLayout

from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.widgets.qxref_viewer import QXRefViewer

_l = logging.getLogger(__name__)


class XRefDialog(QDialog):
    """
    Dialog displaying cross-references.
    """

    def __init__(
        self,
        addr=None,
        variable_manager=None,
        variable=None,
        xrefs_manager=None,
        dst_addr=None,
        instance=None,
        disassembly_view=None,
        parent=None,
    ):
        super().__init__(parent)

        self._variable_manager = variable_manager
        self._variable = variable
        self._xrefs_manager = xrefs_manager
        self._addr = addr  # current address
        self._dst_addr = dst_addr
        self._instance = instance
        self._disassembly_view = disassembly_view

        if variable is not None:
            self.setWindowTitle(f"XRefs to variable {variable.name}({variable.ident})")
        elif dst_addr is not None:
            # is there a label for it?
            try:
                lbl = self._instance.kb.labels.get(dst_addr)
            except KeyError:
                lbl = None
            if lbl is not None:
                self.setWindowTitle(f"XRefs to {lbl}")
            else:
                self.setWindowTitle(f"XRefs to address {dst_addr:#x}")
        else:
            raise ValueError("Either variable or dst_addr must be specified.")

        self._init_widgets()

        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint | Qt.WindowCloseButtonHint)
        self.setMinimumSize(self.sizeHint())
        self.adjustSize()

    def sizeHint(self, *args, **kwargs):  # pylint: disable=unused-argument,no-self-use
        return QSize(600, 400)

    def _init_widgets(self):
        # xref viewer
        xref_viewer = QXRefViewer(
            addr=self._addr,
            variable_manager=self._variable_manager,
            variable=self._variable,
            xrefs_manager=self._xrefs_manager,
            dst_addr=self._dst_addr,
            instance=self._instance,
            xref_dialog=self,
            parent=self,
        )

        layout = QVBoxLayout()
        layout.addWidget(xref_viewer)

        self.setLayout(layout)

    def jump_to(self, addr):
        self.close()
        disasm_view = self._disassembly_view
        if disasm_view is None:
            GlobalInfo.main_window.workspace.jump_to(addr)
        else:
            disasm_view.jump_to(addr, src_ins_addr=self._addr)
            disasm_view.focus()
