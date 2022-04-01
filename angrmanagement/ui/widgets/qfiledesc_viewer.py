import os
import typing
from PySide2.QtWidgets import QFileDialog, QFrame, QComboBox, QMessageBox, QPushButton, QVBoxLayout, QTextEdit
from angr.storage.file import SimFileDescriptor


if typing.TYPE_CHECKING:
    from angr.sim_state import SimState


class QFileDescriptorViewer(QFrame):
    """
    embeded in `StateInspector`
    Display content of a file descriptor ( include stdin/stdout/stderr ) for the selected state.
    """
    STD = {
        0: "stdin",
        1: "stdout",
        2: "stderr",
    }

    def __init__(self, state, parent, workspace):
        super().__init__(parent)

        self._state = state  # type: SimState
        self.workspace = workspace

        self.select_fd = None
        self._current_fd = None
        self.textedit = None

        self._state.am_subscribe(self._watch_state)

    def dump_fd(self, fd):
        # Clean up when nothing is selected
        if fd == -1:
            self._current_fd = None
            self.textedit.setPlainText("")
            return

        if self._state.am_none:
            return
        self._current_fd = fd
        self.textedit.setPlainText(
            self._state.posix.dumps(fd).decode(
                "ascii", "ignore").replace("\x00", "\\x00")
        )

    def save_as(self):
        if self._state.am_none or self._current_fd is None:
            return
        filename, folder = QFileDialog.getSaveFileName(self,"Save content to ...","","Any file (*);")
        if filename and folder:
            save_to = os.path.join(folder, filename)
            open(save_to,"wb").write(self._state.posix.dumps(self._current_fd))

    def _init_widgets(self):
        layout = QVBoxLayout()
        self.select_fd = QComboBox(self)
        self.select_fd.currentIndexChanged.connect(self.dump_fd)
        layout.addWidget(self.select_fd)

        self.textedit = QTextEdit(self)
        self.textedit.setAcceptRichText(False)
        self.textedit.setReadOnly(True)
        layout.addWidget(self.textedit)

        save_as = QPushButton("Save as...", self)
        save_as.clicked.connect(self.save_as)
        layout.addWidget(save_as)

        self.setLayout(layout)

    def _watch_state(self, **kwargs):  # pylint: disable=unused-argument
        if self._state.am_none:
            return
        if self.select_fd is None:
            self._init_widgets()
        self.select_fd.clear()
        for fd, simfile in self._state.posix.fd.items():
            if fd in self.STD:
                self.select_fd.addItem(self.STD[fd])
            elif isinstance(simfile, SimFileDescriptor):
                self.select_fd.addItem(str(simfile.file.name))
            else:
                self.select_fd.addItem(str(simfile))
