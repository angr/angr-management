
from PySide2.QtWidgets import QPlainTextEdit
from PySide2.QtCore import Qt, QEvent


class QCCodeEdit(QPlainTextEdit):
    def __init__(self, code_view):
        super().__init__()

        self._code_view = code_view
        self.setTabChangesFocus(False)
        self.setReadOnly(True)

    @property
    def workspace(self):
        return self._code_view.workspace if self._code_view is not None else None

    def event(self, event):
        """
        Reimplemented to capture the Tab key pressed event.

        :param event:
        :return:
        """

        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.keyPressEvent(event)
            return True

        return super().event(event)


    def keyPressEvent(self, key_event):
        key = key_event.key()
        if key == Qt.Key_Tab:
            # Switch back to disassembly view
            self.workspace.jump_to(self._code_view.function.addr)
            return True

        super().keyPressEvent(key_event)
