from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QLabel, QPlainTextEdit, QVBoxLayout

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class QCommentTextBox(QPlainTextEdit):
    """
    Multiline text box for comment entry.
    """

    def __init__(self, textchanged_callback=None, textconfirmed_callback=None, parent=None) -> None:
        super().__init__(parent)
        if textchanged_callback is not None:
            self.textChanged.connect(textchanged_callback)
        self._textconfirmed_callback = textconfirmed_callback

    @property
    def text(self):
        text = self.toPlainText()
        if text is not None:
            return text.strip()
        return None

    def keyReleaseEvent(self, event):
        if (
            event.key() == Qt.Key_Return
            and QApplication.keyboardModifiers() == Qt.ControlModifier
            and self._textconfirmed_callback is not None
        ):
            self._textconfirmed_callback()
            return True
        return super().keyReleaseEvent(event)


class SetComment(QDialog):
    """
    Dialog for setting comment.
    """

    def __init__(self, workspace: Workspace, comment_addr, parent=None) -> None:
        super().__init__(parent)

        # initialization
        self._workspace = workspace
        self._comment_addr = comment_addr

        self._comment_textbox: QCommentTextBox

        self.setWindowTitle("Set Comment")
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        # name label
        comment_lbl = QLabel(self)
        comment_lbl.setText("Comment text")

        # comment textbox
        comment_txtbox = QCommentTextBox(textconfirmed_callback=self._on_ok_clicked, parent=self)
        if self._comment_addr in self._workspace.main_instance.project.kb.comments:
            comment_txtbox.setPlainText(self._workspace.main_instance.project.kb.comments[self._comment_addr])
            comment_txtbox.selectAll()
        self._comment_textbox = comment_txtbox

        comment_layout = QVBoxLayout()
        comment_layout.addWidget(comment_lbl)
        comment_layout.addWidget(comment_txtbox)
        self.main_layout.addLayout(comment_layout)

        # buttons
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)
        self.main_layout.addWidget(buttons)

    #
    # Event handlers
    #

    def _on_ok_clicked(self) -> None:
        comment_txt = self._comment_textbox.text
        self._workspace.set_comment(self._comment_addr, comment_txt)
        self.close()
