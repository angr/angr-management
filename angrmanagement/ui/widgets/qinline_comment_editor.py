from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLineEdit

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from collections.abc import Callable

    import PySide6
    from PySide6.QtCore import QPoint
    from PySide6.QtWidgets import QWidget


class QInlineCommentEditor(QLineEdit):
    """
    A one-line comment editor floating over the view it edits. Enter commits, Escape cancels.

    Committing empty text is meaningful: it removes the comment.
    """

    MIN_WIDTH = 320

    def __init__(
        self,
        parent: QWidget,
        addr: int,
        text: str,
        on_commit: Callable[[int, str], None],
    ) -> None:
        super().__init__(parent)
        self.addr = addr
        self._on_commit = on_commit
        self._finished = False

        self.setText(text)
        self.selectAll()
        self.setFont(Conf.disasm_font)
        self.setPlaceholderText("Comment (Enter to commit, Esc to cancel)")
        self.setFrame(True)

    #
    # Public methods
    #

    def show_at(self, pos: QPoint, width: int | None = None) -> None:
        self.resize(max(self.MIN_WIDTH, width or 0), self.sizeHint().height())
        self.move(pos)
        self.show()
        self.raise_()
        self.setFocus(Qt.FocusReason.OtherFocusReason)

    def commit(self) -> None:
        if self._finished:
            return
        self._finished = True
        text = self.text().strip()
        self._close()
        self._on_commit(self.addr, text)

    def cancel(self) -> None:
        if self._finished:
            return
        self._finished = True
        self._close()

    #
    # Events
    #

    def keyPressEvent(self, event: PySide6.QtGui.QKeyEvent) -> None:
        key = event.key()
        if key == Qt.Key.Key_Escape:
            self.cancel()
            event.accept()
            return
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.commit()
            event.accept()
            return
        super().keyPressEvent(event)

    def focusOutEvent(self, event: PySide6.QtGui.QFocusEvent) -> None:
        super().focusOutEvent(event)
        self.cancel()

    #
    # Private methods
    #

    def _close(self) -> None:
        self.hide()
        self.setParent(None)
        self.deleteLater()
