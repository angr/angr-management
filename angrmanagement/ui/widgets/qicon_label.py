from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

if TYPE_CHECKING:
    from PySide6.QtGui import QIcon


class QIconLabel(QWidget):
    """
    Show a label with an icon on the left.
    """

    clicked = Signal()

    def __init__(self, icon: QIcon, text: str = "") -> None:
        super().__init__()
        lyt = QHBoxLayout()
        lyt.setContentsMargins(0, 0, 0, 0)

        self._icon_label = QLabel()
        self._icon_label.setPixmap(icon.pixmap(QSize(16, 16)))
        lyt.addWidget(self._icon_label)

        self._text_label = QLabel(text)
        lyt.addWidget(self._text_label)

        self.setLayout(lyt)
        self._update_visibility()

    def mouseReleaseEvent(self, _) -> None:
        self.clicked.emit()

    def setText(self, text: str) -> None:
        self._text_label.setText(text)
        self._update_visibility()

    def _update_visibility(self) -> None:
        self._text_label.setVisible(self._text_label.text() != "")
