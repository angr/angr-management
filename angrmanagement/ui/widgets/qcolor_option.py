from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QColorDialog, QFrame, QHBoxLayout, QLabel, QWidget

from angrmanagement.data.object_container import ObjectContainer

if TYPE_CHECKING:
    from PySide6.QtGui import QColor


class QColorOption(QWidget):
    def __init__(self, color: QColor, label: str, parent=None) -> None:
        super().__init__(parent=parent)

        self.color = ObjectContainer(color, "The current color")
        self.label = label

        self._init_widgets()

    def set_color(self, color) -> None:
        self.color.am_obj = color
        self.color.am_event()

    def mouseReleaseEvent(self, event) -> None:  # pylint:disable=unused-argument
        dialog = QColorDialog()
        dialog.setCurrentColor(self.color.am_obj)
        dialog.exec()
        if dialog.result() == QColorDialog.DialogCode.Accepted:
            self.set_color(dialog.currentColor())

    def _init_widgets(self) -> None:
        layout = QHBoxLayout()
        frame = QFrame()
        frame.setFixedWidth(30)
        frame.setFixedHeight(15)

        def update_color(**kwargs) -> None:  # pylint:disable=unused-argument
            r, g, b, a = self.color.getRgb()
            frame.setStyleSheet(f"background-color: rgba({r},{g},{b},{a});")

        update_color()
        self.color.am_subscribe(update_color)

        text = QLabel(self.label)

        layout.addWidget(frame)
        layout.addWidget(text)
        self.setLayout(layout)
