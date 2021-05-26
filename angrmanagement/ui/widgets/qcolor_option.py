from PySide2.QtGui import QColor
from PySide2.QtWidgets import QWidget, QHBoxLayout, QFrame, QLabel, QColorDialog

from ...data.object_container import ObjectContainer


class QColorOption(QWidget):
    def __init__(self, color: QColor, label: str, parent=None):
        super().__init__(parent=parent)

        self.color = ObjectContainer(color, "The current color")
        self.label = label

        self._init_widgets()

    def set_color(self, color):
        self.color.am_obj = color
        self.color.am_event()

    def mouseReleaseEvent(self, event): # pylint:disable=unused-argument
        dialog = QColorDialog()
        dialog.setCurrentColor(self.color.am_obj)
        dialog.exec()
        if dialog.result() == QColorDialog.Accepted:
            self.set_color(dialog.currentColor())

    def _init_widgets(self):
        layout = QHBoxLayout()
        frame = QFrame()
        frame.setFixedWidth(30)
        frame.setFixedHeight(15)

        def update_color(**kwargs): # pylint:disable=unused-argument
            r,g,b,a = self.color.getRgb()
            frame.setStyleSheet(f"background-color: rgba({r},{g},{b},{a});")
        update_color()
        self.color.am_subscribe(update_color)

        text = QLabel(self.label)

        layout.addWidget(frame)
        layout.addWidget(text)
        self.setLayout(layout)
