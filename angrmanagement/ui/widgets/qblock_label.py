
from PySide.QtGui import QLabel


class QBlockLabel(QLabel):
    def __init__(self, addr, text, parent):
        super(QBlockLabel, self).__init__(parent)

        self.addr = addr

        self.setText(text)

    @property
    def label(self):
        return self.text()

    @label.setter
    def label(self, v):
        self.setText(v)
