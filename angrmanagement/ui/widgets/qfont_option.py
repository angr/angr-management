from typing import TYPE_CHECKING

from PySide6.QtWidgets import QFontDialog, QHBoxLayout, QLabel, QPushButton, QWidget

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from PySide6.QtGui import QFont


class QFontOption(QWidget):
    """
    A widget used to allow users to change a font stored in Conf
    """

    def __init__(self, name: str, key: str, parent=None):
        """
        :param name: The name of the font
        :param key: The key of the font in Conf
        :parent: The optional parent of this QWidget
        """
        super().__init__(parent)
        self.name: str = name
        self._key = key
        self.font: QFont = getattr(Conf, key)
        layout = QHBoxLayout(self)
        # Label
        self.label = QLabel(parent=self)
        layout.addWidget(self.label)
        # Button
        self.button = QPushButton("Change", parent=self)
        self.button.released.connect(self._prompt)
        layout.addWidget(self.button)
        # Finish
        self.setLayout(layout)
        self._format()

    def update(self):
        """
        Update Conf with the selected font
        """
        setattr(Conf, self._key, self.font)

    def _format(self):
        """
        Format the widget's UI elements
        """
        self.label.setText(f"{self.name}: {self.font.family()}")
        self.label.setFont(self.font)  # We do not ._sync.keep_synced this; it should update always

    def _prompt(self):
        """
        Prompt the user to select a font
        """
        ok, font = QFontDialog.getFont(self.font, parent=self)
        if ok:
            self.font = font
            self._format()
