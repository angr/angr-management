from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QFontDialog, QPushButton

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from PySide6.QtGui import QFont


class QFontOption(QPushButton):
    """
    A widget used to allow users to change a font stored in Conf
    """

    def __init__(self, config_key: str, parent=None) -> None:
        """
        :param key: Key of the font in Conf
        :parent:    Optional parent of this QWidget
        """
        super().__init__(parent)
        self._config_key = config_key
        self.font: QFont = getattr(Conf, config_key)
        self.released.connect(self._prompt)
        self._format()

    def update(self) -> None:
        """
        Update Conf with the selected font
        """
        setattr(Conf, self._config_key, self.font)

    def _format(self) -> None:
        """
        Format the widget's UI elements
        """
        self.setText(f"{self.font.family()}, {self.font.pointSize()} pt")
        self.setFont(self.font)  # We do not ._sync.keep_synced this; it should update always

    def _prompt(self) -> None:
        """
        Prompt the user to select a font
        """
        ok, font = QFontDialog.getFont(self.font, parent=self)
        if ok:
            self.font = font
            self._format()
