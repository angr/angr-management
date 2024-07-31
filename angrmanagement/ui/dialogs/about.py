from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon, QPixmap
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QVBoxLayout

import angrmanagement
from angrmanagement.config import IMG_LOCATION


class LoadAboutDialog(QDialog):
    """
    Dialog that shows application version, credits, etc.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowFlags(Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint)
        self.setWindowTitle("About")
        # mdiIcon
        angr_icon_location = os.path.join(IMG_LOCATION, "angr.png")
        self.setWindowIcon(QIcon(angr_icon_location))
        self._init_widgets()

    def _init_widgets(self) -> None:
        # icon
        icon_label = QLabel(self)
        icon_location = os.path.join(IMG_LOCATION, "angr-ds.png")
        angr_icon = QPixmap(icon_location)
        icon_label.setPixmap(angr_icon)
        # textbox
        angr_text = QLabel("angr")
        angr_text.setFont(QFont("Consolas", 24, weight=QFont.Weight.Bold))
        version_text_tup = "Version: " + angrmanagement.__version__
        version_text = QLabel(version_text_tup)
        version_text.setFont(QFont("Consolas", weight=QFont.Weight.Bold))
        version_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        credits_text = QLabel('<a href="http://angr.io/">Credits</a>')
        credits_text.setFont(QFont("Consolas", weight=QFont.Weight.Bold))
        credits_text.setTextFormat(Qt.TextFormat.RichText)
        credits_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        credits_text.setOpenExternalLinks(True)

        structure = QVBoxLayout()
        structure.addWidget(angr_text)
        structure.addWidget(version_text)
        structure.addWidget(credits_text)

        layout = QHBoxLayout()
        layout.addWidget(icon_label)
        layout.addLayout(structure)

        self.setLayout(layout)

        #
        # Event handlers
        #
