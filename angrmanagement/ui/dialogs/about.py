import os

from PySide2.QtWidgets import QDialog, QLabel, QVBoxLayout, QHBoxLayout
from PySide2.QtGui import QIcon, QPixmap, QFont
from PySide2.QtCore import Qt
import angr

from ...config import IMG_LOCATION


class LoadAboutDialog(QDialog):
    """
    Dialog that shows application version, credits, etc.
    """

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.setWindowTitle('About')
        #mdiIcon
        angr_icon_location = os.path.join(IMG_LOCATION, 'angr.png')
        self.setWindowIcon(QIcon(angr_icon_location))
        self._init_widgets()

    def _init_widgets(self):
        # icon
        icon_label = QLabel(self)
        icon_location = os.path.join(IMG_LOCATION, 'angr-ds.png')
        angr_icon = QPixmap(icon_location)
        icon_label.setPixmap(angr_icon)
        # textbox
        angr_text = QLabel("angr")
        angr_text.setFont(QFont("Consolas", 24, weight=QFont.Bold))
        version_text_tup = "Version: " + ".".join(str(x) for x in angr.__version__[0:4])
        version_text = QLabel(version_text_tup)
        version_text.setFont(QFont("Consolas", weight=QFont.Bold))
        version_text.setAlignment(Qt.AlignCenter)
        credits_text = QLabel("<a href=\"http://angr.io/\">Credits</a>")
        credits_text.setFont(QFont("Consolas", weight=QFont.Bold))
        credits_text.setTextFormat(Qt.RichText)
        credits_text.setTextInteractionFlags(Qt.TextBrowserInteraction)
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
