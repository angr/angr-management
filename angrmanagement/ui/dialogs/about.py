import angr

import os

from PySide2.QtWidgets import QDialog, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QPushButton, QApplication
from PySide2.QtGui import QIcon, QDesktopServices, QPixmap, QFont
from PySide2.QtCore import Qt, QSize, QEvent, QUrl
from ...config import IMG_LOCATION




class LoadAboutDialog(QDialog):
    def __init__(self):
        super(LoadAboutDialog, self).__init__()
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
        # buttons
        btn_ok = QPushButton('OK')
        btn_ok.clicked.connect(self._on_close_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(btn_ok)

        structure = QVBoxLayout()
        structure.addWidget(angr_text)
        structure.addWidget(version_text)
        structure.addWidget(credits_text)
        structure.addLayout(buttons_layout)

        layout = QHBoxLayout()
        layout.addWidget(icon_label)
        layout.addLayout(structure)

        self.setLayout(layout)

        #
        # Event handlers
        #

    def _on_close_clicked(self):
        self.close()
