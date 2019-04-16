import angr

from PySide2.QtWidgets import QDialog, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QPushButton
from PySide2.QtGui import QIcon, QDesktopServices, QPixmap
from PySide2.QtCore import Qt, QSize, QEvent, QUrl

from angr.misc.bug_report import get_version


class LoadAboutDialog(QDialog):
    def __init__(self):
        super(LoadAboutDialog, self).__init__()

        self.setWindowTitle('about Angr')

        self._init_widgets()

    def sizeHint(self, *args, **kwargs):
        return QSize(600, 400)

    def _init_widgets(self):
        # icon
        icon_label = QLabel(self)
        angr_icon = QPixmap('angr.png')
        icon_label.setPixmap(angr_icon)
        # textbox
        about_text = QLabel("About Angr")
        version_text = QLabel("Angr version " + get_version())
        credits_text = QLabel("<a href=\"http://angr.io/\">Credits</a>")
        credits_text.setTextFormat(Qt.RichText)
        credits_text.setTextInteractionFlags(Qt.TextBrowserInteraction)
        credits_text.setOpenExternalLinks(True)
        # buttons
        btn_ok = QPushButton('OK')
        btn_ok.clicked.connect(self._on_close_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(btn_ok)

        layout = QVBoxLayout()
        layout.addWidget(icon_label)
        layout.addWidget(about_text)
        layout.addWidget(version_text)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

        #
        # Event handlers
        #

    def _on_close_clicked(self):
        self.close()
