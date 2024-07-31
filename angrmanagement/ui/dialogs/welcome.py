from __future__ import annotations

import functools
import os.path

from PySide6.QtGui import QPixmap, Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QGraphicsScene,
    QGraphicsView,
    QGroupBox,
    QHBoxLayout,
    QPushButton,
    QVBoxLayout,
)

from angrmanagement import __version__
from angrmanagement.config import IMG_LOCATION, Conf
from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.icons import icon


class WelcomeDialog(QDialog):
    """
    Welcome dialog.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Welcome")
        self._init_widgets()

    def _init_widgets(self) -> None:
        self.setStyleSheet("QPushButton { text-align:left; }")

        # Banner with angr-management version string
        banner_pixmap = QPixmap(os.path.join(IMG_LOCATION, "angr-splash.png"))
        banner_view = QGraphicsView(self)
        banner_view.setContentsMargins(0, 0, 0, 0)
        banner_view.setFrameStyle(QFrame.Shape.NoFrame)
        banner_view.resize(banner_pixmap.size())
        banner_scene = QGraphicsScene()
        banner_view.setScene(banner_scene)
        pi = banner_scene.addPixmap(banner_pixmap)
        font = QApplication.font()
        font.setPointSizeF(9.0)
        ti = banner_scene.addSimpleText(__version__, font)
        ti.setBrush(Qt.GlobalColor.white)
        ti.moveBy(pi.boundingRect().width() - ti.boundingRect().width() - 6, 6)

        # Recent files
        recent_files_group = QGroupBox("Recent Projects")
        recent_files_layout = QVBoxLayout()
        recent_files_group.setLayout(recent_files_layout)

        for path in reversed(Conf.recent_files):
            pb = QPushButton(icon("file"), os.path.basename(path))
            pb.setFlat(True)
            pb.clicked.connect(functools.partial(self._load_recent_file, path))
            recent_files_layout.addWidget(pb)

        recent_files_layout.addStretch()

        # Getting Started actions
        actions_group = QGroupBox("Getting Started")
        actions_layout = QVBoxLayout()

        pb = QPushButton(icon("file-open"), "Open file...")
        pb.setFlat(True)
        pb.clicked.connect(self._open_file)
        actions_layout.addWidget(pb)

        pb = QPushButton(icon("docs"), "Documentation")
        pb.setFlat(True)
        pb.clicked.connect(GlobalInfo.main_window.open_doc_link)
        actions_layout.addWidget(pb)

        pb = QPushButton(icon("about"), "About...")
        pb.setFlat(True)
        pb.clicked.connect(GlobalInfo.main_window.open_about_dialog)
        actions_layout.addWidget(pb)
        actions_layout.addStretch()
        actions_group.setLayout(actions_layout)

        main_layout = QHBoxLayout()
        main_layout.addWidget(recent_files_group)
        main_layout.addWidget(actions_group)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)

        outer_layout = QVBoxLayout()
        outer_layout.setSpacing(0)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(banner_view)
        outer_layout.addLayout(main_layout)
        self.setLayout(outer_layout)

    def _load_recent_file(self, path) -> None:
        GlobalInfo.main_window.load_file(path)
        self.close()

    def _open_file(self) -> None:
        GlobalInfo.main_window.open_file_button()
        self.close()
