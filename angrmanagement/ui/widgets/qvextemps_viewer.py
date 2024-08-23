from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QScrollArea, QSizePolicy, QVBoxLayout

from .qast_viewer import QASTViewer

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class QVEXTempsViewer(QFrame):
    def __init__(self, state, parent, workspace: Workspace) -> None:
        super().__init__(parent)
        self.workspace = workspace

        self.state = state

        # widgets
        self._area = None
        self._tmps = {}

        self._init_widgets()

    #
    # Overridden methods
    #

    def sizeHint(self):
        return QSize(100, 100)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        area = QScrollArea()
        area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        area.setWidgetResizable(True)

        self._area = area

        base_layout = QVBoxLayout()
        base_layout.addWidget(area)
        self.setLayout(base_layout)

    def _load_tmps(self) -> None:
        state = self.state.am_obj

        layout = QVBoxLayout()

        self._tmps.clear()
        tmps = {} if state is None else state.scratch.temps

        # tmps
        for tmp_id, tmp_value in tmps.items():
            sublayout = QHBoxLayout()

            lbl_tmp_name = QLabel(self)
            lbl_tmp_name.setProperty("class", "reg_viewer_label")
            lbl_tmp_name.setText("tmp_%d" % tmp_id)
            lbl_tmp_name.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            sublayout.addWidget(lbl_tmp_name)

            sublayout.addSpacing(10)

            tmp_viewer = QASTViewer(tmp_value, workspace=self.workspace, parent=self)
            self._tmps[tmp_id] = tmp_viewer
            sublayout.addWidget(tmp_viewer)

            layout.addLayout(sublayout)

        layout.setSpacing(0)
        layout.addStretch(0)
        layout.setContentsMargins(2, 2, 2, 2)

        # the container
        container = QFrame()
        container.setAutoFillBackground(True)
        palette = container.palette()
        palette.setColor(container.backgroundRole(), Qt.GlobalColor.white)
        container.setPalette(palette)
        container.setLayout(layout)

        self._area.setWidget(container)

    def _watch_state(self, **_) -> None:
        self._load_tmps()
