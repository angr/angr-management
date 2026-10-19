from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.present.comments import CommentsPresenter
from angrmanagement.ui.widgets.qcomment_table import QCommentTable

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class CommentsView(InstanceView):
    """
    Lists every comment in the project, live-updating as comments are added and removed.
    """

    presenter: CommentsPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "comments",
            workspace,
            default_docking_position,
            instance,
            CommentsPresenter(workspace, instance, default_docking_position),
        )
        self.base_caption = "Comments"

        self._comment_table: QCommentTable

        self._init_widgets()

        self.width_hint = 500
        self.height_hint = 0
        self.updateGeometry()

        self.reload()

    @staticmethod
    def minimumSizeHint() -> QSize:
        return QSize(200, 100)

    def reload(self) -> None:
        self._comment_table.reload()

    def refresh(self) -> None:
        self._comment_table.reload()

    def closeEvent(self, event) -> None:
        self.presenter.close()
        super().closeEvent(event)

    #
    # Events
    #

    def _on_comments_changed(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.reload()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._comment_table = QCommentTable(self, self.workspace, self.instance, self.presenter)
        layout = QVBoxLayout()
        layout.addWidget(self._comment_table)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
