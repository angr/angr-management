from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.ui.widgets.qbookmark_table import QBookmarkTable

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class BookmarksView(InstanceView):
    """
    Lists the bookmarked addresses, with inline-editable labels.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("bookmarks", workspace, default_docking_position, instance)
        self.base_caption = "Bookmarks"

        self._table: QBookmarkTable

        self._init_widgets()

        self.instance.annotations.bookmarks.am_subscribe(self._on_bookmarks_changed)

        self.width_hint = 500
        self.height_hint = 0
        self.updateGeometry()

        self.reload()

    @staticmethod
    def minimumSizeHint() -> QSize:
        return QSize(200, 100)

    def reload(self) -> None:
        self._table.reload()

    def refresh(self) -> None:
        self._table.reload()

    def closeEvent(self, event) -> None:
        self.instance.annotations.bookmarks.am_unsubscribe(self._on_bookmarks_changed)
        super().closeEvent(event)

    #
    # Events
    #

    def _on_bookmarks_changed(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.reload()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._table = QBookmarkTable(self.workspace, self.instance, self)
        layout = QVBoxLayout()
        layout.addWidget(self._table)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
