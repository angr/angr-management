from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QHBoxLayout, QHeaderView, QLabel, QLineEdit, QVBoxLayout, QWidget

from angrmanagement.present.comments import CommentsPresenter, CommentsTableModel
from angrmanagement.ui.icons import icon

from .qfast_table_view import QFastTableView
from .qt_table import QtTableModelAdapter

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.annotations import Comment, CommentKind
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QCommentTableModel(QtTableModelAdapter):
    """
    Qt model over a :class:`~angrmanagement.present.comments.CommentsTableModel`, listing every comment in the
    project.
    """

    Headers = CommentsTableModel.Headers
    ADDRESS_COL = CommentsTableModel.ADDRESS_COL
    FUNCTION_COL = CommentsTableModel.FUNCTION_COL
    KIND_COL = CommentsTableModel.KIND_COL
    COMMENT_COL = CommentsTableModel.COMMENT_COL

    table_model: CommentsTableModel

    def __init__(self, comments_model: CommentsTableModel | None = None) -> None:
        super().__init__(comments_model if comments_model is not None else CommentsTableModel())

    @property
    def comments(self) -> list[Comment]:
        return self.table_model.comments

    @comments.setter
    def comments(self, v: Sequence[Comment]) -> None:
        self.table_model.comments = v

    @property
    def _raw_comments(self) -> list[Comment]:
        return self.table_model.all_rows

    def filter(self, keyword: str) -> None:
        self.table_model.filter(keyword)

    def comment_at(self, row: int) -> Comment | None:
        return self.table_model.comment_at(row)


class QCommentTableView(QFastTableView):
    """
    The comment table itself.
    """

    def __init__(
        self, parent: QCommentTable, workspace: Workspace, instance: Instance, presenter: CommentsPresenter
    ) -> None:
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance
        self.presenter = presenter
        self._comment_table: QCommentTable = parent

        header = self.header()
        header.setSectionsClickable(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        header.setSortIndicatorShown(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.set_row_height(24)

        self._model = QCommentTableModel(presenter.model)
        self.setModel(self._model)

        for idx, width in enumerate([110, 150, 90]):
            header.resizeSection(idx, width)

        self.row_double_clicked.connect(self._on_row_double_clicked)
        self.context_menu_requested.connect(self._on_context_menu_requested)
        self.key_pressed.connect(self._on_key_pressed)

    @property
    def comments_model(self) -> QCommentTableModel:
        return self._model

    #
    # Public methods
    #

    def reload(self) -> None:
        self.presenter.reload()
        self.viewport_update()

    def filter(self, keyword: str) -> None:
        self.comments_model.filter(keyword)
        self.viewport_update()

    def selected_comments(self) -> list[Comment]:
        return [c for c in (self.comments_model.comment_at(r) for r in self.selected_rows()) if c is not None]

    #
    # Events
    #

    def _on_row_double_clicked(self, row: int) -> None:
        self.presenter.model.activate(row)

    def _on_key_pressed(self, text: str) -> None:
        self._comment_table.show_filter_box(prefix=text)

    def _on_context_menu_requested(self, global_pos) -> None:
        menu = self.presenter.comments_menu(self.selected_comments(), edit=self._edit_comment)
        if menu is not None:
            menu.qmenu(cached=False).exec_(global_pos)

    #
    # Private methods
    #

    def _edit_comment(self, comment: Comment) -> None:
        from angrmanagement.ui.dialogs.set_comment import SetComment  # pylint:disable=import-outside-toplevel

        SetComment(self.workspace, comment.addr, parent=self).exec_()

    def _copy_text(self, comment: Comment) -> None:
        self.presenter.copy_text(comment)

    def _set_kind(self, comment: Comment, kind: CommentKind) -> None:
        self.presenter.set_kind(comment, kind)

    def _delete(self, comments: list[Comment]) -> None:
        self.presenter.delete(comments)


class QCommentTableFilterBox(QLineEdit):
    """
    Filter box for the comment table.
    """

    def __init__(self, parent) -> None:
        super().__init__()
        self._table = parent
        self.installEventFilter(self)

    def eventFilter(self, _, event) -> bool:
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Escape:
            if self.text():
                self.setText("")
            else:
                self._table.clear_filter_box()
            return True
        return False


class QCommentTable(QWidget):
    """
    Filterable table of all comments in the project.
    """

    def __init__(self, parent, workspace: Workspace, instance: Instance, presenter: CommentsPresenter | None = None):
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance
        self.presenter = presenter if presenter is not None else CommentsPresenter(workspace, instance)

        self._table_view: QCommentTableView
        self._filter_box: QCommentTableFilterBox
        self._status_label: QLabel

        self._init_widgets()
        self.presenter.model.changed.connect(self._on_model_changed)

    #
    # Public methods
    #

    def reload(self) -> None:
        self._table_view.reload()
        self._update_displayed_comment_count()

    def show_filter_box(self, prefix: str = "") -> None:
        if prefix:
            self._filter_box.setText(prefix)
        self._filter_box.setFocus()

    def clear_filter_box(self) -> None:
        self._filter_box.setText("")
        self._table_view.setFocus()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._table_view = QCommentTableView(self, self.workspace, self.instance, self.presenter)

        self._filter_box = QCommentTableFilterBox(self)
        self._filter_box.setClearButtonEnabled(True)
        self._filter_box.addAction(
            icon("search", color_role=QPalette.ColorRole.PlaceholderText), QLineEdit.ActionPosition.LeadingPosition
        )
        self._filter_box.setPlaceholderText("Filter comments...")
        self._filter_box.textChanged.connect(self._on_filter_box_text_changed)

        self._status_label = QLabel()

        status_lyt = QHBoxLayout()
        status_lyt.setContentsMargins(3, 3, 3, 3)
        status_lyt.setSpacing(3)
        status_lyt.addWidget(self._filter_box)
        status_lyt.addWidget(self._status_label)

        layout = QVBoxLayout()
        layout.addLayout(status_lyt)
        layout.addWidget(self._table_view)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setLayout(layout)

    def _update_displayed_comment_count(self) -> None:
        self._status_label.setText(self.presenter.count_text())

    #
    # Events
    #

    def _on_model_changed(self, *_args) -> None:
        self._table_view.viewport_update()
        self._update_displayed_comment_count()

    def _on_filter_box_text_changed(self, text: str) -> None:
        self._table_view.filter(text)
        self._update_displayed_comment_count()
