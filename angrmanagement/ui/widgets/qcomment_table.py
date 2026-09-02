from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, QEvent, Qt
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QVBoxLayout, QWidget

from angrmanagement.config import Conf
from angrmanagement.data.annotations import CommentKind
from angrmanagement.ui.icons import icon

from .qfast_table_view import QFastTableView

if TYPE_CHECKING:
    import PySide6

    from angrmanagement.data.annotations import Comment
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QCommentTableModel(QAbstractTableModel):
    """
    Table model listing every comment in the project.
    """

    Headers = ["Address", "Function", "Kind", "Comment"]
    ADDRESS_COL = 0
    FUNCTION_COL = 1
    KIND_COL = 2
    COMMENT_COL = 3

    def __init__(self) -> None:
        super().__init__()
        self._comments: list[Comment] = []
        self._raw_comments: list[Comment] = []
        self._filter_keyword: str = ""

    #
    # Properties
    #

    @property
    def comments(self) -> list[Comment]:
        return self._comments

    @comments.setter
    def comments(self, v: list[Comment]) -> None:
        self.beginResetModel()
        self._raw_comments = v
        self._apply_filter()
        self.endResetModel()

    #
    # Public methods
    #

    def filter(self, keyword: str) -> None:
        self.layoutAboutToBeChanged.emit()
        self._filter_keyword = keyword
        self._apply_filter()
        self.layoutChanged.emit()

    def comment_at(self, row: int) -> Comment | None:
        if 0 <= row < len(self._comments):
            return self._comments[row]
        return None

    #
    # QAbstractTableModel
    #

    def rowCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return len(self._comments)

    def columnCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return len(self.Headers)

    def headerData(self, section: int, orientation: PySide6.QtCore.Qt.Orientation, role: int = ...) -> Any:  # pylint:disable=unused-argument
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def data(self, index: PySide6.QtCore.QModelIndex, role: int = ...) -> Any:
        if not index.isValid():
            return None
        comment = self.comment_at(index.row())
        if comment is None:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._get_column_text(comment, index.column())
        if role == Qt.ItemDataRole.ToolTipRole:
            return comment.text
        if role == Qt.ItemDataRole.FontRole:
            return Conf.tabular_view_font
        return None

    def sort(self, column: int, order=None) -> None:
        self.layoutAboutToBeChanged.emit()
        self._raw_comments = sorted(
            self._raw_comments,
            key=lambda c: self._get_column_data(c, column),
            reverse=order == Qt.SortOrder.DescendingOrder,
        )
        self._apply_filter()
        self.layoutChanged.emit()

    #
    # Private methods
    #

    def _apply_filter(self) -> None:
        if not self._filter_keyword:
            self._comments = list(self._raw_comments)
        else:
            keyword = self._filter_keyword.lower()
            self._comments = [c for c in self._raw_comments if self._match_keyword(c, keyword)]

    @staticmethod
    def _match_keyword(comment: Comment, keyword: str) -> bool:
        return (
            keyword in comment.text.lower()
            or keyword in f"{comment.addr:x}"
            or keyword in f"{comment.addr:#x}"
            or keyword in comment.kind.display_name.lower()
            or (comment.func_name is not None and keyword in comment.func_name.lower())
        )

    @staticmethod
    def _get_column_data(comment: Comment, column: int) -> Any:
        if column == QCommentTableModel.ADDRESS_COL:
            return comment.addr
        if column == QCommentTableModel.FUNCTION_COL:
            return comment.func_name or ""
        if column == QCommentTableModel.KIND_COL:
            return int(comment.kind)
        if column == QCommentTableModel.COMMENT_COL:
            return comment.first_line
        return None

    @staticmethod
    def _get_column_text(comment: Comment, column: int) -> str:
        if column == QCommentTableModel.ADDRESS_COL:
            return f"{comment.addr:#x}"
        if column == QCommentTableModel.FUNCTION_COL:
            return comment.func_name or ""
        if column == QCommentTableModel.KIND_COL:
            return comment.kind.display_name
        if column == QCommentTableModel.COMMENT_COL:
            first_line = comment.first_line
            return first_line + " ..." if "\n" in comment.text else first_line
        return ""


class QCommentTableView(QFastTableView):
    """
    The comment table itself.
    """

    def __init__(self, parent: QCommentTable, workspace: Workspace, instance: Instance) -> None:
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance
        self._comment_table: QCommentTable = parent

        header = self.header()
        header.setSectionsClickable(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        header.setSortIndicatorShown(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.set_row_height(24)

        self._model = QCommentTableModel()
        self.setModel(self._model)

        for idx, width in enumerate([110, 150, 90]):
            header.resizeSection(idx, width)

        self.row_double_clicked.connect(self._on_row_double_clicked)
        self.context_menu_requested.connect(self._on_context_menu_requested)
        self.key_pressed.connect(self._on_key_pressed)

    #
    # Public methods
    #

    def reload(self) -> None:
        self._model.comments = list(self.instance.annotations.iter_comments())
        self.viewport_update()

    def filter(self, keyword: str) -> None:
        self._model.filter(keyword)
        self.viewport_update()

    def selected_comments(self) -> list[Comment]:
        return [c for c in (self._model.comment_at(r) for r in self.selected_rows()) if c is not None]

    #
    # Events
    #

    def _on_row_double_clicked(self, row: int) -> None:
        comment = self._model.comment_at(row)
        if comment is not None:
            self.workspace.jump_to(comment.addr)

    def _on_key_pressed(self, text: str) -> None:
        self._comment_table.show_filter_box(prefix=text)

    def _on_context_menu_requested(self, global_pos) -> None:
        comments = self.selected_comments()
        if not comments:
            return
        menu = QMenu("", self)
        if len(comments) == 1:
            menu.addAction("Edit comment...", lambda: self._edit_comment(comments[0]))
            menu.addAction("Copy text", lambda: self._copy_text(comments[0]))
            menu.addSeparator()
            kind_menu = menu.addMenu("Change kind to")
            for kind in CommentKind:
                action = kind_menu.addAction(kind.display_name, lambda k=kind: self._set_kind(comments[0], k))
                action.setCheckable(True)
                action.setChecked(comments[0].kind == kind)
            menu.addSeparator()
        menu.addAction("Delete" + ("" if len(comments) == 1 else f" ({len(comments)})"), lambda: self._delete(comments))
        menu.exec_(global_pos)

    #
    # Private methods
    #

    def _edit_comment(self, comment: Comment) -> None:
        from angrmanagement.ui.dialogs.set_comment import SetComment  # pylint:disable=import-outside-toplevel

        SetComment(self.workspace, comment.addr, parent=self).exec_()

    @staticmethod
    def _copy_text(comment: Comment) -> None:
        from PySide6.QtWidgets import QApplication  # pylint:disable=import-outside-toplevel

        QApplication.clipboard().setText(comment.text)

    def _set_kind(self, comment: Comment, kind: CommentKind) -> None:
        self.instance.annotations.set_kind(comment.addr, kind)
        self.workspace.refresh_after_comment_change(comment.addr)
        self.instance.annotations.notify_comments_changed(comment.addr)

    def _delete(self, comments: list[Comment]) -> None:
        for comment in comments:
            self.workspace.set_comment(comment.addr, "")


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

    def __init__(self, parent, workspace: Workspace, instance: Instance) -> None:
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance

        self._table_view: QCommentTableView
        self._filter_box: QCommentTableFilterBox
        self._status_label: QLabel

        self._init_widgets()

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
        self._table_view = QCommentTableView(self, self.workspace, self.instance)

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
        shown = self._table_view.row_count()
        total = len(self._table_view._model._raw_comments)
        self._status_label.setText(f"{shown} comments" if shown == total else f"{shown} of {total} comments")

    #
    # Events
    #

    def _on_filter_box_text_changed(self, text: str) -> None:
        self._table_view.filter(text)
        self._update_displayed_comment_count()
