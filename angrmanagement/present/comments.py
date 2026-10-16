"""The comments view without a toolkit: every comment in the project, filterable, with its context menu."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from angrmanagement.data.annotations import CommentKind
from angrmanagement.logic import GlobalInfo

from .base import InstancePresenter, ask_text, container
from .keymap import table_keymap
from .menus import Menu, MenuEntry, MenuSeparator
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.annotations import Comment
    from angrmanagement.data.instance import Instance

    from .keymap import Keymap


class CommentsTableModel(ListTableModel["Comment"]):
    """Every comment in the project; the full text is the tooltip of each cell."""

    ADDRESS_COL = 0
    FUNCTION_COL = 1
    KIND_COL = 2
    COMMENT_COL = 3

    COLUMNS: ClassVar[list[Column]] = [
        Column("Address", 14),
        Column("Function", 19),
        Column("Kind", 11),
        Column("Comment", stretch=True),
    ]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, presenter: CommentsPresenter | None = None) -> None:
        super().__init__()
        self.presenter = presenter

    @property
    def comments(self) -> list[Comment]:
        return self.rows

    @comments.setter
    def comments(self, comments: Sequence[Comment]) -> None:
        self.set_rows(comments)

    def comment_at(self, row: int) -> Comment | None:
        return self.row(row)

    def matches(self, obj: Comment, keyword: str) -> bool:
        return (
            keyword in obj.text.lower()
            or keyword in f"{obj.addr:x}"
            or keyword in f"{obj.addr:#x}"
            or keyword in obj.kind.display_name.lower()
            or (obj.func_name is not None and keyword in obj.func_name.lower())
        )

    def column_value(self, obj: Comment, col: int) -> Any:
        if col == self.ADDRESS_COL:
            return obj.addr
        if col == self.FUNCTION_COL:
            return obj.func_name or ""
        if col == self.KIND_COL:
            return int(obj.kind)
        if col == self.COMMENT_COL:
            return obj.first_line
        return None

    def column_text(self, obj: Comment, col: int) -> str:
        if col == self.ADDRESS_COL:
            return f"{obj.addr:#x}"
        if col == self.FUNCTION_COL:
            return obj.func_name or ""
        if col == self.KIND_COL:
            return obj.kind.display_name
        if col == self.COMMENT_COL:
            first_line = obj.first_line
            return first_line + " ..." if "\n" in obj.text else first_line
        return ""

    def tooltip(self, obj: Comment, col: int) -> str | None:
        return obj.text

    def on_activate(self, obj: Comment) -> None:
        if self.presenter is not None:
            self.presenter.workspace.jump_to(obj.addr)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.comments_menu(self.objects(rows))


class CommentsPresenter(InstancePresenter):
    """The comments view; it follows comment and CFG changes."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "bottom") -> None:
        super().__init__(workspace, "comments", instance, default_docking_position)
        self.base_caption = "Comments"
        self.model = CommentsTableModel(self)
        self.instance.annotations.comments.am_subscribe(self._on_comments_changed)
        container(self.instance.cfg).am_subscribe(self._on_comments_changed)

    def close(self) -> None:
        self.instance.annotations.comments.am_unsubscribe(self._on_comments_changed)
        container(self.instance.cfg).am_unsubscribe(self._on_comments_changed)

    @property
    def keymap(self) -> Keymap:
        return table_keymap()

    def reload(self) -> None:
        self.model.set_rows(self.instance.annotations.iter_comments())

    def refresh(self) -> None:
        self.reload()

    def count_text(self) -> str:
        shown = self.model.row_count
        total = self.model.total_count
        return f"{shown} comments" if shown == total else f"{shown} of {total} comments"

    #
    # Actions
    #

    def edit_comment(self, comment: Comment) -> None:
        """Ask for a new text for ``comment``; the Qt view uses its comment dialog instead."""

        def then(text: str | None) -> None:
            if text is not None:
                self.workspace.set_comment(comment.addr, text)

        ask_text("Set comment", f"Comment at {comment.addr:#x}:", comment.text, then)

    @staticmethod
    def copy_text(comment: Comment) -> None:
        GlobalInfo.ui_services.set_clipboard_text(comment.text)

    def set_kind(self, comment: Comment, kind: CommentKind) -> None:
        self.instance.annotations.set_kind(comment.addr, kind)
        self.workspace.refresh_after_comment_change(comment.addr)
        self.instance.annotations.notify_comments_changed(comment.addr)

    def delete(self, comments: Sequence[Comment]) -> None:
        for comment in list(comments):
            self.workspace.set_comment(comment.addr, "")

    def comments_menu(self, comments: Sequence[Comment], edit=None) -> Menu | None:
        """
        Edit, copy, change the kind of, or delete the selected comments.

        :param edit:    What "Edit comment..." does with the comment; :meth:`edit_comment` by default.
        """
        if not comments:
            return None
        comments = list(comments)
        do_edit = edit if edit is not None else self.edit_comment
        menu = Menu("")
        if len(comments) == 1:
            comment = comments[0]
            menu.add(MenuEntry("Edit comment...", lambda: do_edit(comment)))
            menu.add(MenuEntry("Copy text", lambda: self.copy_text(comment)))
            menu.add(MenuSeparator())
            kinds = Menu("Change kind to")
            for kind in CommentKind:
                kinds.add(
                    MenuEntry(
                        kind.display_name,
                        lambda k=kind: self.set_kind(comment, k),
                        checkable=True,
                        checked=comment.kind == kind,
                    )
                )
            menu.add(kinds)
            menu.add(MenuSeparator())
        menu.add(
            MenuEntry("Delete" + ("" if len(comments) == 1 else f" ({len(comments)})"), lambda: self.delete(comments))
        )
        return menu

    def _on_comments_changed(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.reload()
