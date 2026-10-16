"""The bookmarks view without a toolkit: the bookmarked addresses, with editable labels."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, ClassVar

from .base import InstancePresenter, ask_text
from .keymap import table_keymap
from .menus import Menu, MenuEntry
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.annotations import AnnotationManager, Bookmark
    from angrmanagement.data.instance import Instance

    from .keymap import Keymap


class BookmarksTableModel(ListTableModel["Bookmark"]):
    """The instance's bookmarks; the label column is editable."""

    ADDRESS_COL = 0
    FUNCTION_COL = 1
    LABEL_COL = 2
    ADDED_COL = 3

    COLUMNS: ClassVar[list[Column]] = [
        Column("Address", 14),
        Column("Function", 19),
        Column("Label", 27, editable=True),
        Column("Added", stretch=True),
    ]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, instance: Instance, presenter: BookmarksPresenter | None = None) -> None:
        super().__init__()
        self.instance = instance
        self.presenter = presenter
        self.reload()

    @property
    def annotations(self) -> AnnotationManager:
        return self.instance.annotations

    def reload(self) -> None:
        self.set_rows(list(self.annotations.bookmarks))

    def bookmark_at(self, row: int) -> Bookmark | None:
        return self.row(row)

    def containing_function_name(self, addr: int) -> str:
        kb = self.instance.kb
        if kb is None:
            return ""
        func = kb.functions.floor_func(addr)
        if func is None or not func.addr <= addr < func.addr + max(func.size, 1):
            return ""
        return func.name

    def column_value(self, obj: Bookmark, col: int) -> Any:
        if col == self.ADDRESS_COL:
            return obj.addr
        if col == self.FUNCTION_COL:
            return self.containing_function_name(obj.addr)
        if col == self.LABEL_COL:
            return obj.label
        if col == self.ADDED_COL:
            return obj.created_at
        return None

    def column_text(self, obj: Bookmark, col: int) -> str:
        if col == self.ADDRESS_COL:
            return f"{obj.addr:#x}"
        if col == self.FUNCTION_COL:
            return self.containing_function_name(obj.addr)
        if col == self.LABEL_COL:
            return obj.label
        if col == self.ADDED_COL:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(obj.created_at))
        return ""

    def set_text(self, row: int, col: int, text: str) -> bool:
        bookmark = self.bookmark_at(row)
        if bookmark is None or col != self.LABEL_COL:
            return False
        self.annotations.set_bookmark_label(bookmark, text)
        return True

    def on_activate(self, obj: Bookmark) -> None:
        if self.presenter is not None:
            self.presenter.workspace.jump_to(obj.addr)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.bookmarks_menu(self.objects(rows))


class BookmarksPresenter(InstancePresenter):
    """The bookmarks view; it follows bookmark changes."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "bottom") -> None:
        super().__init__(workspace, "bookmarks", instance, default_docking_position)
        self.base_caption = "Bookmarks"
        self.model = BookmarksTableModel(instance, self)
        self.instance.annotations.bookmarks.am_subscribe(self._on_bookmarks_changed)

    def close(self) -> None:
        self.instance.annotations.bookmarks.am_unsubscribe(self._on_bookmarks_changed)

    @property
    def keymap(self) -> Keymap:
        return table_keymap()

    def reload(self) -> None:
        self.model.reload()

    def refresh(self) -> None:
        self.model.reload()

    def rename(self, bookmark: Bookmark) -> None:
        """Ask for a new label; the Qt view edits the cell in place instead."""

        def then(label: str | None) -> None:
            if label is not None:
                self.instance.annotations.set_bookmark_label(bookmark, label)

        ask_text("Rename bookmark", f"Label for {bookmark.addr:#x}:", bookmark.label, then)

    def delete(self, bookmarks: Sequence[Bookmark]) -> None:
        for bookmark in list(bookmarks):
            self.instance.annotations.remove_bookmark(bookmark)

    def bookmarks_menu(self, bookmarks: Sequence[Bookmark], rename=None) -> Menu:
        """
        Go to, rename or delete the selected bookmarks.

        :param rename:  What "Rename label" does with the bookmark; :meth:`rename` by default.
        """
        bookmarks = list(bookmarks)
        menu = Menu("")
        if bookmarks:
            menu.add(MenuEntry("Go to", lambda: self.workspace.jump_to(bookmarks[0].addr)))
            if len(bookmarks) == 1:
                do_rename = rename if rename is not None else self.rename
                menu.add(MenuEntry("Rename label", lambda: do_rename(bookmarks[0])))
            menu.add(
                MenuEntry(
                    "Delete" + ("" if len(bookmarks) == 1 else f" ({len(bookmarks)})"),
                    lambda: self.delete(bookmarks),
                )
            )
        return menu

    def _on_bookmarks_changed(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.reload()
