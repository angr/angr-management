from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from angr.knowledge_plugins.bookmarks import Bookmark
from angr.knowledge_plugins.comments import Comment, CommentKind

from .object_container import ObjectContainer

if TYPE_CHECKING:
    from collections.abc import Iterator

    import angr

_l = logging.getLogger(__name__)

__all__ = ("AnnotationManager", "Bookmark", "Comment", "CommentKind")


class AnnotationManager:
    """
    GUI adapter over ``kb.comments`` and ``kb.bookmarks``: forwards reads and writes to the
    knowledge base, which owns all comment/bookmark state, and turns changes into ObjectContainer
    events for the views.
    """

    BOOKMARKS_KEY = "angr_management_bookmarks"
    COMMENT_KINDS_KEY = "angr_management_comment_kinds"

    def __init__(self, instance) -> None:
        self._instance = instance

        self.comments: ObjectContainer = ObjectContainer(None, "Comment annotations")
        self.bookmarks: ObjectContainer = ObjectContainer([], "List of bookmarks")

        self._instance.project.am_subscribe(self._on_project_changed)

    #
    # Properties
    #

    @property
    def _kb(self) -> angr.KnowledgeBase | None:
        project = self._instance.project
        return None if project.am_none else project.kb

    def _on_project_changed(self, **kwargs) -> None:  # pylint:disable=unused-argument
        kb = self._kb
        self.bookmarks.am_obj = [] if kb is None else kb.bookmarks
        self.bookmarks.am_event()
        self.comments.am_event()

    #
    # Comment kinds
    #

    def kind_of(self, addr: int) -> CommentKind:
        kb = self._kb
        return CommentKind.PLAIN if kb is None else kb.comments.kind_of(addr)

    def set_kind(self, addr: int, kind: CommentKind | None) -> None:
        kb = self._kb
        if kb is not None:
            kb.comments.set_kind(addr, kind)

    def is_function_entry(self, addr: int) -> bool:
        kb = self._kb
        return kb is not None and kb.comments.is_function_entry(addr)

    def function_comment(self, func_addr: int) -> str | None:
        """The comment rendered as a function's header block, if any."""
        kb = self._kb
        return None if kb is None else kb.comments.function_comment(func_addr)

    def inline_comment(self, addr: int) -> str | None:
        """The comment rendered next to the instruction at ``addr``."""
        kb = self._kb
        return None if kb is None else kb.comments.inline_comment(addr)

    def iter_comments(self) -> Iterator[Comment]:
        kb = self._kb
        if kb is None:
            return
        yield from kb.comments.iter_comments()

    #
    # Repeatable comments
    #

    def repeatable_comments_at(self, ins_addr: int) -> list[tuple[int, str]]:
        """
        Repeatable comments that should show at ``ins_addr`` because it references their address.
        """
        kb = self._kb
        return [] if kb is None else kb.comments.repeatable_comments_at(ins_addr)

    def invalidate(self) -> None:
        kb = self._kb
        if kb is not None:
            kb.comments.invalidate()

    def notify_comments_changed(self, addr: int | None = None) -> None:
        self.invalidate()
        self.comments.am_event(addr=addr)

    #
    # Bookmarks
    #

    def get_bookmark(self, addr: int) -> Bookmark | None:
        kb = self._kb
        return None if kb is None else kb.bookmarks.get_bookmark(addr)

    def has_bookmark(self, addr: int) -> bool:
        return self.get_bookmark(addr) is not None

    def add_bookmark(self, addr: int, label: str = "") -> Bookmark | None:
        kb = self._kb
        if kb is None:
            return None
        bookmark, created = kb.bookmarks.add_bookmark(addr, label)
        if created:
            self.bookmarks.am_event(added=bookmark)
        elif label:
            self.bookmarks.am_event(changed=bookmark)
        return bookmark

    def remove_bookmark(self, bookmark: Bookmark) -> None:
        kb = self._kb
        if kb is not None and kb.bookmarks.remove_bookmark(bookmark):
            self.bookmarks.am_event(removed=bookmark)

    def toggle_bookmark(self, addr: int, label: str = "") -> Bookmark | None:
        """Add a bookmark at ``addr``, or remove the one already there. Returns the new one, if any."""
        existing = self.get_bookmark(addr)
        if existing is None:
            return self.add_bookmark(addr, label)
        self.remove_bookmark(existing)
        return None

    def set_bookmark_label(self, bookmark: Bookmark, label: str) -> None:
        bookmark.label = label
        self.bookmarks.am_event(changed=bookmark)

    def sorted_bookmarks(self) -> list[Bookmark]:
        kb = self._kb
        return [] if kb is None else kb.bookmarks.sorted_bookmarks()

    def next_bookmark(self, after_addr: int | None) -> Bookmark | None:
        kb = self._kb
        return None if kb is None else kb.bookmarks.next_bookmark(after_addr)

    #
    # Persistence
    #

    def deserialize(self, entries: dict[str, str]) -> None:
        """
        Migrate bookmarks and comment kinds from the angrdb ``extra_info`` JSON entries that
        angr management wrote before angr's knowledge base owned them. Databases saved since then
        carry both in the knowledge base itself, which loads them before this runs; the knowledge
        base wins over the legacy entries. Unknown or malformed entries are ignored.
        """
        kb = self._kb
        if kb is None:
            return

        raw_bookmarks = entries.get(self.BOOKMARKS_KEY)
        if raw_bookmarks and not kb.bookmarks:
            try:
                loaded = json.loads(raw_bookmarks)
            except ValueError:
                _l.warning("Ignoring malformed bookmark data in the database.")
                loaded = []
            kb.bookmarks.extend(
                Bookmark(int(d["addr"]), str(d.get("label", "")), float(d.get("created_at", 0.0)))
                for d in loaded
                if isinstance(d, dict) and "addr" in d
            )
            self.bookmarks.am_event()

        raw_kinds = entries.get(self.COMMENT_KINDS_KEY)
        if raw_kinds:
            try:
                loaded = json.loads(raw_kinds)
            except ValueError:
                _l.warning("Ignoring malformed comment-kind data in the database.")
                loaded = {}
            for addr, kind in loaded.items():
                kb.comments.kinds.setdefault(int(addr), CommentKind(int(kind)))
            self.notify_comments_changed()

    def clear(self) -> None:
        """Detach from the (outgoing) project's knowledge base."""
        self.bookmarks.am_obj = []
        self.bookmarks.am_event()
        self.comments.am_event()
