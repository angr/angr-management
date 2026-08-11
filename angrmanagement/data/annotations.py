from __future__ import annotations

import json
import logging
import time
from enum import IntEnum
from typing import TYPE_CHECKING

from .object_container import ObjectContainer

if TYPE_CHECKING:
    from collections.abc import Iterator

    import angr

_l = logging.getLogger(__name__)


class CommentKind(IntEnum):
    """
    How a comment is displayed.

    ``PLAIN`` shows only at its own address. ``FUNCTION`` renders as a header block above the
    function, which is also what the decompiler does with a comment on a function entry.
    ``REPEATABLE`` additionally shows at every location referencing the commented address.
    """

    PLAIN = 0
    FUNCTION = 1
    REPEATABLE = 2

    @property
    def display_name(self) -> str:
        return _KIND_NAMES[self]


_KIND_NAMES = {
    CommentKind.PLAIN: "Plain",
    CommentKind.FUNCTION: "Function",
    CommentKind.REPEATABLE: "Repeatable",
}


class Comment:
    """
    A comment as displayed in the Comments view. Rebuilt on demand from the knowledge base.
    """

    __slots__ = ("addr", "text", "kind", "func_addr", "func_name")

    def __init__(
        self, addr: int, text: str, kind: CommentKind, func_addr: int | None = None, func_name: str | None = None
    ) -> None:
        self.addr = addr
        self.text = text
        self.kind = kind
        self.func_addr = func_addr
        self.func_name = func_name

    @property
    def first_line(self) -> str:
        return self.text.split("\n", 1)[0]

    def __repr__(self) -> str:
        return f"<Comment {self.addr:#x} {self.kind.display_name}: {self.first_line!r}>"


class Bookmark:
    """
    A user-marked address with an optional label.
    """

    __slots__ = ("addr", "label", "created_at")

    def __init__(self, addr: int, label: str = "", created_at: float | None = None) -> None:
        self.addr = addr
        self.label = label
        self.created_at = time.time() if created_at is None else created_at

    def __repr__(self) -> str:
        return f"<Bookmark {self.addr:#x} {self.label!r}>"


class AnnotationManager:
    """
    Owns everything about comments and bookmarks that the knowledge base cannot hold by itself.

    Comment *text* lives in ``kb.comments``; only the per-address :class:`CommentKind` is kept here,
    alongside the bookmark list. Both are serialized into the angrdb ``information`` table through
    :meth:`serialize` / :meth:`deserialize`.
    """

    BOOKMARKS_KEY = "angr_management_bookmarks"
    COMMENT_KINDS_KEY = "angr_management_comment_kinds"

    def __init__(self, instance) -> None:
        self._instance = instance
        self._kinds: dict[int, CommentKind] = {}
        self._repeatable_map: dict[int, list[tuple[int, str]]] | None = None

        self.comments: ObjectContainer = ObjectContainer(None, "Comment annotations")
        self.bookmarks: ObjectContainer = ObjectContainer([], "List of bookmarks")

    #
    # Properties
    #

    @property
    def _kb(self) -> angr.KnowledgeBase | None:
        project = self._instance.project
        return None if project.am_none else project.kb

    #
    # Comment kinds
    #

    def kind_of(self, addr: int) -> CommentKind:
        kind = self._kinds.get(addr)
        if kind is not None:
            return kind
        return CommentKind.FUNCTION if self.is_function_entry(addr) else CommentKind.PLAIN

    def set_kind(self, addr: int, kind: CommentKind | None) -> None:
        if kind is None or kind == CommentKind.PLAIN and not self.is_function_entry(addr):
            self._kinds.pop(addr, None)
        else:
            self._kinds[addr] = CommentKind(kind)
        self.invalidate()

    def is_function_entry(self, addr: int) -> bool:
        kb = self._kb
        return kb is not None and addr in kb.functions

    def function_comment(self, func_addr: int) -> str | None:
        """The comment rendered as a function's header block, if any."""
        kb = self._kb
        if kb is None:
            return None
        text = kb.comments.get(func_addr)
        if not text:
            return None
        return text if self.kind_of(func_addr) != CommentKind.PLAIN else None

    def inline_comment(self, addr: int) -> str | None:
        """
        The comment rendered next to the instruction at ``addr``. A comment that already renders as
        a function header block is not repeated inline.
        """
        kb = self._kb
        if kb is None:
            return None
        text = kb.comments.get(addr)
        if not text:
            return None
        if self.kind_of(addr) != CommentKind.PLAIN and self.is_function_entry(addr):
            return None
        return text

    def iter_comments(self) -> Iterator[Comment]:
        kb = self._kb
        if kb is None:
            return
        for addr in sorted(kb.comments):
            text = kb.comments[addr]
            if not text:
                continue
            func = kb.functions.floor_func(addr)
            if func is not None and not (func.addr <= addr < func.addr + max(func.size, 1)):
                func = None
            yield Comment(
                addr,
                text,
                self.kind_of(addr),
                func_addr=None if func is None else func.addr,
                func_name=None if func is None else func.name,
            )

    #
    # Repeatable comments
    #

    def repeatable_comments_at(self, ins_addr: int) -> list[tuple[int, str]]:
        """
        Repeatable comments that should show at ``ins_addr`` because it references their address.
        """
        if self._repeatable_map is None:
            self._repeatable_map = self._build_repeatable_map()
        return self._repeatable_map.get(ins_addr, [])

    def invalidate(self) -> None:
        self._repeatable_map = None

    def notify_comments_changed(self, addr: int | None = None) -> None:
        self.invalidate()
        self.comments.am_event(addr=addr)

    def _build_repeatable_map(self) -> dict[int, list[tuple[int, str]]]:
        kb = self._kb
        if kb is None:
            return {}
        mapping: dict[int, list[tuple[int, str]]] = {}
        for addr, kind in self._kinds.items():
            if kind != CommentKind.REPEATABLE:
                continue
            text = kb.comments.get(addr)
            if not text:
                continue
            for ins_addr in self._referencing_insns(kb, addr):
                if ins_addr != addr:
                    mapping.setdefault(ins_addr, []).append((addr, text))
        return mapping

    @staticmethod
    def _referencing_insns(kb: angr.KnowledgeBase, addr: int) -> set[int]:
        """Instruction addresses that reference ``addr``: data xrefs plus call sites."""
        out: set[int] = set()
        for xref in kb.xrefs.get_xrefs_by_dst(addr):
            if xref.ins_addr is not None:
                out.add(xref.ins_addr)

        if addr not in kb.functions:
            return out

        callgraph = kb.functions.callgraph
        if addr not in callgraph:
            return out
        cfg = kb.cfgs.get_most_accurate()
        for caller_addr in callgraph.predecessors(addr):
            caller = kb.functions.get_by_addr(caller_addr)
            if caller is None:
                continue
            for site in caller.get_call_sites():
                if caller.get_call_target(site) != addr:
                    continue
                node = cfg.get_any_node(site) if cfg is not None else None
                if node is not None and node.instruction_addrs:
                    out.add(node.instruction_addrs[-1])
                else:
                    out.add(site)
        return out

    #
    # Bookmarks
    #

    def get_bookmark(self, addr: int) -> Bookmark | None:
        for bookmark in self.bookmarks:
            if bookmark.addr == addr:
                return bookmark
        return None

    def has_bookmark(self, addr: int) -> bool:
        return self.get_bookmark(addr) is not None

    def add_bookmark(self, addr: int, label: str = "") -> Bookmark:
        existing = self.get_bookmark(addr)
        if existing is not None:
            if label:
                existing.label = label
                self.bookmarks.am_event(changed=existing)
            return existing
        bookmark = Bookmark(addr, label)
        self.bookmarks.append(bookmark)
        self.bookmarks.am_event(added=bookmark)
        return bookmark

    def remove_bookmark(self, bookmark: Bookmark) -> None:
        if bookmark in self.bookmarks:
            self.bookmarks.remove(bookmark)
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
        return sorted(self.bookmarks, key=lambda b: b.addr)

    def next_bookmark(self, after_addr: int | None) -> Bookmark | None:
        """The next bookmark by address, wrapping around."""
        ordered = self.sorted_bookmarks()
        if not ordered:
            return None
        if after_addr is None:
            return ordered[0]
        for bookmark in ordered:
            if bookmark.addr > after_addr:
                return bookmark
        return ordered[0]

    #
    # Persistence
    #

    def serialize(self) -> dict[str, str]:
        """Entries to merge into the angrdb ``extra_info`` map."""
        bookmarks = [{"addr": b.addr, "label": b.label, "created_at": b.created_at} for b in self.bookmarks]
        kinds = {str(addr): int(kind) for addr, kind in self._kinds.items()}
        return {
            self.BOOKMARKS_KEY: json.dumps(bookmarks),
            self.COMMENT_KINDS_KEY: json.dumps(kinds),
        }

    def deserialize(self, entries: dict[str, str]) -> None:
        """Restore from an angrdb ``extra_info`` map. Unknown or malformed entries are ignored."""
        raw_bookmarks = entries.get(self.BOOKMARKS_KEY)
        if raw_bookmarks:
            try:
                loaded = json.loads(raw_bookmarks)
            except ValueError:
                _l.warning("Ignoring malformed bookmark data in the database.")
                loaded = []
            self.bookmarks.am_obj = [
                Bookmark(int(d["addr"]), str(d.get("label", "")), float(d.get("created_at", 0.0)))
                for d in loaded
                if isinstance(d, dict) and "addr" in d
            ]
            self.bookmarks.am_event()

        raw_kinds = entries.get(self.COMMENT_KINDS_KEY)
        if raw_kinds:
            try:
                loaded = json.loads(raw_kinds)
            except ValueError:
                _l.warning("Ignoring malformed comment-kind data in the database.")
                loaded = {}
            self._kinds = {int(addr): CommentKind(int(kind)) for addr, kind in loaded.items()}
            self.notify_comments_changed()

    def clear(self) -> None:
        self._kinds = {}
        self.invalidate()
        self.bookmarks.am_obj = []
        self.bookmarks.am_event()
        self.comments.am_event()
