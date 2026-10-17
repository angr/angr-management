"""
The terminal's Load File from Archive screen: the Qt ArchiveLoaderDialog's tree of the archive's entries with their
sizes, and a password screen for an encrypted entry. It dismisses with the extracted file's path, or None.
"""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Tree

from angrmanagement.present.archive import ArchiveNode, archive_tree, extract_member
from angrmanagement.utils.archive import Archive, ArchiveError, ArchiveMember, get_archive_object

from . import MessageScreen, PromptScreen, dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult


class ArchiveScreen(ModalScreen["str | None"]):
    """Pick the file in an archive to load."""

    DEFAULT_CSS = (
        dialog_css("ArchiveScreen")
        + """
ArchiveScreen > Vertical { width: 80; height: 70%; }
ArchiveScreen Tree { height: 1fr; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, archive_path: str) -> None:
        super().__init__()
        self.title_text = "Load File from Archive"
        self.archive_path = archive_path
        #: why the archive cannot be read, if it cannot
        self.error: str | None = None
        self.archive: Archive | None = None
        self.roots: list[ArchiveNode] = []
        #: where the chosen file was extracted, which the caller removes when it is done with it
        self.temp_dir: str | None = None
        self._password: str | None = None
        try:
            self.archive = get_archive_object(archive_path)
            self.roots = archive_tree(self.archive.list_members())
        except ArchiveError as e:
            self.error = str(e)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            yield Label(Text(f"Archive: {os.path.basename(self.archive_path)}"))
            tree: Tree[Any] = Tree("archive", id="members")
            tree.show_root = False

            def add(node: ArchiveNode, parent: Any) -> None:
                label = Text(node.name)
                if node.member is not None:
                    label.append(f"  {node.size_text}", style="dim")
                    parent.add_leaf(label, data=node.member)
                    return
                branch = parent.add(label, expand=True)
                for child in node.children:
                    add(child, branch)

            for root in self.roots:
                add(root, tree.root)
            yield tree
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary", disabled=True)
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        if self.error is not None:
            self.app.push_screen(MessageScreen("critical", "Error", self.error), lambda _: self.action_cancel())
            return
        for tree in self.query("#members"):
            tree.focus()

    def _member(self) -> ArchiveMember | None:
        node = self.query_one("#members", Tree).cursor_node
        data = node.data if node is not None else None
        return data if isinstance(data, ArchiveMember) else None

    def on_tree_node_highlighted(self, _event: Tree.NodeHighlighted) -> None:
        self.query_one("#ok", Button).disabled = self._member() is None

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if isinstance(event.node.data, ArchiveMember):
            event.stop()
            self.accept(event.node.data)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "ok":
            member = self._member()
            if member is not None:
                self.accept(member)
        else:
            self.action_cancel()

    def accept(self, member: ArchiveMember, password: str | None = None) -> None:
        """Extract ``member``, asking for its password as often as it is refused, then dismiss with its path."""
        assert self.archive is not None
        if member.encrypted and password is None:

            def answered(text: str | None) -> None:
                if text is not None:
                    self.accept(member, text)

            self.app.push_screen(
                PromptScreen("Archive Password", f"Password required for {member.name}:", self._password or "", True),
                answered,
            )
            return
        result = extract_member(self.archive, member, password)
        if result.outcome == "password":
            self.accept(ArchiveMember(member.name, member.size, encrypted=True))
        elif result.outcome == "wrong":
            retry = ArchiveMember(member.name, member.size, encrypted=True)
            self.app.push_screen(
                MessageScreen("warning", "Incorrect Password", result.message), lambda _: self.accept(retry)
            )
        elif result.outcome == "error":
            self.app.push_screen(MessageScreen("critical", "Extraction Error", result.message))
            self._close_archive()
            self.dismiss(None)
        else:
            if password is not None:
                self._password = password
            self.temp_dir = result.temp_dir
            self._close_archive()
            self.dismiss(result.path)

    def _close_archive(self) -> None:
        if self.archive is not None:
            self.archive.close()
            self.archive = None

    def action_cancel(self) -> None:
        self._close_archive()
        self.dismiss(None)

    def cleanup(self) -> None:
        """Remove the extracted file's directory."""
        if self.temp_dir and os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.temp_dir = None


__all__ = ["ArchiveScreen"]
