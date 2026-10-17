"""
The call explorer of the terminal frontend: the trace debugger's current function and the tree of the calls it made,
each opened on demand. Moving to a call replays the trace to just before it; Enter or a double click replays into it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.widgets import Label, Tree

from angrmanagement.present.call_explorer import CallExplorerPresenter, CallNode

from .base import TuiView

if TYPE_CHECKING:
    from textual.app import ComposeResult
    from textual.widgets.tree import TreeNode


class CallTree(Tree):
    """The calls; a call shows the expand marker until it is opened and found to make no calls."""

    def __init__(self, view: CallExplorerTuiView) -> None:
        super().__init__("Function", id="calls")
        self.view = view
        self.show_root = False

    def rebuild(self) -> None:
        self.clear()
        for node in self.view.presenter.roots:
            self._add(self.root, node)

    def _add(self, parent: TreeNode, node: CallNode) -> None:
        item = parent.add(Text(node.name), data=node, allow_expand=node.expandable)
        for child in node.children:
            self._add(item, child)

    def on_tree_node_expanded(self, event: Tree.NodeExpanded) -> None:
        node = event.node.data
        if not isinstance(node, CallNode) or node.populated:
            return
        event.stop()
        self.view.presenter.expand(node)
        for child in node.children:
            self._add(event.node, child)
        event.node.allow_expand = node.expandable

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        node = event.node.data
        if isinstance(node, CallNode) and self.has_focus:
            event.stop()
            self.view.presenter.select(node)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node = event.node.data
        if isinstance(node, CallNode):
            event.stop()
            self.view.presenter.activate(node)


class CallExplorerTuiView(TuiView):
    """The call explorer: the current function, then its calls."""

    PRESENTER_CLASS = CallExplorerPresenter
    DEFAULT_CSS = """
    CallExplorerTuiView > Label {
        padding: 0 1;
    }
    CallExplorerTuiView > Tree {
        height: 1fr;
    }
    """

    presenter: CallExplorerPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self._shown_roots: list[CallNode] | None = None
        self.label = Label("", id="function")
        self.calls = CallTree(self)
        self.presenter.on_changed = self.calls_changed

    def compose(self) -> ComposeResult:
        yield self.label
        yield self.calls

    def on_mount(self) -> None:
        self.calls_changed()

    def calls_changed(self) -> None:
        if not self.is_attached:
            return
        self.label.update(Text(self.presenter.label))
        if self.presenter.roots is not self._shown_roots:
            self._shown_roots = self.presenter.roots
            self.calls.rebuild()

    def focus_view(self) -> None:
        self.calls.focus()


__all__ = ["CallExplorerTuiView", "CallTree"]
