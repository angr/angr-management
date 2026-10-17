"""
The graph views of the terminal frontend: proximity, dependencies and data dependency. Each draws its presenter's
graph of boxes (:class:`~angrmanagement.tui.widgets.graph.BoxGraphWidget`) and runs the presenter's keys.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angrmanagement.present.proximity import ProximityPresenter
from angrmanagement.tui.widgets.graph import BoxGraphWidget

from .base import TuiView

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from angrmanagement.present.menus import Menu


class GraphTuiView(TuiView):
    """A view whose content is its presenter's ``graph``: a click selects a box, Enter activates it."""

    #: shown in the middle of an empty graph
    EMPTY_TEXT = ""

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        presenter = self.presenter
        self.graph = BoxGraphWidget(
            presenter.graph,
            empty_text=self.EMPTY_TEXT,
            on_select=self.box_selected,
            on_activate=presenter.activate,
            on_context_menu=self.box_context_menu,
            tooltip_of=self.tooltip_of,
            on_key=self.handle_graph_key,
        )
        presenter.on_reloaded = self.graph_changed

    def compose(self) -> ComposeResult:
        yield self.graph

    def on_mount(self) -> None:
        self.graph.rebuild()

    def graph_changed(self) -> None:
        if self.is_attached:
            self.graph.rebuild()

    def focus_view(self) -> None:
        if self.is_mounted:
            self.graph.focus()

    def box_selected(self, node: Any) -> None:
        """A box was selected (the presenter's graph knows which)."""

    def tooltip_of(self, node: Any) -> str | None:  # pylint: disable=unused-argument,no-self-use
        return None

    def context_menu(self, node: Any) -> Menu | None:  # pylint: disable=unused-argument
        menu = getattr(self.presenter, "context_menu", None)
        return menu(node) if menu is not None else None

    def box_context_menu(self, node: Any, offset: tuple[int, int]) -> None:
        menu = self.context_menu(node)
        open_context_menu = getattr(self.app, "open_context_menu", None) if self.is_attached else None
        if menu is not None and open_context_menu is not None:
            open_context_menu(menu, offset)

    def handle_graph_key(self, key: str) -> bool:
        """Run the action bound to ``key``; whether one was."""
        action = self.key_actions().get(key)
        if action is None:
            return False
        if action == "context_menu":
            region = self.graph.region
            self.box_context_menu(self.presenter.graph.selected, (region.x + 2, region.y + 1))
        else:
            getattr(self.presenter, action)()
        self.graph.redraw()
        return True


class ProximityTuiView(GraphTuiView):
    """The proximity graph of a function: Enter shows a block's reference, + and - expand and collapse calls."""

    PRESENTER_CLASS = ProximityPresenter

    presenter: ProximityPresenter

    @property
    def function(self):
        return self.presenter.function

    @function.setter
    def function(self, func) -> None:
        self.presenter.function = func


__all__ = ["GraphTuiView", "ProximityTuiView"]
