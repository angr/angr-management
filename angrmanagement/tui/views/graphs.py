"""
The graph views of the terminal frontend: proximity, dependencies and data dependency. Each draws its presenter's
graph of boxes (:class:`~angrmanagement.tui.widgets.graph.BoxGraphWidget`) and runs the presenter's keys.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label

from angrmanagement.present.data_dep import DataDepPresenter, node_tooltip
from angrmanagement.present.dependencies import DependencyPresenter
from angrmanagement.present.proximity import ProximityPresenter
from angrmanagement.tui.screens import dialog_css
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
        self.graph.before_draw = getattr(presenter, "edge_styles", None)

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

    def context_menu(self, node: Any) -> Menu | None:
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


class DependencyTuiView(GraphTuiView):
    """
    The dependency tree of a sink, from the dependency analysis (operation-mango's): the job sets the sink and the
    closures on the view and reloads it, as on the Qt view. Without operation-mango the job says so and the view
    stays empty, as in Qt.
    """

    PRESENTER_CLASS = DependencyPresenter

    presenter: DependencyPresenter

    @property
    def sink_atom(self):
        return self.presenter.sink_atom

    @sink_atom.setter
    def sink_atom(self, atom) -> None:
        self.presenter.sink_atom = atom

    @property
    def sink_ins_addr(self) -> int | None:
        return self.presenter.sink_ins_addr

    @sink_ins_addr.setter
    def sink_ins_addr(self, addr: int | None) -> None:
        self.presenter.sink_ins_addr = addr

    @property
    def closures(self):
        return self.presenter.closures

    @closures.setter
    def closures(self, closures) -> None:
        self.presenter.closures = closures


class DataDepSearchScreen(ModalScreen[None]):
    """
    The node search: a node's name (part of its text), its value and its instruction's address, both in hex. Search
    (or Enter) selects the next match in the graph; Close (or Escape) ends.
    """

    DEFAULT_CSS = dialog_css("DataDepSearchScreen") + (
        "DataDepSearchScreen .row { height: auto; width: auto; } DataDepSearchScreen .row > Label { width: 22; }"
        "DataDepSearchScreen Input { width: 40; } DataDepSearchScreen #error { color: $error; }"
    )
    BINDINGS: ClassVar = [Binding("escape", "close", "Close")]

    def __init__(self, view: DataDepTuiView) -> None:
        super().__init__()
        self.view = view

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text("Data Dependency Node Search"), classes="title")
            for label, field_id in (("Name", "name"), ("Value", "value"), ("Instruction address", "address")):
                with Horizontal(classes="row"):
                    yield Label(label)
                    yield Input("", id=field_id)
            yield Label("", id="error")
            with Horizontal(classes="buttons"):
                yield Button("Search", id="search", variant="primary")
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        self.query_one("#name", Input).focus()

    def search(self) -> None:
        values = [self.query_one(f"#{field_id}", Input).value for field_id in ("name", "value", "address")]
        presenter = self.view.presenter
        node = presenter.search_next(*values)
        error = presenter.search.error if node is None else ""
        self.query_one("#error", Label).update(Text(error))
        if node is not None:
            self.view.graph.select(node)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.search()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "search":
            self.search()
        else:
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class DataDepTuiView(GraphTuiView):
    """
    The data dependency graph of a trace. Selecting a node highlights the edges from its ancestors (D: to its
    descendants, as Ctrl does while hovering in Qt); its menu traces it backward or forward, the view's menu (off the
    nodes) hides or shows the temporaries or untracks the node; Ctrl+F searches.
    """

    PRESENTER_CLASS = DataDepPresenter
    EMPTY_TEXT = "Load a trace file (File > Load a trace file...) to see its data dependencies"

    presenter: DataDepPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.presenter.on_traced = self.graph.redraw

    @property
    def analysis_params(self) -> dict:
        return self.presenter.analysis_params

    @analysis_params.setter
    def analysis_params(self, params: dict) -> None:
        self.presenter.analysis_params = params

    def box_selected(self, node: Any) -> None:
        self.presenter.trace(node)

    def tooltip_of(self, node: Any) -> str | None:
        return node_tooltip(node)

    def show_search(self) -> None:
        self.app.push_screen(DataDepSearchScreen(self))

    def handle_graph_key(self, key: str) -> bool:
        if self.key_actions().get(key) == "show_search":
            self.show_search()
            return True
        return super().handle_graph_key(key)


__all__ = ["DataDepSearchScreen", "DataDepTuiView", "DependencyTuiView", "GraphTuiView", "ProximityTuiView"]
