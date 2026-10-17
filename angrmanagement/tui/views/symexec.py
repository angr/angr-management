"""
The symbolic execution view of the terminal frontend.

:class:`SymexecTuiView` draws a :class:`~angrmanagement.present.symexec.SymexecPresenter` as the Qt view lays out its
docks: the path tree (a graph of boxes) on the left; on the right the simulation managers panel (the manager, its
stash tree, Explore and the step buttons; the setting that keeps one active state; the avoid and find lists) and
the state inspector (registers, memory, constraints, file descriptors and VEX temporaries of the selected state).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Select, Static, TabbedContent, TabPane, Tree

from angrmanagement.logic import GlobalInfo
from angrmanagement.present.symexec import (
    CONSTRAINT_COLUMNS,
    ExploreAddresses,
    StashRow,
    SymexecPresenter,
    ast_strings,
    constraint_rows,
    fd_choices,
    fd_text,
    memory_rows,
    register_rows,
    temp_rows,
)
from angrmanagement.tui.widgets.graph import BoxGraphWidget
from angrmanagement.tui.widgets.styles import StyleCache

from .base import TuiView

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.style import Style
    from textual import events
    from textual.app import ComposeResult

    from angrmanagement.present.menus import Menu

#: The colours of concrete and symbolic values, the AST viewer's configuration entries.
CONCRETE_STYLE = "ast_viewer_concrete_color"
SYMBOLIC_STYLE = "ast_viewer_symbolic_color"


def value_text(ast: Any, style_of: Callable[[str], Style], display_size: bool = True) -> Text:
    """A value as the AST viewer shows it: its size, then the value coloured concrete or symbolic."""
    if ast is None:
        return Text("")
    size, text, symbolic = ast_strings(ast, display_size)
    out = Text()
    if size:
        out.append(f"{size:>5} ")
    out.append(text, style=style_of(SYMBOLIC_STYLE if symbolic else CONCRETE_STYLE))
    return out


class StashTree(Tree):
    """
    The stash tree: each stash with its number of states, and its states under it. Enter on a state selects it (the
    inspector shows it), Space adds it to (or takes it from) the states the menu's copy, cut and delete act on, and
    Shift+F10 or a right click opens the row's menu.
    """

    DEFAULT_CSS = """
    StashTree {
        height: 1fr;
    }
    """

    def __init__(self, view: SymexecTuiView) -> None:
        super().__init__("Stashes", id="stashes")
        self.view = view
        self.show_root = False

    @property
    def panel(self):
        return self.view.presenter.simgrs

    def rebuild(self) -> None:
        panel = self.panel
        cursor = self.cursor_node.data if self.cursor_node is not None else None
        self.clear()
        nodes: dict[str, Any] = {}
        for row in panel.stash_rows():
            if row.is_stash:
                nodes[row.stash] = self.root.add(
                    Text(panel.row_text(row)), data=row, expand=row.stash in panel.expanded, allow_expand=True
                )
            else:
                marked = any(row.state is s for s in panel.selected_states)
                nodes[row.stash].add_leaf(Text(("* " if marked else "") + panel.row_text(row)), data=row)
        if cursor is not None:
            for node in self._all_nodes():
                if self._same_row(node.data, cursor):
                    self.move_cursor(node)
                    break

    def _all_nodes(self):
        stack = list(self.root.children)
        while stack:
            node = stack.pop(0)
            yield node
            stack[:0] = list(node.children)

    @staticmethod
    def _same_row(a: Any, b: Any) -> bool:
        return isinstance(a, StashRow) and isinstance(b, StashRow) and a.stash == b.stash and a.state is b.state

    def on_tree_node_expanded(self, event: Tree.NodeExpanded) -> None:
        row = event.node.data
        if isinstance(row, StashRow) and row.is_stash and row.stash not in self.panel.expanded:
            event.stop()
            self.panel.toggle_stash(row.stash)

    def on_tree_node_collapsed(self, event: Tree.NodeCollapsed) -> None:
        row = event.node.data
        if isinstance(row, StashRow) and row.is_stash and row.stash in self.panel.expanded:
            event.stop()
            self.panel.toggle_stash(row.stash)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        row = event.node.data
        if isinstance(row, StashRow) and not row.is_stash:
            event.stop()
            self.panel.select_state(row.state)

    def on_key(self, event: events.Key) -> None:
        node = self.cursor_node
        row = node.data if node is not None else None
        if event.key == "space" and isinstance(row, StashRow) and not row.is_stash:
            event.stop()
            panel = self.panel
            if any(row.state is s for s in panel.selected_states):
                panel.selected_states = [s for s in panel.selected_states if s is not row.state]
            else:
                panel.selected_states.append(row.state)
            self.rebuild()
        elif event.key == "shift+f10":
            event.stop()
            region = self.region
            line = node.line if node is not None else 0
            self.view.open_menu(
                self.panel.row_menu(row if isinstance(row, StashRow) else None),
                (region.x + 4, region.y + line - int(self.scroll_offset.y) + 1),
            )

    def on_click(self, event: events.Click) -> None:
        if event.button != 3:
            return
        event.stop()
        node = self.get_node_at_line(int(event.y) + int(self.scroll_offset.y))
        row = node.data if node is not None else None
        if node is not None:
            self.move_cursor(node)
        self.view.open_menu(
            self.panel.row_menu(row if isinstance(row, StashRow) else None),
            (int(event.screen_x), int(event.screen_y)),
        )


class AddressList(Vertical):
    """An avoid or find list: each address with its check box; Enter or a click checks or unchecks it."""

    DEFAULT_CSS = """
    AddressList > Tree {
        height: 1fr;
    }
    AddressList > Button {
        width: 100%;
    }
    """

    def __init__(self, addresses: ExploreAddresses, view: SymexecTuiView, list_id: str) -> None:
        super().__init__(id=list_id)
        self.addresses = addresses
        self.view = view
        self.address_tree: Tree = Tree("Addresses")
        self.address_tree.show_root = False

    def compose(self) -> ComposeResult:
        yield self.address_tree
        yield Button("Import List", classes="import")

    def on_mount(self) -> None:
        self.rebuild()

    def rebuild(self) -> None:
        self.address_tree.clear()
        for addr, checked in self.addresses.entries.items():
            self.address_tree.root.add_leaf(Text(f"[{'x' if checked else ' '}] {addr:#x}"), data=addr)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        event.stop()
        addr = event.node.data
        if isinstance(addr, int):
            self.addresses.set_checked(addr, not self.addresses.entries[addr])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.view.presenter.simgrs.import_addresses(self.addresses)


class StateInspector(TabbedContent):
    """The selected state: registers, memory from an address, constraints, file descriptors and VEX temporaries."""

    DEFAULT_CSS = """
    StateInspector {
        height: 1fr;
    }
    StateInspector TabPane {
        padding: 0;
    }
    StateInspector #memory-address {
        width: 1fr;
    }
    """

    def __init__(self, view: SymexecTuiView) -> None:
        super().__init__(id="inspector")
        self.view = view
        self.memory_addr: int | None = None
        self.fd_list: list[tuple[int, str]] = []
        self.style_of = StyleCache(self)

    @staticmethod
    def panes() -> list[TabPane]:
        constraints: DataTable = DataTable(id="constraints", zebra_stripes=True)
        constraints.add_columns(*CONSTRAINT_COLUMNS)
        return [
            TabPane("Registers", VerticalScroll(Static("", id="registers")), id="tab-registers"),
            TabPane(
                "Memory",
                Horizontal(Label("Address "), Input("", id="memory-address"), classes="row"),
                VerticalScroll(Static("", id="memory")),
                id="tab-memory",
            ),
            TabPane("Constraints", constraints, id="tab-constraints"),
            TabPane(
                "File Descriptors",
                Select([], prompt="File descriptor", id="fd", compact=True),
                VerticalScroll(Static("", id="fd-text")),
                Button("Save as...", id="fd-save"),
                id="tab-fds",
            ),
            TabPane("Temps", VerticalScroll(Static("", id="temps")), id="tab-temps"),
        ]

    @property
    def state(self) -> Any:
        return self.view.presenter.current_state.am_obj

    def reload(self) -> None:
        state = self.state
        self._registers(state)
        self._memory(state)
        self._constraints(state)
        self._fds(state)
        self._temps(state)

    def _registers(self, state: Any) -> None:
        text = Text()
        rows = register_rows(state) if state is not None else []
        if rows is None:
            text.append(f"Architecture {state.arch.name} is not listed.")  # pyright: ignore[reportOptionalMemberAccess]
            rows = []
        for name, ast in rows:
            text.append(f"{name:<5} ")
            text.append_text(value_text(ast, self.style_of))
            text.append("\n")
        self.query_one("#registers", Static).update(text)

    def _memory(self, state: Any) -> None:
        text = Text()
        if state is not None and self.memory_addr is not None:
            for addr, data in memory_rows(state, self.memory_addr):
                text.append(f"{addr:08x}", style=self.style_of("memory_viewer_address_color"))
                for ast in data:
                    text.append(" ")
                    text.append_text(value_text(ast, self.style_of, display_size=False))
                text.append("\n")
        self.query_one("#memory", Static).update(text)

    def _constraints(self, state: Any) -> None:
        table = self.query_one("#constraints", DataTable)
        table.clear()
        if state is not None:
            for cells in constraint_rows(state):
                table.add_row(*cells)

    def _fds(self, state: Any) -> None:
        select = self.query_one("#fd", Select)
        self.fd_list = fd_choices(state) if state is not None else []
        select.set_options([(name, fd) for fd, name in self.fd_list])
        self.query_one("#fd-text", Static).update("")

    def _temps(self, state: Any) -> None:
        text = Text()
        for name, ast in temp_rows(state):
            text.append(f"{name:<8} ")
            text.append_text(value_text(ast, self.style_of))
            text.append("\n")
        self.query_one("#temps", Static).update(text)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "memory-address":
            return
        event.stop()
        try:
            self.memory_addr = int(event.value, 16)
        except ValueError:
            return
        self._memory(self.state)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "fd":
            return
        event.stop()
        state = self.state
        fd = event.value
        self.query_one("#fd-text", Static).update(
            Text(fd_text(state, fd)) if state is not None and isinstance(fd, int) else ""
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "fd-save":
            return
        event.stop()
        state = self.state
        fd = self.query_one("#fd", Select).value
        if state is None or not isinstance(fd, int):
            return

        def save(path: str | None) -> None:
            if path:
                with open(path, "wb") as f:
                    f.write(state.posix.dumps(fd))

        GlobalInfo.ui_services.pick_save_file_async("Save content to ...", "", "Any file (*)", save)


class SymexecTuiView(TuiView):
    """The symbolic execution view: the path tree, the simulation managers panel and the state inspector."""

    PRESENTER_CLASS = SymexecPresenter
    DEFAULT_CSS = """
    SymexecTuiView > Horizontal {
        height: 1fr;
    }
    SymexecTuiView #right {
        width: 64;
        height: 1fr;
    }
    SymexecTuiView #panel {
        height: 1fr;
    }
    SymexecTuiView .row {
        height: auto;
    }
    SymexecTuiView .row > Label {
        padding: 0 1 0 0;
    }
    SymexecTuiView #simgr {
        width: 1fr;
    }
    SymexecTuiView .buttons Button {
        width: 1fr;
        min-width: 8;
    }
    SymexecTuiView .buttons {
        height: auto;
    }
    """

    EXTRA_KEYS: ClassVar[dict[str, str]] = {}

    presenter: SymexecPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        presenter = self.presenter
        self.graph = BoxGraphWidget(
            presenter.path_tree,
            on_select=presenter.select_history,
            on_activate=presenter.activate_history,
            on_key=self.handle_symexec_key,
        )
        self.stash_tree = StashTree(self)
        self.avoids = AddressList(presenter.simgrs.avoids, self, "avoids")
        self.finds = AddressList(presenter.simgrs.finds, self, "finds")
        self.inspector = StateInspector(self)
        presenter.simgrs.changed.connect(self._panel_changed)
        presenter.path_tree_changed.connect(self._path_tree_changed)
        presenter.current_state.am_subscribe(self._state_changed)

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield self.graph
            with Vertical(id="right"):
                with TabbedContent(id="panel"):
                    with TabPane("General", id="tab-general"):
                        with Horizontal(classes="row"):
                            yield Label("Simulation Manager")
                            yield Select([], prompt="", id="simgr", compact=True)
                        yield self.stash_tree
                        with Horizontal(classes="buttons"):
                            yield Button("Explore", id="explore", compact=True)
                        with Horizontal(classes="buttons"):
                            yield Button("Step actives", id="step", compact=True)
                            yield Button("Step actives until branch", id="step-branch", compact=True)
                    with TabPane("Settings", id="tab-settings"):
                        yield Checkbox("Keep at most one active path", False, id="one-active")
                    with TabPane("Avoids", id="tab-avoids"):
                        yield self.avoids
                    with TabPane("Finds", id="tab-finds"):
                        yield self.finds
                with self.inspector:
                    yield from self.inspector.panes()

    def on_mount(self) -> None:
        self._panel_changed()
        self.graph.rebuild()
        self.inspector.reload()

    def close_view(self) -> None:
        presenter = self.presenter
        presenter.simgrs.changed.disconnect(self._panel_changed)
        presenter.path_tree_changed.disconnect(self._path_tree_changed)
        presenter.current_state.am_unsubscribe(self._state_changed)
        super().close_view()

    #
    # Events of the presenter
    #

    def _panel_changed(self) -> None:
        if not self.is_attached:
            return
        panel = self.presenter.simgrs
        select = self.query_one("#simgr", Select)
        names = panel.simgr_names()
        select.set_options([(name, idx) for idx, name in enumerate(names)])
        idx = panel.current_index()
        if idx >= 0:
            select.value = idx
        self.stash_tree.rebuild()
        self.avoids.rebuild()
        self.finds.rebuild()

    def _path_tree_changed(self) -> None:
        if self.is_attached:
            self.graph.rebuild(keep_view=self.graph.canvas is not None)

    def _state_changed(self, **_kwargs) -> None:
        if self.is_attached:
            self.inspector.reload()
            self.graph.redraw()

    #
    # Widgets
    #

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "simgr" and isinstance(event.value, int):
            event.stop()
            self.presenter.simgrs.select_simgr_index(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {"explore": self.presenter.explore, "step": self.presenter.step}
        actions["step-branch"] = self.presenter.step_until_branch
        action = actions.get(event.button.id or "")
        if action is not None:
            event.stop()
            action()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "one-active":
            event.stop()
            self.presenter.simgrs.keep_one_active = event.value

    def open_menu(self, menu: Menu, offset: tuple[int, int]) -> None:
        open_context_menu = getattr(self.app, "open_context_menu", None) if self.is_attached else None
        if open_context_menu is not None:
            open_context_menu(menu, offset)

    def handle_symexec_key(self, key: str) -> bool:
        action = self.key_actions().get(key)
        if action is None:
            return False
        if action == "context_menu":
            region = self.stash_tree.region
            self.open_menu(self.presenter.simgrs.row_menu(None), (region.x + 2, region.y + 1))
        else:
            getattr(self.presenter, action)()
        return True

    def focus_view(self) -> None:
        if self.is_mounted:
            self.graph.focus()

    #
    # What the workspace, the disassembly and plugins call
    #

    @property
    def _simgrs(self):
        return self.presenter.simgrs

    @property
    def current_simgr(self):
        return self.presenter.current_simgr

    @property
    def current_state(self):
        return self.presenter.current_state

    def select_simgr(self, simgr) -> None:
        self.presenter.select_simgr(simgr)

    def select_states(self, states) -> None:
        self.presenter.select_states(states)

    def view_state(self, state) -> None:
        self.presenter.view_state(state)

    def avoid_addr_in_exec(self, addr: int) -> None:
        self.presenter.avoid_addr_in_exec(addr)

    def find_addr_in_exec(self, addr: int) -> None:
        self.presenter.find_addr_in_exec(addr)

    def remove_avoid_addr_in_exec(self, addr: int) -> None:
        self.presenter.remove_avoid_addr_in_exec(addr)

    def remove_find_addr_in_exec(self, addr: int) -> None:
        self.presenter.remove_find_addr_in_exec(addr)

    def redraw_graph(self) -> None:
        self.graph.redraw()

    def switch_to_disassembly_view(self) -> None:
        self.presenter.switch_to_disassembly_view()


__all__ = ["StashTree", "StateInspector", "SymexecTuiView"]
