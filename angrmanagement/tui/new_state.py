"""
The new state dialog of the terminal frontend.

:class:`NewStateScreen` edits a :class:`~angrmanagement.present.symexec.StateSpec` as the Qt ``NewState`` dialog does:
the name and address (checked as they are typed), the template, the base state, the program arguments, the mode and
the options tree with its filter, and three sub-screens: :class:`PairsScreen` for the environment and the file system
mounts (editable two-column tables) and :class:`SocketsScreen` for the sockets. It dismisses with the spec, or None.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Tree

from angrmanagement.present.symexec import (
    MODES,
    SOCKET_FAMILIES,
    SOCKET_TYPES,
    TEMPLATES,
    SocketSpec,
    SocketsSpec,
    StateSpec,
    gui_data,
    option_groups,
)

from .screens import dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult
    from textual.widgets.tree import TreeNode

    from angrmanagement.data.instance import Instance

_FORM_CSS = """
{name} .row {{
    height: auto;
    width: auto;
}}
{name} .row > Label {{
    width: 14;
    padding: 1 1 0 0;
}}
{name} Input {{
    width: 60;
}}
{name} Select {{
    width: 60;
}}
"""


def checked_label(option: str, checked: bool) -> Text:
    """An option's row in the tree: a check box and its name (Text, so the brackets are not markup)."""
    return Text(f"[{'x' if checked else ' '}] {option}")


class PairsScreen(ModalScreen["list[tuple[str, str]] | None"]):
    """
    A table of two columns to edit (the environment's names and values, the mount points and host paths): each row is
    two boxes; Add a row, Delete the focused row. OK keeps the rows, Escape keeps what there was.
    """

    DEFAULT_CSS = (
        dialog_css("PairsScreen")
        + "PairsScreen .pair { height: auto; width: auto; } PairsScreen .pair Input { width: 36; }"
        + "PairsScreen VerticalScroll { height: auto; max-height: 16; width: auto; }"
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, headers: tuple[str, str], rows: list[tuple[str, str]], new_row: str) -> None:
        super().__init__()
        self.title_text = title
        self.headers = headers
        self.rows = [tuple(row) for row in rows]
        self.new_row = new_row

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            yield Label(Text(f"{self.headers[0]:<36} {self.headers[1]}"))
            with VerticalScroll(id="rows"):
                for first, second in self.rows:
                    yield self._pair(first, second)
            with Horizontal(classes="buttons"):
                yield Button("Add a Row", id="add")
                yield Button("Delete this Row", id="delete")
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    @staticmethod
    def _pair(first: str, second: str) -> Horizontal:
        return Horizontal(Input(first, classes="first"), Input(second, classes="second"), classes="pair")

    def result(self) -> list[tuple[str, str]]:
        out = []
        for pair in self.query(".pair"):
            out.append((pair.query_one(".first", Input).value, pair.query_one(".second", Input).value))
        return out

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id
        if button == "add":
            first = Input(self.new_row, classes="first")
            self.query_one("#rows", VerticalScroll).mount(
                Horizontal(first, Input("", classes="second"), classes="pair")
            )
            self.call_after_refresh(first.focus)
        elif button == "delete":
            focused = self.focused
            for pair in self.query(".pair"):
                if focused is not None and focused in pair.query("Input"):
                    pair.remove()
                    break
        elif button == "ok":
            self.dismiss(self.result())
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class SocketsScreen(ModalScreen["SocketsSpec | None"]):
    """
    The sockets of the new state, as the Qt socket dialog's tree: a socket (family, type, nonce), the packets it
    receives (base64) and its accepted sockets with theirs.
    """

    DEFAULT_CSS = (
        dialog_css("SocketsScreen")
        + "SocketsScreen Tree { width: 80; height: 12; } SocketsScreen Select { width: 22; }"
        + "SocketsScreen Input { width: 12; } SocketsScreen .row { height: auto; width: auto; }"
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, sockets: SocketsSpec | None) -> None:
        super().__init__()
        self.sockets = sockets if sockets is not None else SocketsSpec()

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text("Sockets"), classes="title")
            yield Tree("Sockets", id="tree")
            with Horizontal(classes="row"):
                yield Select([(f, f) for f in SOCKET_FAMILIES], prompt="Family", id="family", compact=True)
                yield Select([(t, t) for t in SOCKET_TYPES], prompt="Type", id="type", compact=True)
                yield Input("", placeholder="nonce", id="nonce", type="integer")
                yield Button("Add new socket", id="add-socket")
            with Horizontal(classes="buttons"):
                yield Button("Add an accepted socket", id="accept")
                yield Button("Add a recv package", id="packet")
                yield Button("Delete", id="delete")
                yield Button("OK", id="ok", variant="primary")

    def on_mount(self) -> None:
        self.reload()

    def reload(self) -> None:
        tree = self.query_one("#tree", Tree)
        tree.clear()
        tree.root.expand()
        for sock in self.sockets.sockets:
            node = tree.root.add(Text(sock.ident), data=sock, expand=True)
            self._add_socket_children(node, sock)

    @staticmethod
    def _add_socket_children(node: TreeNode, sock: SocketSpec) -> None:
        for idx, packet in enumerate(sock.packets):
            node.add_leaf(Text(f"Package: {packet}"), data=(sock, idx))
        for accepted in sock.accepted:
            child = node.add(Text(accepted.ident), data=accepted, expand=True)
            for idx, packet in enumerate(accepted.packets):
                child.add_leaf(Text(f"Package: {packet}"), data=(accepted, idx))

    def _current_socket(self) -> tuple[SocketSpec | None, SocketSpec | None]:
        """The socket of the selected row and the top-level socket it belongs to."""
        node = self.query_one("#tree", Tree).cursor_node
        while node is not None and not isinstance(node.data, SocketSpec):
            node = node.parent
        if node is None:
            return None, None
        top = node
        while top.parent is not None and isinstance(top.parent.data, SocketSpec):
            top = top.parent
        return node.data, top.data

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id
        if button == "add-socket":
            family = self.query_one("#family", Select).value
            type_ = self.query_one("#type", Select).value
            nonce = self.query_one("#nonce", Input).value
            if isinstance(family, str) and isinstance(type_, str):
                self.sockets.add_socket(family, type_, nonce)
        elif button == "accept":
            _sock, top = self._current_socket()
            if top is not None:
                self.sockets.accept(top)
        elif button == "packet":
            sock, _top = self._current_socket()
            if sock is not None:
                self.app.push_screen(PacketScreen(), lambda answer: self._add_packet(sock, answer))
                return
        elif button == "delete":
            self._delete()
        elif button == "ok":
            self.dismiss(self.sockets)
            return
        self.reload()

    def _add_packet(self, sock: SocketSpec, answer: str | None) -> None:
        if answer:
            sock.packets.append(answer)
            self.reload()

    def _delete(self) -> None:
        node = self.query_one("#tree", Tree).cursor_node
        if node is None or node.parent is None:
            return
        data = node.data
        if isinstance(data, tuple):
            sock, idx = data
            del sock.packets[idx]
        elif isinstance(data, SocketSpec):
            parent = node.parent.data
            siblings = parent.accepted if isinstance(parent, SocketSpec) else self.sockets.sockets
            siblings.remove(data)

    def action_cancel(self) -> None:
        self.dismiss(None)


class PacketScreen(ModalScreen["str | None"]):
    """A packet a socket receives, in base64."""

    DEFAULT_CSS = dialog_css("PacketScreen") + "PacketScreen Input { width: 60; }"
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text("Package (base64)"), classes="title")
            yield Input("", id="answer")

    def on_mount(self) -> None:
        self.query_one("#answer", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip() or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class NewStateScreen(ModalScreen["StateSpec | None"]):
    """
    The new state dialog. The name must be new and the address a label or a hex number, or OK is disabled, as in Qt;
    choosing a mode resets the options to its own; the filter hides the options that do not contain its text; Space or
    Enter on an option checks or unchecks it everywhere it is listed.
    """

    DEFAULT_CSS = (
        dialog_css("NewStateScreen")
        + _FORM_CSS.format(name="NewStateScreen")
        + "NewStateScreen Tree { width: 74; height: 12; }"
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, instance: Instance, spec: StateSpec) -> None:
        super().__init__()
        self.instance = instance
        self.spec = spec
        self.states = list(instance.states)
        self._option_nodes: list[tuple[TreeNode, str]] = []

    def compose(self) -> ComposeResult:
        spec = self.spec
        with Vertical():
            yield Label(Text("New State"), classes="title")
            with Horizontal(classes="row"):
                yield Label("Name")
                yield Input(spec.name, id="name")
            with Horizontal(classes="row"):
                yield Label("Address")
                yield Input(spec.address, id="address")
            with Horizontal(classes="row"):
                yield Label("Template")
                yield Select(
                    list(TEMPLATES),
                    value=spec.template,
                    allow_blank=False,
                    id="template",
                    compact=True,
                )
            with Horizontal(classes="row", id="base-row"):
                yield Label("Base state")
                yield Select(
                    [("<None>", -1)] + [(str(gui_data(s).name), idx) for idx, s in enumerate(self.states)],
                    value=-1,
                    allow_blank=False,
                    id="base",
                    compact=True,
                )
            with Horizontal(classes="row", id="args-row"):
                yield Label("Args")
                yield Input(spec.args or "", id="args")
            with Horizontal(classes="row", id="env-row"):
                yield Label("Environment")
                yield Button(self._items_text(spec.env, "Change"), id="env")
            with Horizontal(classes="row"):
                yield Label("Filesystem")
                yield Button(self._items_text(spec.fs_mounts, "Change"), id="fs")
            with Horizontal(classes="row"):
                yield Label("Sockets")
                yield Button("Change", id="sockets")
            with Horizontal(classes="row"):
                yield Label("Mode")
                yield Select(
                    list(MODES),
                    value=spec.mode,
                    allow_blank=False,
                    id="mode",
                    compact=True,
                )
            with Horizontal(classes="row"):
                yield Label("Options")
                yield Tree("Options", id="options")
            with Horizontal(classes="row"):
                yield Label("")
                yield Input("", placeholder="Filter", id="filter")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    @staticmethod
    def _items_text(items: list[Any], empty: str) -> str:
        return f"{len(items)} Items" if items else empty

    def on_mount(self) -> None:
        self._build_options("")
        self._template_changed()
        self._validate()
        self.query_one("#name", Input).focus()

    #
    # The options tree
    #

    def _build_options(self, filter_text: str) -> None:
        tree = self.query_one("#options", Tree)
        tree.clear()
        tree.show_root = False
        self._option_nodes = []
        wanted = filter_text.upper()
        for group, options in option_groups():
            shown = [o for o in options if wanted in o]
            if not shown:
                continue
            node = tree.root.add(group, data=None, expand=bool(wanted))
            for option in shown:
                leaf = node.add_leaf(checked_label(option, option in self.spec.options), data=option)
                self._option_nodes.append((leaf, option))

    def _relabel_options(self) -> None:
        for node, option in self._option_nodes:
            node.set_label(checked_label(option, option in self.spec.options))

    def toggle_option(self, option: str) -> None:
        if option in self.spec.options:
            self.spec.options.discard(option)
        else:
            self.spec.options.add(option)
        self._relabel_options()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if event.control.id == "options" and isinstance(event.node.data, str):
            event.stop()
            self.toggle_option(event.node.data)

    #
    # The form
    #

    def _template_changed(self) -> None:
        self.query_one("#base-row").display = self.spec.base_allowed
        self.query_one("#args-row").display = self.spec.args_allowed
        self.query_one("#env-row").display = self.spec.args_allowed

    def _validate(self) -> None:
        problems = self.spec.problems(self.instance)
        self.query_one("#name", Input).set_class("name" in problems, "-invalid")
        self.query_one("#address", Input).set_class("address" in problems, "-invalid")
        self.query_one("#ok", Button).disabled = bool(problems)

    def on_input_changed(self, event: Input.Changed) -> None:
        control = event.input.id
        if control == "name":
            self.spec.name = event.value
        elif control == "address":
            self.spec.address = event.value
        elif control == "args":
            self.spec.args = event.value
        elif control == "filter":
            self._build_options(event.value)
            return
        self._validate()

    def on_select_changed(self, event: Select.Changed) -> None:
        control = event.select.id
        value = event.value
        if control == "template" and isinstance(value, str):
            self.spec.template = value
            self._template_changed()
        elif control == "mode" and isinstance(value, str) and value != self.spec.mode:
            self.spec.set_mode(value)
            self._relabel_options()
        elif control == "base" and isinstance(value, int):
            self.spec.base_state = self.states[value] if value >= 0 else None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id
        spec = self.spec
        if button == "env":
            self.app.push_screen(
                PairsScreen("Environment", ("Name", "Value"), spec.env, "change me"),
                lambda rows: self._set_pairs("env", rows),
            )
        elif button == "fs":
            self.app.push_screen(
                PairsScreen("Filesystem", ("Mount Point", "Host Path"), spec.fs_mounts, "Edit Me"),
                lambda rows: self._set_pairs("fs", rows),
            )
        elif button == "sockets":
            self.app.push_screen(SocketsScreen(spec.sockets), self._set_sockets)
        elif button == "ok":
            if not spec.problems(self.instance):
                self.dismiss(spec)
        else:
            self.dismiss(None)

    def _set_pairs(self, which: str, rows: list[tuple[str, str]] | None) -> None:
        if rows is None:
            return
        if which == "env":
            self.spec.env = rows
        else:
            self.spec.fs_mounts = rows
        self.query_one(f"#{which}", Button).label = self._items_text(rows, "Change")

    def _set_sockets(self, sockets: SocketsSpec | None) -> None:
        if sockets is not None:
            self.spec.sockets = sockets

    def action_cancel(self) -> None:
        self.dismiss(None)


__all__ = ["NewStateScreen", "PacketScreen", "PairsScreen", "SocketsScreen"]
