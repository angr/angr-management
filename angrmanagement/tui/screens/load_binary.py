"""
The terminal's Load a new binary screen: the Qt Load Binary dialog's three tabs, over the same load options model.

Overview has the outer backend (with the encryption key for CaRT), the backend, the OS, the architecture list, the
three address fields and whether to load debug information; Dependencies has the libraries to load; Debug Symbols, for
a PE file, has the symbol download switch and the symbol path entries. OK checks the choices with
:func:`~angrmanagement.data.load_options.selection_from_choices`, as the Qt dialog does, and dismisses with the
:class:`~angrmanagement.data.load_options.LoadSelection`; Cancel dismisses with None.
"""

from __future__ import annotations

import contextlib
import os
from typing import TYPE_CHECKING, Any, ClassVar

import cle
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    Label,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from angrmanagement.data.load_options import (
    CART_BACKEND_NAME,
    CART_ENCKEY_ARGNAME,
    SYMBOL_PATH_ENTRY_TYPES,
    LoadChoiceError,
    arch_choices,
    arch_label,
    available_simos,
    file_hashes,
    initial_address_texts,
    inner_backend_names,
    key_to_hex,
    outer_backend_names,
    requested_dependencies,
    selection_from_choices,
    suggested_backend_name,
    suggested_outer_backend_name,
    suggested_simos_name,
    symbol_path_entry_error,
    symbol_path_rows,
)
from angrmanagement.present.dialogs import encryption_key_form, key_of_form
from angrmanagement.present.forms import Form, FormField
from angrmanagement.utils.cart_config import CART_CONFIG_KEY_OPTION, CART_CONFIG_PATH, load_cart_config_key

from . import MessageScreen, PromptScreen, dialog_css
from .form import FormScreen

if TYPE_CHECKING:
    from textual.app import ComposeResult


#: the address fields: key and caption
ADDRESS_CAPTIONS = (("base_addr", "Base address:"), ("entry_addr", "Entry address:"), ("offset", "Offset:"))


class LoadBinaryScreen(ModalScreen["LoadSelection | None"]):
    """Load a new binary: how to load the file a partial load has looked at."""

    DEFAULT_CSS = (
        dialog_css("LoadBinaryScreen")
        + """
LoadBinaryScreen > Vertical { width: 100; height: 90%; }
LoadBinaryScreen TabbedContent { height: 1fr; }
LoadBinaryScreen .row { height: auto; }
LoadBinaryScreen .row > Label { width: 16; padding: 0 1 0 0; }
LoadBinaryScreen .row > Select { width: 40; }
LoadBinaryScreen .row > Input { width: 24; }
LoadBinaryScreen .row > Checkbox { width: 18; }
LoadBinaryScreen #arch-tree { height: 1fr; min-height: 6; }
LoadBinaryScreen #dependencies { height: 1fr; }
LoadBinaryScreen #symbol-paths { height: 1fr; }
LoadBinaryScreen .facts { height: auto; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self,
        partial_ld: cle.Loader,
        suggested_backend: type[cle.Backend] | None = None,
        suggested_os_name: str | None = None,
        suggested_main_opts: dict | None = None,
        suggested_original_backend: type[cle.Backend] | None = None,
        suggested_main_filename: str | None = None,
    ) -> None:
        super().__init__()
        self.title_text = "Load a new binary"
        self.partial_ld = partial_ld
        self.suggested_backend = suggested_backend
        self.suggested_os_name = suggested_os_name
        self.suggested_main_opts = suggested_main_opts or {}
        self.suggested_original_backend = suggested_original_backend
        main = partial_ld.main_object
        self.file_path: str | None = main.binary if suggested_main_filename is None else suggested_main_filename
        self.md5, self.sha256 = file_hashes(main)
        self.is_pe = isinstance(main, cle.PE)
        self.dependencies = requested_dependencies(partial_ld)
        #: the key the outer backend should use; the partial load may already have been given one
        self.enckey: bytes | None = self.suggested_main_opts.get(CART_ENCKEY_ARGNAME)
        self.symbol_rows: list[tuple[str, str, str]] = []
        if self.is_pe:
            nt_symbol_path = os.environ.get("_NT_SYMBOL_PATH", "")
            if nt_symbol_path:
                self.symbol_rows = symbol_path_rows(nt_symbol_path)

    @property
    def filename(self) -> str:
        return os.path.basename(self.file_path) if self.file_path else ""

    #
    # Building
    #

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            facts = [f"File name: {self.filename or '<Unknown>'}"]
            if self.md5 is not None:
                facts.append(f"MD5:       {self.md5}")
            if self.sha256 is not None:
                facts.append(f"SHA256:    {self.sha256}")
            yield Static(Text("\n".join(facts)), classes="facts")
            with TabbedContent(id="load-tabs"):
                with TabPane("Overview", id="overview"):
                    yield from self._overview()
                with TabPane(f"Dependencies ({len(self.dependencies)})", id="dependencies-tab"):
                    yield Checkbox(
                        "Automatically load all libraries (slow, not recommended)", False, id="auto_load_libs"
                    )
                    yield SelectionList[str](*((dep, dep, False) for dep in self.dependencies), id="dependencies")
                if self.is_pe:
                    with TabPane("Debug Symbols", id="symbols"):
                        yield Checkbox("Allow downloading debug symbols from the Internet", True, id="allow_download")
                        yield DataTable(id="symbol-paths", cursor_type="row")
                        with Horizontal(classes="buttons"):
                            yield Button("Add...", id="add-symbol-path")
                            yield Button("Remove Selected", id="remove-symbol-path")
                            yield Button("Enter Symbol Path...", id="parse-symbol-path")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def _overview(self) -> ComposeResult:
        outer = suggested_outer_backend_name(self.suggested_original_backend)
        with Horizontal(classes="row"):
            yield Label("Outer backend:")
            names = outer_backend_names()
            yield Select(
                [(n, n) for n in names], value=outer if outer is not None else names[0], allow_blank=False, id="outer"
            )
            yield Button("Encryption key...", id="enckey")
        yield Label("", id="enckey-label")
        inner = inner_backend_names()
        backend = suggested_backend_name(self.suggested_backend) or (inner[0] if inner else None)
        with Horizontal(classes="row"):
            yield Label("Backend:")
            yield Select([(n, n) for n in inner], value=backend if backend else Select.NULL, id="backend")
        simos = available_simos()
        with Horizontal(classes="row"):
            yield Label("OS:")
            yield Select(
                [(n, n) for n in simos],
                value=suggested_simos_name(self.suggested_os_name, simos),
                allow_blank=False,
                id="os",
            )
        yield Label("Architecture:")
        yield self._arch_tree()
        enabled, texts = initial_address_texts(self.partial_ld, self.suggested_backend)
        for key, caption in ADDRESS_CAPTIONS:
            with Horizontal(classes="row"):
                yield Checkbox(caption, False, id=f"{key}-on")
                yield Input(texts.get(key, ""), id=key, disabled=not enabled, compact=True)
        yield Checkbox("Load debug information if available", True, id="load_debug_info")

    def _arch_tree(self) -> Tree[Any]:
        tree: Tree[Any] = Tree("Architectures", id="arch-tree")
        tree.show_root = False
        recommended, other, ideal = arch_choices(self.partial_ld)
        suggested = tree.root.add("Suggested architectures", expand=bool(recommended))
        others = tree.root.add("Other architectures", expand=not recommended)
        self._ideal_node = None
        for arch in recommended:
            node = suggested.add_leaf(arch_label(arch), data=arch)
            if arch is ideal:
                self._ideal_node = node
        for arch in other:
            others.add_leaf(arch_label(arch), data=arch)
        return tree

    def on_mount(self) -> None:
        if not self.query("#outer"):
            # the app tore the screen down while it mounted (it exits)
            return
        self._update_enckey_widgets()
        if self._ideal_node is not None:
            tree = self.query_one("#arch-tree", Tree)
            self.call_after_refresh(tree.move_cursor, self._ideal_node)
        if self.is_pe:
            table = self.query_one("#symbol-paths", DataTable)
            table.add_columns("Type", "Cache", "Server")
            self._fill_symbol_table()
            self._update_symbols_enabled()
        with contextlib.suppress(Exception):
            self.query_one("#ok", Button).focus()

    #
    # The encryption key and the symbol paths
    #

    def _update_enckey_widgets(self) -> None:
        """Offer the encryption key only for an outer backend that takes one."""
        supported = self.query_one("#outer", Select).value == CART_BACKEND_NAME
        self.query_one("#enckey", Button).disabled = not supported
        label = self.query_one("#enckey-label", Label)
        label.display = supported
        if self.enckey is None:
            label.update("Using the default encryption key")
        else:
            label.update("Encryption key: " + key_to_hex(self.enckey))

    def _ask_enckey(self) -> None:
        prompt = f"Set the encryption key that the {CART_BACKEND_NAME} backend should use."
        enckey = self.enckey
        if enckey is None:
            enckey = load_cart_config_key()
            if enckey is not None:
                prompt += f"\nPre-filled with {CART_CONFIG_KEY_OPTION} from {CART_CONFIG_PATH}."

        def then(values: dict[str, Any] | None) -> None:
            key = key_of_form(values)
            if key is not None:
                self.enckey = key
                self._update_enckey_widgets()

        self.app.push_screen(
            FormScreen(encryption_key_form(prompt, "" if enckey is None else key_to_hex(enckey))), then
        )

    def _fill_symbol_table(self) -> None:
        table = self.query_one("#symbol-paths", DataTable)
        table.clear()
        for row in self.symbol_rows:
            table.add_row(*(Text(cell) for cell in row))

    def _update_symbols_enabled(self) -> None:
        """The symbol options apply only when debug information is loaded, as the Qt dialog greys its tab out."""
        on = self.query_one("#load_debug_info", Checkbox).value
        for widget in self.query_one("#symbols", TabPane).query("*"):
            widget.disabled = not on

    def _add_symbol_path(self) -> None:
        form = Form(
            "Add Symbol Path Entry",
            [
                FormField("type", "Type:", "choice", "local", [(t, t) for t in SYMBOL_PATH_ENTRY_TYPES]),
                FormField("cache", "Cache Path:", description="For a symbol server: where downloads are kept"),
                FormField("path", "Path/Server:", description="A directory, or the URL of a symbol server"),
            ],
        )

        def then(values: dict[str, Any] | None) -> None:
            if values is None:
                return
            entry_type, cache, path = values["type"], values["cache"].strip(), values["path"].strip()
            error = symbol_path_entry_error(entry_type, path)
            if error is not None:
                self.app.push_screen(MessageScreen("warning", "Invalid Input", error))
                return
            self.symbol_rows.append((entry_type, cache if entry_type == "srv" else "", path))
            self._fill_symbol_table()

        self.app.push_screen(FormScreen(form), then)

    def _remove_symbol_path(self) -> None:
        table = self.query_one("#symbol-paths", DataTable)
        if not self.symbol_rows or table.cursor_row is None or not 0 <= table.cursor_row < len(self.symbol_rows):
            self.app.push_screen(MessageScreen("info", "No Selection", "Please select one or more rows to remove."))
            return
        del self.symbol_rows[table.cursor_row]
        self._fill_symbol_table()

    def _parse_symbol_path(self) -> None:
        def then(text: str | None) -> None:
            if text:
                self.symbol_rows.extend(symbol_path_rows(text))
                self._fill_symbol_table()

        self.app.push_screen(
            PromptScreen(
                "Enter Symbol Path String",
                "Enter symbol path string (e.g., from _NT_SYMBOL_PATH):",
                os.environ.get("_NT_SYMBOL_PATH", ""),
            ),
            then,
        )

    #
    # Events
    #

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "outer":
            self._update_enckey_widgets()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        checkbox_id = event.checkbox.id or ""
        if checkbox_id.endswith("-on"):
            self.query_one(f"#{checkbox_id.removesuffix('-on')}", Input).disabled = not event.value
        elif checkbox_id == "load_debug_info" and self.is_pe:
            self._update_symbols_enabled()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        actions = {
            "ok": self.action_accept,
            "cancel": self.action_cancel,
            "enckey": self._ask_enckey,
            "add-symbol-path": self._add_symbol_path,
            "remove-symbol-path": self._remove_symbol_path,
            "parse-symbol-path": self._parse_symbol_path,
        }
        action = actions.get(event.button.id or "")
        if action is not None:
            action()

    #
    # Answers
    #

    def choices(self) -> dict[str, Any]:
        """What the widgets hold, as selection_from_choices takes it."""

        def text_of(select_id: str) -> str:
            value = self.query_one(f"#{select_id}", Select).value
            return value if isinstance(value, str) else ""

        node = self.query_one("#arch-tree", Tree).cursor_node
        selected = set(self.query_one("#dependencies", SelectionList).selected)
        address_texts: dict[str, str | None] = {}
        for key, _caption in ADDRESS_CAPTIONS:
            on = self.query_one(f"#{key}-on", Checkbox).value
            address_texts[key] = self.query_one(f"#{key}", Input).value if on else None
        return {
            "outer_backend": text_of("outer"),
            "backend": text_of("backend"),
            "simos_name": text_of("os"),
            "arch": node.data if node is not None else None,
            "auto_load_libs": self.query_one("#auto_load_libs", Checkbox).value,
            "load_debug_info": self.query_one("#load_debug_info", Checkbox).value,
            "dependencies": [(dep, dep in selected) for dep in self.dependencies],
            "address_texts": address_texts,
            "allow_symbol_download": self.query_one("#allow_download", Checkbox).value if self.is_pe else True,
            "symbol_path_rows": list(self.symbol_rows),
            "enckey": self.enckey,
        }

    def action_accept(self) -> None:
        try:
            selection = selection_from_choices(**self.choices())
        except LoadChoiceError as e:
            self.app.push_screen(MessageScreen("critical", e.caption, e.message))
            return
        self.dismiss(selection)

    def action_cancel(self) -> None:
        self.dismiss(None)


__all__ = ["LoadBinaryScreen"]
