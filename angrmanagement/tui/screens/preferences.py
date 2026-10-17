"""
The terminal's Preferences screen: the Qt Preferences dialog's pages as tabs, over the same entries.

OS Integration has the URL scheme and the daemon; Theme and Colors the scheme and a sheet of every colour entry, each
with its hexadecimal value and a swatch; Style the log's timestamp format and the fonts, which a terminal does not
use; LLM and MCP Server their settings. Save writes the configuration file, as the Qt dialog's Save does, and
dismisses with True; Close and Escape dismiss with None and keep nothing.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.widgets import Button, Checkbox, Input, Label, Select, Static, TabbedContent, TabPane

from angrmanagement.config import Conf, save_config
from angrmanagement.present.preferences import (
    LLM_SWITCHES,
    MCP_TEXT,
    color_entry_names,
    color_text,
    current_theme_values,
    font_texts,
    generate_auth_token,
    known_model_names,
    llm_values,
    log_format_choices,
    mcp_values,
    parse_color,
    save_integration,
    save_llm,
    save_log_format,
    save_mcp,
    save_theme,
    scheme_entry_values,
    theme_choices,
    url_scheme_state,
)
from angrmanagement.present.theme import CUSTOM_SCHEME_NAME

from . import dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from angrmanagement.config.color import Color

#: what the Style page says about the font entries
FONTS_NOTE = "The terminal draws every view in its own font; these entries are for the Qt frontend and are kept as set."


class PreferencesScreen(ModalScreen["bool | None"]):
    """Preferences: the five pages of the Qt dialog."""

    DEFAULT_CSS = (
        dialog_css("PreferencesScreen")
        + """
PreferencesScreen > Vertical { width: 110; height: 90%; }
PreferencesScreen TabbedContent { height: 1fr; }
PreferencesScreen .row { height: auto; }
PreferencesScreen .row > Label { width: 30; padding: 0 1 0 0; }
PreferencesScreen .row > Input { width: 1fr; }
PreferencesScreen .row > Select { width: 1fr; }
PreferencesScreen .color > Input { width: 12; }
PreferencesScreen .color > .swatch { width: 4; }
PreferencesScreen .note { color: $text-muted; padding: 1 0; }
PreferencesScreen #colors { height: 1fr; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "close", "Close"), Binding("ctrl+s", "save", "Save", show=False)]

    def __init__(self, workspace: Any = None) -> None:
        super().__init__()
        self.title_text = "Preferences"
        self.workspace = workspace
        self.url_scheme_supported, self.url_scheme_registered, self.url_scheme_target = url_scheme_state()
        self.color_values, self.others = current_theme_values()
        self.base_theme_name = Conf.base_theme_name
        self.fmt_map, self.shown_format = log_format_choices()
        self.llm = llm_values()
        self.mcp = mcp_values()

    #
    # Building
    #

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            with TabbedContent(id="pages"):
                with TabPane("OS Integration", id="integration"):
                    yield from self._integration()
                with TabPane("Theme and Colors", id="theme"):
                    yield from self._theme()
                with TabPane("Style", id="style"):
                    yield from self._style()
                with TabPane("LLM", id="llm"):
                    yield from self._llm()
                with TabPane("MCP Server", id="mcp"):
                    yield from self._mcp()
            with Horizontal(classes="buttons"):
                yield Button("Save", id="save", variant="primary")
                yield Button("Close", id="close")

    def _integration(self) -> ComposeResult:
        yield Checkbox(
            "Register angr URL scheme (angr://).",
            self.url_scheme_registered,
            id="url_scheme",
            disabled=not self.url_scheme_supported,
        )
        yield Checkbox("Always use local RPC daemon", Conf.use_daemon, id="use_daemon")
        yield Label("Currently registered to:")
        yield Static(Text(self.url_scheme_target), id="url_scheme_target")

    def _theme(self) -> ComposeResult:
        with Horizontal(classes="row"):
            yield Label("Load Theme:")
            choices = theme_choices()
            current = Conf.theme_name if Conf.theme_name in choices else choices[0]
            yield Select([(name, name) for name in choices], value=current, allow_blank=False, id="theme_name")
        with Horizontal(classes="row"):
            yield Label("Base Theme:")
            yield Static(Text(self.base_theme_name), id="base_theme")
        with VerticalScroll(id="colors"):
            for name in color_entry_names():
                color = self.color_values[name]
                with Horizontal(classes="row color"):
                    yield Label(name)
                    yield Input(color_text(color) if color is not None else "", id=f"color-{name}", compact=True)
                    yield Static("", classes="swatch", id=f"swatch-{name}")

    def _style(self) -> ComposeResult:
        with Horizontal(classes="row"):
            yield Label("Log datetime Format String:")
            yield Input(self.shown_format, suggester=SuggestFromList(list(self.fmt_map)), id="log_format", compact=True)
        yield Label(Text("Shown as: " + ", ".join(self.fmt_map)), classes="note")
        yield Label("Fonts", classes="group")
        for caption, value in font_texts():
            with Horizontal(classes="row"):
                yield Label(f"{caption}:")
                yield Static(Text(value))
        yield Static(Text(FONTS_NOTE), classes="note")

    def _llm(self) -> ComposeResult:
        with Horizontal(classes="row"):
            yield Label("Model:")
            yield Input(
                self.llm["llm_model"],
                placeholder="e.g. gpt-4o, claude-sonnet-4-20250514, ollama/llama3",
                suggester=SuggestFromList(known_model_names(), case_sensitive=False),
                id="llm_model",
                compact=True,
            )
        with Horizontal(classes="row"):
            yield Label("API Key:")
            yield Input(
                self.llm["llm_api_key"],
                password=True,
                placeholder="Optional (uses env var if empty)",
                id="llm_api_key",
                compact=True,
            )
        with Horizontal(classes="row"):
            yield Label("API Base URL:")
            yield Input(
                self.llm["llm_api_base"], placeholder="Optional (for custom endpoints)", id="llm_api_base", compact=True
            )
        for name, caption in LLM_SWITCHES:
            yield Checkbox(caption, bool(self.llm[name]), id=name)

    def _mcp(self) -> ComposeResult:
        yield Static(Text(MCP_TEXT), classes="note")
        with Horizontal(classes="row"):
            yield Label("Port:")
            yield Input(str(self.mcp["mcp_server_port"]), type="integer", id="mcp_server_port", compact=True)
        yield Checkbox(
            "Start the MCP server automatically on launch", self.mcp["mcp_server_autostart"], id="mcp_server_autostart"
        )
        with Horizontal(classes="row"):
            yield Label("History limit (0 = unlimited):")
            yield Input(
                str(self.mcp["mcp_server_history_limit"]), type="integer", id="mcp_server_history_limit", compact=True
            )
        yield Checkbox(
            "Require a bearer token to connect", self.mcp["mcp_server_auth_enabled"], id="mcp_server_auth_enabled"
        )
        with Horizontal(classes="row"):
            yield Label("Token:")
            yield Input(
                self.mcp["mcp_server_auth_token"],
                placeholder="Leave empty to generate one when the server starts",
                id="mcp_server_auth_token",
                disabled=not self.mcp["mcp_server_auth_enabled"],
                compact=True,
            )
            yield Button("Generate", id="generate_token")

    def on_mount(self) -> None:
        if not self.query("#pages"):
            # the app tore the screen down while it mounted (it exits)
            return
        for name, color in self.color_values.items():
            self._show_swatch(name, color)
        with contextlib.suppress(Exception):
            self.query_one("#save", Button).focus()

    #
    # Colours
    #

    def _show_swatch(self, name: str, color: Color | None) -> None:
        with contextlib.suppress(Exception):
            swatch = self.query_one(f"#swatch-{name}", Static)
            swatch.styles.background = f"#{color.rgb_hex}" if color is not None else None
            swatch.update("" if color is not None else "??")

    def load_scheme(self, name: str) -> None:
        """Show the colours of the scheme ``name``, as picking it in the Qt dialog's Load Theme box does."""
        scheme = scheme_entry_values(name)
        if not scheme:
            return
        for entry, value in scheme.items():
            if entry in self.color_values:
                self.color_values[entry] = value
                with contextlib.suppress(Exception):
                    self.query_one(f"#color-{entry}", Input).value = color_text(value)
                self._show_swatch(entry, value)
            if entry in self.others:
                self.others[entry] = value
        self.base_theme_name = name
        self.query_one("#base_theme", Static).update(Text(name))

    #
    # Events
    #

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "theme_name" and isinstance(event.value, str) and event.value != CUSTOM_SCHEME_NAME:
            self.load_scheme(event.value)

    def on_input_changed(self, event: Input.Changed) -> None:
        input_id = event.input.id or ""
        if input_id.startswith("color-"):
            name = input_id.removeprefix("color-")
            color = parse_color(event.value)
            if color is not None:
                self.color_values[name] = color
            event.input.set_class(color is None, "-invalid")
            self._show_swatch(name, color)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "mcp_server_auth_enabled":
            self.query_one("#mcp_server_auth_token", Input).disabled = not event.value

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "save":
            self.action_save()
        elif event.button.id == "close":
            self.action_close()
        elif event.button.id == "generate_token":
            self.query_one("#mcp_server_auth_token", Input).value = generate_auth_token()

    #
    # Saving
    #

    def _value(self, widget_id: str) -> Any:
        widget = self.query_one(f"#{widget_id}")
        return widget.value  # type: ignore[attr-defined]

    def _number(self, widget_id: str, default: int, low: int, high: int) -> int:
        try:
            number = int(self._value(widget_id))
        except ValueError:
            return default
        return min(max(number, low), high)

    def action_save(self) -> None:
        """Write every page to the configuration and save the file."""
        save_integration(bool(self._value("url_scheme")), bool(self._value("use_daemon")))
        theme_name = self._value("theme_name")
        save_theme(theme_name, self.base_theme_name, self.color_values, self.others)
        save_log_format(self._value("log_format"), self.fmt_map)
        llm = {name: self._value(name) for name in ("llm_model", "llm_api_key", "llm_api_base")}
        llm.update({name: self._value(name) for name, _caption in LLM_SWITCHES})
        save_llm(llm, self.workspace)
        save_mcp(
            {
                "mcp_server_port": self._number("mcp_server_port", self.mcp["mcp_server_port"], 1, 65535),
                "mcp_server_autostart": self._value("mcp_server_autostart"),
                "mcp_server_history_limit": self._number(
                    "mcp_server_history_limit", self.mcp["mcp_server_history_limit"], 0, 1_000_000
                ),
                "mcp_server_auth_enabled": self._value("mcp_server_auth_enabled"),
                "mcp_server_auth_token": self._value("mcp_server_auth_token"),
            }
        )
        try:
            save_config()
        except OSError as ex:
            self.notify(f"The configuration was not saved: {ex}", severity="error")
        self.dismiss(True)

    def action_close(self) -> None:
        self.dismiss(None)


__all__ = ["PreferencesScreen"]
