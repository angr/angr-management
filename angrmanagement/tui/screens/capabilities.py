"""
Help > Terminal capabilities: what angrmanagement.tui.caps detected about the terminal, the tier it chose (or that
``AM_TUI_TIER`` forced) and what each tier adds, the one in effect marked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, Static

from angrmanagement.tui.caps import TIER_ENV, TIER_FEATURES, TerminalCaps, capability_rows

from . import dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult


class CapabilitiesScreen(ModalScreen[None]):
    """The terminal's detected features and tier."""

    DEFAULT_CSS = (
        dialog_css("CapabilitiesScreen")
        + """
CapabilitiesScreen DataTable { height: auto; max-height: 14; }
CapabilitiesScreen #tiers { height: auto; padding: 1 0 0 0; }
CapabilitiesScreen #hint { height: auto; color: $text-muted; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "close", "Close"), Binding("enter", "close", "Close", show=False)]

    def __init__(self, caps: TerminalCaps, env: dict[str, str] | None = None) -> None:
        super().__init__()
        self.title_text = "Terminal capabilities"
        self.caps = caps
        self.rows = capability_rows(caps, env)

    def tier_text(self) -> Text:
        text = Text()
        for tier, features in TIER_FEATURES:
            current = tier <= self.caps.tier
            text.append("✔ " if current else "  ", style="bold green" if current else "")
            text.append(f"Tier {tier}: ", style="bold" if tier == self.caps.tier else "")
            text.append(features + "\n", style="" if current else "dim")
        return text

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            table: DataTable = DataTable(id="caps", cursor_type="row", zebra_stripes=True)
            table.add_columns("Feature", "Detected")
            for name, value in self.rows:
                table.add_row(name, value)
            yield table
            yield Static(self.tier_text(), id="tiers")
            yield Static(Text(f"Set {TIER_ENV}=0 to 3 before starting am-tui to use another tier."), id="hint")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")

    def on_mount(self) -> None:
        for button in self.query("#ok"):
            button.focus()

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


__all__ = ["CapabilitiesScreen"]
