"""
The terminal's Signature Matches screen: the functions a signature matched, which of them already have a name of
their own, whether to overwrite those or keep them, and Apply Functions. Enter on a row jumps to that function.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Label, RadioButton, RadioSet

from angrmanagement.present.signatures import apply_signature_matches, signature_match_rows

from . import dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from angrmanagement.data.instance import Instance


class SignatureMatchesScreen(ModalScreen["str | None"]):
    """
    The matches of one signature. Dismisses with ``"applied"`` after Apply Functions, ``"jumped"`` after a jump, None
    when closed.
    """

    DEFAULT_CSS = (
        dialog_css("SignatureMatchesScreen")
        + """
SignatureMatchesScreen > Vertical { width: 90; height: 70%; }
SignatureMatchesScreen DataTable { height: 1fr; }
SignatureMatchesScreen RadioSet { height: auto; width: auto; layout: horizontal; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "close", "Close")]

    def __init__(self, workspace: Any, sig: Any, matches: dict[int, str], instance: Instance, signature_mgr) -> None:
        super().__init__()
        self.title_text = f"Signature Matches: {sig.sig_name}"
        self.workspace = workspace
        self.sig = sig
        self.matches = matches
        self.instance = instance
        self.signature_mgr = signature_mgr
        self.rows = signature_match_rows(instance, matches)

    def compose(self) -> ComposeResult:
        conflicts = sum(1 for _addr, _name, conflict in self.rows if conflict)
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            yield DataTable(id="matches", cursor_type="row")
            yield Label(f"Conflict Resolution ({conflicts}/{len(self.rows)} conflicts)", id="conflicts")
            yield RadioSet(RadioButton("Overwrite", value=True, id="overwrite"), RadioButton("Ignore", id="ignore"))
            with Horizontal(classes="buttons"):
                yield Button("Apply Functions", id="apply", variant="primary")
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        if not self.query("#matches"):
            return
        table = self.query_one("#matches", DataTable)
        table.add_columns("Function Address", "Function Name", "Conflict")
        for addr, name, conflict in self.rows:
            table.add_row(Text(f"{addr:#x}"), Text(name), Text("✓" if conflict else ""))
        table.focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        addr = self.rows[event.cursor_row][0]
        self.workspace.jump_to(addr)
        self.dismiss("jumped")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "apply":
            ignore = self.query_one("#ignore", RadioButton).value
            apply_signature_matches(self.signature_mgr, self.instance, self.sig, self.matches, ignore)
            self.dismiss("applied")
        elif event.button.id == "close":
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


__all__ = ["SignatureMatchesScreen"]
