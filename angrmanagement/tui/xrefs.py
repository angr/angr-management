"""The cross-references screen of the terminal frontend."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Label

from angrmanagement.tui.screens import dialog_css
from angrmanagement.tui.widgets.table import TableWidget

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from angrmanagement.present.xrefs import XRefsModel


class XRefsScreen(ModalScreen[int | None]):
    """The references to an address or a variable; Enter jumps to one, Escape closes."""

    DEFAULT_CSS = dialog_css("XRefsScreen") + "XRefsScreen > Vertical { width: 90%; height: 70%; }"
    BINDINGS: ClassVar = [Binding("escape", "close", "Close")]

    def __init__(self, model: XRefsModel) -> None:
        super().__init__()
        self.model = model
        model.on_jump = self._jump
        self.table = TableWidget(model)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.model.title), classes="title")
            yield self.table

    def on_mount(self) -> None:
        self.table.focus()

    def _jump(self, addr: int) -> None:
        self.dismiss(addr)

    def action_close(self) -> None:
        self.dismiss(None)
