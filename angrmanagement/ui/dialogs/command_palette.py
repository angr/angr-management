"""
Command palette dialog for selecting and executing commands.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .palette import PaletteDialog, PaletteItemDelegate, PaletteModel

if TYPE_CHECKING:
    from angrmanagement.logic.commands import Command
    from angrmanagement.ui.workspace import Workspace


class CommandPaletteModel(PaletteModel):
    """
    Data provider for command palette.
    """

    def get_items(self) -> list[Command]:
        return sorted(
            [cmd for cmd in self.workspace.command_manager.get_commands() if cmd.is_visible],
            key=lambda cmd: cmd.caption,
        )

    def get_caption_for_item(self, item: Command) -> str:
        return item.caption


class CommandPaletteDialog(PaletteDialog):
    """
    Dialog for selecting commands.
    """

    def __init__(self, workspace: Workspace, parent=None) -> None:
        super().__init__(CommandPaletteModel(workspace), PaletteItemDelegate(display_icons=False), parent)
        self.setWindowTitle("Command Palette")
