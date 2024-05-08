from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .command import Command


class CommandManager:
    """
    Manages available commands.
    """

    def __init__(self) -> None:
        self._commands: dict[str, Command] = {}

    def register_command(self, command: Command) -> None:
        assert command.name not in self._commands, "Command by this name already registered"
        self._commands[command.name] = command

    def register_commands(self, commands: Sequence[Command]) -> None:
        for command in commands:
            self.register_command(command)

    def unregister_command(self, command: Command) -> None:
        self._commands.pop(command.name, None)

    def unregister_commands(self, commands: Sequence[Command]) -> None:
        for command in commands:
            self.unregister_command(command)

    def get_commands(self):
        return self._commands.values()
