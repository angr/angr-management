from typing import TYPE_CHECKING, Dict, Sequence

if TYPE_CHECKING:
    from .command import Command


class CommandManager:
    """
    Manages available commands.
    """

    def __init__(self):
        self._commands: Dict[str, Command] = {}

    def register_command(self, command: "Command"):
        assert command.name not in self._commands, "Command by this name already registered"
        self._commands[command.name] = command

    def register_commands(self, commands: Sequence["Command"]):
        for command in commands:
            self.register_command(command)

    def unregister_command(self, command: "Command"):
        self._commands.pop(command.name, None)

    def unregister_commands(self, commands: Sequence["Command"]):
        for command in commands:
            self.unregister_command(command)

    def get_commands(self):
        return self._commands.values()
