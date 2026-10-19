"""
Command palettes: the commands of the command manager, and a goto palette over the functions.

Both rank with thefuzz, as the Qt palettes do, and show the shortcut a command has on this terminal.
"""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from textual.command import DiscoveryHit, Hit, Hits, Provider
from thefuzz import process

if TYPE_CHECKING:
    from angrmanagement.logic.commands import Command


def fuzzy_rank(query: str, choices: dict[int, str], limit: int = 50) -> list[tuple[int, int]]:
    """``(key, score 0..100)`` of the choices that best match ``query``, best first, as the Qt palette ranks them."""
    extract = process.extract  # pyright: ignore[reportAttributeAccessIssue]
    return [(key, score) for _caption, score, key in extract(query, choices, limit=limit)]


class AmCommandProvider(Provider):
    """The visible commands of the workspace's command manager."""

    def _commands(self) -> list[Command]:
        workspace = getattr(self.app, "workspace", None)
        if workspace is None:
            return []
        return sorted((c for c in workspace.command_manager.get_commands() if c.is_visible), key=lambda c: c.caption)

    def _help(self, command: Command) -> str | None:
        shortcut_for = getattr(self.app, "shortcut_for_command", None)
        return shortcut_for(command) if shortcut_for is not None else None

    async def discover(self) -> Hits:
        for command in self._commands():
            yield DiscoveryHit(command.caption, partial(self.app.call_later, command.run), help=self._help(command))

    async def search(self, query: str) -> Hits:
        commands = self._commands()
        matcher = self.matcher(query)
        for key, score in fuzzy_rank(query, {i: c.caption for i, c in enumerate(commands)}):
            command = commands[key]
            yield Hit(
                score / 100,
                matcher.highlight(command.caption),
                partial(self.app.call_later, command.run),
                text=command.caption,
                help=self._help(command),
            )


class GotoProvider(Provider):
    """The functions of the project, by name; choosing one shows it."""

    def _functions(self) -> list:
        workspace = getattr(self.app, "workspace", None)
        if workspace is None or workspace.main_instance.project.am_none:
            return []
        return list(workspace.main_instance.project.kb.functions.values())

    def _go(self, func) -> None:
        go = getattr(self.app, "goto_function", None)
        if go is not None:
            go(func)

    async def discover(self) -> Hits:
        for func in self._functions()[:200]:
            yield DiscoveryHit(func.name, partial(self._go, func), help=f"{func.addr:x}")

    async def search(self, query: str) -> Hits:
        funcs = self._functions()
        matcher = self.matcher(query)
        for key, score in fuzzy_rank(query, {i: f.name for i, f in enumerate(funcs)}):
            func = funcs[key]
            yield Hit(
                score / 100,
                matcher.highlight(func.name),
                partial(self._go, func),
                text=func.name,
                help=f"{func.addr:x}",
            )
