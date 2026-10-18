"""Waiting helpers for the terminal app's pilot tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.pilot import Pilot


def kb_of(app: Any) -> Any:
    """The knowledge base of the app's main instance (typed loosely: it is None before a project loads)."""
    return app.workspace.main_instance.kb


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    """Let the app handle what is queued, ``rounds`` times."""
    for _ in range(rounds):
        await pilot.pause()


async def wait_for(pilot: Pilot, condition: Callable[[], bool], rounds: int = 300, then_settle: int = 0) -> None:
    """
    Pause until ``condition()`` holds, then :func:`settle` ``then_settle`` rounds; fail when it has not held after
    ``rounds`` short pauses.
    """
    for _ in range(rounds):
        if condition():
            await settle(pilot, then_settle)
            return
        await pilot.pause(0.02)
    raise AssertionError("the condition never held")
