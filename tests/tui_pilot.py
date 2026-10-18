"""Waiting helpers for the terminal app's pilot tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.pilot import Pilot


async def settle(pilot: Pilot, rounds: int = 4) -> None:
    """Let the app handle what is queued, ``rounds`` times."""
    for _ in range(rounds):
        await pilot.pause()


async def wait_for(pilot: Pilot, condition: Callable[[], bool], rounds: int = 300) -> None:
    """Pause until ``condition()`` holds; fail when it has not after ``rounds`` short pauses."""
    for _ in range(rounds):
        if condition():
            return
        await pilot.pause(0.02)
    raise AssertionError("the condition never held")
