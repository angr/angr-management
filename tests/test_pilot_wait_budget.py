"""
conftest.py gives a Textual pilot's wait for pending messages a longer budget than Textual's own 30 s, because the
macOS runner freezes for longer than that. These tests stand in for a freeze by moving the event loop's clock forward
while a message is being handled, which is what a process sees when it is resumed after being stopped.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import asyncio
import inspect
import unittest

from textual.app import App, ComposeResult
from textual.message import Message
from textual.pilot import Pilot, WaitForScreenTimeout
from textual.widgets import Static

#: longer than any stall measured: on the macOS runner, tests in flight across one ran up to 60 s over their usual
#: time, and on Linux the slowest wait across a 35 s stop took 77 s
LONGEST_FREEZE = 80.0


class Freeze(Message):
    """Handled by moving the loop's clock forward, then going on with the rest of the work."""


class FreezingApp(App[None]):
    """An app that freezes, on the clock of the loop, while it handles a Freeze message."""

    def __init__(self, clock: list[float], seconds: float, on_mount_too: bool = False) -> None:
        super().__init__()
        self.clock = clock
        self.seconds = seconds
        self.on_mount_too = on_mount_too

    def compose(self) -> ComposeResult:
        yield Static("frozen")

    def on_mount(self) -> None:
        if self.on_mount_too:
            self.post_message(Freeze())

    async def on_freeze(self, _message: Freeze) -> None:
        self.clock[0] += self.seconds
        # the work the freeze interrupted, still to do when the loop runs again
        await asyncio.sleep(0.05)


def run_frozen(seconds: float, while_starting: bool) -> None:
    """Run a pilot over an app whose handling of one message spans a freeze of ``seconds``."""
    loop = asyncio.new_event_loop()
    clock = [0.0]
    loop_time = loop.time
    loop.time = lambda: loop_time() + clock[0]  # type: ignore[method-assign]

    async def main() -> None:
        app = FreezingApp(clock, seconds, on_mount_too=while_starting)
        async with app.run_test() as pilot:
            if not while_starting:
                app.post_message(Freeze())
                await pilot.pause()

    try:
        loop.run_until_complete(main())
    finally:
        loop.close()


def budget() -> float:
    return inspect.signature(Pilot._wait_for_screen).parameters["timeout"].default  # pylint: disable=protected-access


class TestPilotWaitBudget(unittest.TestCase):
    """The budget conftest.py gives the pilot's waits, against a freeze."""

    def test_the_budget_outlasts_the_longest_freeze_and_ends_before_pytest_timeout(self) -> None:
        # CI runs pytest with --timeout 900, and conftest.py's late stack dump fires at nine tenths of that, so a wait
        # whose messages are really stuck fails on its own, with its own error, well before either
        assert LONGEST_FREEZE < budget() < 900 * 0.9

    def test_a_pause_outlasts_a_freeze(self) -> None:
        run_frozen(LONGEST_FREEZE, while_starting=False)

    def test_the_wait_when_the_app_starts_outlasts_a_freeze(self) -> None:
        # where the macOS run failed: run_test's own wait, before the test does anything
        run_frozen(LONGEST_FREEZE, while_starting=True)

    def test_messages_still_pending_after_the_budget_fail_the_wait(self) -> None:
        with self.assertRaises(WaitForScreenTimeout):
            run_frozen(budget() + 1, while_starting=False)
        with self.assertRaises(WaitForScreenTimeout):
            run_frozen(budget() + 1, while_starting=True)


if __name__ == "__main__":
    unittest.main()
