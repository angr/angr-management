"""
Screenshots of the terminal frontend, without a terminal.

:func:`shoot` runs the app headless through Textual's pilot, opens a binary, shows each view in turn and saves an SVG
of the screen for each, the way ``am-tui --screenshot-dir`` does. :func:`show_view` and :func:`capture` are the steps,
for tests and other harnesses.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps

if TYPE_CHECKING:
    from collections.abc import Iterable

    from textual.pilot import Pilot
    from textual.widget import Widget


async def show_view(pilot: Pilot, category: str) -> Widget | None:
    """Show the view of ``category`` through the app's own action, and wait until it is drawn."""
    app = pilot.app
    assert isinstance(app, AmApp)
    app.action_show_view(category)
    await pilot.pause()
    await pilot.pause()
    await pilot.wait_for_scheduled_animations()
    return app.view_widget(category)


def capture(app: AmApp, path: str) -> str:
    """Save the screen as an SVG at ``path``; returns the path."""
    return app.capture(path)


async def shoot(
    outdir: str,
    binary: str | None = None,
    size: tuple[int, int] = (200, 60),
    categories: Iterable[str] | None = None,
    theme_name: str | None = None,
    function: str | None = "main",
) -> list[str]:
    """Open ``binary`` and save ``<outdir>/<category>.svg`` for each view; returns the files written."""
    os.makedirs(outdir, exist_ok=True)
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name=theme_name, interactive=False)
    written = []
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        if binary:
            await app.open_binary(binary, function=function)
            await pilot.pause()
        written.append(capture(app, os.path.join(outdir, "window.svg")))
        for category in categories if categories is not None else app.VIEW_CATEGORIES:
            if await show_view(pilot, category) is not None:
                written.append(capture(app, os.path.join(outdir, f"{category}.svg")))
    return written
