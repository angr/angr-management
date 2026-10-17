"""
The trace map, without a toolkit and in the terminal, over a trace debugger whose trace is scripted: the numbers read
from the debugger, positions and events, the segments drawn, a click replaying, and the empty map without a trace.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import asyncio
import unittest
from typing import Any

from scripted_trace import ScriptedTrace

from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.present.trace_map import (
    TraceMapModel,
    TraceMapPresenter,
    addr_from_pos,
    pos_from_addr,
    trace_position,
)
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.views.trace_map import TraceMapTuiView

#: the terminal size of every view's snapshot
SIZE = (200, 60)


class TestModel(unittest.TestCase):
    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)

    def tearDown(self):
        self.workspace.job_manager.quit()

    def test_positions(self):
        assert pos_from_addr(250, 1000, 100) == 25
        assert pos_from_addr(1001, 1000, 100) is None and pos_from_addr(5, 0, 100) is None
        assert addr_from_pos(25, 1000, 100) == 250
        assert trace_position(None) == (0, 0, [])
        assert trace_position(ScriptedTrace(self.workspace)) == (250, 1000, [100, 600])

    def test_segments(self):
        model = TraceMapModel()
        assert not model.segments(100)
        model.update(ScriptedTrace(self.workspace))
        model.hover_addr = 900
        assert model.segments(100) == [
            (10, 25, "frontier_before"),
            (26, 41, "frontier_after"),
            (10, 11, "checkpoint"),
            (60, 61, "checkpoint"),
            (25, 26, "current"),
            (90, 91, "hover"),
        ]

    def test_presenter_follows_and_replays(self):
        instance = self.workspace.main_instance
        presenter = TraceMapPresenter(self.workspace, instance)
        assert presenter.model.total == 0
        dbg = ScriptedTrace(self.workspace)
        instance.debugger_mgr.set_debugger(dbg)
        assert (presenter.model.addr, presenter.model.total) == (250, 1000)
        presenter.select_offset(50, 100)
        assert dbg.replayed == [500] and presenter.model.addr == 500
        presenter.hover(10, 100)
        assert presenter.model.hover_addr == 100
        presenter.hover(None, 100)
        assert presenter.model.hover_addr is None
        presenter.close()


class TestTerminal(unittest.TestCase):
    def test_map_draws_and_a_click_replays(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                assert await app.run_action("show_view('tracemap')")
                for _ in range(4):
                    await pilot.pause()
                view = app.view_widget("tracemap")
                assert isinstance(view, TraceMapTuiView)
                assert app.workspace.view_manager.area_of(view) == "top"
                widget = view.map
                assert "".join(s.text for s in widget.render_line(1)).strip() == ""
                dbg = ScriptedTrace(app.workspace)
                app.workspace.main_instance.debugger_mgr.set_debugger(dbg)
                for _ in range(4):
                    await pilot.pause()
                width = widget.size.width
                current = pos_from_addr(250, 1000, width)
                assert current is not None
                middle = "".join(s.text for s in widget.render_line(1))
                top = "".join(s.text for s in widget.render_line(0))
                assert middle[current] == "│" and top[current] == "▼"
                assert middle[pos_from_addr(600, 1000, width) or 0] == "│"
                await pilot.click(widget, offset=(width // 2, 1))
                for _ in range(4):
                    await pilot.pause()
                assert dbg.replayed == [addr_from_pos(width // 2, 1000, width)]
                widget.focus()
                await pilot.press("right")
                for _ in range(2):
                    await pilot.pause()
                assert len(dbg.replayed) == 2 and dbg.replayed[1] > dbg.replayed[0]

        asyncio.run(main())


async def _scripted_for_snapshot(pilot) -> None:
    app = pilot.app
    await pilot.pause()
    await app.run_action("show_view('tracemap')")
    app.workspace.main_instance.debugger_mgr.set_debugger(ScriptedTrace(app.workspace))
    for _ in range(4):
        await pilot.pause()


def test_snapshot_trace_map(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=SIZE, run_before=_scripted_for_snapshot)


if __name__ == "__main__":
    unittest.main()
