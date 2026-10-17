"""
The call explorer, without a toolkit and in the terminal, over a trace debugger whose trace is scripted: the current
function's calls, opening a call, replaying before and into a call, and the empty view without a trace debugger.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use

from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from typing import Any

from scripted_trace import ScriptedTrace

from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.present.call_explorer import NO_FUNCTION, CallExplorerPresenter, call_name
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.views.call_explorer import CallExplorerTuiView

#: the terminal size of every view's snapshot
SIZE = (200, 60)


class TestPresenter(unittest.TestCase):
    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance

    def tearDown(self):
        self.workspace.job_manager.quit()

    def test_without_a_trace_debugger(self):
        presenter = CallExplorerPresenter(self.workspace, self.instance)
        assert presenter.label == NO_FUNCTION and presenter.roots == []
        presenter.close()

    def test_calls(self):
        presenter = CallExplorerPresenter(self.workspace, self.instance)
        changes: list[int] = []
        presenter.on_changed = lambda: changes.append(1)
        dbg = ScriptedTrace(self.workspace)
        self.instance.debugger_mgr.set_debugger(dbg)
        assert presenter.label == "Current function: main"
        assert [node.name for node in presenter.roots] == ["puts", "0x401000"]
        puts, addr = presenter.roots
        presenter.expand(puts)
        assert [node.name for node in puts.children] == ["write"] and puts.expandable and puts.populated
        presenter.expand(addr)
        assert addr.children == [] and not addr.expandable
        presenter.select(puts)
        presenter.activate(puts)
        assert dbg.replayed == [("before", "call-puts"), ("after", "call-puts")]
        # the same function again changes nothing
        roots = presenter.roots
        presenter._on_debugger_state_updated()
        assert presenter.roots is roots and changes
        self.instance.debugger_mgr.set_debugger(None)
        assert presenter.label == NO_FUNCTION and presenter.roots == []
        presenter.close()

    def test_call_names(self):
        assert call_name(0x401000) == "0x401000"
        assert call_name(SimpleNamespace(name="f")) == "f"  # type: ignore[arg-type]


class TestTerminal(unittest.TestCase):
    def test_tree_opens_and_replays(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                assert await app.run_action("show_view('call_explorer')")
                for _ in range(4):
                    await pilot.pause()
                view = app.view_widget("call_explorer")
                assert isinstance(view, CallExplorerTuiView)
                assert str(view.label.render()) == NO_FUNCTION
                dbg = ScriptedTrace(app.workspace)
                app.workspace.main_instance.debugger_mgr.set_debugger(dbg)
                for _ in range(4):
                    await pilot.pause()
                assert str(view.label.render()) == "Current function: main"
                tree = view.calls
                assert [str(node.label) for node in tree.root.children] == ["puts", "0x401000"]
                tree.focus()
                await pilot.press("down")
                for _ in range(4):
                    await pilot.pause()
                assert dbg.replayed and dbg.replayed[-1][0] == "before"
                tree.root.children[0].expand()
                for _ in range(4):
                    await pilot.pause()
                assert [str(node.label) for node in tree.root.children[0].children] == ["write"]
                tree.move_cursor(tree.root.children[0])
                await pilot.press("enter")
                for _ in range(4):
                    await pilot.pause()
                assert ("after", "call-puts") in dbg.replayed

        asyncio.run(main())


async def _scripted_for_snapshot(pilot) -> None:
    app = pilot.app
    await pilot.pause()
    await app.run_action("show_view('call_explorer')")
    app.workspace.main_instance.debugger_mgr.set_debugger(ScriptedTrace(app.workspace))
    for _ in range(4):
        await pilot.pause()
    view = app.view_widget("call_explorer")
    view.calls.root.children[0].expand()
    view.calls.focus()
    for _ in range(4):
        await pilot.pause()


def test_snapshot_call_explorer(snap_compare):
    app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), theme_name="Light", interactive=False)
    assert snap_compare(app, terminal_size=SIZE, run_before=_scripted_for_snapshot)


if __name__ == "__main__":
    unittest.main()
