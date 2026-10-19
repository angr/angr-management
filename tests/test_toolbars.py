"""
The File, Debug and Feature Map toolbars, without a toolkit and in the terminal, on fauxware: the feature map's
regions, tags and layout (as the Qt feature map lays them out), its cursors and the jump a click asks for; the debug
bar's buttons as a simulation debugger allows them, the debugger selector, the launch menu, and stepping; the file
bar's Open and Save; and the View > Toolbars entries that hide them.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import angr
import cle
from angr.block import Block

from angrmanagement.config.color import Color
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.logic.debugger.simgr import SimulationDebugger
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.present.debug_bar import NO_DEBUGGER, DebugBarPresenter, action_states
from angrmanagement.present.feature_map import (
    UNSCALED_REGION_BYTES,
    FeatureMapPresenter,
    feature_tags,
    tag_color,
)
from angrmanagement.present.menus import walk_entries
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.widgets.menubar import MenuPopup

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
MAIN = 0x40071D
SIZE = (200, 60)


def captions(menu) -> list[str]:
    return [entry.text for _path, entry in walk_entries(menu)]


class ProjectCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.cfg = cls.project.analyses.CFGFast(normalize=True)
        analyses: Any = cls.project.analyses
        cls.cfb = analyses.CFB(kb=cls.cfg.kb, exclude_region_types={"kernel", "tls"})

    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance
        self.instance.project.am_obj = self.project
        self.instance.project.am_event()

    def tearDown(self):
        self.workspace.job_manager.quit()


class TestFeatureMap(ProjectCase):
    def test_tags_and_colors(self):
        block = self.project.factory.block(MAIN)
        assert isinstance(block, Block) and feature_tags(block) == 1
        assert feature_tags(object()) is None
        code, data = Color(0, 160, 232), Color(192, 192, 192)
        assert tag_color([code, data, data], 1) == code
        assert tag_color([code, data, data], 3) == Color(96, 176, 212)

    def test_layout_and_positions(self):
        presenter = FeatureMapPresenter(self.workspace)
        model = presenter.model
        assert not model.position_to_region, "no CFB, no regions"
        self.instance.cfb.am_obj = self.cfb
        self.instance.cfb.am_event()
        self.workspace.job_manager.join_all_jobs()
        model.layout(200)
        regions = list(model.position_to_region.values())
        assert regions and sum(model.region_to_width.values()) == 200
        # in address order, side by side
        assert [mr.addr for mr in regions] == sorted(mr.addr for mr in regions)
        positions = list(model.position_to_region)
        assert positions[0] == 0 and all(
            positions[i + 1] == positions[i] + model.region_to_width[regions[i]] for i in range(len(regions) - 1)
        )
        # the main object's region is drawn to scale, the extern object's as 80 bytes
        main_region = model.region_at_addr(MAIN)
        assert main_region is not None and main_region.addr <= MAIN < main_region.addr + main_region.size
        extern = next((mr for mr in regions if isinstance(mr.object, cle.ExternObject)), None)
        if extern is not None:
            assert model.region_to_width[extern] < model.region_to_width[main_region]
            assert model.region_to_width[extern] <= round(200 * UNSCALED_REGION_BYTES / main_region.size) + 1
        # an address, its position and back
        pos = model.position_at_addr(MAIN)
        assert pos is not None
        back = model.addr_at_position(pos)
        assert back is not None and abs(back - MAIN) <= main_region.size / model.region_to_width[main_region] + 1
        # main is code
        assert model.tags_between(main_region, MAIN, MAIN + 0x10) & 1
        assert "in <MemoryRegion" in model.tooltip_at(pos)
        presenter.close()

    def test_cursors_and_jump(self):
        self.instance.cfb.am_obj = self.cfb
        presenter = FeatureMapPresenter(self.workspace)
        presenter.model.layout(200)
        changed: list[int] = []
        presenter.on_cursors_changed = lambda: changed.append(1)
        self.instance.active_view_state.am_obj = SimpleNamespace(cursors=[MAIN])
        self.instance.active_view_state.am_event()
        self.workspace.job_manager.join_all_jobs()
        assert presenter.cursors == [MAIN] and changed
        # a click jumps the view the user worked in last
        jumped: list[int] = []
        view = SimpleNamespace(jump_to=jumped.append)
        with patch.object(type(self.workspace.view_manager), "most_recently_focused_view", view):
            addr = presenter.select_at_position(presenter.model.position_at_addr(MAIN) or 0)
        assert addr is not None and jumped == [addr]
        presenter.close()


class TestDebugBar(ProjectCase):
    def test_no_debugger(self):
        presenter = DebugBarPresenter(self.workspace)
        states = presenter.action_states()
        assert states == action_states(None)
        assert [name for name, (enabled, _shown) in states.items() if enabled] == ["start"]
        assert states["halt"] == (False, False) and states["cont"] == (False, True)
        assert presenter.choices() == [NO_DEBUGGER] and presenter.current_index() == 0
        assert presenter.state_text() == ""
        # a simulation needs a project, a trace debugger a trace
        menu = presenter.launch_menu()
        assert captions(menu) == ["New simulation...", "New trace debugger"]
        assert [entry.enabled for _path, entry in walk_entries(menu)] == [True, False]

    def test_simulation_debugger(self):
        presenter = DebugBarPresenter(self.workspace)
        changed: list[int] = []
        presenter.on_changed = lambda: changed.append(1)
        presenter.start()
        state = self.project.factory.blank_state(addr=MAIN)
        simgr = self.project.factory.simulation_manager(state)
        self.instance.simgrs.append(simgr)
        # what the symbolic execution view hands the debugger: its simulation manager and state containers
        panel: Any = SimpleNamespace(simgr=ObjectContainer(simgr, "simgr"), state=ObjectContainer(None, "state"))
        dbg = SimulationDebugger(panel, self.workspace)
        self.instance.debugger_list_mgr.add_debugger(dbg)
        self.instance.debugger_mgr.set_debugger(dbg)
        assert changed, "the bar hears of the new debugger"
        assert presenter.choices() == [NO_DEBUGGER, str(dbg)] and presenter.current_index() == 1
        states = presenter.action_states()
        assert states["step"] == (dbg.can_step_forward, True)
        assert states["stop"] == (dbg.can_stop, True)
        presenter.select_index(0)
        assert presenter.debugger is None
        presenter.select_index(1)
        assert presenter.debugger is dbg
        presenter.stop_listening()


#
# The terminal
#


async def settle(pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


class TestTerminal(unittest.TestCase):
    def test_toolbar_row(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=SIZE) as pilot:
                await settle(pilot)
                # before a project: no regions, every button but Launch disabled
                assert not app.feature_map.presenter.model.position_to_region
                bar = app.debug_bar
                assert [name for name, button in bar.buttons.items() if not button.disabled] == ["start"]
                assert not bar.buttons["halt"].display and bar.selector.disabled
                # the File toolbar's Open and Save, at the left of the row as in Qt, run the File menu's actions
                row = list(app.query_one("#toolbars").children)
                assert row.index(app.file_bar) == 0 and row.index(bar) == 1
                assert [str(b.label) for b in app.file_bar.buttons.values()] == ["Open", "Save"]
                pressed: list[str] = []
                with (
                    patch.object(app, "open_file_button", lambda: pressed.append("open")),
                    patch.object(app, "save_database", lambda: pressed.append("save")),
                ):
                    await pilot.click("#file-open")
                    await pilot.click("#file-save")
                    await settle(pilot)
                assert pressed == ["open", "save"]
                await app.open_binary(FAUXWARE, function="main")
                await settle(pilot, 8)
                strip = app.feature_map
                model = strip.presenter.model
                assert model.position_to_region and sum(model.region_to_width.values()) == strip.size.width
                cells = strip.cells()
                assert len(cells) == strip.size.width and any(seg.text == "▏" for seg in cells)
                # a click on the strip shows its address in the view the user worked in last, here the disassembly
                disasm: Any = app.view_widget("disassembly")
                app.workspace.view_manager.raise_view(disasm)
                await settle(pilot)
                assert app.workspace.view_manager.most_recently_focused_view is disasm
                x = int(model.position_at_addr(MAIN + 0x30) or 0)
                await pilot.click("#feature-map", offset=(x, 0))
                await settle(pilot)
                shown = model.addr_at_position(x + 0.5)
                # the disassembly lands on the instruction that holds it, away from where it was
                current = disasm.presenter.jump_history.current
                assert shown is not None and current is not None and MAIN < current <= shown < current + 16
                # Launch opens the menu of new debuggers
                await pilot.click("#dbg-start")
                await settle(pilot)
                assert isinstance(app.screen, MenuPopup)
                assert captions(app.screen.menu) == ["New simulation...", "New trace debugger"]
                await pilot.press("escape")
                await settle(pilot)
                # View > Toolbars hides them, and the row goes when all are hidden
                assert list(app._toolbar_entries) == ["file-bar", "debug-bar", "feature-map"]
                app.set_toolbar_visible("debug-bar", False)
                await settle(pilot)
                assert not bar.display and app.query_one("#toolbars").display
                app.set_toolbar_visible("file-bar", False)
                await settle(pilot)
                assert not app.file_bar.display and app.query_one("#toolbars").display
                app.set_all_toolbars_visible(False)
                await settle(pilot)
                assert not app.query_one("#toolbars").display
                assert not app._toolbar_entries["feature-map"].checked
                app.set_all_toolbars_visible(True)
                await settle(pilot)
                assert app.query_one("#toolbars").display and strip.display and bar.display and app.file_bar.display

        asyncio.run(main())


if __name__ == "__main__":
    unittest.main()
