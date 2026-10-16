"""
The neutral plugin hooks: a plugin written for Qt works through them, and a plugin written only against them works in
both frontends.
"""

# pylint: disable=missing-class-docstring,no-self-use,unused-argument

from __future__ import annotations

import os
import unittest

from common import AngrManagementTestCase, open_analyzed_project, test_location
from headless import run_without_qt  # pylint: disable=import-error
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtGui import QColor

from angrmanagement.config.color import Color
from angrmanagement.plugins import BasePlugin
from angrmanagement.present.marks import Mark
from angrmanagement.present.menus import walk_entries
from angrmanagement.ui.views import DisassemblyView
from angrmanagement.ui.widgets.qinst_annotation import QHookAnnotation, QMarkAnnotation

FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")


class LegacyPlugin(BasePlugin):
    """A plugin written for the Qt frontend: QColor answers."""

    def __init__(self, workspace, insn_addr: int) -> None:
        super().__init__(workspace)
        self.insn_addr = insn_addr

    def color_insn(self, addr, selected, disasm_view):
        return QColor(0x12, 0x34, 0x56) if addr == self.insn_addr else None

    def color_block(self, addr):
        return QColor(0x01, 0x02, 0x03, 0x04)

    def color_func(self, func):
        return QColor(0x0A, 0x0B, 0x0C)

    def build_qblock_annotations(self, qblock):
        if self.insn_addr in qblock.addr_to_insns:
            return [QHookAnnotation(self.insn_addr)]
        return []

    def build_context_menu_insn(self, item):
        return [("Legacy entry", lambda: None)] if item is not None and item.addr == self.insn_addr else []


class NeutralPlugin(BasePlugin):
    """A plugin written against the neutral hooks only."""

    def __init__(self, workspace, insn_addr: int) -> None:
        super().__init__(workspace)
        self.insn_addr = insn_addr
        self.activated: list[tuple[int, str]] = []

    def insn_style(self, addr, selected, view):
        return Color(0xAB, 0xCD, 0xEF) if addr == self.insn_addr else None

    def decorate_insn(self, addr, view):
        return [Mark("hit", "disasm.mark")] if addr == self.insn_addr else []

    def block_marks(self, block_addr, view):
        return [Mark("blk", "disasm.mark.find", addr=self.insn_addr)]

    def handle_activate_insn(self, addr, button, view):
        self.activated.append((addr, button))
        return addr == self.insn_addr

    def status_bar_text(self):
        return "neutral: on"


class TestShimInQt(AngrManagementTestCase):
    """Both plugins in the Qt frontend."""

    def setUp(self):
        super().setUp()
        self.project = open_analyzed_project(self.main, FAUXWARE)
        self.func = self.project.kb.functions["main"]
        self.insns = sorted(a for b in self.func.blocks for a in b.instruction_addrs)
        plugins = self.main.workspace.plugins
        self.legacy = LegacyPlugin(self.main.workspace, self.insns[1])
        self.neutral = NeutralPlugin(self.main.workspace, self.insns[2])
        plugins.active_plugins["legacy"] = self.legacy
        plugins.active_plugins["neutral"] = self.neutral

    def tearDown(self):
        plugins = self.main.workspace.plugins
        plugins.active_plugins.pop("legacy", None)
        plugins.active_plugins.pop("neutral", None)
        super().tearDown()

    def test_neutral_hooks_route_to_the_qt_hooks(self):
        plugins = self.main.workspace.plugins
        assert plugins.insn_style(self.insns[1], False, None) == Color(0x12, 0x34, 0x56)
        assert plugins.insn_style(self.insns[2], False, None) == Color(0xAB, 0xCD, 0xEF)
        assert plugins.insn_style(self.insns[3], False, None) is None
        assert plugins.block_style(self.func.addr) == Color(0x01, 0x02, 0x03, 0x04)
        assert plugins.func_style(self.func) == Color(0x0A, 0x0B, 0x0C)
        # only plugins that implement the neutral hook itself
        assert plugins.insn_style(self.insns[1], False, None, neutral_only=True) is None
        assert plugins.status_bar_texts() == ["neutral: on"]
        assert plugins.handle_activate_insn(self.insns[2], "left", None)
        assert not plugins.handle_activate_insn(self.insns[1], "right", None)
        assert self.neutral.activated == [(self.insns[2], "left"), (self.insns[1], "right")]
        marks = plugins.decorate_insn(self.insns[2], None)
        assert [(m.text, m.addr) for m in marks] == [("hit", self.insns[2])]

    def test_the_qt_view_shows_both_plugins(self):
        view = DisassemblyView(self.main.workspace, "center", self.main.workspace.main_instance)
        view.display_disasm_graph()
        view.display_function(self.func)
        block = view.flow_graph._insaddr_to_block[self.insns[1]]  # pylint: disable=protected-access
        legacy_color = block.addr_to_insns[self.insns[1]]._calc_backcolor()  # pylint: disable=protected-access
        neutral_color = block.addr_to_insns[self.insns[2]]._calc_backcolor()  # pylint: disable=protected-access
        assert legacy_color == QColor(0x12, 0x34, 0x56)
        assert neutral_color == QColor(0xAB, 0xCD, 0xEF)
        # the legacy plugin's block colour, as always
        assert block._calc_backcolor(False) == QColor(0x01, 0x02, 0x03, 0x04)  # pylint: disable=protected-access
        marks = block.qblock_annotations.get(self.insns[2])
        assert sorted(a.text() for a in marks if isinstance(a, QMarkAnnotation)) == ["blk", "hit"]
        # a Qt plugin's own annotation items reach the block (they used to be dropped for a stray object)
        assert [a.text() for a in block.qblock_annotations.get(self.insns[1])] == ["hook"]
        # the menu of the selected instruction (what a keyboard menu opens) has the plugin's instruction entries
        view.infodock.select_instruction(self.insns[1], unique=True, use_animation=False)
        menu = view.presenter.context_menu()
        assert menu is not None and "Legacy entry" in [e.text for _p, e in walk_entries(menu)]
        view.close()
        # no Qt parent: delete it through Qt, not whenever the cyclic collector runs, on whatever thread
        view.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


HEADLESS_SCRIPT = """

from angrmanagement.config.color import Color
from angrmanagement.plugins import BasePlugin
from angrmanagement.plugins.plugin_manager import PluginManager
from angrmanagement.present.marks import Mark


class DuckQColor:
    # what a Qt plugin hands back, without Qt
    def red(self): return 1
    def green(self): return 2
    def blue(self): return 3
    def alpha(self): return 4


class Legacy(BasePlugin):
    REQUIRE_WORKSPACE = False

    def color_insn(self, addr, selected, view):
        return DuckQColor() if addr == 0x10 else None


class Neutral(BasePlugin):
    REQUIRE_WORKSPACE = False

    def insn_style(self, addr, selected, view):
        return Color(9, 9, 9) if addr == 0x20 else None

    def decorate_insn(self, addr, view):
        return [Mark("x")]

    def status_bar_text(self):
        return "ok"


manager = PluginManager(None)
manager.active_plugins["legacy"] = Legacy(None)
manager.active_plugins["neutral"] = Neutral(None)
RESULT = {
    "legacy": repr(manager.insn_style(0x10, False, None)),
    "neutral": repr(manager.insn_style(0x20, False, None)),
    "none": repr(manager.insn_style(0x30, False, None)),
    "marks": [(m.text, m.addr) for m in manager.decorate_insn(0x40, None)],
    "status": manager.status_bar_texts(),
}
"""


class TestShimHeadless(unittest.TestCase):
    """The hooks without PySide6."""

    def test_hooks_without_qt(self):
        out = run_without_qt(HEADLESS_SCRIPT)
        assert out["qt_modules_loaded"] == []
        result = out["result"]
        assert result["legacy"] == repr(Color(1, 2, 3, 4))
        assert result["neutral"] == repr(Color(9, 9, 9))
        assert result["none"] == "None"
        assert result["marks"] == [["x", 0x40]]
        assert result["status"] == ["ok"]


if __name__ == "__main__":
    unittest.main()
