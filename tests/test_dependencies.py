"""
The dependency view, without a toolkit and in the terminal, on fauxware: a tree made from hand-built closures (the
dependency analysis needs operation-mango, which this environment has not got), the definitions' text, the sink as
the only root, and the view without operation-mango, which stays empty while the job says it cannot run.
"""

# pylint: disable=missing-class-docstring,protected-access,no-self-use,unused-argument

from __future__ import annotations

import asyncio
import os
import unittest
from typing import Any
from unittest.mock import patch

import angr
import networkx
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
from angr.knowledge_plugins.key_definitions.definition import Definition

from angrmanagement.config import Conf
from angrmanagement.data.jobs.dependency_analysis import DependencyAnalysisJob
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.headless_workspace import HeadlessWorkspace
from angrmanagement.present.dependencies import (
    DependencyPresenter,
    atom_text,
    definition_lines,
    dependency_graph,
    function_offset_text,
)
from angrmanagement.present.menus import walk_entries
from angrmanagement.tui.app import AmApp
from angrmanagement.tui.caps import TerminalCaps
from angrmanagement.tui.views.graphs import DependencyTuiView

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(test_location, "x86_64", "fauxware")
#: main's instructions: mov edi, 0x400915 (Username), and the call of puts
MOV_EDI = 0x400734
CALL_PUTS = 0x400739


def closures(project) -> tuple[dict[Any, networkx.DiGraph], Register]:
    """rdi at the call of puts comes from the mov before it, which uses a stack slot."""
    rdi = Register(project.arch.registers["rdi"][0], 8)
    slot = Definition(MemoryLocation(SpOffset(64, -0x20), 8), CodeLocation(0x40071D, 0, ins_addr=0x400725))
    mov = Definition(rdi, CodeLocation(0x40071D, 1, ins_addr=MOV_EDI))
    outside = Definition(rdi, ExternalCodeLocation())
    graph = networkx.DiGraph()
    graph.add_edge(slot, mov)
    graph.add_edge(outside, mov)
    return {mov: graph}, rdi


class TestTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(FAUXWARE, auto_load_libs=False)
        cls.cfg = cls.project.analyses.CFGFast(normalize=True, data_references=True)
        analyses: Any = cls.project.analyses
        cls.cfb = analyses.CFB(kb=cls.project.kb)

    def setUp(self):
        self.workspace: Any = HeadlessWorkspace(auto_analyze=False)
        self.instance: Any = self.workspace.main_instance
        self.instance.project.am_obj = self.project
        self.instance.project.am_event()
        self.instance.cfg.am_obj = self.cfg.model
        self.instance.cfb.am_obj = self.cfb

    def tearDown(self):
        self.workspace.job_manager.quit()

    def test_tree_has_the_sink_as_its_root(self):
        clos, rdi = closures(self.project)
        graph, sink = dependency_graph(self.project, clos, rdi, CALL_PUTS)
        # the external definition is left out, with its edge
        assert graph.number_of_nodes() == 3 and graph.number_of_edges() == 2
        assert [n for n in graph.nodes() if graph.out_degree(n) == 0] == [sink]

    def test_lines(self):
        clos, rdi = closures(self.project)
        presenter = DependencyPresenter(self.workspace, self.instance)
        presenter.sink_atom, presenter.sink_ins_addr, presenter.closures = rdi, CALL_PUTS, clos
        presenter.reload()
        texts = sorted(tuple(line.text for line in box.lines) for box in presenter.graph.picture.boxes)
        # the definition, then the function and offset (hex without 0x, as the Qt blocks write it), the instruction
        # and the string it loads
        assert texts == [
            ("Register rdi @ 0x400734", 'main+17:  mov     edi, 0x400915  "Username: "'),
            ("Register rdi @ 0x400739", "main+1c:  call    puts"),
            ("Stack sp-0x20 @ 0x400725", "main+8:  mov     dword ptr [rbp-0x34], edi"),
        ]
        assert presenter.graph.layouter == "tree"
        assert function_offset_text(self.instance, None) == "Unknown"
        assert atom_text(self.instance, object(), None) == ""
        lines = definition_lines(self.instance, presenter.graph.picture.boxes[0].node)
        assert len(lines) == 2

    def test_without_operation_mango_the_job_says_so(self):
        assert not Conf.has_operation_mango
        messages: list[str] = []
        services: Any = GlobalInfo.ui_services
        with patch.object(services, "message", lambda level, title, text: messages.append(text)):
            DependencyAnalysisJob._display_import_error()
        assert messages == ["Failed to import argument_resolver package. Is operation-mango installed?"]


class TestTerminal(unittest.TestCase):
    def test_view_shows_the_tree_and_is_empty_without_one(self):
        async def main() -> None:
            app = AmApp(caps=TerminalCaps(truecolor=True, forced_tier=2), interactive=True)
            async with app.run_test(size=(200, 60)) as pilot:
                await pilot.pause()
                await app.open_binary(FAUXWARE, function="main")
                for _ in range(4):
                    await pilot.pause()
                # not among the default views without operation-mango, as in Qt
                assert app.view_widget("dependencies") is None
                assert await app.run_action("show_view('dependencies')")
                for _ in range(4):
                    await pilot.pause()
                view = app.view_widget("dependencies")
                assert isinstance(view, DependencyTuiView)
                assert view.graph.canvas is None
                project = app.workspace.main_instance.project.am_obj
                clos, rdi = closures(project)
                view.sink_atom, view.sink_ins_addr, view.closures = rdi, CALL_PUTS, clos
                view.reload()
                for _ in range(4):
                    await pilot.pause()
                assert view.graph.canvas is not None
                assert "Register rdi @ 0x400739" in str(view.graph.canvas)
                # the disassembly's menu has no Depends on without operation-mango (XRefs... shows the menu is read)
                disasm: Any = app.view_widget("disassembly")
                texts = [entry.text for _path, entry in walk_entries(disasm.presenter.insn_context_menu(MOV_EDI))]
                assert "XRefs..." in texts and not any("Depends on" in text for text in texts)

        asyncio.run(main())


if __name__ == "__main__":
    unittest.main()
