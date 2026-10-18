# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import contextlib
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import angr
from common import AngrManagementTestCase, open_analyzed_project, test_location

from angrmanagement.ui.views import DisassemblyView


class TestQDisassemblyGraph(AngrManagementTestCase):
    def test_disassembly_level_change(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        # load the disassembly view in graph mode
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)
        main.workspace.job_manager.join_all_jobs()

        # find the entry block in the graph view
        flow_graph = disasm_view.flow_graph
        entry_block = next((b for b in flow_graph.blocks if b.addr == func.addr), None)
        assert entry_block is not None
        assert entry_block.disasm._include_ir is False

        # change disassembly level to LifterIR
        disasm_view.set_disassembly_level_lifter_ir()
        main.workspace.job_manager.join_all_jobs()

        # blocks list is rebuilt by reload() — re-fetch the entry block
        entry_block = next((b for b in flow_graph.blocks if b.addr == func.addr), None)
        assert entry_block is not None
        assert entry_block.disasm._include_ir is True

    def test_ail_graph(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        # authenticate's AIL graph keeps Load expressions, which used to crash rendering after variables moved off
        # AIL objects and into VariableMap
        func = main.workspace.main_instance.project.kb.functions["authenticate"]
        assert func is not None

        # load the disassembly view in graph mode
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)
        main.workspace.job_manager.join_all_jobs()

        # change disassembly level to AIL; this rebuilds all graph blocks and renders AIL statements
        disasm_view.set_disassembly_level_ail()
        main.workspace.job_manager.join_all_jobs()

        flow_graph = disasm_view.flow_graph
        entry_block = next((b for b in flow_graph.blocks if b.addr == func.addr), None)
        assert entry_block is not None
        assert isinstance(entry_block.disasm, angr.analyses.decompiler.clinic.Clinic)

    def test_a_layout_put_off_until_cfg_recovery_is_done_selects_what_was_selected(self):
        main = self.main
        proj = open_analyzed_project(main, os.path.join(test_location, "x86_64", "fauxware"))
        func = proj.kb.functions["main"]
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)
        flow_graph = disasm_view.flow_graph
        insn = sorted(addr for block in func.blocks for addr in block.instruction_addrs)[3]
        # another view's infodock, as when the graph takes over from the linear view
        old_infodock = SimpleNamespace(selected_insns=SimpleNamespace(am_obj={insn}))
        disasm_view.infodock.clear_selection()

        # CFG recovery does not stop for the layout: it is put off until the recovery is done
        deferred = []

        @contextlib.contextmanager
        def refused(timeout: float = 0.0):  # pylint:disable=unused-argument
            yield False

        with patch.multiple(
            main.workspace.main_instance.analysis_gate, access=refused, retry_when_done=deferred.append
        ):
            flow_graph.reload(old_infodock)
        assert not flow_graph.blocks
        assert deferred == [flow_graph.reload]

        deferred[0]()
        assert flow_graph.blocks
        assert insn in disasm_view.infodock.selected_insns


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
