# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import sys
import unittest

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.ui.views import DisassemblyView
from angrmanagement.ui.widgets import DisassemblyLevel


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
        assert entry_block.disassembly_level is DisassemblyLevel.MachineCode

        # change disassembly level to LifterIR
        disasm_view.set_disassembly_level_lifter_ir()
        main.workspace.job_manager.join_all_jobs()

        # blocks list is rebuilt by reload() — re-fetch the entry block
        entry_block = next((b for b in flow_graph.blocks if b.addr == func.addr), None)
        assert entry_block is not None
        assert entry_block.disassembly_level is DisassemblyLevel.LifterIR


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
