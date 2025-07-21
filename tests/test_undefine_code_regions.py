# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import sys
import unittest

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.ui.views import DisassemblyView


class TestUndefineCodeRegions(AngrManagementTestCase):

    def test_undefine_code_region_in_disasm_view(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        cfg = main.workspace.main_instance.cfg
        assert cfg.get_any_node(func.addr) is not None

        # load the disassembly view
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)

        # select the instruction at the beginning of the function
        disasm_view.infodock.select_instruction(func.addr)
        assert len(disasm_view.infodock.selected_insns) == 1
        assert disasm_view.infodock.selected_insns == {func.addr}
        # print(len(cfg.graph))

        # undefine at the beginning of the function
        disasm_view.undefine_code()

        main.workspace.job_manager.join_all_jobs()

        # the starting block should no longer be in the graph
        assert cfg.get_any_node(func.addr) is None

        main.workspace.job_manager.join_all_jobs()

        # define at the beginning of the function
        disasm_view.infodock.select_label(func.addr)
        assert disasm_view.infodock.selected_labels == {func.addr}
        # print(len(cfg.graph))
        disasm_view.define_code()

        main.workspace.job_manager.join_all_jobs()
        # print(len(cfg.graph))

        assert cfg.get_any_node(func.addr) is not None


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
