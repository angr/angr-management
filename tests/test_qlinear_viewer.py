# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import sys
import unittest

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.ui.views import DisassemblyView
from angrmanagement.ui.widgets import DisassemblyLevel


class TestQLinearViewer(AngrManagementTestCase):
    def test_disassembly_level_change(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        # load the disassembly view
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        disasm_view.display_function(func)

        # make sure function block is in cache
        assert func.addr in disasm_view.linear_viewer.objects
        assert disasm_view.linear_viewer.objects[func.addr] is not None
        assert disasm_view.linear_viewer.objects[func.addr].disassembly_level is DisassemblyLevel.MachineCode

        # change disassembly level to LifterIR
        disasm_view.set_disassembly_level_lifter_ir()
        main.workspace.job_manager.join_all_jobs()
        disasm_view.display_function(func)

        # the block should be reloaded and the disassembly level should be updated
        assert func.addr in disasm_view.linear_viewer.objects
        assert disasm_view.linear_viewer.objects[func.addr] is not None
        assert disasm_view.linear_viewer.objects[func.addr].disassembly_level is DisassemblyLevel.LifterIR

    def test_cfb_update(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        # load the disassembly view
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        disasm_view.display_function(func)

        # make sure function block is in cache
        assert func.addr in disasm_view.linear_viewer.objects
        assert disasm_view.linear_viewer.objects[func.addr] is not None
        assert len(disasm_view.linear_viewer.objects[func.addr].addr_to_insns) == 9

        # select the third instruction of the function
        disasm_view.infodock.select_instruction(func.addr + 4)
        assert len(disasm_view.infodock.selected_insns) == 1
        assert disasm_view.infodock.selected_insns == {func.addr + 4}

        # undefine third instruction to trigger cfb update
        disasm_view.undefine_code()
        main.workspace.job_manager.join_all_jobs()

        disasm_view.display_function(func)

        # the block should be updated to reflect removed instructions
        assert func.addr in disasm_view.linear_viewer.objects
        assert disasm_view.linear_viewer.objects[func.addr] is not None
        assert len(disasm_view.linear_viewer.objects[func.addr].addr_to_insns) == 2


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
