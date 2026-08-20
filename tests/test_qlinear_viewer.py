# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import sys
import unittest

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.ui.views import DisassemblyView
from angrmanagement.ui.widgets import DisassemblyLevel
from angrmanagement.ui.widgets.qfunction_comment import QFunctionCommentBanner


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

    def test_disassembly_comment_prefix(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        disasm_view.display_function(func)
        assert func.addr in disasm_view.linear_viewer.objects
        block = disasm_view.linear_viewer.objects[func.addr]

        # a comment on a non-entry instruction renders next to that instruction
        comment_addr = next(a for a in sorted(block.addr_to_insns) if a != func.addr)
        main.workspace.set_comment(comment_addr, "test comment")
        disasm_view.linear_viewer.refresh()

        insn = block.addr_to_insns[comment_addr]
        assert insn._comment_items is not None
        assert insn._comment_items[0].text() == "; test comment"

    def test_function_comment_renders_as_a_banner(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        # a comment on the function entry is the function comment, so it goes into the header block
        # rather than next to the first instruction
        main.workspace.set_comment(func.addr, "what main does")

        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        disasm_view.display_function(func)

        block = disasm_view.linear_viewer.objects[func.addr]
        banner = next(o for o in block.objects if isinstance(o, QFunctionCommentBanner))
        assert [item.text() for item in banner._text_items] == ["; what main does"]
        assert block.addr_to_insns[func.addr]._comment_items is None


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
