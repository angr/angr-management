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

    def test_no_overlapping_objects_during_recovery(self):
        """
        Simulate CFG recovery: stream overlapping blocks into a temporary CFB built over an empty knowledge base and
        verify that the linear viewer renders a non-overlapping, vertically contiguous sequence of objects.
        """
        from angr.knowledge_base import KnowledgeBase

        main = self.main
        main.workspace.run_analysis = lambda *args, **kwargs: None  # suppress the automatic analysis
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_obj = proj
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        # a temporary CFB over an empty kb, like the one a CFG generation job creates
        temp_cfb = proj.analyses.CFB(kb=KnowledgeBase(proj), exclude_region_types={"kernel", "tls"})
        main.workspace.main_instance.cfb = temp_cfb
        main.workspace.main_instance.cfb.am_event()

        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        viewer = disasm_view.linear_viewer
        # the window is never shown; give the viewer a real height so that multiple objects are rendered
        viewer.resize(800, 600)
        entry = proj.entry
        viewer.navigate_to_addr(entry)

        def assert_blanket_nonoverlapping():
            prev_end = None
            for addr, obj in temp_cfb._blanket.items():
                size = obj.size if isinstance(getattr(obj, "size", None), int) else None
                if prev_end is not None:
                    assert addr >= prev_end, f"blanket overlap at {addr:#x}"
                prev_end = addr + max(size or 1, 1)

        def assert_contiguous_rendering(min_visible):
            # the rendered objects are vertically contiguous (no stacked duplicates, no offset desync)
            visible = sorted((qobj for qobj in viewer.objects.values() if qobj.isVisible()), key=lambda o: o.y())
            assert len(visible) >= min_visible
            for prev, curr in zip(visible, visible[1:], strict=False):
                assert abs(curr.y() - (prev.y() + prev.height)) < 1e-3, (
                    f"vertical gap/overlap between objects at y={prev.y()} (height {prev.height}) and y={curr.y()}"
                )

        # stream overlapping blocks: one at the entry, then one starting midway through it (jump-into-middle): the
        # first block gets trimmed, leaving trimmed-block + block + unknown-remainder in the viewport
        block = proj.factory.block(entry)
        temp_cfb.add_obj(entry, block)
        temp_cfb.add_obj(entry + 8, proj.factory.block(entry + 8))
        viewer.refresh_objects()
        assert_blanket_nonoverlapping()
        assert_contiguous_rendering(3)

        # a block covering the previous two entirely (the stale-size overwrite case) drops them
        temp_cfb.add_obj(entry, proj.factory.block(entry, size=block.size))
        viewer.refresh_objects()
        assert_blanket_nonoverlapping()
        assert temp_cfb._blanket[entry].size == block.size
        assert entry + 8 not in temp_cfb._blanket
        assert_contiguous_rendering(2)

    def test_disassembly_comment_prefix(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        comment_addr = func.addr
        main.workspace.main_instance.project.kb.comments[comment_addr] = "test comment"

        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_linear_viewer()
        disasm_view.display_function(func)

        assert func.addr in disasm_view.linear_viewer.objects
        block = disasm_view.linear_viewer.objects[func.addr]
        insn = block.addr_to_insns[comment_addr]

        assert insn._comment_items is not None
        assert insn._comment_items[0].text() == "; test comment"


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
