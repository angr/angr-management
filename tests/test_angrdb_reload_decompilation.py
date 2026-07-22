# pylint:disable=missing-class-docstring,wrong-import-order,no-member
from __future__ import annotations

import os
import tempfile
import unittest
from typing import TYPE_CHECKING

import angr
from angr.angrdb import AngrDB
from common import AngrManagementTestCase, test_location

from angrmanagement.ui.main_window import MainWindow
from angrmanagement.ui.views import DisassemblyView

if TYPE_CHECKING:
    from angrmanagement.ui.views import CodeView


class TestAngrDBReloadDecompilation(AngrManagementTestCase):
    def _decompile_doit(self, main: MainWindow) -> CodeView:
        func = main.workspace.main_instance.project.kb.functions.function(name="doit")
        disasm_view = main.workspace._get_or_create_view("disassembly", DisassemblyView)
        disasm_view.display_disasm_graph()
        disasm_view.display_function(func)
        disasm_view.decompile_current_function()
        main.workspace.job_manager.join_all_jobs()
        return main.workspace.view_manager.first_view_in_category("pseudocode")  # type: ignore

    def test_reloaded_decompilation_has_variables_and_strings(self):
        binpath = os.path.join(test_location, "x86_64", "1after909")

        # 1) load + decompile in the first window
        proj = angr.Project(binpath, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        inst = self.main.workspace.main_instance
        inst.project.am_obj = proj
        inst.cfg = proj.kb.cfgs["CFGFast"]
        inst.cfb = proj.analyses.CFB()
        inst.project.am_event(initialized=True)
        self.main.workspace.job_manager.join_all_jobs()

        code_view = self._decompile_doit(self.main)
        original_text = code_view.codegen.text
        assert original_text
        # the original has typed variable declarations and rendered strings
        assert "int node;" in original_text
        assert "1 AFTER 909" in original_text

        # 2) save to angrdb (matching MainWindow._save_database: dumps the main kb)
        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "1after909.adb")
            AngrDB(project=proj, nullpool=True).dump(db_file, kbs=[self.main.workspace.main_instance.kb])

            # 3) reload into a fresh window, wiring up the instance like _on_load_database_finished does
            main2 = MainWindow(show=False)
            try:
                reloaded = AngrDB(nullpool=True).load(db_file)
                inst = main2.workspace.main_instance
                inst._reset_containers()
                inst.project.am_obj = reloaded
                inst.cfg = reloaded.kb.cfgs["CFGFast"]
                inst.cfb = reloaded.analyses.CFB()
                inst.project.am_event(initialized=True)
                main2.workspace.job_manager.join_all_jobs()

                # 4) decompile the same function; the displayed text must match the original
                code_view2 = self._decompile_doit(main2)
                assert code_view2.codegen.text == original_text

                # 5) re-rendering (as happens on any edit) must also match
                code_view2.codegen.regenerate_text()
                assert code_view2.codegen.text == original_text
                assert "int node;" in code_view2.codegen.text
                assert "1 AFTER 909" in code_view2.codegen.text
            finally:
                main2.close()


if __name__ == "__main__":
    unittest.main(argv=["-v"])
