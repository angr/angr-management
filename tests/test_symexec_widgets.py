"""
The Qt symbolic execution widgets over the neutral code: the new state dialog makes the state at the address it was
given, the AST viewer shows a symbolic expression, and the constraint viewer lists constraints.
"""

# pylint: disable=missing-class-docstring

from __future__ import annotations

import unittest

from angr import claripy
from common import ProjectOpenTestCase
from PySide6.QtWidgets import QApplication, QDialogButtonBox

from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.ui.dialogs.new_state import NewState
from angrmanagement.ui.widgets.qast_viewer import QASTViewer
from angrmanagement.ui.widgets.qconstraint_viewer import QConstraintViewer


class TestSymexecWidgets(ProjectOpenTestCase):
    def function_addr(self) -> int:
        kb = self.instance.kb
        assert kb is not None
        return next(f.addr for f in kb.functions.values() if f.addr != self.project.entry and not f.is_plt)

    def test_new_state_is_made_at_its_address(self):
        # the state starts at the address the dialog was given, which no label names, not at the entry point
        addr = self.function_addr()
        dialog = NewState(self.workspace, self.instance, addr=addr)
        box = dialog.findChild(QDialogButtonBox)
        assert box is not None
        ok = box.button(QDialogButtonBox.StandardButton.Ok)
        assert ok is not None
        ok.click()
        QApplication.processEvents()
        states = list(self.instance.states)
        assert len(states) == 1 and states[0].addr == addr
        assert dialog.state is states[0]
        dialog.deleteLater()

    def test_ast_viewer_shows_a_symbolic_expression(self):
        # claripy's repr takes no max_depth: the viewer raised TypeError on any symbolic expression but a variable
        viewer = QASTViewer(claripy.BVS("v", 32) + 1, workspace=self.workspace)
        label = viewer._ast_label  # pylint: disable=protected-access
        assert label is not None and label.text().startswith("<BV32")
        viewer.deleteLater()

    def test_constraint_viewer_lists_constraints(self):
        # claripy dropped leaf_asts: the viewer raised AttributeError on the first constraint
        state = self.project.factory.blank_state()
        state.solver.add(claripy.BVS("z", 8) == 3)
        container = ObjectContainer(None, name="state")
        viewer = QConstraintViewer(container, None, self.workspace)
        container.am_obj = state
        container.am_event()
        table = viewer.table
        assert table is not None and table.rowCount() == len(state.solver.constraints) >= 1
        item = table.item(table.rowCount() - 1, 3)
        assert item is not None and item.text() == "2"
        viewer.deleteLater()


if __name__ == "__main__":
    unittest.main()
