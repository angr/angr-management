"""
The Qt table widgets still take the arguments they took before their rows moved into neutral models.
"""

# pylint: disable=protected-access,missing-class-docstring

from __future__ import annotations

import unittest

from common import ProjectOpenTestCase

from angrmanagement.present.comments import CommentsPresenter
from angrmanagement.present.xrefs import XRefsModel
from angrmanagement.ui.widgets.qcomment_table import QCommentTable, QCommentTableView
from angrmanagement.ui.widgets.qxref_viewer import QXRefAddressModel, QXRefViewer


class TestXRefModelArguments(ProjectOpenTestCase):
    def test_old_and_new_constructor(self):
        func = self.project.kb.functions[self.project.entry]
        viewer = QXRefViewer(
            addr=func.addr,
            xrefs_manager=self.project.kb.xrefs,
            dst_addr=func.addr,
            instance=self.instance,
        )
        # the viewer's own model knows the viewer
        assert viewer._model.view is viewer and viewer._model.table_model is viewer.xrefs_model
        # QXRefModel(addr, instance, view), as before: it shows the view's references
        old = QXRefAddressModel(func.addr, self.instance, viewer)
        assert old.table_model is viewer.xrefs_model
        assert (old.addr, old.instance, old.view) == (func.addr, self.instance, viewer)
        assert old.rowCount() == viewer._model.rowCount()
        # without a view it makes its own model of the address
        alone = QXRefAddressModel(func.addr, self.instance, None)
        assert isinstance(alone.table_model, XRefsModel) and alone.addr == func.addr
        # the new shape
        new = QXRefAddressModel(viewer.xrefs_model)
        assert new.table_model is viewer.xrefs_model and new.instance is self.instance and new.view is None


class TestCommentTableArguments(ProjectOpenTestCase):
    def test_view_without_a_presenter(self):
        table = QCommentTable(None, self.workspace, self.instance)
        try:
            view = QCommentTableView(table, self.workspace, self.instance)
            assert isinstance(view.presenter, CommentsPresenter)
            func = next(iter(self.project.kb.functions.values()))
            self.workspace.set_comment(func.addr + 1, "alpha")
            assert view.comments_model.rowCount() == 1
        finally:
            table.close()


if __name__ == "__main__":
    unittest.main()
