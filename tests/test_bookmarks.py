"""
Test cases for bookmarks: toggling, navigation, the Bookmarks view and angrdb persistence.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from angr.angrdb import AngrDB
from common import ProjectOpenTestCase
from PySide6.QtCore import Qt

from angrmanagement.data.annotations import CommentKind
from angrmanagement.ui.main_window import MainWindow
from angrmanagement.ui.views.bookmarks_view import BookmarksView


class TestBookmarkToggling(ProjectOpenTestCase):
    """Adding, removing and cycling through bookmarks."""

    def setUp(self):
        super().setUp()
        self.annotations = self.instance.annotations
        self.func = next(iter(self.project.kb.functions.values()))

    def test_toggle_adds_then_removes(self):
        self.workspace.toggle_bookmark(self.func.addr)
        assert self.annotations.has_bookmark(self.func.addr)
        self.workspace.toggle_bookmark(self.func.addr)
        assert not self.annotations.has_bookmark(self.func.addr)

    def test_label_can_be_set(self):
        bookmark = self.annotations.add_bookmark(self.func.addr)
        self.annotations.set_bookmark_label(bookmark, "start here")
        assert self.annotations.get_bookmark(self.func.addr).label == "start here"

    def test_next_bookmark_cycles_in_address_order(self):
        for offset in (0x30, 0x10, 0x20):
            self.annotations.add_bookmark(self.func.addr + offset)
        first = self.annotations.next_bookmark(None)
        assert first.addr == self.func.addr + 0x10
        assert self.annotations.next_bookmark(first.addr).addr == self.func.addr + 0x20
        # wraps around at the end
        assert self.annotations.next_bookmark(self.func.addr + 0x30).addr == self.func.addr + 0x10

    def test_next_bookmark_without_any_returns_none(self):
        assert self.annotations.next_bookmark(None) is None

    def test_goto_next_bookmark_jumps(self):
        self.annotations.add_bookmark(self.func.addr + 0x10)
        with patch.object(self.workspace, "jump_to") as mock_jump:
            self.workspace.goto_next_bookmark()
            mock_jump.assert_called_once_with(self.func.addr + 0x10)

    def test_bookmarked_instruction_gets_a_background(self):
        from angrmanagement.config import Conf  # pylint:disable=import-outside-toplevel

        self.annotations.add_bookmark(self.func.addr)
        assert Conf.disasm_view_bookmark_color is not None
        assert self.annotations.has_bookmark(self.func.addr)


class TestBookmarksView(ProjectOpenTestCase):
    """The dockable Bookmarks view."""

    def setUp(self):
        super().setUp()
        self.view = BookmarksView(self.workspace, "bottom", self.instance)
        self.table = self.view._table
        self.model = self.table._model
        self.func = next(iter(self.project.kb.functions.values()))

    def tearDown(self):
        self.view.close()
        super().tearDown()

    def _text(self, row, column):
        return self.model.data(self.model.index(row, column), Qt.ItemDataRole.DisplayRole)

    def test_lists_bookmarks_and_updates_live(self):
        assert self.model.rowCount() == 0
        self.workspace.toggle_bookmark(self.func.addr)
        assert self.model.rowCount() == 1
        assert self._text(0, self.model.ADDRESS_COL) == f"{self.func.addr:#x}"
        assert self._text(0, self.model.FUNCTION_COL) == self.func.name
        self.workspace.toggle_bookmark(self.func.addr)
        assert self.model.rowCount() == 0

    def test_label_is_editable_inline(self):
        self.workspace.toggle_bookmark(self.func.addr)
        index = self.model.index(0, self.model.LABEL_COL)
        assert self.model.flags(index) & Qt.ItemFlag.ItemIsEditable
        assert self.model.setData(index, "entry point", Qt.ItemDataRole.EditRole)
        assert self.instance.annotations.get_bookmark(self.func.addr).label == "entry point"

    def test_added_column_is_populated(self):
        self.workspace.toggle_bookmark(self.func.addr)
        assert self._text(0, self.model.ADDED_COL)

    def test_delete_removes_bookmark(self):
        self.workspace.toggle_bookmark(self.func.addr)
        self.table._delete([self.model.bookmark_at(0)])
        assert not self.instance.annotations.has_bookmark(self.func.addr)


class TestAnnotationPersistence(ProjectOpenTestCase):
    """Comments, comment kinds and bookmarks must survive an angrdb save/load round trip."""

    def test_angrdb_roundtrip(self):
        func = next(iter(self.project.kb.functions.values()))
        annotations = self.instance.annotations
        self.workspace.set_comment(func.addr, "the function comment", kind=CommentKind.FUNCTION)
        self.workspace.set_comment(func.addr + 1, "a repeatable one", kind=CommentKind.REPEATABLE)
        bookmark = annotations.add_bookmark(func.addr + 2, "look here")

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "annotations.adb")
            assert self.workspace.save_database(db_file)

            extra_info = {}
            reloaded = AngrDB(nullpool=True).load(db_file, extra_info=extra_info)
            main2 = MainWindow(show=False)
            try:
                inst2 = main2.workspace.main_instance
                inst2._reset_containers()
                inst2.project.am_obj = reloaded
                inst2.cfg = reloaded.kb.cfgs["CFGFast"]
                inst2.project.am_event(initialized=True)
                inst2.annotations.deserialize(extra_info)

                assert reloaded.kb.comments[func.addr] == "the function comment"
                assert reloaded.kb.comments[func.addr + 1] == "a repeatable one"
                assert inst2.annotations.kind_of(func.addr) == CommentKind.FUNCTION
                assert inst2.annotations.kind_of(func.addr + 1) == CommentKind.REPEATABLE

                restored = inst2.annotations.get_bookmark(bookmark.addr)
                assert restored is not None
                assert restored.label == "look here"
                assert restored.created_at == bookmark.created_at
            finally:
                main2.close()


if __name__ == "__main__":
    unittest.main()
