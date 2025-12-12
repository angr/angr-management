# pylint: disable=missing-class-docstring
from __future__ import annotations

import unittest
from typing import TYPE_CHECKING
from unittest.mock import patch

from common import ProjectOpenTestCase
from PySide6.QtWidgets import QApplication

from angrmanagement.ui.views import types_view

if TYPE_CHECKING:
    from angrmanagement.ui.dialogs.type_editor import CTypeEditor


class TestTypeEditor(ProjectOpenTestCase):
    def setUp(self):
        super().setUp()

        self2 = self

        def editor_exec(self, *args, **kwargs):
            assert self2._next_exec is not None
            self2._next_exec(self, *args, **kwargs)

        mock_exec = patch("PySide6.QtWidgets.QDialog.exec_", editor_exec)
        self.addCleanup(mock_exec.stop)
        mock_exec.start()

        self.types_view = types_view.TypesView(self.main.workspace, "center", self.main.workspace.main_instance)
        self.types_view.show()
        self._next_exec = None

    def editor_input(self, s):
        def wrapper(f):
            @self.next_exec
            def _(editor: CTypeEditor):
                editor.setText(s)
                editor._evaluate()

            f()
            QApplication.processEvents()

        return wrapper

    def next_exec(self, f):
        self._next_exec = f
        return f

    def tearDown(self):
        self.types_view.hide()
        del self.types_view
        super().tearDown()

    def test_wawa(self):
        QApplication.processEvents()
        assert len(self.types_view.typedefs) == 0

        @self.editor_input("struct wawa{};")
        def _a():
            self.types_view._on_new_type()

        assert len(self.types_view.typedefs) == 1
        assert set(self.project.kb.types.iter_own_keys()) == {"wawa", "struct wawa"}

        @self.editor_input("struct foo { struct wawa a; wawa b; int c; };")
        def _b():
            self.types_view._on_new_type()

        assert len(self.types_view.typedefs) == 2
        assert set(self.project.kb.types.iter_own_keys()) == {"wawa", "struct wawa", "foo", "struct foo"}
        assert self.types_view.typedefs[0].type.name == "wawa"
        assert self.types_view.typedefs[1].type.name == "foo"
        assert self.project.kb.types["wawa"].type.size == 0
        assert self.project.kb.types["foo"].type.size == 32

        @self.editor_input("struct wawa { int hey; };")
        def _c():
            self.types_view.typedefs[0].highlight = 0
            self.types_view.typedefs[0].mouseDoubleClickEvent(None)

        assert len(self.types_view.typedefs) == 2
        assert set(self.project.kb.types.iter_own_keys()) == {"wawa", "struct wawa", "foo", "struct foo"}
        assert self.types_view.typedefs[0].type.name == "wawa"
        assert self.types_view.typedefs[1].type.name == "foo"
        assert self.project.kb.types["wawa"].type.size == 32
        assert self.project.kb.types["foo"].type.size == 96


if __name__ == "__main__":
    unittest.main()
