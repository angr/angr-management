"""
Test cases for DataDepView.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from common import ProjectOpenTestCase
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QDialog

from angrmanagement.ui.dialogs.data_dep_graph_search import QDataDepGraphSearch
from angrmanagement.ui.views.data_dep_view import DataDepView


class TestDataDepView(ProjectOpenTestCase):
    """Test DataDepView functionality."""

    def setUp(self):
        super().setUp()

        self.data_dep_view = DataDepView(self.workspace, "center", self.instance)

        self._exec_called = False
        self._dialog_instance = None

        def mock_exec(dialog_self, *_args, **_kwargs):
            self._exec_called = True
            self._dialog_instance = dialog_self
            return QDialog.DialogCode.Accepted

        self._exec_patcher = patch("PySide6.QtWidgets.QDialog.exec_", mock_exec)
        self._exec_patcher.start()
        self.addCleanup(self._exec_patcher.stop)

    def test_search_dialog_opens_with_ctrl_f(self):
        """Test that DataDepView opens search dialog with Ctrl+F and uses exec_() (modal)."""
        mock_graph_widget = MagicMock()

        with patch.object(
            type(self.data_dep_view), "graph_widget", new_callable=lambda: property(lambda self: mock_graph_widget)
        ):
            self._exec_called = False
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_F, Qt.KeyboardModifier.ControlModifier)
            self.data_dep_view.keyPressEvent(key_event)

            assert self._exec_called, "Search dialog should use .exec_() (modal)"
            assert isinstance(self._dialog_instance, QDataDepGraphSearch)
            self._dialog_instance.close()


if __name__ == "__main__":
    unittest.main()
