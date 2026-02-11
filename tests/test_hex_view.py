"""
Test cases for HexView.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from common import ProjectOpenTestCase
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent

from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.views.hex_view import HexView


class TestHexViewBase(ProjectOpenTestCase):
    """Base class with shared view setup for HexView tests."""

    def setUp(self):
        super().setUp()
        self.hex_view = HexView(self.workspace, "center", self.instance)

    def tearDown(self):
        self.hex_view.close()
        del self.hex_view
        super().tearDown()


class TestPopupDialogs(TestHexViewBase):
    """Test popup_*_dialog methods that create and show dialogs."""

    def setUp(self):
        super().setUp()

        self._show_called = False
        self._dialog_instance = None

        def mock_show(dialog_self):
            self._show_called = True
            self._dialog_instance = dialog_self

        self._show_patcher = patch("PySide6.QtWidgets.QDialog.show", mock_show)
        self._show_patcher.start()
        self.addCleanup(self._show_patcher.stop)

    def test_popup_jumpto_dialog(self):
        """Test that HexView.popup_jumpto_dialog() opens JumpTo dialog."""
        self.hex_view.popup_jumpto_dialog()

        assert self._show_called, "JumpTo dialog should be shown with .show()"
        assert isinstance(self._dialog_instance, JumpTo)
        self._dialog_instance.close()


class TestKeyboardShortcuts(TestHexViewBase):
    """Test keyboard shortcut routing in keyPressEvent."""

    def test_g_key_calls_popup_jumpto(self):
        """Test that pressing 'g' key calls popup_jumpto_dialog."""
        with patch.object(self.hex_view, "popup_jumpto_dialog") as mock_popup:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_G, Qt.KeyboardModifier.NoModifier)
            self.hex_view.keyPressEvent(key_event)
            mock_popup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
