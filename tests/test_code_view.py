"""
Test cases for CodeView.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import SimStackVariable
from common import ProjectOpenTestCase
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QDialog

from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.dialogs.xref import XRefDialog
from angrmanagement.ui.views.code_view import CodeView


class TestCodeView(ProjectOpenTestCase):
    """Test CodeView functionality."""

    def setUp(self):
        super().setUp()

        self._show_called = False
        self._exec_called = False
        self._dialog_instance = None

        def mock_show(dialog_self):
            self._show_called = True
            self._dialog_instance = dialog_self

        def mock_exec(dialog_self, *_args, **_kwargs):
            self._exec_called = True
            self._dialog_instance = dialog_self
            return QDialog.DialogCode.Accepted

        self._show_patcher = patch("PySide6.QtWidgets.QDialog.show", mock_show)
        self._exec_patcher = patch("PySide6.QtWidgets.QDialog.exec_", mock_exec)
        self._show_patcher.start()
        self._exec_patcher.start()
        self.addCleanup(self._show_patcher.stop)
        self.addCleanup(self._exec_patcher.stop)

        self.code_view = CodeView(self.workspace, "center", self.instance)

    def tearDown(self):
        self.code_view.close()
        del self.code_view
        super().tearDown()

    def test_popup_jumpto_dialog(self):
        """Test that CodeView.popup_jumpto_dialog() opens JumpTo dialog."""
        self._show_called = False

        self.code_view.popup_jumpto_dialog()

        assert self._show_called, "JumpTo dialog should be shown with .show()"
        assert isinstance(self._dialog_instance, JumpTo)
        self._dialog_instance.close()

    def test_qccodeedit_xref_node_variable(self):
        """Test that QCCodeEdit.xref_node() opens XRefDialog for variables (modal)."""
        self._exec_called = False

        mock_variable = MagicMock(spec=SimStackVariable)
        mock_cvar = MagicMock(spec=CVariable)
        mock_cvar.variable = mock_variable
        mock_cvar.tags = {"ins_addr": 0x1000}

        assert self.code_view.textedit is not None
        with patch.object(self.code_view, "variable_manager", return_value=MagicMock()):
            self.code_view.textedit.xref_node(node=mock_cvar)

            assert self._exec_called, "XRefDialog should use .exec_() (modal)"
            assert isinstance(self._dialog_instance, XRefDialog)
            self._dialog_instance.close()

    def test_qccodeedit_x_key_context_menu_action(self):
        """Test that 'X' key triggers xref action via QCCodeEdit context menu shortcuts."""
        self._exec_called = False

        mock_variable = MagicMock(spec=SimStackVariable)
        mock_cvar = MagicMock(spec=CVariable)
        mock_cvar.variable = mock_variable
        mock_cvar.tags = {"ins_addr": 0x1000}

        assert self.code_view.textedit is not None
        with (
            patch.object(self.code_view.textedit, "node_under_cursor", return_value=mock_cvar),
            patch.object(self.code_view, "variable_manager", return_value=MagicMock()),
        ):
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_X, Qt.KeyboardModifier.NoModifier)
            self.code_view.textedit.keyPressEvent(key_event)

            assert self._exec_called, "Pressing 'X' should open XRefDialog with .exec_()"
            assert isinstance(self._dialog_instance, XRefDialog)
            self._dialog_instance.close()


if __name__ == "__main__":
    unittest.main()
