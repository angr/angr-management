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
from PySide6.QtGui import QAction, QKeyEvent
from PySide6.QtWidgets import QDialog

from angrmanagement.present import code as code_module
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.dialogs.xref import XRefDialog
from angrmanagement.ui.views.code_view import CodeView
from angrmanagement.ui.widgets.qdecomp_options import QDecompilationOptions


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

    def test_the_view_decompiles_with_its_options_widget_and_makes_no_sheet(self):
        sheet_class = code_module.DecompilationOptionsSheet
        with patch.object(code_module, "DecompilationOptionsSheet", wraps=sheet_class) as sheet:
            view = CodeView(self.workspace, "center", self.instance)
            try:
                assert isinstance(view.presenter.options, QDecompilationOptions)
                view.presenter.reload()
            finally:
                view.close()
        sheet.assert_not_called()

    def test_every_menu_key_of_the_presenter_names_an_action_of_the_editor(self):
        """The presenter decides the context menu; the editor only owns the QAction each of its keys names."""
        edit = self.code_view.textedit
        for key, (caption, _shortcut, _method) in code_module.MENU_ACTIONS.items():
            action = getattr(edit, key, None)
            assert isinstance(action, QAction), key
            assert action.text().replace("&", "").lower() == caption.replace("&", "").lower(), key

    def test_the_action_lists_hold_what_they_held_before_the_presenter(self):
        """Plugins read and extend QCCodeEdit's per-node lists; each still holds its group's actions, in order."""
        edit = self.code_view.textedit
        assert edit is not None
        named = [action for action in edit.variable_actions if not action.isSeparator()]
        assert named[:5] == [
            edit.action_rename_node,
            edit.action_retype_node,
            edit.action_toggle_struct,
            edit.action_asmgen,
            edit.action_xref,
        ]
        assert edit.function_name_actions[:3] == [edit.action_rename_node, edit.action_xref, edit.action_retype_node]
        assert [action for action in edit.llm_actions if not action.isSeparator()] == [
            edit.action_llm_refine_all,
            edit.action_llm_suggest_var_names,
            edit.action_llm_suggest_func_name,
            edit.action_llm_suggest_var_types,
        ]
        for name in ("constant", "operator", "call", "default"):
            assert edit.action_comment in getattr(edit, f"{name}_actions"), name

    def test_an_action_a_plugin_adds_to_a_list_shows_in_the_menu(self):
        """An action appended to variable_actions or llm_actions shows once, where the Qt menu always put it."""
        edit = self.code_view.textedit
        assert edit is not None
        mock_cvar = MagicMock(spec=CVariable)
        mock_cvar.variable = MagicMock(spec=SimStackVariable)
        mock_cvar.tags = {"ins_addr": 0x1000}

        def captions():
            with patch.object(edit, "node_under_cursor", return_value=mock_cvar):
                menu = edit.get_context_menu()
            return [action.text() for action in menu.actions() if not action.isSeparator()]

        before = captions()
        assert len(before) == len(set(before))
        plugin_action = QAction("Plugin: variable thing", edit)
        plugin_ai_action = QAction("Plugin: AI thing", edit)
        edit.variable_actions.append(plugin_action)
        edit.llm_actions.append(plugin_ai_action)
        try:
            after = captions()
        finally:
            edit.variable_actions.remove(plugin_action)
            edit.llm_actions.remove(plugin_ai_action)
        assert after.count("Plugin: variable thing") == 1
        assert after.count("Plugin: AI thing") == 1
        # the variable group ends with the expression actions, then the default group's Comment...
        assert after[after.index("Plugin: variable thing") - 1] == "Expand expression"
        assert after[after.index("Plugin: variable thing") + 1] == "Comment..."
        assert after[after.index("Plugin: AI thing") - 1] == "AI: Suggest Variable Types"
        assert [caption for caption in after if not caption.startswith("Plugin: ")] == before
        assert captions() == before

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
