"""
Test cases for DisassemblyView.
"""

from __future__ import annotations

import contextlib
import unittest
from unittest.mock import MagicMock, call, patch

from common import ProjectOpenTestCase
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QDialog

from angrmanagement.ui.dialogs.assemble_patch import AssemblePatchDialog
from angrmanagement.ui.dialogs.hook import HookDialog
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.dialogs.new_state import NewState
from angrmanagement.ui.dialogs.rename_label import RenameLabel
from angrmanagement.ui.dialogs.set_comment import SetComment
from angrmanagement.ui.dialogs.xref import XRefDialog
from angrmanagement.ui.views.disassembly_view import DisassemblyView


class TestDisassemblyViewBase(ProjectOpenTestCase):
    """Base class with shared view setup for DisassemblyView tests."""

    def setUp(self):
        super().setUp()

        self.disasm_view = DisassemblyView(self.workspace, "center", self.instance)

        # Mock disasm property to avoid None access errors in dialog constructors
        mock_disasm = MagicMock()
        mock_disasm.kb = self.instance.project.kb
        self.disasm_view._flow_graph.disasm = mock_disasm


class TestPopupDialogs(TestDisassemblyViewBase):
    """Test popup_*_dialog methods that create and show dialogs."""

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

    def test_popup_newstate_dialog(self):
        """Test that DisassemblyView.popup_newstate_dialog() opens NewState dialog."""

        with patch.object(self.disasm_view, "_instruction_address_in_selection", return_value=0x1000):
            self.disasm_view.popup_newstate_dialog()

            assert self._exec_called, "NewState dialog should use .exec_() (modal)"
            assert isinstance(self._dialog_instance, NewState)
            self._dialog_instance.close()

    def test_popup_patch_dialog(self):
        """Test that DisassemblyView.popup_patch_dialog() opens AssemblePatchDialog (modal)."""

        mock_dialog_instance = MagicMock(spec=AssemblePatchDialog)

        with patch("angrmanagement.ui.views.disassembly_view.AssemblePatchDialog", return_value=mock_dialog_instance):
            self.disasm_view._insn_addr_on_context_menu = 0x1418
            self.disasm_view.popup_patch_dialog()
            mock_dialog_instance.exec_.assert_called_once()

    def test_popup_hook_dialog(self):
        """Test that DisassemblyView.popup_hook_dialog() opens HookDialog (modal)."""

        with patch.object(self.disasm_view, "_instruction_address_in_selection", return_value=0x1000):
            self.disasm_view.popup_hook_dialog()

            assert self._exec_called, "HookDialog should use .exec_() (modal)"
            assert isinstance(self._dialog_instance, HookDialog)
            self._dialog_instance.close()

    def test_popup_xref_dialog_with_variable(self):
        """Test that popup_xref_dialog creates and shows XRefDialog with variable."""
        mock_variable = MagicMock()
        self.disasm_view.variable_manager = MagicMock()

        self.disasm_view.popup_xref_dialog(addr=0x1000, variable=mock_variable)

        assert self._exec_called, "popup_xref_dialog should open XRefDialog with .exec_()"
        assert isinstance(self._dialog_instance, XRefDialog)
        self._dialog_instance.close()

    def test_popup_xref_dialog_with_dst_addr(self):
        """Test that popup_xref_dialog creates and shows XRefDialog with destination address."""
        self.disasm_view.popup_xref_dialog(addr=0x1000, dst_addr=0x2000)

        assert self._exec_called, "popup_xref_dialog should open XRefDialog with .exec_()"
        assert isinstance(self._dialog_instance, XRefDialog)
        self._dialog_instance.close()

    def test_parse_operand_and_popup_xref_dialog_with_constant(self):
        """Test that parse_operand_and_popup_xref_dialog handles constant operand."""
        mock_operand = MagicMock()
        mock_operand.is_constant = True
        mock_operand.constant_value = 0x2000
        mock_operand.variable = None

        self.disasm_view.parse_operand_and_popup_xref_dialog(0x1000, mock_operand)

        assert self._exec_called, "parse_operand_and_popup_xref_dialog should open XRefDialog with .exec_()"
        assert isinstance(self._dialog_instance, XRefDialog)
        self._dialog_instance.close()

    def test_parse_operand_and_popup_xref_dialog_with_variable(self):
        """Test that parse_operand_and_popup_xref_dialog handles variable operand."""
        mock_variable = MagicMock()
        mock_operand = MagicMock()
        mock_operand.variable = mock_variable
        self.disasm_view.variable_manager = MagicMock()

        self.disasm_view.parse_operand_and_popup_xref_dialog(0x1000, mock_operand)

        assert self._exec_called, "parse_operand_and_popup_xref_dialog should open XRefDialog with .exec_()"
        assert isinstance(self._dialog_instance, XRefDialog)
        self._dialog_instance.close()

    def test_parse_operand_and_popup_xref_dialog_with_constant_memory(self):
        """Test that parse_operand_and_popup_xref_dialog handles constant_memory operand."""
        mock_operand = MagicMock()
        mock_operand.variable = None
        mock_operand.is_constant = False
        mock_operand.is_constant_memory = True
        mock_operand.constant_memory_value = 0x3000

        self.disasm_view.parse_operand_and_popup_xref_dialog(0x1000, mock_operand)

        assert self._exec_called, "parse_operand_and_popup_xref_dialog should open XRefDialog with .exec_()"
        assert isinstance(self._dialog_instance, XRefDialog)
        self._dialog_instance.close()

    def test_parse_operand_and_popup_xref_dialog_with_none_operand(self):
        """Test that parse_operand_and_popup_xref_dialog handles None operand gracefully."""
        self.disasm_view.parse_operand_and_popup_xref_dialog(0x1000, None)

        assert not self._exec_called, "No dialog should be created when operand is None"
        assert self._dialog_instance is None

    def test_popup_jumpto_dialog(self):
        """Test that popup_jumpto_dialog creates and shows JumpTo dialog (non-modal)."""
        self.disasm_view.popup_jumpto_dialog()

        assert self._show_called, "popup_jumpto_dialog should open JumpTo with .show()"
        assert isinstance(self._dialog_instance, JumpTo)
        self._dialog_instance.close()

    def test_popup_comment_dialog(self):
        """Test that popup_comment_dialog creates and shows SetComment dialog (modal)."""
        with patch.object(self.disasm_view, "_instruction_address_in_selection", return_value=0x1000):
            self.disasm_view.popup_comment_dialog()

            assert self._exec_called, "popup_comment_dialog should open SetComment with .exec_()"
            assert isinstance(self._dialog_instance, SetComment)
            self._dialog_instance.close()

    def test_popup_rename_label_dialog(self):
        """Test that popup_rename_label_dialog creates and shows RenameLabel dialog (modal)."""
        with patch.object(self.disasm_view, "_address_in_selection", return_value=(0x1000, False)):
            self.disasm_view.popup_rename_label_dialog()

            assert self._exec_called, "popup_rename_label_dialog should open RenameLabel with .exec_()"
            assert isinstance(self._dialog_instance, RenameLabel)
            self._dialog_instance.close()


class TestKeyboardShortcuts(TestDisassemblyViewBase):
    """Test keyboard shortcut routing in keyPressEvent."""

    def test_g_key_calls_popup_jumpto(self):
        """Test that pressing 'g' key calls popup_jumpto_dialog."""
        with patch.object(self.disasm_view, "popup_jumpto_dialog") as mock_popup:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_G, Qt.KeyboardModifier.NoModifier)
            self.disasm_view.keyPressEvent(key_event)
            mock_popup.assert_called_once()

    def test_semicolon_key_calls_popup_comment(self):
        """Test that pressing ';' key calls popup_comment_dialog."""
        with patch.object(self.disasm_view, "popup_comment_dialog") as mock_popup:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Semicolon, Qt.KeyboardModifier.NoModifier)
            self.disasm_view.keyPressEvent(key_event)
            mock_popup.assert_called_once()

    def test_n_key_calls_popup_rename_label(self):
        """Test that pressing 'n' key in control calls popup_rename_label_dialog."""
        control = self.disasm_view._flow_graph

        with patch.object(self.disasm_view, "popup_rename_label_dialog") as mock_popup:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_N, Qt.KeyboardModifier.NoModifier)
            control.keyPressEvent(key_event)
            mock_popup.assert_called_once()

    @staticmethod
    @contextlib.contextmanager
    def _mock_infodock_selection(control, operands=None, labels=None, variables=None, block_tree_node=None):
        """
        Context manager to mock infodock selections.
        """
        operands = operands if operands is not None else set()
        labels = labels if labels is not None else set()
        variables = variables if variables is not None else set()

        if block_tree_node is None:
            block_tree_node = MagicMock()
            block_tree_node.am_none = True

        with (
            patch.object(control.infodock, "selected_operands", operands),
            patch.object(control.infodock, "selected_labels", labels),
            patch.object(control.infodock, "selected_variables", variables),
            patch.object(control.infodock, "selected_block_tree_node", block_tree_node),
        ):
            yield

    def _test_x_key_calls_method(self, method_name, expected_call, **selection_kwargs):
        """
        Test that X key calls the specified method with expected arguments.
        """
        control = self.disasm_view._flow_graph

        with (
            self._mock_infodock_selection(control, **selection_kwargs),
            patch.object(self.disasm_view, method_name) as mock_method,
        ):
            control.keyPressEvent(QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_X, Qt.KeyboardModifier.NoModifier))
            assert mock_method.call_args == expected_call

    def test_x_key_with_operand_calls_parse_operand_xref(self):
        """Test that pressing 'x' key with operand selected calls parse_operand_and_popup_xref_dialog."""
        control = self.disasm_view._flow_graph

        mock_operand = MagicMock()
        mock_operand.is_constant = True
        mock_operand.constant_value = 0x2000
        mock_operand.variable = None

        mock_block = MagicMock()
        mock_insn = MagicMock()
        mock_insn.get_operand.return_value = mock_operand
        mock_block.addr_to_insns = {0x1000: mock_insn}
        control._insaddr_to_block[0x1000] = mock_block

        self._test_x_key_calls_method(
            "parse_operand_and_popup_xref_dialog",
            call(0x1000, mock_operand),
            operands={(0x1000, 0)},
        )

    def test_x_key_with_label_calls_popup_xref(self):
        """Test that pressing 'x' key with label selected calls popup_xref_dialog."""
        self._test_x_key_calls_method("popup_xref_dialog", call(addr=0x3000, dst_addr=0x3000), labels={0x3000})

    def test_x_key_with_variable_calls_popup_xref(self):
        """Test that pressing 'x' key with variable selected calls popup_xref_dialog."""
        mock_variable = MagicMock()
        self._test_x_key_calls_method(
            "popup_xref_dialog", call(addr=0, variable=mock_variable), variables={mock_variable}
        )

    def test_x_key_with_function_header_calls_popup_xref(self):
        """Test that pressing 'x' key with function header selected calls popup_xref_dialog."""
        mock_block_tree_node = MagicMock()
        mock_block_tree_node.am_none = False
        mock_block_tree_node.am_obj = ("func_name", 0x4000)

        self._test_x_key_calls_method(
            "popup_xref_dialog", call(addr=0x4000, dst_addr=0x4000), block_tree_node=mock_block_tree_node
        )

    def _test_x_key_shows_error(self, **selection_kwargs):
        """
        Test that X key shows error with given selection.
        """
        control = self.disasm_view._flow_graph

        with (
            self._mock_infodock_selection(control, **selection_kwargs),
            patch("angrmanagement.ui.widgets.qdisasm_base_control.QMessageBox.critical") as mock_msgbox,
        ):
            control.keyPressEvent(QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_X, Qt.KeyboardModifier.NoModifier))

            mock_msgbox.assert_called_once()
            call_args = mock_msgbox.call_args
            assert "Invalid selection for XRefs" in call_args[0][1]

    def test_x_key_with_no_selection_shows_error(self):
        """Test that pressing 'x' key with no valid selection shows error message."""
        self._test_x_key_shows_error()

    def test_x_key_with_non_function_block_tree_node_shows_error(self):
        """Test that pressing 'x' key with non-function block tree node shows error message."""
        mock_block_tree_node = MagicMock()
        mock_block_tree_node.am_none = False
        mock_block_tree_node.am_obj = ("some_other_type", 0x5000)

        self._test_x_key_shows_error(block_tree_node=mock_block_tree_node)

    def test_other_key_delegates_to_base_class(self):
        """Test that pressing other keys delegates to base class keyPressEvent."""
        control = self.disasm_view._flow_graph

        with patch.object(control._base_cls, "keyPressEvent") as mock_base_key_event:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.NoModifier)
            control.keyPressEvent(key_event)
            mock_base_key_event.assert_called_once_with(control, key_event)


class TestContextMenus(TestDisassemblyViewBase):
    """Test context menu creation and action routing."""

    def test_instruction_context_menu_sets_address_and_creates_qmenu(self):
        """Test that instruction_context_menu sets insn_addr and creates QMenu."""
        mock_insn = MagicMock()
        mock_insn.addr = 0x1000

        assert self.disasm_view._insn_menu is not None
        with patch.object(self.disasm_view._insn_menu, "qmenu") as mock_qmenu:
            mock_qmenu.return_value = MagicMock()
            mock_qmenu.return_value.exec_ = MagicMock()

            self.disasm_view.instruction_context_menu(mock_insn, QPointF(100, 100))

            assert self.disasm_view._insn_menu.insn_addr == 0x1000
            mock_qmenu.assert_called_once()
            call_kwargs = mock_qmenu.call_args[1]
            assert "extra_entries" in call_kwargs
            assert call_kwargs.get("cached") is False

    def test_label_context_menu_sets_address_and_creates_qmenu(self):
        """Test that label_context_menu sets addr and creates QMenu."""
        assert self.disasm_view._label_menu is not None
        with patch.object(self.disasm_view._label_menu, "qmenu") as mock_qmenu:
            mock_qmenu.return_value = MagicMock()
            mock_qmenu.return_value.exec_ = MagicMock()

            self.disasm_view.label_context_menu(0x2000, QPointF(100, 100))

            assert self.disasm_view._label_menu.addr == 0x2000
            mock_qmenu.assert_called_once()

    def test_insn_menu_toggle_selection(self):
        """Test that instruction menu 'Toggle selection' calls toggle_instruction_selection."""
        assert self.disasm_view._insn_menu is not None
        self.disasm_view._insn_menu.insn_addr = 0x1000

        with patch.object(self.disasm_view.infodock, "toggle_instruction_selection") as mock_toggle:
            self.disasm_view._insn_menu._toggle_instruction_selection()
            mock_toggle.assert_called_once_with(0x1000)

    def test_insn_menu_popup_xrefs(self):
        """Test that instruction menu 'XRefs...' calls parse_operand_and_popup_xref_dialog."""
        assert self.disasm_view._insn_menu is not None
        self.disasm_view._insn_menu.insn_addr = 0x1000

        mock_operand = MagicMock()
        with (
            patch.object(
                self.disasm_view._flow_graph,
                "get_selected_operand_info",
                return_value=(MagicMock(), 0x1000, mock_operand),
            ),
            patch.object(self.disasm_view, "parse_operand_and_popup_xref_dialog") as mock_popup,
        ):
            self.disasm_view._insn_menu._popup_xrefs()
            mock_popup.assert_called_once_with(0x1000, mock_operand)

    def test_insn_menu_popup_newstate_dialog(self):
        """Test that instruction menu 'Execute symbolically...' calls popup_newstate_dialog."""
        assert self.disasm_view._insn_menu is not None
        self.disasm_view._insn_menu.insn_addr = 0x1000

        with patch.object(self.disasm_view, "popup_newstate_dialog") as mock_popup:
            self.disasm_view._insn_menu._popup_newstate_dialog()
            mock_popup.assert_called_once()

    def test_insn_menu_add_hook(self):
        """Test that instruction menu 'Add hook...' calls popup_hook_dialog."""
        assert self.disasm_view._insn_menu is not None
        self.disasm_view._insn_menu.insn_addr = 0x1000

        with patch.object(self.disasm_view, "popup_hook_dialog") as mock_popup:
            self.disasm_view._insn_menu._add_hook()
            mock_popup.assert_called_once()

    def test_insn_menu_toggle_breakpoint(self):
        """Test that instruction menu 'Toggle breakpoint' calls toggle_exec_breakpoint."""
        assert self.disasm_view._insn_menu is not None
        self.disasm_view._insn_menu.insn_addr = 0x1000

        with (
            patch.object(self.instance.breakpoint_mgr, "toggle_exec_breakpoint") as mock_toggle,
            patch.object(self.disasm_view, "refresh"),
        ):
            self.disasm_view._insn_menu._toggle_breakpoint()
            mock_toggle.assert_called_once_with(0x1000)

    def test_insn_menu_popup_patch_dialog(self):
        """Test that instruction menu 'Patch...' calls popup_patch_dialog."""
        assert self.disasm_view._insn_menu is not None
        self.disasm_view._insn_menu.insn_addr = 0x1000

        with patch.object(self.disasm_view, "popup_patch_dialog") as mock_popup:
            self.disasm_view._insn_menu._popup_patch_dialog()
            mock_popup.assert_called_once()

    def test_label_menu_popup_newstate_dialog(self):
        """Test that label menu 'Execute symbolically...' calls popup_newstate_dialog."""
        assert self.disasm_view._label_menu is not None
        self.disasm_view._label_menu.addr = 0x2000

        with patch.object(self.disasm_view, "popup_newstate_dialog") as mock_popup:
            self.disasm_view._label_menu._popup_newstate_dialog()
            mock_popup.assert_called_once()

    def test_label_menu_toggle_selection(self):
        """Test that label menu 'Toggle selection' calls toggle_label_selection."""
        assert self.disasm_view._label_menu is not None
        self.disasm_view._label_menu.addr = 0x2000

        with patch.object(self.disasm_view.infodock, "toggle_label_selection") as mock_toggle:
            self.disasm_view._label_menu._toggle_label_selection()
            mock_toggle.assert_called_once_with(0x2000)

    def test_label_menu_popup_xrefs(self):
        """Test that label menu 'XRefs...' calls popup_xref_dialog."""
        assert self.disasm_view._label_menu is not None
        self.disasm_view._label_menu.addr = 0x2000

        with patch.object(self.disasm_view, "popup_xref_dialog") as mock_popup:
            self.disasm_view._label_menu._popup_xrefs()
            mock_popup.assert_called_once_with(addr=0x2000, variable=None, dst_addr=0x2000)


if __name__ == "__main__":
    unittest.main()
