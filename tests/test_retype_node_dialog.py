"""
Test cases for the RetypeNode dialog and TypeBox widget.
"""
# pylint: disable=no-self-use,protected-access

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

import angr
from angr.analyses.decompiler.structured_codegen.c import CFunction, CVariable
from angr.sim_type import ALL_TYPES
from angr.sim_variable import SimRegisterVariable
from common import AngrManagementTestCase
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from angrmanagement.ui.dialogs.retype_node import RetypeNode


class RetypeNodeDialogTestCase(AngrManagementTestCase):
    """Base class for RetypeNode dialog and TypeBox tests."""

    def setUp(self) -> None:
        """Provide a minimal mocked Instance and CodeView for the dialog."""
        super().setUp()
        self.mock_instance = MagicMock()
        self.mock_instance.kb.types = dict(ALL_TYPES)

        self.mock_code_view = MagicMock()

    def _make_dialog(self, node=None, node_type=None) -> RetypeNode:
        """Construct a RetypeNode dialog and schedule cleanup."""
        dialog = RetypeNode(self.mock_instance, code_view=self.mock_code_view, node=node, node_type=node_type)
        self.addCleanup(dialog.close)
        self.addCleanup(dialog.deleteLater)
        return dialog

    @staticmethod
    def _make_cvariable_node(var_name: str = "my_var", var_type: str = "long long") -> CVariable:
        """Build a CVariable stand-in carrying a real SimVariable."""
        cvar = MagicMock(spec=CVariable)
        cvar.unified_variable = SimRegisterVariable(0, 8, ident="v0", name=var_name)
        cvar.type = angr.types.parse_type(var_type)
        return cvar

    @staticmethod
    def _make_cfunction_node(func_name: str = "foo", func_type: str = "int (char *)") -> CFunction:
        """Build a CFunction stand-in with a real SimTypeFunction."""
        cfunc = MagicMock(spec=CFunction)
        cfunc.demangled_name = func_name
        cfunc.functy = angr.types.parse_type(func_type)
        return cfunc


class TestRetypeNodeDialog(RetypeNodeDialogTestCase):
    """Test RetypeNode dialog and TypeBox initialization, validation, and interaction."""

    # ---- Dialog initialization tests ----

    def test_dialog_init_no_node(self):
        """Test that dialog opens with empty text, disabled OK, and correct title."""
        dialog = self._make_dialog()
        assert dialog._type_box is not None
        assert dialog._ok_button is not None
        assert dialog._ok_button.isEnabled() is False
        assert dialog.new_type is None
        assert dialog.windowTitle() == "Specify a type"

    def test_dialog_init_cvariable_populates_type_box(self):
        """Test that a CVariable node populates the type box with the variable's name and type."""
        cvar = self._make_cvariable_node(var_name="local_x", var_type="long long")
        dialog = self._make_dialog(node=cvar, node_type=cvar.type)
        assert dialog._type_box is not None
        assert dialog._type_box.text() == "long long local_x"

    def test_dialog_init_cfunction_populates_signature(self):
        """Test that a CFunction node populates the type box with its full prototype."""
        cfunc = self._make_cfunction_node(func_name="foo", func_type="int (char *)")
        dialog = self._make_dialog(node=cfunc)
        assert dialog._type_box is not None
        assert dialog._type_box.text() == "int foo(char *)"

    # ---- Type validation via dialog ----

    def test_valid_variable_type_enables_ok(self):
        """Test that entering a valid variable type enables OK and shows 'Valid' status."""
        dialog = self._make_dialog()
        assert dialog._type_box is not None
        assert dialog._ok_button is not None
        assert dialog._status_label is not None

        dialog._type_box.setText("int")
        QApplication.processEvents()
        assert dialog._ok_button.isEnabled() is True
        assert dialog._status_label.text() == "Valid"

    def test_valid_variable_type_with_name_enables_ok(self):
        """Test that entering a valid variable type with name enables OK and shows 'Valid' status."""
        dialog = self._make_dialog()
        assert dialog._type_box is not None
        assert dialog._ok_button is not None
        assert dialog._status_label is not None

        dialog._type_box.setText("int var")
        QApplication.processEvents()
        assert dialog._ok_button.isEnabled() is True
        assert dialog._status_label.text() == "Valid"

    def test_valid_function_type_enables_ok(self):
        """Test that entering a valid function type enables OK and shows 'Valid' status."""
        dialog = self._make_dialog()
        assert dialog._type_box is not None
        assert dialog._ok_button is not None
        assert dialog._status_label is not None

        dialog._type_box.setText("int (char *)")
        QApplication.processEvents()
        assert dialog._ok_button.isEnabled() is True
        assert dialog._status_label.text() == "Valid"

    def test_valid_function_type_with_name_enables_ok(self):
        """Test that entering a valid function type with names enables OK and shows 'Valid' status."""
        dialog = self._make_dialog()
        assert dialog._type_box is not None
        assert dialog._ok_button is not None
        assert dialog._status_label is not None

        dialog._type_box.setText("int foo(char *arg)")
        QApplication.processEvents()
        assert dialog._ok_button.isEnabled() is True
        assert dialog._status_label.text() == "Valid"

    def test_invalid_type_disables_ok(self):
        """Test that an invalid type disables OK and shows an error in the status label."""
        dialog = self._make_dialog()
        assert dialog._type_box is not None
        assert dialog._ok_button is not None
        assert dialog._status_label is not None

        dialog._type_box.setText("invalid_type")
        QApplication.processEvents()
        assert dialog._ok_button.isEnabled() is False
        assert dialog._status_label.text().startswith("Invalid:")

    # ---- Dialog interaction ----

    def test_ok_button_stores_parsed_type(self):
        """Test that clicking the OK button stores the parsed SimType on the dialog."""
        dialog = self._make_dialog()
        assert dialog._type_box is not None
        assert dialog._ok_button is not None
        dialog._type_box.setText("int")
        QApplication.processEvents()
        QTest.mouseClick(dialog._ok_button, Qt.MouseButton.LeftButton)
        QApplication.processEvents()
        assert dialog.new_type is not None
        assert dialog.new_type is angr.types.parse_type("int")


if __name__ == "__main__":
    unittest.main()
