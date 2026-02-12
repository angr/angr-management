"""
Test cases for Goto Palette.
"""
# pylint: disable=no-self-use

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from common import AngrManagementTestCase, ProjectOpenTestCase

from angrmanagement.ui.dialogs.goto_palette import GotoPaletteDialog, GotoPaletteModel


class TestGotoPaletteModel(AngrManagementTestCase):
    """Test GotoPaletteModel functionality."""

    def setUp(self):
        super().setUp()
        self.mock_workspace = MagicMock()

        self.mock_func1 = MagicMock()
        self.mock_func1.name = "main"
        self.mock_func1.addr = 0x400000
        self.mock_func1.is_syscall = False
        self.mock_func1.is_plt = False
        self.mock_func1.is_simprocedure = False
        self.mock_func1.is_alignment = False

        self.mock_func2 = MagicMock()
        self.mock_func2.name = "foo"
        self.mock_func2.addr = 0x401000
        self.mock_func2.is_syscall = False
        self.mock_func2.is_plt = True
        self.mock_func2.is_simprocedure = False
        self.mock_func2.is_alignment = False

        mock_kb = MagicMock()
        mock_kb.functions.items.return_value = [
            (0x400000, self.mock_func1),
            (0x401000, self.mock_func2),
        ]

        mock_project = MagicMock()
        mock_project.kb = mock_kb

        mock_instance = MagicMock()
        mock_instance.project.am_none = False
        mock_instance.project.am_obj = mock_project

        self.mock_workspace.main_instance = mock_instance
        self.model = GotoPaletteModel(self.mock_workspace)

    def test_get_items_with_project(self):
        """Test that get_items returns functions from mocked project."""
        items = self.model.get_items()
        assert isinstance(items, list)
        assert len(items) == 2
        assert items[0] == self.mock_func1
        assert items[1] == self.mock_func2

    def test_get_items_without_project(self):
        """Test that get_items returns empty list without project."""
        self.mock_workspace.main_instance.project.am_none = True
        model = GotoPaletteModel(self.mock_workspace)
        items = model.get_items()
        assert not items

    def test_get_caption_for_item(self):
        """Test that get_caption_for_item returns function name."""
        caption = self.model.get_caption_for_item(self.mock_func1)
        assert caption == "main"

    def test_get_annotation_for_item(self):
        """Test that get_annotation_for_item returns function address in hex."""
        annotation = self.model.get_annotation_for_item(self.mock_func1)
        assert annotation == "400000"

    def test_get_icon_color_and_text_for_item_syscall(self):
        """Test icon color and text for syscall function."""
        mock_func = MagicMock()
        mock_func.is_syscall = True
        mock_func.is_plt = False
        mock_func.is_simprocedure = False
        mock_func.is_alignment = False

        color, text = self.model.get_icon_color_and_text_for_item(mock_func)
        assert color is not None
        assert text == "f"

    def test_get_icon_color_and_text_for_item_plt(self):
        """Test icon color and text for PLT function."""
        mock_func = MagicMock()
        mock_func.is_syscall = False
        mock_func.is_plt = True
        mock_func.is_simprocedure = False
        mock_func.is_alignment = False

        color, text = self.model.get_icon_color_and_text_for_item(mock_func)
        assert color is not None
        assert text == "f"

    def test_get_icon_color_and_text_for_item_simprocedure(self):
        """Test icon color and text for simprocedure function."""
        mock_func = MagicMock()
        mock_func.is_syscall = False
        mock_func.is_plt = False
        mock_func.is_simprocedure = True
        mock_func.is_alignment = False

        color, text = self.model.get_icon_color_and_text_for_item(mock_func)
        assert color is not None
        assert text == "f"

    def test_get_icon_color_and_text_for_item_alignment(self):
        """Test icon color and text for alignment function."""
        mock_func = MagicMock()
        mock_func.is_syscall = False
        mock_func.is_plt = False
        mock_func.is_simprocedure = False
        mock_func.is_alignment = True

        color, text = self.model.get_icon_color_and_text_for_item(mock_func)
        assert color is not None
        assert text == "f"

    def test_get_icon_color_and_text_for_item_regular(self):
        """Test icon color and text for regular function."""
        mock_func = MagicMock()
        mock_func.is_syscall = False
        mock_func.is_plt = False
        mock_func.is_simprocedure = False
        mock_func.is_alignment = False

        color, text = self.model.get_icon_color_and_text_for_item(mock_func)
        assert color is not None
        assert text == "f"


class TestGotoPaletteDialog(ProjectOpenTestCase):
    """Test GotoPaletteDialog functionality."""

    def setUp(self):
        super().setUp()
        self.dialog = GotoPaletteDialog(self.main.workspace, parent=self.main)

    def tearDown(self):
        if hasattr(self, "dialog"):
            self.dialog.close()
            del self.dialog
        super().tearDown()

    def test_dialog_initialization(self):
        """Test that GotoPaletteDialog initializes correctly."""
        assert isinstance(self.dialog._model, GotoPaletteModel)
        assert self.dialog.windowTitle() == "Goto Anything"

    def test_dialog_shows_functions(self):
        """Test that dialog shows functions from project."""
        model = self.dialog._model
        assert model.rowCount() > 0


class TestGotoPaletteIntegration(AngrManagementTestCase):
    """Test Goto Palette integration with MainWindow."""

    def test_show_goto_palette_creates_dialog(self):
        """Test that show_goto_palette creates and shows GotoPaletteDialog."""
        with (
            patch("angrmanagement.ui.main_window.GotoPaletteDialog") as mock_dialog_class,
            patch.object(self.main, "workspace"),
        ):
            mock_dialog = MagicMock()
            mock_dialog_class.return_value = mock_dialog
            mock_dialog.selected_item = None

            self.main.show_goto_palette()

            mock_dialog_class.assert_called_once_with(self.main.workspace, parent=self.main)
            mock_dialog.setModal.assert_called_once_with(True)
            mock_dialog.exec_.assert_called_once()

    def test_show_goto_palette_jumps_to_function(self):
        """Test that show_goto_palette calls workspace.jump_to with selected function address."""
        with (
            patch("angrmanagement.ui.main_window.GotoPaletteDialog") as mock_dialog_class,
            patch.object(self.main.workspace, "jump_to") as mock_jump_to,
        ):
            mock_func = MagicMock()
            mock_func.addr = 0x1000
            mock_dialog = MagicMock()
            mock_dialog_class.return_value = mock_dialog
            mock_dialog.selected_item = mock_func

            self.main.show_goto_palette()

            mock_jump_to.assert_called_once_with(0x1000)


if __name__ == "__main__":
    unittest.main()
