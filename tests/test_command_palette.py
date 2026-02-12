"""
Test cases for Command Palette.
"""
# pylint: disable=no-self-use

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from common import AngrManagementTestCase
from PySide6.QtWidgets import QApplication

from angrmanagement.logic.commands import BasicCommand, Command, ViewCommand
from angrmanagement.logic.commands.command_manager import CommandManager
from angrmanagement.ui.dialogs.command_palette import (
    CommandPaletteDialog,
    CommandPaletteModel,
)


class DummyView:
    """Lightweight dummy view class for testing ViewCommand without UI dependencies."""


class TestCommand(unittest.TestCase):
    """Test Command base class functionality."""

    def test_command_name_default(self):
        """Test that command name defaults to class name."""

        class TestCmd(Command):
            """Test command."""

        cmd = TestCmd()
        assert cmd.name == "TestCmd"

    def test_command_name_override(self):
        """Test that command name can be overridden."""

        class TestCmd(Command):
            """Test command."""

            _name = "custom_name"

        cmd = TestCmd()
        assert cmd.name == "custom_name"

    def test_command_caption_default(self):
        """Test that command caption defaults to name."""

        class TestCmd(Command):
            """Test command."""

        cmd = TestCmd()
        assert cmd.caption == "TestCmd"

    def test_command_caption_override(self):
        """Test that command caption can be overridden."""

        class TestCmd(Command):
            """Test command."""

            _name = "test_name"
            _caption = "Test Caption"

        cmd = TestCmd()
        assert cmd.caption == "Test Caption"

    def test_command_is_visible_default(self):
        """Test that command is visible by default."""

        class TestCmd(Command):
            """Test command."""

        cmd = TestCmd()
        assert cmd.is_visible is True


class TestBasicCommand(unittest.TestCase):
    """Test BasicCommand functionality."""

    def test_basic_command_initialization(self):
        """Test that BasicCommand initializes correctly."""
        action = MagicMock()
        cmd = BasicCommand("test_cmd", "Test Command", action)

        assert cmd.name == "test_cmd"
        assert cmd.caption == "Test Command"

    def test_basic_command_run(self):
        """Test that BasicCommand.run() calls the action."""
        action = MagicMock()
        cmd = BasicCommand("test_cmd", "Test Command", action)

        cmd.run()
        action.assert_called_once()


class TestViewCommand(unittest.TestCase):
    """Test ViewCommand functionality."""

    def setUp(self):
        self.mock_workspace = MagicMock()
        self.mock_view_manager = MagicMock()
        self.mock_workspace.view_manager = self.mock_view_manager

    def test_view_command_initialization(self):
        """Test that ViewCommand initializes correctly."""
        action = MagicMock()
        cmd = ViewCommand("test_cmd", "Test Command", action, DummyView, self.mock_workspace)  # type: ignore[arg-type]

        assert cmd.name == "test_cmd"
        assert cmd.caption == "Test Command"

    def test_view_command_is_visible_with_matching_view(self):
        """Test that ViewCommand is visible when matching view is focused."""
        action = MagicMock()
        cmd = ViewCommand("test_cmd", "Test Command", action, DummyView, self.mock_workspace)  # type: ignore[arg-type]

        mock_view = MagicMock(spec=DummyView)
        self.mock_view_manager.most_recently_focused_view = mock_view

        assert cmd.is_visible is True

    def test_view_command_is_not_visible_without_matching_view(self):
        """Test that ViewCommand is not visible when no matching view is focused."""
        action = MagicMock()
        cmd = ViewCommand("test_cmd", "Test Command", action, DummyView, self.mock_workspace)  # type: ignore[arg-type]

        self.mock_view_manager.most_recently_focused_view = None

        assert cmd.is_visible is False

    def test_view_command_run_with_matching_view(self):
        """Test that ViewCommand.run() calls action with matching view."""
        action = MagicMock()
        cmd = ViewCommand("test_cmd", "Test Command", action, DummyView, self.mock_workspace)  # type: ignore[arg-type]

        mock_view = MagicMock(spec=DummyView)
        self.mock_view_manager.most_recently_focused_view = mock_view

        cmd.run()
        action.assert_called_once_with(mock_view)

    def test_view_command_run_without_matching_view(self):
        """Test that ViewCommand.run() does nothing when no matching view is focused."""
        action = MagicMock()
        cmd = ViewCommand("test_cmd", "Test Command", action, DummyView, self.mock_workspace)  # type: ignore[arg-type]

        self.mock_view_manager.most_recently_focused_view = None

        cmd.run()
        action.assert_not_called()


class TestCommandPaletteModel(unittest.TestCase):
    """Test CommandPaletteModel functionality."""

    def setUp(self):
        self.mock_workspace = MagicMock()
        self.command_manager = CommandManager()
        self.mock_workspace.command_manager = self.command_manager
        self.model = CommandPaletteModel(self.mock_workspace)

    def test_model_initialization(self):
        """Test that CommandPaletteModel initializes correctly."""
        assert self.model.workspace == self.mock_workspace
        assert isinstance(self.model._available_items, list)
        assert isinstance(self.model._filtered_items, list)

    def test_get_items_returns_sorted_visible_commands(self):
        """Test that get_items returns only visible commands sorted by caption."""
        cmd1 = BasicCommand("cmd1", "Z Command", MagicMock())
        cmd2 = BasicCommand("cmd2", "A Command", MagicMock())

        class InvisibleCommand(Command):
            """Test command that is not visible."""

            _caption = "Invisible"

            @property
            def is_visible(self):
                return False

        cmd3 = InvisibleCommand()

        self.command_manager.register_command(cmd1)
        self.command_manager.register_command(cmd2)
        self.command_manager.register_command(cmd3)

        model = CommandPaletteModel(self.mock_workspace)
        items = model.get_items()

        assert cmd3 not in items
        visible_commands = [item for item in items if item in (cmd1, cmd2)]
        assert len(visible_commands) == 2
        captions = [model.get_caption_for_item(item) for item in visible_commands]
        assert captions == sorted(captions)

    def test_get_caption_for_item(self):
        """Test that get_caption_for_item returns command caption."""
        cmd = BasicCommand("test_cmd", "Test Command", MagicMock())
        caption = self.model.get_caption_for_item(cmd)
        assert caption == "Test Command"


class TestCommandPaletteDialog(AngrManagementTestCase):
    """Test CommandPaletteDialog functionality."""

    def setUp(self):
        super().setUp()
        self.mock_workspace = MagicMock()
        self.command_manager = CommandManager()
        self.mock_workspace.command_manager = self.command_manager
        self.dialog = CommandPaletteDialog(self.mock_workspace, parent=self.main)

    def tearDown(self):
        if hasattr(self, "dialog"):
            self.dialog.close()
            del self.dialog
        super().tearDown()

    def test_dialog_initialization(self):
        """Test that CommandPaletteDialog initializes correctly."""
        assert isinstance(self.dialog._model, CommandPaletteModel)
        assert self.dialog.windowTitle() == "Command Palette"

    def test_dialog_uses_workspace(self):
        """Test that dialog uses the provided workspace."""
        assert self.dialog._model.workspace == self.mock_workspace

    def test_dialog_shows_all_commands(self):
        """Test that dialog shows all visible commands."""
        cmd1 = BasicCommand("cmd1", "Test Command 1", MagicMock())
        cmd2 = BasicCommand("cmd2", "Test Command 2", MagicMock())
        self.command_manager.register_command(cmd1)
        self.command_manager.register_command(cmd2)

        dialog = CommandPaletteDialog(self.mock_workspace, parent=self.main)
        model = dialog._model

        items = [model.data(model.index(i, 0)) for i in range(model.rowCount())]
        assert cmd1 in items or cmd2 in items

        dialog.close()

    def test_dialog_filters_commands_by_text(self):
        """Test that dialog filters commands by query text."""
        cmd1 = BasicCommand("cmd1", "Unique Test Command", MagicMock())
        cmd2 = BasicCommand("cmd2", "Other Command", MagicMock())
        self.command_manager.register_command(cmd1)
        self.command_manager.register_command(cmd2)

        dialog = CommandPaletteDialog(self.mock_workspace, parent=self.main)

        dialog._query.setText("Unique")
        QApplication.processEvents()

        items = [dialog._model.data(dialog._model.index(i, 0)) for i in range(dialog._model.rowCount())]
        captions = [dialog._model.get_caption_for_item(item) for item in items if item is not None]

        assert any("Unique" in caption for caption in captions)

        dialog.close()


class TestCommandPaletteIntegration(AngrManagementTestCase):
    """Test Command Palette integration with MainWindow."""

    def test_show_command_palette_creates_dialog(self):
        """Test that show_command_palette creates and shows CommandPaletteDialog."""
        with (
            patch("angrmanagement.ui.main_window.CommandPaletteDialog") as mock_dialog_class,
            patch.object(self.main, "workspace"),
        ):
            mock_dialog = MagicMock()
            mock_dialog_class.return_value = mock_dialog
            mock_dialog.selected_item = None

            self.main.show_command_palette()

            mock_dialog_class.assert_called_once_with(self.main.workspace, parent=self.main)
            mock_dialog.setModal.assert_called_once_with(True)
            mock_dialog.exec_.assert_called_once()

    def test_show_command_palette_runs_selected_command(self):
        """Test that show_command_palette runs the selected command."""
        with (
            patch("angrmanagement.ui.main_window.CommandPaletteDialog") as mock_dialog_class,
            patch.object(self.main, "workspace"),
        ):
            mock_command = MagicMock()
            mock_dialog = MagicMock()
            mock_dialog_class.return_value = mock_dialog
            mock_dialog.selected_item = mock_command

            self.main.show_command_palette()

            mock_command.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
