"""
Test cases for generic Palette framework (base classes).
"""
# pylint: disable=no-self-use

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from common import AngrManagementTestCase
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication

from angrmanagement.logic.commands import BasicCommand
from angrmanagement.logic.commands.command_manager import CommandManager
from angrmanagement.ui.dialogs.command_palette import CommandPaletteModel
from angrmanagement.ui.dialogs.palette import (
    PaletteDialog,
    PaletteItemDelegate,
    PaletteModel,
)


class SimplePaletteModel(PaletteModel):
    """Simple test model for testing base palette functionality."""

    def __init__(self, workspace, items=None):
        self._test_items = items or []
        super().__init__(workspace)

    def get_items(self):
        return self._test_items

    def get_caption_for_item(self, item):
        return item if isinstance(item, str) else str(item)


class TestPaletteModelBase(unittest.TestCase):
    """Test PaletteModel base class functionality."""

    def setUp(self):
        self.mock_workspace = MagicMock()

    def test_base_model_get_items(self):
        """Test that base PaletteModel.get_items() returns empty list."""
        model = PaletteModel(self.mock_workspace)
        items = model.get_items()
        assert not items

    def test_base_model_get_caption_for_item(self):
        """Test that base PaletteModel.get_caption_for_item() returns empty string."""
        model = PaletteModel(self.mock_workspace)
        caption = model.get_caption_for_item("test_item")
        assert caption == ""

    def test_base_model_get_subcaption_for_item(self):
        """Test that base PaletteModel.get_subcaption_for_item() returns None."""
        model = PaletteModel(self.mock_workspace)
        assert model.get_subcaption_for_item("test_item") is None

    def test_base_model_get_annotation_for_item(self):
        """Test that base PaletteModel.get_annotation_for_item() returns None."""
        model = PaletteModel(self.mock_workspace)
        assert model.get_annotation_for_item("test_item") is None

    def test_base_model_get_icon_color_and_text_for_item(self):
        """Test that base PaletteModel.get_icon_color_and_text_for_item() returns None and empty string."""
        model = PaletteModel(self.mock_workspace)
        color, text = model.get_icon_color_and_text_for_item("test_item")
        assert color is None
        assert text == ""

    def test_row_count_with_no_filter(self):
        """Test that rowCount returns all items when no filter is applied."""
        model = SimplePaletteModel(self.mock_workspace, ["item1", "item2", "item3"])
        assert model.rowCount() == 3

    def test_column_count(self):
        """Test that columnCount returns 1."""
        model = SimplePaletteModel(self.mock_workspace)
        assert model.columnCount() == 1

    def test_set_filter_text_empty(self):
        """Test that set_filter_text with empty string shows all items."""
        model = SimplePaletteModel(self.mock_workspace, ["Test Item", "Other Item"])
        original_count = model.rowCount()

        model.set_filter_text("Test")
        model.set_filter_text("")

        assert model.rowCount() == original_count

    def test_set_filter_text_filters_by_caption(self):
        """Test that set_filter_text filters items by matching caption."""
        model = SimplePaletteModel(self.mock_workspace, ["Test Item", "Other Item"])
        model.set_filter_text("Test")

        filtered_items = [model.data(model.index(i, 0)) for i in range(model.rowCount())]
        captions = [model.get_caption_for_item(item) for item in filtered_items if item is not None]

        assert any("Test" in caption for caption in captions)

    def test_set_filter_text_fuzzy_matches_with_typos(self):
        """Test that fuzzy matching finds items even with typos."""
        model = SimplePaletteModel(self.mock_workspace, ["Test Command", "Other Command"])
        # "Tst Commnd" should fuzzy match "Test Command"
        model.set_filter_text("Tst Commnd")

        filtered_items = [model.data(model.index(i, 0)) for i in range(model.rowCount())]
        captions = [model.get_caption_for_item(item) for item in filtered_items if item is not None]

        # Should find Test Command despite typos
        assert any("Test Command" in caption for caption in captions)

    def test_set_filter_text_fuzzy_matches_partial(self):
        """Test that fuzzy matching finds items with partial text."""
        model = SimplePaletteModel(self.mock_workspace, ["Open File", "Save File", "Close Window"])
        # "File" should match both "Open File" and "Save File"
        model.set_filter_text("File")

        filtered_items = [model.data(model.index(i, 0)) for i in range(model.rowCount())]
        captions = [model.get_caption_for_item(item) for item in filtered_items if item is not None]

        # Should find both file-related commands
        assert any("Open File" in caption for caption in captions)
        assert any("Save File" in caption for caption in captions)
        # Should return some results (fuzzy matching is working)
        assert len(captions) > 0

    def test_set_filter_text_fuzzy_matches_abbreviations(self):
        """Test that fuzzy matching finds items using abbreviations."""
        model = SimplePaletteModel(self.mock_workspace, ["Test Command", "Other Item"])
        # "TC" should fuzzy match "Test Command" (first letters)
        model.set_filter_text("TC")

        filtered_items = [model.data(model.index(i, 0)) for i in range(model.rowCount())]
        captions = [model.get_caption_for_item(item) for item in filtered_items if item is not None]

        # Should find Test Command via abbreviation
        assert any("Test Command" in caption for caption in captions)

    def test_data_returns_item(self):
        """Test that data returns the correct item."""
        model = SimplePaletteModel(self.mock_workspace, ["Test Item"])

        index = model.index(0, 0)
        data = model.data(index)
        assert data == "Test Item"

    def test_data_returns_none_for_invalid_index(self):
        """Test that data returns None for invalid index."""
        model = SimplePaletteModel(self.mock_workspace)
        index = model.index(-1, 0)
        assert model.data(index) is None

    def test_parent_returns_empty_index(self):
        """Test that parent returns empty QModelIndex."""
        model = SimplePaletteModel(self.mock_workspace, ["Test Item"])
        index = model.index(0, 0)
        parent_index = model.parent(index)
        assert not parent_index.isValid()


class TestPaletteDialog(AngrManagementTestCase):
    """Test PaletteDialog base functionality."""

    def setUp(self):
        super().setUp()
        mock_workspace = MagicMock()
        mock_workspace.command_manager = CommandManager()
        self.model = CommandPaletteModel(mock_workspace)
        self.dialog = PaletteDialog(self.model, parent=self.main)

    def tearDown(self):
        if hasattr(self, "dialog"):
            self.dialog.close()
            del self.dialog
        super().tearDown()

    def test_dialog_initialization(self):
        """Test that PaletteDialog initializes correctly."""
        assert self.dialog._model == self.model
        assert self.dialog.selected_item is None
        assert self.dialog.windowTitle() == "Palette"

    def test_dialog_has_query_input(self):
        """Test that dialog has query input field."""
        assert self.dialog._query is not None
        assert hasattr(self.dialog._query, "text")

    def test_dialog_has_list_view(self):
        """Test that dialog has list view."""
        assert self.dialog._view is not None
        assert self.dialog._view.model() == self.model

    def test_query_text_changed_updates_filter(self):
        """Test that changing query text updates model filter."""
        with patch.object(self.model, "set_filter_text") as mock_set_filter:
            self.dialog._query.setText("test")
            QApplication.processEvents()
            mock_set_filter.assert_called()

    def test_up_key_navigates_list(self):
        """Test that Up key is passed to list view."""
        with patch.object(self.dialog._view, "keyPressEvent") as mock_key_press:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Up, Qt.KeyboardModifier.NoModifier)
            self.dialog.keyPressEvent(key_event)
            mock_key_press.assert_called_once()

    def test_down_key_navigates_list(self):
        """Test that Down key is passed to list view."""
        with patch.object(self.dialog._view, "keyPressEvent") as mock_key_press:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Down, Qt.KeyboardModifier.NoModifier)
            self.dialog.keyPressEvent(key_event)
            mock_key_press.assert_called_once()

    def test_enter_key_accepts_dialog(self):
        """Test that Enter key accepts the dialog."""
        cmd = BasicCommand("test_cmd", "Test Command", MagicMock())
        self.model.workspace.command_manager.register_command(cmd)

        with patch.object(self.dialog, "accept") as mock_accept:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Enter, Qt.KeyboardModifier.NoModifier)
            self.dialog.keyPressEvent(key_event)
            mock_accept.assert_called_once()

    def test_return_key_accepts_dialog(self):
        """Test that Return key accepts the dialog."""
        cmd = BasicCommand("test_cmd", "Test Command", MagicMock())
        self.model.workspace.command_manager.register_command(cmd)

        with patch.object(self.dialog, "accept") as mock_accept:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Return, Qt.KeyboardModifier.NoModifier)
            self.dialog.keyPressEvent(key_event)
            mock_accept.assert_called_once()

    def test_accept_sets_selected_item(self):
        """Test that accept sets the selected_item."""
        cmd = BasicCommand("test_cmd", "Test Command", MagicMock())
        mock_workspace = MagicMock()
        mock_workspace.command_manager = CommandManager()
        mock_workspace.command_manager.register_command(cmd)

        model = CommandPaletteModel(mock_workspace)
        dialog = PaletteDialog(model, parent=self.main)

        index = model.index(0, 0)
        dialog._view.setCurrentIndex(index)

        with patch("PySide6.QtWidgets.QDialog.accept"):
            dialog.accept()

        assert dialog.selected_item is not None
        dialog.close()

    def test_get_selected_returns_none_when_nothing_selected(self):
        """Test that _get_selected returns None when nothing is selected."""
        # Clear any auto-selection
        self.dialog._view.clearSelection()
        QApplication.processEvents()

        result = self.dialog._get_selected()
        assert result is None

    def test_other_keys_passed_to_parent(self):
        """Test that other keys are passed to parent keyPressEvent."""
        with patch("PySide6.QtWidgets.QDialog.keyPressEvent") as mock_parent_key_press:
            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.NoModifier)
            self.dialog.keyPressEvent(key_event)
            mock_parent_key_press.assert_called_once()


class TestPaletteItemDelegate(AngrManagementTestCase):
    """Test PaletteItemDelegate functionality."""

    def test_delegate_initialization_with_icons(self):
        """Test that PaletteItemDelegate initializes with icons enabled."""
        delegate = PaletteItemDelegate(display_icons=True)
        assert delegate._display_icons is True

    def test_delegate_initialization_without_icons(self):
        """Test that PaletteItemDelegate initializes with icons disabled."""
        delegate = PaletteItemDelegate(display_icons=False)
        assert delegate._display_icons is False

    def test_delegate_get_text_document(self):
        """Test that _get_text_document returns QTextDocument."""
        mock_workspace = MagicMock()
        cmd = BasicCommand("test_cmd", "Test Command", MagicMock())

        mock_command_manager = MagicMock()
        mock_command_manager.get_commands.return_value = [cmd]
        mock_workspace.command_manager = mock_command_manager

        model = CommandPaletteModel(mock_workspace)
        delegate = PaletteItemDelegate()

        index = model.index(0, 0)
        text_doc = delegate._get_text_document(index)

        assert text_doc is not None
        assert hasattr(text_doc, "toHtml")

    def test_delegate_get_text_document_with_filter(self):
        """Test that _get_text_document bolds matching text when filter is applied."""
        mock_workspace = MagicMock()
        cmd = BasicCommand("test_cmd", "Test Command", MagicMock())

        mock_command_manager = MagicMock()
        mock_command_manager.get_commands.return_value = [cmd]
        mock_workspace.command_manager = mock_command_manager

        model = CommandPaletteModel(mock_workspace)
        model.set_filter_text("Test")
        delegate = PaletteItemDelegate()

        index = model.index(0, 0)
        text_doc = delegate._get_text_document(index)

        html = text_doc.toHtml()
        # Qt converts <b> to font-weight style in HTML
        assert "font-weight:700" in html or "<b>" in html

    def test_delegate_get_text_document_with_subcaption(self):
        """Test that _get_text_document includes subcaption when provided."""

        class ModelWithSubcaption(PaletteModel):
            """Test model with subcaption."""

            def get_items(self):
                return ["item1"]

            def get_caption_for_item(self, item):  # noqa: ARG002
                return "Main Caption"

            def get_subcaption_for_item(self, item):  # noqa: ARG002
                return "Subcaption Text"

        mock_workspace = MagicMock()
        model = ModelWithSubcaption(mock_workspace)
        delegate = PaletteItemDelegate()

        index = model.index(0, 0)
        text_doc = delegate._get_text_document(index)

        html = text_doc.toHtml()
        assert "Subcaption Text" in html
        assert "<sub>" in html or "Subcaption Text" in html

    def test_dialog_renders_items_with_annotations(self):
        """Test that dialog renders items with annotations without error."""

        class ModelWithAnnotation(PaletteModel):
            """Test model with annotation."""

            def get_items(self):
                return ["item1", "item2"]

            def get_caption_for_item(self, item):  # noqa: ARG002
                return "Test Item"

            def get_annotation_for_item(self, item):  # noqa: ARG002
                return "0x1000"

        mock_workspace = MagicMock()
        model = ModelWithAnnotation(mock_workspace)
        dialog = PaletteDialog(model, parent=self.main)

        # Select an item to trigger selected state rendering
        dialog._view.setCurrentIndex(model.index(0, 0))

        # Trigger rendering (exercises paint method for all items)
        dialog.show()
        QApplication.processEvents()

        # Force Qt to actually paint all items
        dialog._view.viewport().repaint()
        QApplication.processEvents()

        dialog.close()

    def test_dialog_renders_items_with_icon_variations(self):
        """Test that dialog renders items with different icon configurations."""

        class ModelWithIcons(PaletteModel):
            """Test model with various icon configurations."""

            def get_items(self):
                return ["color_and_text", "color_only", "text_only", "neither"]

            def get_caption_for_item(self, item):  # noqa: ARG002
                return "Test Item"

            def get_icon_color_and_text_for_item(self, item):  # noqa: ARG002  # type: ignore[override]
                if item == "color_and_text":
                    return ("#ff0000", "T")
                if item == "color_only":
                    return ("#00ff00", "")
                if item == "text_only":
                    return (None, "X")
                return (None, "")

        mock_workspace = MagicMock()
        model = ModelWithIcons(mock_workspace)
        dialog = PaletteDialog(model, parent=self.main)

        # Set delegate with icons enabled
        delegate = PaletteItemDelegate(display_icons=True)
        dialog._view.setItemDelegate(delegate)

        # Trigger rendering (exercises all icon variations)
        dialog.show()
        QApplication.processEvents()

        # Force Qt to actually paint all items
        dialog._view.viewport().repaint()
        QApplication.processEvents()

        dialog.close()

    def test_dialog_renders_items_without_icons(self):
        """Test that dialog renders items with icons disabled."""

        class SimpleModel(PaletteModel):
            """Test model with simple items."""

            def get_items(self):
                return ["item1", "item2"]

            def get_caption_for_item(self, item):  # noqa: ARG002
                return "Test Item"

        mock_workspace = MagicMock()
        model = SimpleModel(mock_workspace)
        dialog = PaletteDialog(model, parent=self.main)

        # Set delegate with icons disabled
        delegate = PaletteItemDelegate(display_icons=False)
        dialog._view.setItemDelegate(delegate)

        # Trigger rendering (exercises paint without icons)
        dialog.show()
        QApplication.processEvents()

        # Force Qt to actually paint all items
        dialog._view.viewport().repaint()
        QApplication.processEvents()

        dialog.close()
