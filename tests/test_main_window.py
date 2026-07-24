"""
Test cases for MainWindow keyboard shortcuts and event filters.
"""
# pylint: disable=no-self-use,missing-class-docstring

from __future__ import annotations

import os
import time
import unittest
from unittest.mock import MagicMock, patch

import angr
from common import AngrManagementTestCase, test_location
from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QKeyEvent, QWindow
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

from angrmanagement.ui.main_window import DockShortcutEventFilter, ShiftShiftEventFilter


class TestDockShortcutEventFilter(AngrManagementTestCase):
    """Test DockShortcutEventFilter for Ctrl+Shift+P shortcut."""

    def setUp(self):
        super().setUp()
        self.event_filter = DockShortcutEventFilter(self.main)

    def test_ctrl_shift_p_triggers_command_palette(self):
        """Test that Ctrl+Shift+P opens the command palette."""
        with patch.object(self.main, "show_command_palette") as mock_show:
            mock_widget = QWidget()
            key_event = QKeyEvent(
                QKeyEvent.Type.KeyPress,
                Qt.Key.Key_P,
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
            )

            result = self.event_filter.eventFilter(mock_widget, key_event)

            assert result is True
            mock_show.assert_called_once_with(mock_widget)
            mock_widget.deleteLater()

    def test_other_key_combinations_not_handled(self):
        """Test that other key combinations are not handled by the filter."""
        mock_widget = QWidget()
        key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_P, Qt.KeyboardModifier.ControlModifier)

        result = self.event_filter.eventFilter(mock_widget, key_event)

        assert result is False
        mock_widget.deleteLater()

    def test_non_keypress_events_not_handled(self):
        """Test that non-KeyPress events are not handled."""
        mock_widget = QWidget()
        event = QEvent(QEvent.Type.MouseButtonPress)

        result = self.event_filter.eventFilter(mock_widget, event)

        assert result is False
        mock_widget.deleteLater()


class TestShiftShiftEventFilter(AngrManagementTestCase):
    """Test ShiftShiftEventFilter for double-Shift shortcut."""

    def setUp(self):
        super().setUp()
        self.event_filter = ShiftShiftEventFilter(self.main)

    def test_double_shift_triggers_goto_palette(self):
        """Test that pressing Shift twice quickly opens goto palette."""
        with patch.object(self.main, "show_goto_palette") as mock_show:
            mock_window = MagicMock(spec=QWindow)
            mock_window.modality.return_value = Qt.WindowModality.NonModal
            mock_widget = QWidget()

            # Create key events for Shift press
            key_event1 = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier)
            key_event2 = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier)

            # First Shift press - simulates Qt event propagation (QWindow -> QWidget)
            self.event_filter.eventFilter(mock_window, key_event1)
            self.event_filter.eventFilter(mock_widget, key_event1)

            # Second Shift press - should trigger goto palette
            self.event_filter.eventFilter(mock_window, key_event2)
            result = self.event_filter.eventFilter(mock_widget, key_event2)

            assert result is True
            mock_show.assert_called_once_with(mock_widget)
            mock_widget.deleteLater()

    def test_single_shift_does_not_trigger(self):
        """Test that a single Shift press does not trigger goto palette."""
        with patch.object(self.main, "show_goto_palette") as mock_show:
            mock_window = MagicMock(spec=QWindow)
            mock_window.modality.return_value = Qt.WindowModality.NonModal
            mock_widget = QWidget()

            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier)

            # Single Shift press (QWindow -> QWidget)
            self.event_filter.eventFilter(mock_window, key_event)
            result = self.event_filter.eventFilter(mock_widget, key_event)

            assert result is False
            mock_show.assert_not_called()
            mock_widget.deleteLater()

    def test_shift_presses_outside_timeout_reset(self):
        """Test that Shift presses outside timeout window reset the counter."""
        with patch.object(self.main, "show_goto_palette") as mock_show:
            mock_window = MagicMock(spec=QWindow)
            mock_window.modality.return_value = Qt.WindowModality.NonModal
            mock_widget = QWidget()

            key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier)

            # First Shift press
            self.event_filter.eventFilter(mock_window, key_event)
            self.event_filter.eventFilter(mock_widget, key_event)

            # Simulate time passing beyond the timeout without real sleeping
            self.event_filter._last_press_time = time.time() - (self.event_filter.timeout_secs + 0.1)

            # Second Shift press (after simulated timeout)
            key_event2 = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier)
            self.event_filter.eventFilter(mock_window, key_event2)
            result = self.event_filter.eventFilter(mock_widget, key_event2)

            # Should not trigger because timeout expired
            assert result is False
            mock_show.assert_not_called()
            mock_widget.deleteLater()

    def test_other_keys_reset_counter(self):
        """Test that pressing other keys resets the Shift counter."""
        with patch.object(self.main, "show_goto_palette") as mock_show:
            mock_window = MagicMock(spec=QWindow)
            mock_window.modality.return_value = Qt.WindowModality.NonModal
            mock_widget = QWidget()

            shift_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier)
            other_key_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_A, Qt.KeyboardModifier.NoModifier)

            # First Shift press
            self.event_filter.eventFilter(mock_window, shift_event)
            self.event_filter.eventFilter(mock_widget, shift_event)

            # Press another key
            self.event_filter.eventFilter(mock_window, other_key_event)
            self.event_filter.eventFilter(mock_widget, other_key_event)

            # Second Shift press (counter should have reset)
            shift_event2 = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Shift, Qt.KeyboardModifier.NoModifier)
            self.event_filter.eventFilter(mock_window, shift_event2)
            result = self.event_filter.eventFilter(mock_widget, shift_event2)

            assert result is False
            mock_show.assert_not_called()
            mock_widget.deleteLater()


class TestOpenCloseGuards(AngrManagementTestCase):
    """Opening a new binary is refused while one is loaded; Close project clears it."""

    def _load(self, name: str = "fauxware") -> None:
        instance = self.main.workspace.main_instance
        instance.project.am_obj = angr.Project(os.path.join(test_location, "x86_64", name), auto_load_libs=False)
        instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()

    def test_load_file_refused_when_project_open(self):
        self._load()
        instance = self.main.workspace.main_instance
        before = instance.project.am_obj
        with patch("angrmanagement.ui.main_window.QMessageBox.warning") as warn:
            self.main.load_file(os.path.join(test_location, "x86_64", "true"))
        for _ in range(10):
            QApplication.processEvents()
        assert warn.called
        assert instance.project.am_obj is before

    def test_close_project_confirmed_clears_project(self):
        self._load()
        instance = self.main.workspace.main_instance
        assert not instance.project.am_none
        with patch.object(QMessageBox, "exec_", return_value=QMessageBox.StandardButton.Yes):
            self.main.close_project()
        for _ in range(10):
            QApplication.processEvents()
        assert instance.project.am_none

    def test_close_project_cancelled_keeps_project(self):
        self._load()
        instance = self.main.workspace.main_instance
        with patch.object(QMessageBox, "exec_", return_value=QMessageBox.StandardButton.No):
            self.main.close_project()
        assert not instance.project.am_none


if __name__ == "__main__":
    unittest.main()
