"""
Test cases for the Preferences dialog.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from common import create_qapp  # pylint: disable=import-error
from PySide6.QtWidgets import QApplication, QListWidget, QSplitter

from angrmanagement.ui.dialogs.preferences import Preferences


class TestPreferences(unittest.TestCase):
    """Test the Preferences dialog layout."""

    def setUp(self) -> None:
        create_qapp()
        self.dialog = Preferences(MagicMock())
        self.dialog.show()
        QApplication.processEvents()

    def tearDown(self) -> None:
        self.dialog.close()

    def test_sidebar_cannot_collapse(self) -> None:
        splitter = self.dialog.layout().itemAt(0).widget()
        assert isinstance(splitter, QSplitter)
        contents = splitter.widget(0)
        assert isinstance(contents, QListWidget)

        minimum_width = contents.minimumWidth()
        assert minimum_width == contents.sizeHint().width()
        assert not splitter.isCollapsible(0)

        splitter.setSizes([0, self.dialog.width()])
        QApplication.processEvents()

        assert splitter.sizes()[0] >= minimum_width


if __name__ == "__main__":
    unittest.main(argv=[__file__])
