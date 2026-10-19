"""
Test cases for the Preferences dialog.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from common import create_qapp  # pylint: disable=import-error
from PySide6.QtWidgets import QApplication, QListWidget, QSplitter

from angrmanagement.config import Conf
from angrmanagement.config.font import FontStyle, FontWeight
from angrmanagement.ui.dialogs.preferences import Preferences, ThemeAndColors


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
        layout = self.dialog.layout()
        assert layout is not None
        layout_item = layout.itemAt(0)
        assert layout_item is not None
        splitter = layout_item.widget()
        assert isinstance(splitter, QSplitter)
        contents = splitter.widget(0)
        assert isinstance(contents, QListWidget)

        minimum_width = contents.minimumWidth()
        assert minimum_width > 0
        assert not splitter.isCollapsible(0)

        splitter.setSizes([0, self.dialog.width()])
        QApplication.processEvents()

        assert splitter.sizes()[0] >= minimum_width


class TestThemeAndColors(unittest.TestCase):
    """The theme page saves colours, and leaves the font styles and weights no colour scheme sets alone."""

    _NAMES = ("pseudocode_comment_style", "pseudocode_comment_weight")

    def setUp(self) -> None:
        create_qapp()
        self._saved = {name: Conf.entry(name).value for name in self._NAMES + ("theme_name", "base_theme_name")}

    def tearDown(self) -> None:
        for name, value in self._saved.items():
            setattr(Conf, name, value)

    def test_saving_keeps_font_styles_and_weights(self) -> None:
        Conf.pseudocode_comment_style = FontStyle.OBLIQUE
        Conf.pseudocode_comment_weight = FontWeight(900)
        page = ThemeAndColors()
        page.save_config()
        assert Conf.entry("pseudocode_comment_style").value is FontStyle.OBLIQUE
        assert Conf.entry("pseudocode_comment_weight").value == 900


if __name__ == "__main__":
    unittest.main(argv=[__file__])
