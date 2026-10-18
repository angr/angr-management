"""
Bundled plugins in the Qt frontend: the plugin manager activates them from their plugin.toml entry points.
"""

# pylint: disable=missing-class-docstring

from __future__ import annotations

import unittest

from common import AngrManagementTestCase

from angrmanagement.config import Conf


class TestSourceViewer(AngrManagementTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.saved_plugins = Conf.enabled_plugins

    def tearDown(self) -> None:
        Conf.enabled_plugins = self.saved_plugins
        super().tearDown()

    def test_the_entry_point_activates_the_qt_view(self) -> None:
        plugins = self.main.workspace.plugins
        plugins.discover_and_initialize_plugins()
        plugins.activate_plugin_by_name("source_viewer")
        plugin = plugins.get_plugin_instance_by_name("source_viewer")
        assert plugin is not None
        view = plugin.source_viewer  # type: ignore[attr-defined]
        assert type(view).__name__ == "SourceViewer"
        assert view in self.main.workspace.view_manager.views
        plugins.deactivate_plugin_by_name("source_viewer")
        assert view not in self.main.workspace.view_manager.views


if __name__ == "__main__":
    unittest.main()
