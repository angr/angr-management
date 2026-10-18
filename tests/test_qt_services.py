"""
The Qt frontend's UI services: which window their dialogs open over, and the options the file pickers pass.
"""

# pylint: disable=missing-class-docstring

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from common import AngrManagementTestCase
from PySide6.QtWidgets import QFileDialog

from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.qt_services import QtServices


class TestFilePickers(AngrManagementTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.saved_main_window = GlobalInfo.main_window
        GlobalInfo.main_window = self.main

    def tearDown(self) -> None:
        GlobalInfo.main_window = self.saved_main_window
        super().tearDown()

    def test_the_pickers_open_over_the_main_window(self) -> None:
        # the pickers replaced QFileDialog calls that were parented on the main window or one of its widgets
        calls: list[tuple[str, tuple[Any, ...]]] = []

        def recorder(name: str, answer: Any):
            def record(*args: Any) -> Any:
                calls.append((name, args))
                return answer

            return record

        services = QtServices()
        with (
            patch.object(QFileDialog, "getOpenFileName", recorder("open", ("/tmp/a", ""))),
            patch.object(QFileDialog, "getOpenFileNames", recorder("open many", (["/tmp/a", "/tmp/b"], ""))),
            patch.object(QFileDialog, "getSaveFileName", recorder("save", ("/tmp/c", ""))),
            patch.object(QFileDialog, "getExistingDirectory", recorder("directory", "/tmp")),
        ):
            assert services.pick_open_files("Open", "", "", False) == ["/tmp/a"]
            assert services.pick_open_files("Open", "", "", True) == ["/tmp/a", "/tmp/b"]
            assert services.pick_save_file("Save", "", "") == "/tmp/c"
            assert services.pick_directory("Directory", "") == "/tmp"
        assert [name for name, _ in calls] == ["open", "open many", "save", "directory"]
        assert all(args[0] is self.main for _, args in calls)
        # the directory pickers of Load Binary and the source importer did not resolve symbolic links
        options = calls[-1][1][3]
        assert options & QFileDialog.Option.DontResolveSymlinks
        assert options & QFileDialog.Option.ShowDirsOnly


if __name__ == "__main__":
    unittest.main()
