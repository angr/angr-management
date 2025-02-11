from __future__ import annotations

import os
import unittest

import angr
from PySide6.QtCore import QThread
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from angrmanagement.config import Conf
from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.main_window import MainWindow

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

app = None


def create_qapp():
    global app
    if app is None:
        app = QApplication([])
        Conf.init_font_config()
    return app


class AngrManagementTestCase(unittest.TestCase):
    """A base class for angr management test cases that starts the main window and event loop."""

    main: MainWindow

    def setUp(self):
        self.app = create_qapp()
        GlobalInfo.gui_thread = QThread.currentThread()
        self.main = MainWindow(show=False)
        QTest.qWaitForWindowActive(self.main)

    def tearDown(self) -> None:
        self.main.close()
        del self.main


class ProjectOpenTestCase(AngrManagementTestCase):
    """A base class for angr management test cases that opens a project."""

    def setUp(self):
        super().setUp()
        self.main.workspace.main_instance.project.am_obj = angr.Project(
            os.path.join(test_location, "x86_64", "true"), auto_load_libs=False
        )
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.job_manager.join_all_jobs()
