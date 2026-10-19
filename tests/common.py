from __future__ import annotations

import os
import pickle
import unittest
from typing import TYPE_CHECKING

import angr
from PySide6.QtCore import QThread
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from angrmanagement.config import Conf
from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.main_window import MainWindow

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

app = None


def create_qapp():
    global app
    if app is None:
        app = QApplication([])
        Conf.init_font_config()
    return app


#: binary path -> the project as angr management left it after its initial analyses, pickled
_ANALYZED_PROJECTS: dict[str, bytes] = {}


def open_analyzed_project(main: MainWindow, binpath: str) -> angr.Project:
    """Open ``binpath`` in ``main`` with its initial analyses done.

    The first call in a process runs them as usual and keeps a pickled copy; later calls
    restore the copy, which takes milliseconds instead of a CFG recovery. The workspace
    skips analysis for a project that already has a CFG, so the CFG job's finish is replayed.
    """
    workspace = main.workspace
    instance = workspace.main_instance
    blob = _ANALYZED_PROJECTS.get(binpath)
    if blob is None:
        instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        instance.project.am_event()
        workspace.job_manager.join_all_jobs()
        _ANALYZED_PROJECTS[binpath] = pickle.dumps(instance.project.am_obj)
        return instance.project.am_obj
    proj = pickle.loads(blob)
    instance.project.am_obj = proj
    instance.project.am_event()
    workspace.job_manager.join_all_jobs()
    cfb = proj.analyses.CFB(kb=proj.kb)
    workspace.analysis_manager._on_cfg_generated((proj.kb.cfgs["CFGFast"], cfb))
    workspace.job_manager.join_all_jobs()
    return proj


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

    @property
    def workspace(self) -> Workspace:
        return self.main.workspace

    @property
    def instance(self) -> Instance:
        return self.workspace.main_instance

    @property
    def project(self) -> angr.Project:
        return self.instance.project.am_obj
