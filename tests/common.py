from __future__ import annotations

import os
import threading
import time
import unittest

import angr
from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QApplication

from angrmanagement.config import Conf
from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.main_window import MainWindow

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

app = None
container = {}
thread = None


def create_qapp():
    global app
    if app is None:
        app = QApplication([])
        Conf.init_font_config()
    return app


def _starter():
    global container

    while True:
        # sleep until we are told to start
        while container.get("start", False) is False:
            time.sleep(0.5)
        # remove the start flag
        del container["start"]

        event: threading.Event = container["event"]

        app = create_qapp()
        container["app"] = app
        main = MainWindow(show=False)
        GlobalInfo.gui_thread = threading.get_ident()
        GlobalInfo.is_test = True
        container["main"] = main

        while True:
            while not GlobalInfo.events:
                if event.is_set():
                    break
                time.sleep(0.1)
            if event.is_set():
                break
            ev = GlobalInfo.events.pop(0)
            if ev.type() == QEvent.User:
                try:
                    ev.result = ev.execute()
                except Exception as ex:
                    ev.exception = ex
                ev.event.set()

        main.close()
        del main


def start_main_window_and_event_loop(event):
    global container, thread

    container = {}
    if thread is None:
        thread = threading.Thread(target=_starter, daemon=True)
        thread.start()
    else:
        # reuse the existing thread
        pass
    container["event"] = event
    container["start"] = True

    # wait until the main window is created
    while "main" not in container:
        time.sleep(0.1)

    return container["app"], container["main"]


class AngrManagementTestCase(unittest.TestCase):
    """A base class for angr management test cases that starts the main window and event loop."""

    event: threading.Event
    main: MainWindow

    def setUp(self):
        self.event = threading.Event()
        _, self.main = start_main_window_and_event_loop(self.event)

    def tearDown(self) -> None:
        self.event.set()
        del self.main


class ProjectOpenTestCase(AngrManagementTestCase):
    """A base class for angr management test cases that opens a project."""

    def setUp(self):
        super().setUp()
        self.main.workspace.main_instance.project.am_obj = angr.Project(
            os.path.join(test_location, "x86_64", "true"), auto_load_libs=False
        )
        self.main.workspace.main_instance.project.am_event()
        self.main.workspace.main_instance.join_all_jobs()
