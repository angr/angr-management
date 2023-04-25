# pylint:disable=missing-class-docstring,wrong-import-order,no-self-use
import os
import sys
import threading
import unittest

import angr
from common import start_main_window_and_event_loop, test_location


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        self.event = threading.Event()
        _, self.main = start_main_window_and_event_loop(self.event)

    def tearDown(self) -> None:
        self.event.set()
        del self.main

    def test_workflow(self):
        main = self.main
        proj = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        main.workspace.main_instance.project.am_obj = proj
        main.workspace.main_instance.project.am_event()
        main.workspace.main_instance.join_all_jobs()


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
