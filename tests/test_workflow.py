import unittest
import os
import sys

from angrmanagement.ui.main_window import MainWindow
from common import test_location, setUp
import angr

# pylint: disable=no-self-use

class TestWorkflow(unittest.TestCase):
    def setUp(self):
        setUp()

    def test_workflow(self):
        main = MainWindow(show=False)
        proj = angr.Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        main.workspace.main_instance.project.am_obj = proj
        main.workspace.main_instance.project.am_event()
        main.workspace.main_instance.join_all_jobs()


if __name__ == '__main__':
    unittest.main(argv=sys.argv)
