import unittest
import os

from angrmanagement.ui.main_window import MainWindow
from common import test_location, setUp
import angr


class TestWorkflow(unittest.TestCase):
    def test_workflow(self):
        setUp()

        main = MainWindow(show=False)
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        main.workspace.instance.set_project(proj)
        main.workspace.instance.join_all_jobs()


if __name__ == '__main__':
    unittest.main()
