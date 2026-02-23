# pylint:disable=missing-class-docstring,wrong-import-order
from __future__ import annotations

import os
import sys
import unittest

import angr
from common import AngrManagementTestCase, test_location

from angrmanagement.ui.views.proximity_view import ProximityView
from angrmanagement.ui.widgets.qproximitygraph_block import QProximityGraphBlock


class TestProximityView(AngrManagementTestCase):
    def test_proximity_view(self):
        main = self.main
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        main.workspace.main_instance.project.am_obj = angr.Project(binpath, auto_load_libs=False)
        main.workspace.main_instance.project.am_event()
        main.workspace.job_manager.join_all_jobs()

        func = main.workspace.main_instance.project.kb.functions["main"]
        assert func is not None

        prox_view = main.workspace._get_or_create_view("proximity", ProximityView)
        prox_view.function = func

        assert prox_view._proximity_graph is not None
        g = prox_view._graph

        assert g is not None and g.number_of_nodes() > 0
        for node in g.nodes():
            assert isinstance(node, QProximityGraphBlock)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
