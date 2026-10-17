"""
The Qt feature map follows the CFB through the presenter it shares with the terminal's feature map: a new CFB
rebuilds the maps, added objects redraw at most every MIN_REFRESH_INTERVAL, and hiding the toolbar stops it.
"""

# pylint: disable=protected-access

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from common import ProjectOpenTestCase

from angrmanagement.ui.widgets.qfeature_map import QFeatureMap


class TestQFeatureMap(ProjectOpenTestCase):
    """The feature map of the toolbar, on a loaded project."""

    def setUp(self):
        super().setUp()
        self.feature_map = QFeatureMap(self.instance)
        self.item = self.feature_map.view._feature_map_item
        #: the CFB's container, which tells its subscribers
        self.cfb: Any = self.instance.cfb
        self.shut_down = False

    def tearDown(self) -> None:
        if not self.shut_down:
            self.feature_map.shutdown()
        super().tearDown()

    def test_new_cfb_rebuilds_and_forgets_the_hover(self):
        regions = self.item.model.position_to_region
        assert len(regions)
        self.item._hover_region = regions[regions.keys()[0]]
        with patch.object(self.item.model, "build", wraps=self.item.model.build) as build:
            self.cfb.am_event()
        build.assert_called_once()
        assert self.item._hover_region is None
        assert len(self.item.model.position_to_region)

    def test_added_objects_redraw_at_most_so_often(self):
        presenter = self.item._presenter
        self.item.refresh()
        stamp = presenter._last_refresh
        with patch.object(self.item.model, "add_objects", return_value=True):
            self.cfb.am_event(objects_added=[])
            assert presenter._last_refresh == stamp, "too soon after the last refresh"
            presenter._last_refresh = 0.0
            self.cfb.am_event(objects_added=[])
        assert presenter._last_refresh > stamp

    def test_shutdown_stops_following_the_cfb(self):
        self.feature_map.shutdown()
        self.shut_down = True
        with patch.object(self.item.model, "build") as build:
            self.cfb.am_event()
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
