from __future__ import annotations

from typing import Any

from angrmanagement.present.feature_map import jump_to_feature_addr
from angrmanagement.ui.widgets.qfeature_map import QFeatureMap

from .toolbar import Toolbar
from .toolbar_dock import ToolBarDockWidget


class FeatureMapToolbar(Toolbar):
    """
    Displays the current feature map, which shows the cursors of the most recently focused view, and allows selection
    in the feature map to control location of active view.
    """

    def __init__(self, window) -> None:
        super().__init__(window, "Feature Map")
        self._toolbar = None
        self._feature_map = None
        self._is_subscribed = False

    def _subscribe_events(self) -> None:
        self._feature_map.addr.am_subscribe(self._on_feature_map_addr_selected)
        self._is_subscribed = True

    def _unsubscribe_events(self) -> None:
        if self._is_subscribed:
            self._feature_map.addr.am_unsubscribe(self._on_feature_map_addr_selected)

    def qtoolbar(self):
        if self._toolbar is None:
            self._feature_map = QFeatureMap(self.window.workspace.main_instance, parent=self.window)
            self._toolbar = ToolBarDockWidget(self._feature_map, "Feature Map", parent=None)
            self._subscribe_events()
        return self._toolbar

    def shutdown(self) -> None:
        self._unsubscribe_events()
        if self._feature_map is not None:
            self._feature_map.shutdown()

    def _on_feature_map_addr_selected(self) -> None:
        addr: Any = self._feature_map.addr.am_obj
        jump_to_feature_addr(self.window.workspace, addr)
