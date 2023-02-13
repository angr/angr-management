from angrmanagement.ui.widgets.qfeature_map import QFeatureMap

from .toolbar import Toolbar
from .toolbar_dock import ToolBarDockWidget


class FeatureMapToolbar(Toolbar):
    """
    Displays the current feature map. Monitors most recently focused view via instance.activate_view_state to show
    cursors on the feature map, and allows selection in the feature map to control location of active view.
    """

    def __init__(self, window):
        super().__init__(window, "Feature Map")
        self._toolbar = None
        self._feature_map = None
        self._is_subscribed = False

    def _subscribe_events(self):
        self.window.workspace.main_instance.active_view_state.am_subscribe(self._on_view_state_updated)
        self._feature_map.addr.am_subscribe(self._on_feature_map_addr_selected)
        self._is_subscribed = True

    def _unsubscribe_events(self):
        if self._is_subscribed:
            self.window.workspace.main_instance.active_view_state.am_unsubscribe(self._on_view_state_updated)
            self._feature_map.addr.am_unsubscribe(self._on_feature_map_addr_selected)

    def qtoolbar(self):
        if self._toolbar is None:
            self._feature_map = QFeatureMap(self.window.workspace.main_instance, parent=self.window)
            self._toolbar = ToolBarDockWidget(self._feature_map, "Feature Map", parent=None)
            self._subscribe_events()
        return self._toolbar

    def shutdown(self):
        self._unsubscribe_events()

    def _on_feature_map_addr_selected(self):
        target_view = self.window.workspace.view_manager.most_recently_focused_view
        if hasattr(target_view, "jump_to"):
            addr = self._feature_map.addr.am_obj
            if addr is not None:
                target_view.jump_to(addr)

    def _on_view_state_updated(self):
        vs = self.window.workspace.main_instance.active_view_state
        if vs.am_none:
            return
        self._feature_map.set_cursor_addrs(vs.cursors)
