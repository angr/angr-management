from typing import TYPE_CHECKING, List, Mapping, Optional, Sequence

from PySide6.QtCore import QSize
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QFrame, QMenu

if TYPE_CHECKING:
    import PySide6.QtGui

    from angrmanagement.data.highlight_region import SynchronizedHighlightRegion
    from angrmanagement.ui.workspace import Instance


class BaseView(QFrame):
    """
    Base class for all main views.
    """

    # if this view has function-specific views to show. function setter must be implemented when this property is set
    # to True.
    FUNCTION_SPECIFIC_VIEW = False

    def __init__(self, category: str, instance, default_docking_position, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.instance: Instance = instance
        self.category = category
        self.default_docking_position = default_docking_position

        self.old_width = None
        self.old_height = None
        self.width_hint = -1
        self.height_hint = -1
        self.index: int = 1
        self.base_caption: str = "View"

    @property
    def function(self):
        raise NotImplementedError()

    @function.setter
    def function(self, v):
        raise NotImplementedError()

    def is_shown(self):
        return self.visibleRegion().isEmpty() is False

    def focus(self):
        self.instance.workspace.view_manager.raise_view(self)

    def refresh(self):
        pass

    def reload(self):
        pass

    def sizeHint(self):
        return QSize(self.width_hint, self.height_hint)

    def resizeEvent(self, event):
        # Update current width
        self.old_width = event.oldSize().width()
        self.old_height = event.oldSize().height()

    def closeEvent(self, event: "PySide6.QtGui.QCloseEvent"):
        self.instance.workspace.view_manager.remove_view(self)
        event.accept()

    def mainWindowInitializedEvent(self):
        pass

    #
    # Properties
    #

    @property
    def caption(self):
        s = self.base_caption
        if self.index > 1:
            s += f"-{self.index}"
        return s


class ViewState:
    """
    A basic view state to be published through ViewStatePublisherMixin.
    """

    def __init__(self, cursors: Optional[List[int]] = None):
        self.cursors: List[int] = cursors or []


class ViewStatePublisherMixin:
    """
    Views that wish to update the instance 'active' view state for common visualization use this mixin.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.published_view_state = ViewState()

    def on_focused(self):
        self.notify_view_state_updated()

    def notify_view_state_updated(self):
        if self.instance.workspace.view_manager.most_recently_focused_view is self:
            self.instance.active_view_state.am_obj = self.published_view_state
            self.instance.active_view_state.am_event()


class SynchronizedViewState:
    """
    Simple state tracking for synchronized views.
    """

    def __init__(self):
        self.views = set()
        self.cursor_address: Optional[int] = None
        self.highlight_regions: Mapping[SynchronizedView, Sequence[SynchronizedHighlightRegion]] = {}

    def register_view(self, view: "SynchronizedView"):
        """
        Register a synchronized view.
        """
        self.views.add(view)
        for v in self.views:
            v.on_synchronized_view_group_changed()

    def unregister_view(self, view: "SynchronizedView"):
        """
        Unregister a synchronized view.
        """
        rgns = self.highlight_regions.pop(view, None)
        if rgns is not None:
            for v in self.views:
                v.on_synchronized_highlight_regions_changed()
        self.views.remove(view)
        for v in self.views:
            v.on_synchronized_view_group_changed()


class SynchronizedView(BaseView):
    """
    Base class for views which can be synchronized.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._processing_synchronized_cursor_update: bool = False
        self.sync_state: SynchronizedViewState = SynchronizedViewState()
        self.sync_state.register_view(self)

    def desync(self):
        """
        Stop synchronization with any previously synchronized views.
        """
        self.sync_with_state_object()

    def sync_with_state_object(self, state: Optional[SynchronizedViewState] = None):
        """
        Synchronize with another view state.
        """
        self.sync_state.unregister_view(self)
        self.sync_state = state or SynchronizedViewState()
        self.sync_state.register_view(self)
        self.sync_from_state()

    def sync_with_view(self, view: "SynchronizedView"):
        """
        Synchronize with another view.
        """
        self.sync_with_state_object(view.sync_state)

    def sync_from_state(self):
        """
        Update this view to reflect the synchronized view state.
        """
        self.on_synchronized_cursor_address_changed()
        self.on_synchronized_highlight_regions_changed()

    def set_synchronized_cursor_address(self, address: Optional[int]):
        """
        Set synchronized cursor address.
        """
        if not self._processing_synchronized_cursor_update:
            self.sync_state.cursor_address = address
            for view in self.sync_state.views:
                if view is not self:
                    view.on_synchronized_cursor_address_changed()

    def on_synchronized_cursor_address_changed(self):
        """
        Handle synchronized cursor address change event.
        """
        assert not self._processing_synchronized_cursor_update
        self._processing_synchronized_cursor_update = True
        try:
            if self.sync_state.cursor_address is not None:
                self.jump_to(self.sync_state.cursor_address)
        finally:
            self._processing_synchronized_cursor_update = False

    def set_synchronized_highlight_regions(self, regions: Sequence["SynchronizedHighlightRegion"]):
        """
        Set synchronized highlight regions for this view.
        """
        self.sync_state.highlight_regions[self] = regions
        for view in self.sync_state.views:
            if view is not self:
                view.on_synchronized_highlight_regions_changed()

    def on_synchronized_highlight_regions_changed(self):
        """
        Handle synchronized highlight region change event.
        """

    def on_synchronized_view_group_changed(self):
        """
        Handle view being added to or removed from the view synchronization group.
        """

    def closeEvent(self, event: "PySide6.QtGui.QCloseEvent"):
        """
        View close event handler.
        """
        self.desync()
        super().closeEvent(event)

    def get_synchronize_with_submenu(self) -> QMenu:
        """
        Get submenu for 'Synchronize with' context menu.
        """
        mnu = QMenu("&Synchronize with", self)
        groups = {
            v.sync_state
            for v in self.instance.workspace.view_manager.views
            if (v is not self) and isinstance(v, SynchronizedView)
        }
        if len(groups) == 0:
            act = QAction("None available", self)
            act.setEnabled(False)
            mnu.addAction(act)
        else:
            for group in groups:
                act = QAction(", ".join([v.caption for v in group.views if v is not self]), self)
                act.setCheckable(True)
                act.setChecked(group is self.sync_state)
                act.toggled.connect(lambda checked, s=group: self.sync_with_state_object(s if checked else None))
                mnu.addAction(act)
        return mnu
