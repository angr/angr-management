from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QFrame, QMenu

from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.ui.icons import icon

if TYPE_CHECKING:
    from collections.abc import Sequence

    import angr
    import PySide6.QtGui

    from angrmanagement.data.highlight_region import SynchronizedHighlightRegion
    from angrmanagement.ui.workspace import Instance, Workspace


class BaseView(QFrame):
    """
    Base class for all main views.
    """

    def __init__(
        self,
        category: str,
        workspace: Workspace,
        default_docking_position: str,
    ) -> None:
        super().__init__()

        self.workspace = workspace
        self.category = category
        self.default_docking_position = default_docking_position

        self.old_width = None
        self.old_height = None
        self.width_hint = -1
        self.height_hint = -1
        self.index: int = 1
        self.base_caption: str = "View"
        self.icon = icon(category + "-view")

    def is_shown(self) -> bool:
        return self.visibleRegion().isEmpty() is False

    def focus(self) -> None:
        self.workspace.view_manager.raise_view(self)

    def refresh(self) -> None:
        pass

    def reload(self) -> None:
        pass

    def sizeHint(self) -> QSize:
        return QSize(self.width_hint, self.height_hint)

    def resizeEvent(self, event) -> None:
        # Update current width
        self.old_width = event.oldSize().width()
        self.old_height = event.oldSize().height()

    def closeEvent(self, event: PySide6.QtGui.QCloseEvent) -> None:
        self.workspace.view_manager.remove_view(self)
        event.accept()

    def mainWindowInitializedEvent(self) -> None:
        pass

    #
    # Properties
    #

    @property
    def caption(self) -> str:
        s = self.base_caption
        if self.index > 1:
            s += f"-{self.index}"
        return s


class ViewState:
    """
    A basic view state to be published through ViewStatePublisherMixin.
    """

    cursors: list[int]

    def __init__(self, cursors: list[int] | None = None) -> None:
        self.cursors = cursors or []


class InstanceView(BaseView):
    """
    Base class for views that are associated with an instance.
    """

    instance: Instance
    published_view_state: ViewState

    def __init__(self, category: str, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        BaseView.__init__(self, category, workspace, default_docking_position)
        self.instance = instance
        self.published_view_state = ViewState()

    def on_focused(self) -> None:
        self.notify_view_state_updated()

    def notify_view_state_updated(self) -> None:
        if self.workspace.view_manager.most_recently_focused_view is self:
            self.instance.active_view_state.am_obj = self.published_view_state
            self.instance.active_view_state.am_event()


class FunctionView(InstanceView):
    """
    Base class for views that are function-specific.
    """

    # TODO: function would ideally be provided in the constructor
    _function: ObjectContainer

    def __init__(self, category: str, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        InstanceView.__init__(self, category, workspace, default_docking_position, instance)
        self._function = ObjectContainer(None, "Current function")

    @property
    def function(self) -> angr.knowledge_plugins.Function | None:
        return self._function

    @function.setter
    def function(self, function: angr.knowledge_plugins.Function) -> None:
        self._function.am_obj = function
        self._function.am_event()


class SynchronizedViewState:
    """
    Simple state tracking for synchronized views.
    """

    views: set[SynchronizedView]
    cursor_address: int | None
    highlight_regions: dict[SynchronizedView, Sequence[SynchronizedHighlightRegion]]

    def __init__(self) -> None:
        self.views = set()
        self.cursor_address = None
        self.highlight_regions = {}

    def register_view(self, view: SynchronizedView) -> None:
        """
        Register a synchronized view.
        """
        self.views.add(view)
        for v in self.views:
            v.on_synchronized_view_group_changed()

    def unregister_view(self, view: SynchronizedView) -> None:
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

    _processing_synchronized_cursor_update: bool
    sync_state: SynchronizedViewState

    def __init__(self) -> None:  # pylint: disable=super-init-not-called
        self._processing_synchronized_cursor_update = False
        self.sync_state = SynchronizedViewState()
        self.sync_state.register_view(self)

    def desync(self) -> None:
        """
        Stop synchronization with any previously synchronized views.
        """
        self.sync_with_state_object()

    def sync_with_state_object(self, state: SynchronizedViewState | None = None) -> None:
        """
        Synchronize with another view state.
        """
        self.sync_state.unregister_view(self)
        self.sync_state = state or SynchronizedViewState()
        self.sync_state.register_view(self)
        self.sync_from_state()

    def sync_with_view(self, view: SynchronizedView) -> None:
        """
        Synchronize with another view.
        """
        self.sync_with_state_object(view.sync_state)

    def sync_from_state(self) -> None:
        """
        Update this view to reflect the synchronized view state.
        """
        self.on_synchronized_cursor_address_changed()
        self.on_synchronized_highlight_regions_changed()

    def set_synchronized_cursor_address(self, address: int | None) -> None:
        """
        Set synchronized cursor address.
        """
        if not self._processing_synchronized_cursor_update:
            self.sync_state.cursor_address = address
            for view in self.sync_state.views:
                if view is not self:
                    view.on_synchronized_cursor_address_changed()

    def on_synchronized_cursor_address_changed(self) -> None:
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

    def set_synchronized_highlight_regions(self, regions: Sequence[SynchronizedHighlightRegion]) -> None:
        """
        Set synchronized highlight regions for this view.
        """
        self.sync_state.highlight_regions[self] = regions
        for view in self.sync_state.views:
            if view is not self:
                view.on_synchronized_highlight_regions_changed()

    def on_synchronized_highlight_regions_changed(self) -> None:
        """
        Handle synchronized highlight region change event.
        """

    def on_synchronized_view_group_changed(self) -> None:
        """
        Handle view being added to or removed from the view synchronization group.
        """

    def closeEvent(self, event: PySide6.QtGui.QCloseEvent) -> None:
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
            for v in self.workspace.view_manager.views
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


class SynchronizedInstanceView(InstanceView, SynchronizedView):
    """
    Base class for views that are associated with an instance and can be synchronized.
    """

    def __init__(self, category: str, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        InstanceView.__init__(self, category, workspace, default_docking_position, instance)
        SynchronizedView.__init__(self)


class SynchronizedFunctionView(FunctionView, SynchronizedView):
    """
    Base class for views that are function-specific and can be synchronized.
    """

    def __init__(self, category: str, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        FunctionView.__init__(self, category, workspace, default_docking_position, instance)
        SynchronizedView.__init__(self)
