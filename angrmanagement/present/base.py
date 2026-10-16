"""
Presenters: the half of a view that does not draw.

A presenter holds the state of one view and its actions, and says which commands, context menu and key bindings the
view has. The frontend's view widget owns a presenter (``view.presenter``) and draws what it says. The classes here
mirror the Qt view hierarchy in angrmanagement.ui.views.view: :class:`Presenter` for any view,
:class:`InstancePresenter` for a view of an instance, :class:`FunctionPresenter` for a view of one function, and
:class:`SynchronizedPresenter` for a view whose cursor can follow other views'.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from angrmanagement.data.object_container import ObjectContainer

from .keymap import Keymap
from .menus import Menu, MenuEntry

if TYPE_CHECKING:
    from collections.abc import Sequence

    import angr

    from angrmanagement.data.highlight_region import SynchronizedHighlightRegion
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.commands import Command


class Presenter:
    """
    The state and actions of one view.

    :param workspace:                   The workspace the view belongs to.
    :param category:                    The view category, such as ``"functions"``.
    :param default_docking_position:    Where the view docks: center, left, right, top or bottom.
    """

    def __init__(self, workspace, category: str, default_docking_position: str = "center") -> None:
        self.workspace = workspace
        self.category = category
        self.default_docking_position = default_docking_position
        self.index: int = 1
        self.base_caption: str = "View"
        #: The frontend widget that shows this presenter, once there is one.
        self.view: Any = None

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.caption}>"

    @property
    def caption(self) -> str:
        s = self.base_caption
        if self.index > 1:
            s += f"-{self.index}"
        return s

    def refresh(self) -> None:
        """Bring the shown data up to date after a small change; must be fast."""

    def reload(self) -> None:
        """Rebuild the shown data from scratch."""

    def close(self) -> None:
        """The view is going away: stop listening to events."""

    def commands(self) -> list[Command]:  # pylint:disable=no-self-use
        """Commands this view adds to the command palette while it is focused."""
        return []

    def context_menu(self, *args, **kwargs) -> Menu | None:  # pylint:disable=unused-argument,no-self-use
        """The context menu for what the arguments describe (rows, a node, ...), or None for no menu."""
        return None

    @property
    def keymap(self) -> Keymap:
        """The view's own key bindings."""
        return Keymap(self.category)

    def focus(self) -> None:
        """Bring the view to the front."""
        self.workspace.view_manager.raise_view(self.view if self.view is not None else self)


class ViewState:
    """
    A basic view state to be published through ViewStatePublisherMixin.
    """

    cursors: list[int]

    def __init__(self, cursors: list[int] | None = None) -> None:
        self.cursors = cursors or []


class InstancePresenter(Presenter):
    """The state of a view of an instance."""

    def __init__(self, workspace, category: str, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, category, default_docking_position)
        self.instance = instance
        self.published_view_state = ViewState()

    def on_focused(self) -> None:
        self.notify_view_state_updated()

    def notify_view_state_updated(self) -> None:
        shown = self.view if self.view is not None else self
        if self.workspace.view_manager.most_recently_focused_view is shown:
            state = container(self.instance.active_view_state)
            state.am_obj = self.published_view_state
            state.am_event()


class FunctionPresenter(InstancePresenter):
    """The state of a view of one function; ``function`` is the container of the function shown."""

    def __init__(self, workspace, category: str, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, category, instance, default_docking_position)
        self._function = ObjectContainer(None, "Current function")

    @property
    def function(self) -> ObjectContainer:
        return self._function

    @function.setter
    def function(self, function: angr.knowledge_plugins.Function | None) -> None:
        self._function.am_obj = function
        self._function.am_event()


def container(obj: Any) -> ObjectContainer:
    """``obj``, an attribute of an instance such as ``instance.cfg``, typed as the ObjectContainer it is."""
    return cast("ObjectContainer", obj)


def project_of(instance: Instance) -> angr.Project | None:
    """The instance's project, or None when none is loaded."""
    if instance.project.am_none:
        return None
    return cast("angr.Project", instance.project.am_obj)


def is_function_view(view: Any) -> bool:
    """Whether ``view`` shows one function: its presenter is a :class:`FunctionPresenter`."""
    return isinstance(getattr(view, "presenter", None), FunctionPresenter)


class SynchronizedViewState:
    """
    Simple state tracking for synchronized views.
    """

    views: set[Any]
    cursor_address: int | None
    highlight_regions: dict[Any, Sequence[SynchronizedHighlightRegion]]

    def __init__(self) -> None:
        self.views = set()
        self.cursor_address = None
        self.highlight_regions = {}

    def register_view(self, view) -> None:
        """
        Register a synchronized view.
        """
        self.views.add(view)
        for v in self.views:
            v.on_synchronized_view_group_changed()

    def unregister_view(self, view) -> None:
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


class Synchronized:
    """
    What a synchronized view does: share a cursor address and highlight regions with the other views of its group.

    The class using it provides ``jump_to(addr)`` and ``workspace``, and may override the
    ``on_synchronized_*`` hooks.
    """

    _processing_synchronized_cursor_update: bool
    sync_state: SynchronizedViewState
    workspace: Any

    def __init__(self) -> None:
        self._processing_synchronized_cursor_update = False
        self.sync_state = SynchronizedViewState()
        self.sync_state.register_view(self)

    def jump_to(self, addr: int) -> Any:
        raise NotImplementedError

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

    def synchronization_groups(self) -> list[SynchronizedViewState]:
        """The groups of the other synchronized views of the workspace."""
        groups = []
        for v in self.workspace.view_manager.views:
            target = getattr(v, "presenter", v) if not isinstance(v, Synchronized) else v
            if target is not self and isinstance(target, Synchronized) and target.sync_state not in groups:
                groups.append(target.sync_state)
        return groups

    def synchronize_with_menu(self) -> Menu:
        """The "Synchronize with" submenu: one checkable entry per group of other views."""
        menu = Menu("&Synchronize with")
        groups = self.synchronization_groups()
        if not groups:
            menu.add(MenuEntry("None available", lambda: None, enabled=False))
            return menu
        for group in groups:
            caption = ", ".join(v.caption for v in group.views if v is not self)
            menu.add(
                MenuEntry(
                    caption,
                    lambda checked, s=group: self.sync_with_state_object(s if checked else None),
                    checkable=True,
                    checked=group is self.sync_state,
                )
            )
        return menu


class SynchronizedPresenter(Synchronized, InstancePresenter):
    """The state of a view of an instance that can be synchronized with other views."""

    def __init__(self, workspace, category: str, instance: Instance, default_docking_position: str = "center") -> None:
        InstancePresenter.__init__(self, workspace, category, instance, default_docking_position)
        Synchronized.__init__(self)

    def jump_to(self, addr: int) -> Any:
        """Show ``addr``; the frontend view does the work."""
        if self.view is not None and hasattr(self.view, "jump_to"):
            return self.view.jump_to(addr)
        return None
