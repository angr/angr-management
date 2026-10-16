from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QFrame, QMenu

from angrmanagement.present.base import (
    FunctionPresenter,
    InstancePresenter,
    Presenter,
    Synchronized,
    SynchronizedViewState,
    ViewState,
)
from angrmanagement.ui.icons import icon

if TYPE_CHECKING:
    import angr
    import PySide6.QtGui

    from angrmanagement.data.object_container import ObjectContainer
    from angrmanagement.ui.workspace import Instance, Workspace

__all__ = [
    "BaseView",
    "FunctionView",
    "InstanceView",
    "SynchronizedFunctionView",
    "SynchronizedInstanceView",
    "SynchronizedView",
    "SynchronizedViewState",
    "ViewState",
]


class BaseView(QFrame):
    """
    Base class for all main views.
    """

    # Any, so that a view can declare its own presenter class
    presenter: Any

    def __init__(
        self,
        category: str,
        workspace: Workspace,
        default_docking_position: str,
        presenter: Presenter | None = None,
    ) -> None:
        super().__init__()

        self.workspace = workspace
        self.category = category
        self.default_docking_position = default_docking_position
        self.presenter = (
            presenter if presenter is not None else Presenter(workspace, category, default_docking_position)
        )
        self.presenter.view = self

        self.old_height = None
        self.width_hint = -1
        self.height_hint = -1
        self.icon = icon(category + "-view")

    @property
    def index(self) -> int:
        """The number of this view among the views of its category, from 1."""
        return self.presenter.index

    @index.setter
    def index(self, value: int) -> None:
        self.presenter.index = value

    @property
    def base_caption(self) -> str:
        return self.presenter.base_caption

    @base_caption.setter
    def base_caption(self, value: str) -> None:
        self.presenter.base_caption = value

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
        return self.presenter.caption


class InstanceView(BaseView):
    """
    Base class for views that are associated with an instance.
    """

    instance: Instance
    published_view_state: ViewState

    def __init__(
        self,
        category: str,
        workspace: Workspace,
        default_docking_position: str,
        instance: Instance,
        presenter: InstancePresenter | None = None,
    ) -> None:
        if presenter is None:
            presenter = InstancePresenter(workspace, category, instance, default_docking_position)
        BaseView.__init__(self, category, workspace, default_docking_position, presenter)
        self.instance = instance
        self.published_view_state = presenter.published_view_state

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

    def __init__(
        self,
        category: str,
        workspace: Workspace,
        default_docking_position: str,
        instance: Instance,
        presenter: FunctionPresenter | None = None,
    ) -> None:
        if presenter is None:
            presenter = FunctionPresenter(workspace, category, instance, default_docking_position)
        InstanceView.__init__(self, category, workspace, default_docking_position, instance, presenter)
        self._function = presenter.function

    @property
    def function(self) -> angr.knowledge_plugins.Function | None:
        return self._function

    @function.setter
    def function(self, function: angr.knowledge_plugins.Function | None) -> None:
        self._function.am_obj = function
        self._function.am_event()


class SynchronizedView(Synchronized, BaseView):
    """
    Base class for views which can be synchronized.

    The synchronization itself is :class:`angrmanagement.present.base.Synchronized`.
    """

    def __init__(self) -> None:  # pylint: disable=super-init-not-called
        Synchronized.__init__(self)

    def closeEvent(self, event: PySide6.QtGui.QCloseEvent) -> None:
        """
        View close event handler.
        """
        self.desync()
        super().closeEvent(event)

    def get_synchronize_with_submenu(self) -> QMenu:
        """
        Get submenu for 'Synchronize with' context menu: :meth:`Synchronized.synchronize_with_menu` as a QMenu.
        """
        menu = self.synchronize_with_menu()
        menu.parent = self
        return menu.qmenu(cached=False)


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
