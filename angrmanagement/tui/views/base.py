"""The base class of the views of the terminal frontend."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from textual.containers import Vertical

if TYPE_CHECKING:
    from textual import events

    from angrmanagement.data.instance import Instance
    from angrmanagement.present.base import Presenter


class TuiView(Vertical):
    """
    A view: a widget that draws its presenter.

    Subclasses set :attr:`PRESENTER_CLASS` (or override :meth:`make_presenter`) and compose their widgets. The view
    reports focus to the view manager, so the workspace knows which view the user works in.
    """

    PRESENTER_CLASS: Any = None

    DEFAULT_CSS = """
    TuiView {
        height: 1fr;
        width: 1fr;
    }
    """

    def __init__(self, workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__()
        self.workspace = workspace
        self.instance = instance
        self.default_docking_position = default_docking_position
        self.presenter: Any = self.make_presenter(workspace, instance, default_docking_position)
        self.presenter.view = self
        self.category = self.presenter.category

    def make_presenter(self, workspace, instance: Instance, default_docking_position: str) -> Presenter:
        presenter_class = type(self).PRESENTER_CLASS
        if presenter_class is None:
            raise NotImplementedError(f"{type(self).__name__} names no presenter class")
        return presenter_class(workspace, instance, default_docking_position)  # pylint:disable=not-callable

    #
    # What the view manager and the workspace use
    #

    @property
    def index(self) -> int:
        return self.presenter.index

    @index.setter
    def index(self, value: int) -> None:
        self.presenter.index = value

    @property
    def base_caption(self) -> str:
        return self.presenter.base_caption

    @property
    def caption(self) -> str:
        return self.presenter.caption

    def reload(self) -> None:
        self.presenter.reload()

    def refresh_view(self) -> None:
        self.presenter.refresh()

    def on_focused(self) -> None:
        on_focused = getattr(self.presenter, "on_focused", None)
        if on_focused is not None:
            on_focused()

    def close_view(self) -> None:
        """The view leaves the workspace: the presenter stops listening."""
        self.presenter.close()

    def focus_view(self) -> None:
        """Give the focus to the view's main widget."""
        for widget in self.query("*"):
            if widget.can_focus and widget.display:
                widget.focus()
                return

    def on_descendant_focus(self, _event: events.DescendantFocus) -> None:
        view_manager = getattr(self.workspace, "view_manager", None)
        if view_manager is not None:
            view_manager.handle_focus_changed(self)
