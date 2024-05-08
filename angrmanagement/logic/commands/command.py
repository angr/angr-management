from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.ui.views import BaseView
    from angrmanagement.ui.workspace import Workspace


class Command:
    """
    Command to be run.
    """

    _name: str | None = None
    _caption: str | None = None

    @property
    def name(self) -> str:
        """
        Short name for invocation. By default this name will be derived from the class name.
        """
        return self._name or self.__class__.__name__

    @property
    def caption(self) -> str:
        """
        Message to be displayed to identify the command, e.g. in the command palette.
        """
        return self._caption or self.name

    @property
    def is_visible(self) -> bool:
        """
        Determines whether this command should be displayed or not.
        """
        return True

    def run(self) -> None:
        """
        Runs the command.
        """


class BasicCommand(Command):
    """
    Basic command to invoke a callable.
    """

    def __init__(self, name: str, caption: str, action: Callable) -> None:
        self._name = name
        self._caption = caption
        self._action: Callable = action

    def run(self) -> None:
        self._action()


class ViewCommand(Command):
    """
    Commands to invoke a callable on a view.
    """

    def __init__(
        self, name: str, caption: str, action: Callable, view_class: type[BaseView], workspace: Workspace
    ) -> None:
        self._name = name
        self._caption = caption
        self._action: Callable = action
        self._view_class: type[BaseView] = view_class
        self._workspace: Workspace = workspace

    @property
    def is_visible(self) -> bool:
        view = self._workspace.view_manager.most_recently_focused_view
        return isinstance(view, self._view_class)

    def run(self) -> None:
        view = self._workspace.view_manager.most_recently_focused_view
        if isinstance(view, self._view_class):
            self._action(view)
