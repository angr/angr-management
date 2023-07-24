from typing import TYPE_CHECKING, Callable, Optional, Type

if TYPE_CHECKING:
    from angrmanagement.ui.views import BaseView
    from angrmanagement.ui.workspace import Workspace


class Command:
    """
    Command to be run.
    """

    _name: Optional[str] = None
    _caption: Optional[str] = None

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

    def __init__(self, name: str, caption: str, action: Callable):
        self._name = name
        self._caption = caption
        self._action: Callable = action

    def run(self):
        self._action()


class ViewCommand(Command):
    """
    Commands to invoke a callable on a view.
    """

    def __init__(self, name: str, caption: str, action: Callable, view_class: Type["BaseView"], workspace: "Workspace"):
        self._name = name
        self._caption = caption
        self._action: Callable = action
        self._view_class: Type[BaseView] = view_class
        self._workspace: Workspace = workspace

    @property
    def is_visible(self) -> bool:
        view = self._workspace.view_manager.most_recently_focused_view
        return isinstance(view, self._view_class)

    def run(self) -> None:
        view = self._workspace.view_manager.most_recently_focused_view
        if isinstance(view, self._view_class):
            self._action(view)
