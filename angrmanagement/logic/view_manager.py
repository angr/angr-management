"""
The bookkeeping of the views a workspace shows, without a toolkit.

:class:`BaseViewManager` keeps the list of views, groups them by category, numbers views of the same category, and
remembers which view had the focus most recently. A frontend subclasses it to put views on screen: it implements
:meth:`~BaseViewManager.create_view` from its registry of view classes, and :meth:`~BaseViewManager.add_view`,
:meth:`~BaseViewManager.remove_view` and :meth:`~BaseViewManager.raise_view` with its own docking.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

#: Where a view of each category opens when nothing else is asked for; categories not listed open in the center.
DEFAULT_POSITIONS: dict[str, str] = {
    "functions": "left",
    "tracemap": "top",
    "registers": "right",
    "stack": "right",
    "comments": "bottom",
    "bookmarks": "bottom",
    "console": "bottom",
    "log": "bottom",
    "jobs": "bottom",
    "mcp_history": "bottom",
}

#: The docking areas, in the order a frontend lays them out.
DOCKING_AREAS = ("center", "left", "right", "top", "bottom")


def default_position(category: str) -> str:
    """The docking area a view of ``category`` opens in."""
    return DEFAULT_POSITIONS.get(category, "center")


class BaseViewManager:
    """
    Keeps track of the views of a workspace.

    A view is any object with ``category``, ``index``, ``caption`` and ``default_docking_position`` attributes;
    ``on_focused()`` is called, if the view has it, when the view gets the focus.
    """

    def __init__(self, workspace) -> None:
        self.workspace = workspace
        self.views: list[Any] = []
        self.views_by_category: dict[str, list[Any]] = defaultdict(list)
        self.views_by_activation: list[Any] = []

    #
    # What a frontend implements
    #

    def create_view(self, category: str, position: str | None = None) -> Any | None:
        """
        Create a view of ``category`` and add it, docked at ``position`` (the category's default when None).

        :returns: The new view, or None if this frontend has no view of that category.
        """
        raise NotImplementedError

    def view_categories(self) -> Iterable[str]:  # pylint:disable=no-self-use
        """The categories :meth:`create_view` can create."""
        return ()

    def add_view(self, view) -> None:
        """Add a view to the workspace and show it."""
        self._register_view(view)

    def remove_view(self, view) -> None:
        """Remove a view from the workspace."""
        self._unregister_view(view)

    def raise_view(self, view) -> None:
        """Bring a view to the front."""
        self._promote_view(view)

    def focus_view(self, view) -> None:
        """Give a view the keyboard focus."""

    def next_tab(self) -> None:
        """Show the next tab of the area that holds the most recently focused center view."""

    def previous_tab(self) -> None:
        """Show the previous tab of that area."""

    #
    # Bookkeeping
    #

    def _update_view_index_in_category(self, view) -> None:
        """
        Set lowest available index value in category for a view not yet added.
        """
        existing_views = self.views_by_category[view.category]
        if view in existing_views:
            return
        existing_ids = {v.index for v in existing_views}
        max_id = max(existing_ids) if existing_ids else 0
        candidates = set(range(1, max_id + 2)) - existing_ids
        view.index = min(candidates)

    def _promote_view(self, view) -> None:
        """
        Move view to first position in views_by_activation.
        """
        if view in self.views_by_activation:
            self.views_by_activation.remove(view)
        self.views_by_activation.insert(0, view)

    def _register_view(self, view) -> None:
        """Number the view within its category and record it."""
        self._update_view_index_in_category(view)
        self.views_by_category[view.category].append(view)
        self.views_by_activation.append(view)
        self.views.append(view)

    def _unregister_view(self, view) -> bool:
        """Forget the view; returns whether it was known."""
        if view not in self.views:
            return False
        self.views.remove(view)
        if view in self.views_by_category[view.category]:
            self.views_by_category[view.category].remove(view)
        if view in self.views_by_activation:
            self.views_by_activation.remove(view)
        return True

    def handle_focus_changed(self, view) -> None:
        """Record that ``view`` got the focus, and tell it."""
        if view is None or view not in self.views:
            return
        self._promote_view(view)
        on_focused = getattr(view, "on_focused", None)
        if on_focused is not None:
            on_focused()

    #
    # Lookups
    #

    @property
    def most_recently_focused_view(self) -> Any | None:
        if self.views_by_activation:
            return self.views_by_activation[0]
        return None

    def get_most_recently_focused_view_by_docking_area(self, area: str) -> Any | None:
        for view in self.views_by_activation:
            if view.default_docking_position == area:
                return view
        return None

    def first_view_in_category(self, category: str) -> Any | None:
        """
        Return the first view in a specific category.
        """
        if self.views_by_category[category]:
            return self.views_by_category[category][0]
        return None

    def current_view_in_category(self, category: str) -> Any | None:
        """
        Return the most recently focused view in a specific category.
        """
        for view in self.views_by_activation:
            if view.category == category:
                return view
        return None

    @property
    def current_tab(self) -> Any | None:
        return self.get_most_recently_focused_view_by_docking_area("center")
