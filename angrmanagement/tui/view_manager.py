"""
Docking for the terminal frontend.

The screen has five areas, left, center, right, top and bottom, each a ``TabbedContent`` whose tabs are views.
:class:`TuiViewManager` puts a new view in the area its category opens in, raises and focuses views, cycles the tabs
of the center area, hides empty side areas, lets the bottom area hide itself as the Qt dock does, and resizes areas.
The layout (area sizes, whether the bottom area is hidden, and the tabs open in each area with the active one) is
saved in the configuration's ``tui_layout``; the tabs are saved when the app exits with a binary loaded and opened
again when the next binary loads.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections import Counter
from typing import TYPE_CHECKING, Any

from textual.widgets import TabbedContent, TabPane

from angrmanagement.config import Conf, save_config
from angrmanagement.logic.view_manager import DOCKING_AREAS, BaseViewManager, default_position
from angrmanagement.tui.views import TUI_VIEW_CLASSES

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.tui.views.base import TuiView

_l = logging.getLogger(__name__)

#: Area sizes in cells: the width of the side areas, the height of the top and bottom ones.
DEFAULT_LAYOUT: dict[str, Any] = {"left": 48, "right": 40, "top": 8, "bottom": 14, "bottom_hidden": True}
MIN_SIZES = {"left": 12, "right": 12, "top": 3, "bottom": 4}


class DockArea(TabbedContent):
    """One docking area: a tab per view."""

    DEFAULT_CSS = """
    DockArea {
        height: 1fr;
        width: 1fr;
    }
    DockArea > ContentTabs {
        height: 2;
    }
    DockArea > ContentSwitcher {
        height: 1fr;
    }
    DockArea TabPane {
        padding: 0;
        height: 1fr;
    }
    """

    def __init__(self, area: str) -> None:
        super().__init__(id=f"area-{area}")
        self.area = area

    @property
    def pane_ids(self) -> list[str]:
        return [pane.id for pane in self.query(TabPane) if pane.id]


class TuiViewManager(BaseViewManager):
    """Puts views into the areas of the app's screen."""

    def __init__(self, workspace) -> None:
        super().__init__(workspace)
        self.app = workspace.main_window
        self._panes: dict[Any, tuple[str, str]] = {}
        self._mounting: dict[str, Any] = {}
        self._next_pane = 0
        self.layout: dict[str, Any] = load_layout()

    #
    # Areas
    #

    def area(self, name: str) -> DockArea:
        return self.app.query_one(f"#area-{name}", DockArea)

    def views_in_area(self, name: str) -> list[TuiView]:
        return [view for view, (area, _) in self._panes.items() if area == name]

    def area_of(self, view) -> str | None:
        entry = self._panes.get(view)
        return entry[0] if entry is not None else None

    def pane_id_of(self, view) -> str | None:
        entry = self._panes.get(view)
        return entry[1] if entry is not None else None

    def update_areas(self) -> None:
        """Show the areas that have views, apply the sizes, and hide the bottom area if the user hid it."""
        for name in DOCKING_AREAS:
            area = self.area(name)
            has_views = bool(self.views_in_area(name))
            if name == "center":
                area.display = has_views
                placeholder = self.app.query("#center-placeholder")
                if placeholder:
                    placeholder.first().display = not has_views
                continue
            hidden = name == "bottom" and bool(self.layout.get("bottom_hidden"))
            visible = has_views and not hidden
            area.display = visible
            if name == "bottom":
                self._update_bottom_strip(has_views and hidden)
            size = max(MIN_SIZES[name], int(self.layout.get(name, DEFAULT_LAYOUT[name])))
            if name in ("left", "right"):
                area.styles.width = size
            else:
                area.styles.height = size

    def _update_bottom_strip(self, show: bool) -> None:
        """The row of captions that stands for the hidden bottom area, as Qt's auto-hide tab bar does."""
        strips = self.app.query("#bottom-strip")
        if not strips:
            return
        strip = strips.first()
        strip.display = show
        if show:
            parts = []
            for view in self.views_in_area("bottom"):
                pane_id = self.pane_id_of(view)
                caption = view.caption.replace("[", "\\[")
                parts.append(f"[@click=app.raise_pane('{pane_id}')] {caption} [/]")
            strip.update(" ".join(parts))

    #
    # BaseViewManager
    #

    def view_categories(self):
        return TUI_VIEW_CLASSES.keys()

    def create_view(self, category: str, position: str | None = None) -> TuiView | None:
        view_class = TUI_VIEW_CLASSES.get(category)
        if view_class is None:
            return None
        view = view_class(self.workspace, position or default_position(category), self.workspace.main_instance)
        self.add_view(view)
        return view

    def add_view(self, view) -> None:
        self._register_view(view)
        name = view.default_docking_position if view.default_docking_position in DOCKING_AREAS else "right"
        self._next_pane += 1
        pane_id = f"view-{self._next_pane}"
        self._panes[view] = (name, pane_id)
        area = self.area(name)
        pane = TabPane(view.caption, view, id=pane_id)
        self._mounting[pane_id] = area.add_pane(pane)
        self.update_areas()

    def remove_view(self, view) -> None:
        if not self._unregister_view(view):
            return
        entry = self._panes.pop(view, None)
        close_view = getattr(view, "close_view", None)
        if close_view is not None:
            close_view()
        if entry is not None:
            name, pane_id = entry
            self._mounting.pop(pane_id, None)
            with contextlib.suppress(Exception):
                self.area(name).remove_pane(pane_id)
        self.update_areas()

    def _when_mounted(self, view, func: Callable[[], Any]) -> None:
        """Run ``func`` once the pane of ``view`` is in the screen."""
        pane_id = self.pane_id_of(view)
        mounting = self._mounting.pop(pane_id, None) if pane_id is not None else None
        if mounting is None:
            func()
            return

        async def run() -> None:
            with contextlib.suppress(Exception):
                await mounting
            func()

        self.app.run_worker(run(), exit_on_error=False)

    def raise_view(self, view) -> None:
        self._promote_view(view)
        entry = self._panes.get(view)
        if entry is None:
            return
        name, pane_id = entry
        if name == "bottom" and self.layout.get("bottom_hidden"):
            # raising a view of the hidden bottom area shows it, as raising an auto-hidden Qt dock does
            self.layout["bottom_hidden"] = False
        self.update_areas()

        def activate() -> None:
            with contextlib.suppress(Exception):
                self.area(name).active = pane_id

        self._when_mounted(view, activate)

    def focus_view(self, view) -> None:
        focus_view = getattr(view, "focus_view", None)
        if focus_view is not None:
            self._when_mounted(view, lambda: self.app.call_after_refresh(focus_view))

    def _cycle(self, offset: int) -> None:
        view = self.get_most_recently_focused_view_by_docking_area("center")
        views = self.views_in_area("center")
        if not views:
            return
        area = self.area("center")
        ids = [self.pane_id_of(v) for v in views]
        try:
            idx = ids.index(area.active)
        except ValueError:
            idx = views.index(view) if view in views else 0
        target = views[(idx + offset) % len(views)]
        self.raise_view(target)
        self.focus_view(target)

    def next_tab(self) -> None:
        self._cycle(1)

    def previous_tab(self) -> None:
        self._cycle(-1)

    def raise_view_by_index(self, idx: int) -> None:
        """Raise the ``idx``-th view (Alt+1 is the first), in the order the views were added."""
        if 0 <= idx < len(self.views):
            view = self.views[idx]
            self.raise_view(view)
            self.focus_view(view)

    def view_for_pane(self, pane_id: str) -> TuiView | None:
        for view, (_, pid) in self._panes.items():
            if pid == pane_id:
                return view
        return None

    #
    # Layout
    #

    def tab_state(self) -> tuple[dict[str, list[str]], dict[str, str]]:
        """The categories of the views open in each area, in tab order, and the category of each area's active tab."""
        tabs: dict[str, list[str]] = {}
        active: dict[str, str] = {}
        for view, (name, _pane_id) in self._panes.items():
            if view.category in TUI_VIEW_CLASSES:
                tabs.setdefault(name, []).append(view.category)
        for name in tabs:
            with contextlib.suppress(Exception):
                view = self.view_for_pane(self.area(name).active)
                if view is not None and view.category in TUI_VIEW_CLASSES:
                    active[name] = view.category
        return tabs, active

    def save_tabs(self) -> None:
        """Remember the tabs of every area and the active ones (on exit)."""
        self.layout["tabs"], self.layout["active"] = self.tab_state()
        save_layout(self.layout)

    def restore_tabs(self) -> None:
        """Open the views the saved tabs name that are not open, in their areas, and activate the saved tabs."""
        tabs = self.layout.get("tabs") or {}
        have = Counter(view.category for view in self.views)
        for name, categories in tabs.items():
            if name not in DOCKING_AREAS:
                continue
            for category in categories:
                if have[category] > 0:
                    have[category] -= 1
                    continue
                self.create_view(category, name)
        for name, category in (self.layout.get("active") or {}).items():
            view = next((v for v in self.views_in_area(name) if v.category == category), None)
            if view is None:
                continue
            pane_id = self.pane_id_of(view)
            if pane_id is None:
                continue

            def activate(name: str = name, pane_id: str = pane_id) -> None:
                # not raise_view: that would show the bottom area the user hid
                with contextlib.suppress(Exception):
                    self.area(name).active = pane_id

            self._when_mounted(view, activate)

    def toggle_bottom(self) -> None:
        self.layout["bottom_hidden"] = not self.layout.get("bottom_hidden")
        self.update_areas()
        save_layout(self.layout)

    def resize(self, name: str, delta: int) -> None:
        """Grow (or shrink, for a negative ``delta``) an area by ``delta`` cells."""
        if name not in MIN_SIZES:
            return
        self.layout[name] = max(MIN_SIZES[name], int(self.layout.get(name, DEFAULT_LAYOUT[name])) + delta)
        if name == "bottom":
            self.layout["bottom_hidden"] = False
        self.update_areas()
        save_layout(self.layout)


def load_layout() -> dict[str, Any]:
    layout = dict(DEFAULT_LAYOUT)
    try:
        saved = json.loads(Conf.tui_layout) if Conf.tui_layout else {}
    except (ValueError, AttributeError):
        saved = {}
    if isinstance(saved, dict):
        layout.update({k: v for k, v in saved.items() if k in DEFAULT_LAYOUT})
        tabs, active = saved.get("tabs"), saved.get("active")
        if isinstance(tabs, dict) and all(isinstance(v, list) for v in tabs.values()):
            layout["tabs"] = {str(k): [str(c) for c in v] for k, v in tabs.items()}
        if isinstance(active, dict):
            layout["active"] = {str(k): str(v) for k, v in active.items()}
    return layout


def save_layout(layout: dict[str, Any]) -> None:
    Conf.tui_layout = json.dumps(layout, sort_keys=True)
    try:
        save_config()
    except OSError:
        _l.warning("Could not save the layout", exc_info=True)
