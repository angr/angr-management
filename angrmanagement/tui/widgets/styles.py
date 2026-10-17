"""Rich styles of the presenters' style keys, through the theme the app shows."""

from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.present.theme import Theme
from angrmanagement.tui.theme import rich_style

if TYPE_CHECKING:
    from rich.style import Style
    from textual.widget import Widget


def current_theme(widget: Widget) -> Theme:
    """The theme the app shows, or the configuration's colours."""
    theme = getattr(widget.app, "am_theme", None)
    return theme if isinstance(theme, Theme) else Theme.from_conf()


class StyleCache:
    """Rich styles of style keys through the app's theme, cached until the theme changes."""

    def __init__(self, widget: Widget) -> None:
        self.widget = widget
        self._theme: Theme | None = None
        self._styles: dict[str, Style] = {}

    def __call__(self, key: str) -> Style:
        theme = current_theme(self.widget)
        if theme is not self._theme:
            self._theme = theme
            self._styles = {}
        style = self._styles.get(key)
        if style is None:
            style = self._styles[key] = rich_style(theme.style(key))
        return style


__all__ = ["StyleCache", "current_theme"]
