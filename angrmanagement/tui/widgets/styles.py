"""Rich styles of the presenters' style keys, through the theme the app shows."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.style import Style

from angrmanagement.config.color import Color
from angrmanagement.logic import GlobalInfo
from angrmanagement.present.links import LINK_TIER, angr_url, split_link
from angrmanagement.present.theme import Theme
from angrmanagement.tui.theme import rich_style

if TYPE_CHECKING:
    from textual.widget import Widget


def current_theme(widget: Widget) -> Theme:
    """The theme the app shows, or the configuration's colours."""
    theme = getattr(widget.app, "am_theme", None)
    return theme if isinstance(theme, Theme) else Theme.from_conf()


def links_shown(widget: Widget) -> bool:
    """Whether the terminal shows hyperlinks (OSC 8): tier 1 and up."""
    caps = getattr(widget.app, "caps", None)
    return caps is not None and caps.tier >= LINK_TIER


def blend(color: Color, base: Color, alpha: float) -> Color:
    """``color`` laid over ``base`` with opacity ``alpha``."""
    return Color(
        round(color.r * alpha + base.r * (1 - alpha)),
        round(color.g * alpha + base.g * (1 - alpha)),
        round(color.b * alpha + base.b * (1 - alpha)),
    )


class StyleCache:
    """
    Rich styles of style keys through the app's theme, cached until the theme changes. A ``link:<address>`` token
    (angrmanagement.present.links) adds a hyperlink to the address's angr:// URL where the terminal shows links.
    """

    def __init__(self, widget: Widget) -> None:
        self.widget = widget
        self._theme: Theme | None = None
        self._client_id: str | None = None
        self._styles: dict[str, Style] = {}

    def __call__(self, key: str) -> Style:
        theme = current_theme(self.widget)
        # a link names this window's client id once the app is connected to the daemon
        if theme is not self._theme or GlobalInfo.client_id != self._client_id:
            self._theme = theme
            self._client_id = GlobalInfo.client_id
            self._styles = {}
        style = self._styles.get(key)
        if style is None:
            rest, addr = split_link(key)
            style = rich_style(theme.style(rest))
            if addr is not None and links_shown(self.widget):
                style += Style(link=angr_url(addr))
            self._styles[key] = style
        return style


__all__ = ["StyleCache", "blend", "current_theme", "links_shown"]
