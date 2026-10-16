"""Textual themes and Rich styles from angrmanagement.present.theme."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.color import Color as RichColor
from rich.style import Style
from textual.theme import Theme as TextualTheme

from angrmanagement.present.theme import CUSTOM_SCHEME_NAME, Theme, scheme_names

if TYPE_CHECKING:
    from angrmanagement.config.color import Color
    from angrmanagement.present.theme import StyleSpec


def theme_id(scheme: str) -> str:
    """The Textual theme name of a colour scheme: ``"Catppuccin Mocha"`` is ``"am-catppuccin-mocha"``."""
    return "am-" + scheme.lower().replace(" ", "-")


def hex_of(color: Color) -> str:
    return f"#{color.rgb_hex}"


def rich_color(color: Color | None) -> RichColor | None:
    if color is None:
        return None
    return RichColor.from_rgb(color.r, color.g, color.b)


def rich_style(spec: StyleSpec) -> Style:
    """The Rich style of a neutral style."""
    return Style(
        color=rich_color(spec.fg),
        bgcolor=rich_color(spec.bg),
        bold=spec.bold or None,
        italic=spec.italic or None,
        underline=spec.underline or None,
    )


def textual_theme(theme: Theme, name: str | None = None) -> TextualTheme:
    """A Textual theme with the window colours of ``theme``."""
    return TextualTheme(
        name=name or theme_id(theme.name),
        primary=hex_of(theme.primary),
        secondary=hex_of(theme.link),
        foreground=hex_of(theme.foreground),
        background=hex_of(theme.background),
        surface=hex_of(theme.surface),
        panel=hex_of(theme.panel),
        accent=hex_of(theme.primary),
        dark=theme.is_dark,
        variables={
            "block-cursor-foreground": hex_of(theme.primary_text),
            "block-cursor-background": hex_of(theme.primary),
            "am-disabled": hex_of(theme.disabled),
        },
    )


def all_textual_themes() -> list[tuple[str, Theme, TextualTheme]]:
    """(scheme name, theme, Textual theme) for each built-in scheme and the custom one."""
    out = []
    for scheme in scheme_names():
        theme = Theme.from_scheme(scheme)
        out.append((scheme, theme, textual_theme(theme, theme_id(scheme))))
    return out


__all__ = ["CUSTOM_SCHEME_NAME", "all_textual_themes", "hex_of", "rich_style", "textual_theme", "theme_id"]
