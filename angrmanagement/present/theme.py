"""
Colours by name, without a toolkit.

A :class:`Theme` holds the colour entries of one colour scheme (see angrmanagement.config.color_schemes) and answers
:meth:`Theme.style` for a *style key*. A style key is a configuration entry name, such as
``"function_table_plt_color"``, or one of the names in :data:`EXTRA_STYLES`, such as ``"table.error"``; several keys
separated by spaces combine, so ``"function_table_plt_color function_table_signature_bg_color"`` is green text on
cyan. An entry whose name ends in ``_bg_color`` or ``_background_color`` gives the background, any other the
foreground; ``bg:`` before a name makes it the background whatever it is called (``"bg:disasm_view_bookmark_color"``).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from angrmanagement.config.color import Color
from angrmanagement.config.color_schemes import BASE_SCHEME, COLOR_SCHEMES

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .tables import Cell

#: The name of the scheme made of whatever the configuration currently holds.
CUSTOM_SCHEME_NAME = "Custom"

_BACKGROUND_SUFFIXES = ("_bg_color", "_background_color", "_highlight_color", "_select_color")


@dataclass(frozen=True)
class StyleSpec:
    """How to draw text: colours (None means the frontend's default) and attributes."""

    fg: Color | None = None
    bg: Color | None = None
    bold: bool = False
    italic: bool = False
    underline: bool = False

    def merged(self, other: StyleSpec) -> StyleSpec:
        """This style with whatever ``other`` sets laid over it."""
        return StyleSpec(
            fg=other.fg if other.fg is not None else self.fg,
            bg=other.bg if other.bg is not None else self.bg,
            bold=self.bold or other.bold,
            italic=self.italic or other.italic,
            underline=self.underline or other.underline,
        )

    @property
    def is_plain(self) -> bool:
        return self == StyleSpec()


#: Style keys that are not configuration entries. Their colours do not depend on the scheme.
EXTRA_STYLES: dict[str, StyleSpec] = {
    # a register whose value changed in the last step (Qt.GlobalColor.red in the Qt view)
    "table.changed": StyleSpec(fg=Color(0xFF, 0x00, 0x00)),
    # a failed MCP call
    "table.error": StyleSpec(fg=Color(0xC0, 0x00, 0x00)),
    "log.benchmark": StyleSpec(fg=Color(0x80, 0x80, 0x80)),
    "log.warning": StyleSpec(fg=Color(0xC0, 0x80, 0x00)),
    "log.error": StyleSpec(fg=Color(0xC0, 0x00, 0x00), bold=True),
    "job.pending": StyleSpec(fg=Color(0x80, 0x80, 0x80)),
    "job.running": StyleSpec(fg=Color(0x80, 0x80, 0x80), bold=True),
    "job.finished": StyleSpec(fg=Color(0x00, 0x80, 0x00)),
    "job.cancelled": StyleSpec(fg=Color(0xFF, 0x00, 0x00)),
    "bold": StyleSpec(bold=True),
    "italic": StyleSpec(italic=True),
    # disassembly: the colours the Qt items draw with fixed Qt colours
    "disasm.patched": StyleSpec(bg=Color(0x80, 0x80, 0x00)),
    "disasm.phi.variable": StyleSpec(fg=Color(0x00, 0x80, 0x00)),
    "disasm.phi.ident": StyleSpec(fg=Color(0x00, 0x00, 0xFF)),
    "disasm.phi.punctuation": StyleSpec(fg=Color(0x00, 0x00, 0x00)),
    "disasm.data.delimiter": StyleSpec(fg=Color(0x00, 0x00, 0x00)),
    # instruction marks: the colours of the Qt instruction annotations
    "disasm.mark.hook": StyleSpec(fg=Color(50, 50, 50), bg=Color(230, 230, 230)),
    "disasm.mark.find": StyleSpec(fg=Color(30, 80, 30), bg=Color(200, 230, 100)),
    "disasm.mark.avoid": StyleSpec(fg=Color(80, 30, 30), bg=Color(230, 200, 100)),
    "disasm.mark.break": StyleSpec(fg=Color(220, 220, 220), bg=Color(200, 10, 10)),
    "disasm.mark": StyleSpec(fg=Color(0, 60, 0), bg=Color(0xD8, 0xF0, 0xD8)),
    "disasm.find.match": StyleSpec(underline=True),
}

#: The prefix that makes a style key name a background: ``"bg:disasm_view_bookmark_color"``.
BACKGROUND_PREFIX = "bg:"


def scheme_names() -> list[str]:
    """The built-in schemes, sorted, then the custom one: what the Preferences dialog offers."""
    return [*sorted(COLOR_SCHEMES), CUSTOM_SCHEME_NAME]


def scheme_colors(name: str) -> dict[str, Color]:
    """
    The colour entries of the built-in scheme ``name``: the base scheme with the scheme's own colours laid over it.

    :raises KeyError: If there is no such scheme.
    """
    if name not in COLOR_SCHEMES:
        raise KeyError(name)
    if name == BASE_SCHEME:
        return dict(COLOR_SCHEMES[BASE_SCHEME])
    return {**COLOR_SCHEMES[BASE_SCHEME], **COLOR_SCHEMES[name]}


def _is_background_key(key: str) -> bool:
    return key.endswith(_BACKGROUND_SUFFIXES) or key == "disasm_view_background_color"


def luminance(color: Color) -> float:
    """Relative luminance from 0 (black) to 1 (white), by the sRGB weights."""
    return (0.2126 * color.r + 0.7152 * color.g + 0.0722 * color.b) / 255


class Theme:
    """The colours of one scheme, looked up by style key."""

    def __init__(self, name: str, colors: Mapping[str, Color]) -> None:
        self.name = name
        self.colors: dict[str, Color] = dict(colors)

    def __repr__(self) -> str:
        return f"<Theme {self.name}>"

    @classmethod
    def from_scheme(cls, name: str) -> Theme:
        """The built-in scheme ``name``; the custom scheme reads the current configuration."""
        if name == CUSTOM_SCHEME_NAME:
            return cls.from_conf()
        return cls(name, scheme_colors(name))

    @classmethod
    def from_conf(cls, conf: Any = None, name: str = CUSTOM_SCHEME_NAME) -> Theme:
        """The colour entries the configuration holds now, under the name ``name``."""
        if conf is None:
            from angrmanagement.config import Conf  # pylint:disable=import-outside-toplevel

            conf = Conf
        colors = {}
        for key in scheme_colors(BASE_SCHEME):
            try:
                value = conf.entry(key).value
            except KeyError:
                continue
            if isinstance(value, Color):
                colors[key] = value
        return cls(name, colors)

    def color(self, key: str) -> Color | None:
        return self.colors.get(key)

    def style(self, key: str | None) -> StyleSpec:
        """The style of ``key``, which may name several keys separated by spaces; unknown keys add nothing."""
        spec = StyleSpec()
        if not key:
            return spec
        for part in key.split():
            if part.startswith(BACKGROUND_PREFIX):
                background = self._background_of(part[len(BACKGROUND_PREFIX) :])
                if background is not None:
                    spec = replace(spec, bg=background)
                continue
            extra = EXTRA_STYLES.get(part)
            if extra is not None:
                spec = spec.merged(extra)
                continue
            color = self.colors.get(part)
            if color is None:
                continue
            spec = replace(spec, bg=color) if _is_background_key(part) else replace(spec, fg=color)
        return spec

    def _background_of(self, key: str) -> Color | None:
        """
        The colour of ``key`` used as a background: a colour entry's, an extra style's background or colour, or the
        colour ``#rrggbb`` itself (a plugin's colour).
        """
        if key.startswith("#"):
            try:
                return Color.from_hex(key)
            except ValueError:
                return None
        extra = EXTRA_STYLES.get(key)
        if extra is not None:
            return extra.bg if extra.bg is not None else extra.fg
        return self.colors.get(key)

    def style_of(self, cell: Cell) -> StyleSpec:
        """The style of a table cell: its style key's, with the cell's own style on top."""
        spec = self.style(cell.style_key)
        if cell.style is not None:
            spec = spec.merged(cell.style)
        return spec

    #
    # The window palette, for frontends that theme their whole window
    #

    def _palette(self, key: str, fallback: Color) -> Color:
        return self.colors.get(key, fallback)

    @property
    def background(self) -> Color:
        """Where text and tables sit (Qt's Base role)."""
        return self._palette("palette_base", Color(0xFF, 0xFF, 0xFF))

    @property
    def foreground(self) -> Color:
        return self._palette("palette_text", Color(0x00, 0x00, 0x00))

    @property
    def surface(self) -> Color:
        """The window around the views (Qt's Window role)."""
        return self._palette("palette_window", self.background)

    @property
    def panel(self) -> Color:
        """Buttons and headers (Qt's Button role)."""
        return self._palette("palette_button", self.surface)

    @property
    def primary(self) -> Color:
        """The selection colour (Qt's Highlight role)."""
        return self._palette("palette_highlight", Color(0x30, 0x8C, 0xC6))

    @property
    def primary_text(self) -> Color:
        return self._palette("palette_highlightedtext", Color(0xFF, 0xFF, 0xFF))

    @property
    def alternate(self) -> Color:
        return self._palette("palette_alternatebase", self.background)

    @property
    def disabled(self) -> Color:
        return self._palette("palette_disabled_text", Color(0xBE, 0xBE, 0xBE))

    @property
    def link(self) -> Color:
        return self._palette("palette_link", Color(0x00, 0x00, 0xFF))

    @property
    def is_dark(self) -> bool:
        return luminance(self.background) < 0.5
