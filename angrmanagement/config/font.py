"""
Font values that do not depend on Qt.

A :class:`FontSpec` names a font by family, point size, weight and style. Weights use QFont.Weight's numeric scale
(100 to 900), and the configuration file keeps the names and formats it had when these entries held QFont values.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PySide6.QtGui import QFont

#: QFont.Weight's names, as the configuration file spells them, and their values
WEIGHT_NAMES: dict[str, int] = {
    "Thin": 100,
    "ExtraLight": 200,
    "Light": 300,
    "Normal": 400,
    "Medium": 500,
    "DemiBold": 600,
    "Bold": 700,
    "ExtraBold": 800,
    "Black": 900,
}
_WEIGHTS_BY_VALUE = {value: name for name, value in WEIGHT_NAMES.items()}


class FontWeight(int):
    """
    A font weight on QFont.Weight's scale. It is an int; the type marks configuration entries that hold a weight, so
    that they are saved by name (``Medium``) as they were when they held a QFont.Weight.
    """

    @property
    def name(self) -> str:
        """The QFont.Weight name, or the number when the weight is not one of the nine named ones."""
        return _WEIGHTS_BY_VALUE.get(int(self), str(int(self)))

    @classmethod
    def from_name(cls, name: str) -> FontWeight:
        """
        Parse a weight name (``Bold``) or a number (``700``).

        :raises ValueError: If ``name`` is neither.
        """
        if name in WEIGHT_NAMES:
            return cls(WEIGHT_NAMES[name])
        try:
            return cls(int(name))
        except ValueError:
            raise ValueError(f"Unknown font weight: {name!r}") from None

    def __repr__(self) -> str:
        return f"FontWeight({self.name})"


class FontStyle(enum.Enum):
    """The slant of a font, as QFont.Style has it."""

    NORMAL = 0
    ITALIC = 1
    OBLIQUE = 2

    @property
    def qt_name(self) -> str:
        """The QFont.Style name, which is how the configuration file spells a style."""
        return _STYLE_QT_NAMES[self]

    @classmethod
    def from_qt_name(cls, name: str) -> FontStyle:
        """
        Parse a QFont.Style name such as ``StyleItalic``.

        :raises ValueError: If ``name`` is not one.
        """
        try:
            return STYLE_NAMES[name]
        except KeyError:
            raise ValueError(f"Unknown font style: {name!r}") from None


#: QFont.Style's names, as the configuration file spells them, and the styles they stand for
STYLE_NAMES: dict[str, FontStyle] = {
    "StyleNormal": FontStyle.NORMAL,
    "StyleItalic": FontStyle.ITALIC,
    "StyleOblique": FontStyle.OBLIQUE,
}
_STYLE_QT_NAMES = {style: name for name, style in STYLE_NAMES.items()}


@dataclass(frozen=True)
class FontSpec:
    """
    A font: family, size in points, weight and style.

    The default weight is 400 (``Normal``), which is what ``QFont(family, size)`` gives, so a FontSpec and the QFont
    the same entry used to hold save identically.
    """

    family: str
    size: int
    weight: int = 400
    style: FontStyle = FontStyle.NORMAL

    def to_legacy_string(self) -> str:
        """``<size>px||<family>||<weight>``, the format of the configuration file. It does not record the style."""
        return f"{self.size}px||{self.family}||{self.weight}"

    @classmethod
    def from_legacy_string(cls, text: str) -> FontSpec:
        """
        Parse ``<size>[px]||<family>||<weight>``.

        :raises ValueError: If the text is not in that format or the weight is not one of QFont.Weight's values.
        """
        parts = text.split("||")
        if len(parts) != 3:
            raise ValueError(f"A font is written as size||family||weight: {text!r}")
        size_part, family, weight_part = parts
        size_part = size_part.removesuffix("px")
        size = int(size_part)
        weight = int(weight_part)
        if weight not in _WEIGHTS_BY_VALUE:
            raise ValueError(f"Not a font weight: {weight_part!r}")
        return cls(family, size, weight)

    @classmethod
    def from_qfont(cls, qfont: QFont) -> FontSpec:
        weight = qfont.weight()
        style = qfont.style()
        return cls(
            qfont.family(),
            qfont.pointSize(),
            int(getattr(weight, "value", weight)),
            FontStyle(int(getattr(style, "value", style))),
        )

    def to_qfont(self) -> QFont:
        from PySide6.QtGui import QFont  # pylint:disable=import-outside-toplevel

        # QFont.Weight only takes its nine named values; use the nearest for any other weight
        weight = min(_WEIGHTS_BY_VALUE, key=lambda value: abs(value - self.weight))
        qfont = QFont(self.family, self.size, QFont.Weight(weight))
        if self.style is not FontStyle.NORMAL:
            qfont.setStyle(QFont.Style(self.style.value))
        return qfont
