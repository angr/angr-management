"""
A colour value that does not depend on Qt.

Configuration entries hold :class:`Color` values; a frontend converts them to its own colour type. The methods named
like QColor's (``red()``, ``name()``, ``lighter()`` and so on) behave like QColor's, so code written against QColor
keeps working on a Color.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from PySide6.QtGui import QColor

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_USHRT_MAX = 0xFFFF


def _f32(value: float) -> float:
    """Round a double to the nearest single-precision float; QColor's HSV conversion computes in floats."""
    return struct.unpack("f", struct.pack("f", value))[0]


def _qround(value: float) -> int:
    return int(_f32(value + 0.5)) if value >= 0.0 else int(_f32(value - 0.5))


def _fuzzy_compare(p1: float, p2: float) -> bool:
    return _f32(abs(_f32(p1 - p2)) * 100000.0) <= min(abs(p1), abs(p2))


def _to_8bit(value: int) -> int:
    """The 8-bit channel QColor reports for a 16-bit one: value / 257, rounded."""
    return (value + 128) // 257


def _to_hsv16(r16: int, g16: int, b16: int) -> tuple[int, int, int]:
    """QColor::toHsv() on 16-bit channels: returns (hue * 100 or USHRT_MAX, saturation, value), all 16-bit."""
    r = _f32(r16 / _USHRT_MAX)
    g = _f32(g16 / _USHRT_MAX)
    b = _f32(b16 / _USHRT_MAX)
    max_ = max(r, g, b)
    min_ = min(r, g, b)
    delta = _f32(max_ - min_)
    value = _qround(_f32(max_ * _USHRT_MAX))
    if abs(delta) <= 0.00001:
        return _USHRT_MAX, 0, value
    saturation = _qround(_f32(_f32(delta / max_) * _USHRT_MAX))
    if _fuzzy_compare(r, max_):
        hue = _f32(_f32(g - b) / delta)
    elif _fuzzy_compare(g, max_):
        hue = _f32(2.0 + _f32(_f32(b - r) / delta))
    else:
        hue = _f32(4.0 + _f32(_f32(r - g) / delta))
    hue = _f32(hue * 60.0)
    if hue < 0.0:
        hue = _f32(hue + 360.0)
    return _qround(_f32(hue * 100.0)), saturation, value


def _from_hsv16(hue16: int, sat16: int, val16: int) -> tuple[int, int, int]:
    """QColor::toRgb() from 16-bit HSV channels: returns 16-bit (red, green, blue)."""
    if sat16 == 0 or hue16 == _USHRT_MAX:
        return val16, val16, val16
    h = 0.0 if hue16 == 36000 else _f32(hue16 / 6000.0)
    s = _f32(sat16 / _USHRT_MAX)
    v = _f32(val16 / _USHRT_MAX)
    i = int(h)
    f = _f32(h - i)
    p = _f32(v * _f32(1.0 - s))
    if i & 1:
        q = _f32(v * _f32(1.0 - _f32(s * f)))
        r, g, b = {1: (q, v, p), 3: (p, q, v), 5: (v, p, q)}[i]
    else:
        t = _f32(v * _f32(1.0 - _f32(s * _f32(1.0 - f))))
        r, g, b = {0: (v, t, p), 2: (p, v, t), 4: (t, p, v)}[i]
    return (
        _qround(_f32(r * _USHRT_MAX)),
        _qround(_f32(g * _USHRT_MAX)),
        _qround(_f32(b * _USHRT_MAX)),
    )


@dataclass(frozen=True, eq=False)
class Color:
    """An RGBA colour with 8-bit channels. ``Color(r, g, b)`` is opaque."""

    r: int
    g: int
    b: int
    a: int = 255

    def __post_init__(self) -> None:
        for channel in (self.r, self.g, self.b, self.a):
            if not isinstance(channel, int) or not 0 <= channel <= 255:
                raise ValueError(f"Colour channels are integers from 0 to 255, not {(self.r, self.g, self.b, self.a)}")

    #
    # Construction
    #

    @classmethod
    def from_hex(cls, text: str) -> Color:
        """
        Parse ``RGB``, ``RRGGBB``, ``AARRGGBB`` or ``RRRRGGGGBBBB``, with or without a leading ``#``.

        The 12-digit form has 16-bit channels; each is reduced to 8 bits by dividing by 257 and rounding, as QColor
        does.

        :raises ValueError: If the text is not one of those forms.
        """
        digits = text[1:] if text.startswith("#") else text
        if not _HEX_RE.fullmatch(digits):
            raise ValueError(f"Not a hexadecimal colour: {text!r}")
        if len(digits) == 3:
            r, g, b = (int(d, 16) * 0x11 for d in digits)
            return cls(r, g, b)
        if len(digits) == 6:
            return cls(int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16))
        if len(digits) == 8:
            return cls(int(digits[2:4], 16), int(digits[4:6], 16), int(digits[6:8], 16), int(digits[0:2], 16))
        if len(digits) == 12:
            return cls(*(_to_8bit(int(digits[i : i + 4], 16)) for i in (0, 4, 8)))
        raise ValueError(f"A hexadecimal colour has 3, 6, 8 or 12 digits: {text!r}")

    @classmethod
    def from_qcolor(cls, qcolor: QColor) -> Color:
        return cls(qcolor.red(), qcolor.green(), qcolor.blue(), qcolor.alpha())

    def to_qcolor(self) -> QColor:
        from PySide6.QtGui import QColor  # pylint:disable=import-outside-toplevel

        return QColor(self.r, self.g, self.b, self.a)

    #
    # Formats
    #

    @property
    def hex(self) -> str:
        """``AARRGGBB``, the format of the configuration file."""
        return f"{self.a:02x}{self.r:02x}{self.g:02x}{self.b:02x}"

    @property
    def rgb_hex(self) -> str:
        """``RRGGBB``."""
        return f"{self.r:02x}{self.g:02x}{self.b:02x}"

    #
    # QColor-compatible methods
    #

    def red(self) -> int:
        return self.r

    def green(self) -> int:
        return self.g

    def blue(self) -> int:
        return self.b

    def alpha(self) -> int:
        return self.a

    def getRgb(self) -> tuple[int, int, int, int]:  # pylint:disable=invalid-name
        return self.r, self.g, self.b, self.a

    def name(self) -> str:
        """``#rrggbb``, as QColor.name() returns it."""
        return "#" + self.rgb_hex

    def isValid(self) -> bool:  # pylint:disable=invalid-name
        return True

    def lighter(self, factor: int = 150) -> Color:
        """
        A lighter colour: QColor.lighter()'s algorithm, which multiplies the HSV value by ``factor`` / 100.

        The result agrees with QColor's to within one unit per channel; QColor rounds a few conversions differently.
        """
        if factor <= 0:
            return self
        if factor < 100:
            return self.darker(10000 // factor)
        hue, sat, val = _to_hsv16(self.r * 0x101, self.g * 0x101, self.b * 0x101)
        val = (factor * val) // 100
        if val > _USHRT_MAX:
            # overflow: take it out of the saturation
            sat = max(sat - (val - _USHRT_MAX), 0)
            val = _USHRT_MAX
        return self._from_hsv(hue, sat, val)

    def darker(self, factor: int = 200) -> Color:
        """
        A darker colour: QColor.darker()'s algorithm, which divides the HSV value by ``factor`` / 100.

        The result agrees with QColor's to within one unit per channel.
        """
        if factor <= 0:
            return self
        if factor < 100:
            return self.lighter(10000 // factor)
        hue, sat, val = _to_hsv16(self.r * 0x101, self.g * 0x101, self.b * 0x101)
        val = (val * 100) // factor
        return self._from_hsv(hue, sat, val)

    def _from_hsv(self, hue: int, sat: int, val: int) -> Color:
        r16, g16, b16 = _from_hsv16(hue, sat, val)
        return Color(_to_8bit(r16), _to_8bit(g16), _to_8bit(b16), self.a)

    #
    # Comparison
    #

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Color):
            return self.getRgb() == other.getRgb()
        if type(other).__name__ == "QColor":
            # compare a QColor by its 8-bit channels, so values cached by old Qt code still compare equal. Only
            # ``color == qcolor`` gets here: QColor's own __eq__ answers False for anything that is not a QColor.
            return self.getRgb() == (other.red(), other.green(), other.blue(), other.alpha())
        return NotImplemented

    def __ne__(self, other: Any) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self) -> int:
        return hash(self.getRgb())

    def __repr__(self) -> str:
        return f"Color(0x{self.r:02X}, 0x{self.g:02X}, 0x{self.b:02X}, 0x{self.a:02X})"
