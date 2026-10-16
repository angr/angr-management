"""The configuration's frontend adapter for Qt: stored Color and FontSpec values are read as QColor and QFont."""

from __future__ import annotations

from typing import Any

from PySide6.QtGui import QColor, QFont, QFontMetricsF
from PySide6.QtWidgets import QApplication

from angrmanagement.config.color import Color
from angrmanagement.config.font import WEIGHT_NAMES, FontSpec, FontStyle, FontWeight

_QT_WEIGHTS = sorted(WEIGHT_NAMES.values())


class QtConfigAdapter:
    """
    Converts configuration values to and from QColor, QFont, QFont.Weight and QFont.Style.

    It remembers the Qt object last assigned to each entry, and hands that same object back while the entry holds
    the value it was assigned, so code that assigns a QFont or a QColor reads back exactly what it assigned.
    """

    def __init__(self) -> None:
        # entry name -> (neutral value, the Qt object it was converted from)
        self._originals: dict[str, tuple[Any, Any]] = {}

    def to_frontend(self, entry_name: str, value: Any) -> Any:
        original = self._originals.get(entry_name)
        if original is not None and type(original[0]) is type(value) and original[0] == value:
            return original[1]
        if isinstance(value, Color):
            return value.to_qcolor()
        if isinstance(value, FontSpec):
            return value.to_qfont()
        if isinstance(value, FontWeight):
            return QFont.Weight(min(_QT_WEIGHTS, key=lambda weight: abs(weight - value)))
        if isinstance(value, FontStyle):
            return QFont.Style(value.value)
        return value

    def from_frontend(self, entry_name: str, value: Any) -> Any:
        if isinstance(value, QColor):
            neutral: Any = Color.from_qcolor(value)
        elif isinstance(value, QFont):
            neutral = FontSpec.from_qfont(value)
        elif isinstance(value, QFont.Weight):
            neutral = FontWeight(value.value)
        elif isinstance(value, QFont.Style):
            neutral = FontStyle(value.value)
        else:
            return value
        self._originals[entry_name] = (neutral, value)
        return neutral

    def _qfont(self, font: FontSpec) -> QFont:
        for neutral, original in self._originals.values():
            if isinstance(original, QFont) and neutral == font:
                return original
        return font.to_qfont()

    def font_metrics_object(self, font: FontSpec) -> QFontMetricsF:
        return QFontMetricsF(self._qfont(font))

    def font_metrics(self, font: FontSpec) -> tuple[float, float, float]:
        metrics = self.font_metrics_object(font)
        return metrics.height(), metrics.horizontalAdvance("A"), metrics.ascent()

    def default_fonts(self) -> dict[str, FontSpec]:
        defaults = {}
        for entry_name in ("ui_default_font", "tabular_view_font"):
            qfont = QApplication.font("QMenu")
            defaults[entry_name] = self.from_frontend(entry_name, qfont)
        return defaults
