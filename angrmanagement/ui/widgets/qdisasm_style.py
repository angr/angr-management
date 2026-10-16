"""The Qt colours of the style keys in angrmanagement.present.disasm_style."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt

from angrmanagement.config import Conf
from angrmanagement.config.color import Color
from angrmanagement.present.disasm_style import PATCHED_STYLE

#: Extra style keys and the fixed Qt colours they stand for.
_FIXED_COLORS = {PATCHED_STYLE: Qt.GlobalColor.darkYellow}


def qt_background(background: Any) -> Any:
    """
    The QColor (or Qt global colour) of a background decision: a style key is looked up in the configuration, a
    neutral Color is converted, and anything else (a QColor a plugin returned) is passed through. None stays None.
    """
    if background is None:
        return None
    if isinstance(background, str):
        fixed = _FIXED_COLORS.get(background)
        if fixed is not None:
            return fixed
        # a string that names no entry came from a plugin; Qt reads it as a colour name, as it always has
        entry = getattr(Conf, background, None)
        return entry if entry is not None else background
    if isinstance(background, Color):
        return background.to_qcolor()
    return background


__all__ = ["qt_background"]
