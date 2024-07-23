from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from PySide6.QtWidgets import QGridLayout, QWidget


def add_to_grid(lyt: QGridLayout, cols: int, widgets: Iterable[QWidget]) -> None:
    """
    Adds widgets to a grid layout given a desired column count.
    """
    r = lyt.rowCount()
    c = 0
    for item in widgets:
        lyt.addWidget(item, r, c)
        c += 1
        if c >= cols:
            c = 0
            r += 1
