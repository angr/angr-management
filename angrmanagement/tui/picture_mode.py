"""
Picture mode: the graph drawn by Qt, for a tier 3 terminal on a machine where PySide6 happens to be installed.

The rows the terminal draws (the graph's canvas, or the linear page) go into a QGraphicsScene as text items in a
monospaced font, with each run's background as a rectangle, and the scene is rendered offscreen into a QImage with
a QPainter, which becomes a PIL image for the image widget. Nothing needs it: without PySide6 the pictures are the
cell drawings of :mod:`angrmanagement.tui.pictures`.

The scene is built from the terminal's own rows, not from the Qt frontend's QDisassemblyGraph, whose items need the
Qt main window and workspace.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from angrmanagement.config.color import Color
from angrmanagement.tui.pictures import style_color

if TYPE_CHECKING:
    from collections.abc import Sequence

    from PIL.Image import Image  # pyright: ignore[reportMissingImports]

#: The font size of the text, in points.
FONT_SIZE = 10


def qt_available() -> bool:
    """Whether PySide6's widgets import here."""
    try:
        importlib.import_module("PySide6.QtWidgets")
    except ImportError:
        return False
    return True


def _application() -> Any:
    """The process's QApplication; one on the offscreen platform when there is none, so no window opens."""
    from PySide6.QtWidgets import QApplication  # pylint:disable=import-outside-toplevel

    app = QApplication.instance()
    if app is None:
        app = QApplication(["am-tui", "-platform", "offscreen"])
    return app


def qt_picture(strips: Sequence[Any], background: Color) -> Image | None:
    """``strips`` drawn by Qt into a picture; None when PySide6 is not installed or there is nothing to draw."""
    if not strips or not qt_available():
        return None
    # pylint:disable=import-outside-toplevel
    from PIL import Image as PilImage  # pyright: ignore[reportMissingImports]
    from PySide6.QtCore import QRectF, Qt
    from PySide6.QtGui import QBrush, QColor, QFont, QFontDatabase, QFontMetricsF, QImage, QPainter, QPen
    from PySide6.QtWidgets import QGraphicsScene

    _application()
    font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    font.setPointSize(FONT_SIZE)
    font.setStyleHint(QFont.StyleHint.Monospace)
    metrics = QFontMetricsF(font)
    cell_w, cell_h = metrics.horizontalAdvance("M"), metrics.height()

    def qcolor(color: Color) -> QColor:
        return QColor(color.r, color.g, color.b)

    scene = QGraphicsScene()
    width = max(strip.cell_length for strip in strips)
    scene.setSceneRect(QRectF(0, 0, width * cell_w, len(strips) * cell_h))
    no_pen = QPen(Qt.PenStyle.NoPen)
    for row, strip in enumerate(strips):
        x = 0
        for segment in strip:
            text, style = segment.text, segment.style
            length = len(text)
            bg = style_color(style, False, background)
            if bg != background:
                scene.addRect(QRectF(x * cell_w, row * cell_h, length * cell_w, cell_h), no_pen, QBrush(qcolor(bg)))
            if text.strip():
                item = scene.addSimpleText(text, font)
                item.setBrush(QBrush(qcolor(style_color(style, True, _foreground(background)))))
                item.setPos(x * cell_w, row * cell_h)
            x += length
    size = scene.sceneRect().size().toSize()
    image = QImage(size, QImage.Format.Format_ARGB32)
    image.fill(qcolor(background))
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    scene.render(painter)
    painter.end()
    data = bytes(image.constBits())
    return PilImage.frombuffer("RGBA", (image.width(), image.height()), data, "raw", "BGRA", image.bytesPerLine(), 1)


def _foreground(background: Color) -> Color:
    """Text with no colour of its own: light on a dark background, dark on a light one."""
    light = (background.r * 299 + background.g * 587 + background.b * 114) / 1000 > 128
    return Color(0x20, 0x20, 0x20) if light else Color(0xD0, 0xD0, 0xD0)


__all__ = ["qt_available", "qt_picture"]
