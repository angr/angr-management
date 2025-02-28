from __future__ import annotations

from typing import TYPE_CHECKING

import qtawesome as qta
from PySide6.QtGui import QColor, QPalette

if TYPE_CHECKING:
    from PySide6.QtGui import QIcon


NAME_TO_QTAWESOME_NAME = {
    "about": "fa5s.info-circle",
    "command-palette": "ph.squares-four-light",
    "console-view": "mdi.console-line",
    "disassembly-graph": "fa5s.sitemap",
    "disassembly-linear": "msc.list-selection",
    "disassembly-view": "msc.symbol-constant",
    "docs": "mdi6.book-open-page-variant",
    "file": "mdi.file",
    "file-open": "mdi.folder-open",
    "file-save": "mdi.floppy",
    "functions-view": "mdi.function",
    "hex-view": "mdi.hexadecimal",
    "jobs-view": "fa5s.hammer",
    "log-view": "mdi.message-bulleted",
    "patches-view": "mdi.sticker-outline",
    "plugins": "mdi.puzzle-edit",
    "preferences": "fa6s.gear",
    "pseudocode-view": "msc.json",
    "run-analysis": "mdi.arrow-right-drop-circle",
    "search": "fa5s.search",
    "strings-view": "msc.symbol-string",
    "traces-view": "mdi.go-kart-track",
    "types-view": "msc.symbol-class",
}


# XXX: QtAwesome icons won't update color on palette changes, but we can
# update the QColor objects they are initialized with and that color will be
# used in new paint events.

ICON_COLOR_ROLES = {
    QPalette.ColorGroup.Active: {
        QPalette.ColorRole.PlaceholderText: QColor(),
        QPalette.ColorRole.Text: QColor(),
    },
    QPalette.ColorGroup.Disabled: {
        QPalette.ColorRole.Text: QColor(),
    },
}


ICON_COLORS = {
    "color": ICON_COLOR_ROLES[QPalette.ColorGroup.Active][QPalette.ColorRole.Text],
    "color_disabled": ICON_COLOR_ROLES[QPalette.ColorGroup.Disabled][QPalette.ColorRole.Text],
}


def icon(key, *args, **kwargs) -> QIcon | None:
    qta_name = NAME_TO_QTAWESOME_NAME.get(key)
    if "color_role" in kwargs:
        kwargs["color"] = ICON_COLOR_ROLES[QPalette.ColorGroup.Active][kwargs["color_role"]]
    return qta.icon(qta_name, *args, **kwargs) if qta_name else None


def transfer_color(dst: QColor, src: QColor) -> None:
    dst.setRgba(src.rgba())


def update_icon_colors(palette: QPalette) -> None:
    for group, roles in ICON_COLOR_ROLES.items():
        for role, dst in roles.items():
            src = palette.color(group, role)
            transfer_color(dst, src)


qta.set_global_defaults(**ICON_COLORS)
