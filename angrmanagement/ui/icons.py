from __future__ import annotations

from typing import TYPE_CHECKING

import qtawesome

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
    "functions-view": "mdi.function",
    "hex-view": "mdi.hexadecimal",
    "jobs-view": "fa5s.hammer",
    "log-view": "mdi.message-bulleted",
    "patches-view": "mdi.sticker-outline",
    "plugins": "mdi.puzzle-edit",
    "preferences": "fa.gear",
    "pseudocode-view": "msc.json",
    "run-analysis": "mdi.arrow-right-drop-circle",
    "strings-view": "msc.symbol-string",
    "traces-view": "mdi.go-kart-track",
    "types-view": "msc.symbol-class",
}


def icon(key, *args, **kwargs) -> QIcon | None:
    qta_name = NAME_TO_QTAWESOME_NAME.get(key)
    return qtawesome.icon(qta_name, *args, **kwargs) if qta_name else None
