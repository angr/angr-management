from __future__ import annotations

from typing import TYPE_CHECKING

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class AnalyzeMenu(Menu):
    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&Analyze", parent=main_window)
        self.entries.extend(
            [
                MenuEntry(
                    "&Run Analysis...",
                    main_window.run_analysis,
                    shortcut="F4",
                    icon="run-analysis",
                ),
                MenuSeparator(),
                MenuEntry(
                    "&Decompile",
                    main_window.decompile_current_function,
                    shortcut="F5",
                    icon="pseudocode-view",
                ),
                MenuEntry(
                    "View in Proximity &Browser",
                    main_window.view_proximity_for_current_function,
                    shortcut="Ctrl+B",
                ),
                MenuEntry(
                    "Discover &Patterns...",
                    main_window.discover_patterns,
                    icon="pattern-view",
                ),
            ],
        )
