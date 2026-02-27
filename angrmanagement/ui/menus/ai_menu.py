from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import QKeySequence

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class AIMenu(Menu):
    """
    THe menu for AI-assisted features.
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("A&I", parent=main_window)
        self.entries.extend(
            [
                MenuEntry(
                    "Refine &All",
                    main_window.llm_refine_all,
                    shortcut=QKeySequence("Ctrl+I"),
                ),
                MenuSeparator(),
                MenuEntry(
                    "Suggest &Variable Names",
                    main_window.llm_suggest_variable_names,
                ),
                MenuEntry(
                    "Suggest &Function Name",
                    main_window.llm_suggest_function_name,
                ),
                MenuEntry(
                    "Suggest Variable &Types",
                    main_window.llm_suggest_variable_types,
                ),
            ],
        )
