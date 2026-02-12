"""
Goto palette dialog for navigation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from angrmanagement.config import Conf

from .palette import PaletteDialog, PaletteModel

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.ui.workspace import Workspace


class GotoPaletteModel(PaletteModel):
    """
    Data provider for goto palette.
    """

    def get_items(self) -> list[Function]:
        items = []

        instance = self.workspace.main_instance
        if instance and not instance.project.am_none:
            project = instance.project.am_obj
            assert project is not None
            items.extend([func for _, func in project.kb.functions.items()])

        return items

    def get_icon_color_and_text_for_item(self, item: Function) -> tuple[QColor | None, str]:
        if item.is_syscall:
            color = Conf.function_table_syscall_color
        elif item.is_plt:
            color = Conf.function_table_plt_color
        elif item.is_simprocedure:
            color = Conf.function_table_simprocedure_color
        elif item.is_alignment:
            color = Conf.function_table_alignment_color
        else:
            color = QColor(Qt.GlobalColor.gray)
        return (color, "f")

    def get_caption_for_item(self, item: Function) -> str:
        return item.name

    def get_annotation_for_item(self, item: Function) -> str:
        return f"{item.addr:x}"


class GotoPaletteDialog(PaletteDialog):
    """
    Dialog for selecting navigation targets.
    """

    def __init__(self, workspace: Workspace, parent=None) -> None:
        super().__init__(GotoPaletteModel(workspace), parent=parent)
        self.setWindowTitle("Goto Anything")
