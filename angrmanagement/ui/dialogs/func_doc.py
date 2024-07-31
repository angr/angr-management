from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import Qt
from PySide6.QtWidgets import QDialog, QGridLayout, QLabel, QTextEdit, QVBoxLayout

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class FuncDocDialog(QDialog):
    """
    Implements the FuncDoc dialog.
    """

    def __init__(
        self, instance: Instance, addr: int | None = None, name: str = "", doc_tuple=None, parent=None
    ) -> None:
        super().__init__(parent)

        # initialization
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        self.instance = instance
        self._addr = addr
        self._name = name
        self._doc = doc_tuple[0].strip()
        self._url = doc_tuple[1].strip()
        self._ftype = doc_tuple[2].strip()
        self.setWindowTitle("Function Documentation")
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

    def _init_widgets(self) -> None:
        layout = QGridLayout()

        # validation_failures = set()
        addr = hex(self._addr)
        address_label = QLabel(self)
        address_label.setText(f"Function at address {addr}: {self._name}")

        layout.addWidget(address_label)

        type_label = QLabel(self)
        type_label.setText(f"Type: {self._ftype}")

        layout.addWidget(type_label)

        text_edit = QTextEdit(self)
        text_edit.setMinimumWidth(800)
        text_edit.setMinimumHeight(450)
        text_edit.setFont(Conf.disasm_font)
        text_edit.setText(self._doc)

        url_label = QLabel(self)
        hyperlink = f'<a href="{self._url}">{self._url}</a>'
        url_label.setText(hyperlink)
        url_label.setOpenExternalLinks(True)

        layout.addWidget(text_edit)
        layout.addWidget(url_label)

        self.main_layout.addLayout(layout)
