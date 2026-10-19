from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QLineEdit

from angrmanagement.present.dialogs import address_of_text

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.instance import Instance


class QAddressInput(QLineEdit):
    """A line edit for an address: a hexadecimal number or a function name."""

    def __init__(
        self, textchanged_callback: Callable | None, instance: Instance, parent=None, default: str | None = None
    ) -> None:
        super().__init__(parent)

        self.instance = instance

        if default is not None:
            self.setText(str(default))

        if textchanged_callback is not None:
            self.textChanged.connect(textchanged_callback)

    @property
    def target(self):
        text = self.text()
        if self._is_valid_addr_or_label(text):
            return self._convert_to_addr(text)
        return None

    def _is_valid_addr_or_label(self, text) -> bool:
        r = self._convert_to_addr(text)
        return r is not None

    def _convert_to_addr(self, input_):
        # a hexadecimal number or a function name, as the terminal's address boxes take them
        return address_of_text(self.instance, input_)
