from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QComboBox

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class QStateComboBox(QComboBox):
    def __init__(self, instance: Instance, allow_none: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.states = instance.states
        self.allow_none = allow_none
        self._init_items()

    def _init_items(self):
        if self.allow_none:
            self.addItem("<None>", None)
        elif not self.states:
            raise ValueError("Created QStateComboBox with allow_none=False and no states available")
        for state in self.states:
            self.addItem(state.gui_data.name, state)

    @property
    def state(self):
        idx = self.currentIndex()
        if idx == -1:
            return None

        return self.itemData(idx)
