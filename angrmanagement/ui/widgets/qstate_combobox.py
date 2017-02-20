
from PySide.QtGui import QComboBox


class QStateComboBox(QComboBox):
    def __init__(self, state_manager, parent=None):
        super(QStateComboBox, self).__init__(parent)

        self._state_manager = state_manager

        self._init_items()

    def _init_items(self):
        for state_record in self._state_manager.values():
            self.addItem(state_record.name, state_record)

    @property
    def state_record(self):
        idx = self.currentIndex()
        if idx == -1:
            return None

        return self.itemData(idx)
