from PySide2.QtWidgets import QComboBox


class QStateComboBox(QComboBox):
    def __init__(self, states, parent=None):
        super(QStateComboBox, self).__init__(parent)
        self.states = states
        self._init_items()

    def _init_items(self):
        for state_record in self.states:
            self.addItem(state_record.name, state_record)

    @property
    def state_record(self):
        idx = self.currentIndex()
        if idx == -1:
            return None

        return self.itemData(idx)
