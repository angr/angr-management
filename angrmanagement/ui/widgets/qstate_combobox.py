from PySide2.QtWidgets import QComboBox


class QStateComboBox(QComboBox):
    def __init__(self, instance, allow_none=True, parent=None):
        super(QStateComboBox, self).__init__(parent)
        self.states = instance.states
        self.allow_none = allow_none
        self._init_items()

    def _init_items(self):
        if self.allow_none:
            self.addItem('<None>', None)
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
