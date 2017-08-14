
from PySide.QtGui import QTableWidget, QTableWidgetItem, QColor, QAbstractItemView
from PySide.QtCore import Qt


class QStateTableItem(QTableWidgetItem):
    def __init__(self, state_record, *args, **kwargs):
        super(QStateTableItem, self).__init__(*args, **kwargs)

        self._state_record = state_record

    def widgets(self):
        """

        :param angr.knowledge_plugins.Function function: The Function object.
        :return: a list of QTableWidgetItem objects
        :rtype: list
        """

        state_record = self._state_record

        name = state_record.name
        is_default = 'Yes' if state_record.is_default else 'No'
        base_state = '' if state_record.is_default else state_record.base_state.name
        mode = state_record.mode
        address = '%#x' % state_record.address if isinstance(state_record.address, (int, long)) else 'Unspecified'
        options = str(state_record.custom_options)
        custom_code = 'Yes' if state_record.custom_code else 'No'

        widgets = [
            QTableWidgetItem(name),
            QTableWidgetItem(is_default),
            QTableWidgetItem(base_state),
            QTableWidgetItem(mode),
            QTableWidgetItem(address),
            QTableWidgetItem(options),
            QTableWidgetItem(custom_code),
        ]

        color = QColor(0, 0, 0)
        if state_record.is_default:
            color = QColor(0, 0, 0x80)

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)
            w.setForeground(color)

        return widgets


class QStateTable(QTableWidget):
    def __init__(self, parent, selection_callback=None):
        super(QStateTable, self).__init__(parent)

        self._selected = selection_callback

        header_labels = [ 'Name', 'Default?', 'Base State', 'Mode', 'Initial Address', 'Options', 'Custom Code' ]

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

        self._state_manager = None
        self.items = [ ]

        self.itemDoubleClicked.connect(self._on_state_selected)
        self.cellDoubleClicked.connect(self._on_state_selected)

    @property
    def state_manager(self):
        return self._state_manager

    @state_manager.setter
    def state_manager(self, state_manager):
        self._state_manager = state_manager
        self._state_manager.register_view(self)
        self.reload()

    def reload(self):

        current_row = self.currentRow()

        self.clearContents()

        if self._state_manager is None:
            return

        self.items = [QStateTableItem(f) for f in self._state_manager.values()]

        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        if 0 <= current_row < len(self.items):
            self.setCurrentItem(current_row, 0)

    def _on_state_selected(self, *args):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.items):
            selected_item = self.items[selected_index]
        else:
            selected_item = None

        if self._selected is not None:
            self._selected(selected_item)
