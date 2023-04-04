import re

import angr
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QMenu, QTableWidget, QTableWidgetItem

from angrmanagement.ui.dialogs.new_state import NewState
from angrmanagement.utils.namegen import NameGenerator


class QStateTableItem(QTableWidgetItem):
    """
    An entry within a QStateTable
    """

    def __init__(self, state, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.state = state

    def widgets(self):
        state = self.state

        name = state.gui_data.name
        base_name = state.gui_data.base_name
        is_changed = "No" if state.gui_data.is_original else "Yes"
        mode = state.mode
        address = "%x" % state.addr if isinstance(state.addr, int) else "Symbolic"
        state_options = {o for o, v in state.options._options.items() if v is True}
        options_plus = state_options - angr.sim_options.modes[mode]
        options_minus = angr.sim_options.modes[mode] - state_options
        options = " ".join([" ".join("+" + o for o in options_plus), " ".join("-" + o for o in options_minus)])

        widgets = [
            QTableWidgetItem(name),
            QTableWidgetItem(address),
            QTableWidgetItem(is_changed),
            QTableWidgetItem(base_name),
            QTableWidgetItem(mode),
            QTableWidgetItem(options),
        ]

        if state.gui_data.is_base:
            color = QColor(0, 0, 0x80)
        elif state.gui_data.is_original:
            color = QColor(0, 0x80, 0)
        else:
            color = QColor(0, 0, 0)

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)
            w.setForeground(color)

        return widgets


class QStateTable(QTableWidget):
    """
    The table which is the subject of the States View
    """

    def __init__(self, workspace, instance, parent, selection_callback=None):
        super().__init__(parent)

        self._selected = selection_callback

        header_labels = ["Name", "Address", "Changed?", "Base State", "Mode", "Options"]

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

        self.items = []
        self.workspace = workspace
        self.instance = instance
        self.states = instance.states

        self.itemDoubleClicked.connect(self._on_state_selected)
        self.cellDoubleClicked.connect(self._on_state_selected)
        self.states.am_subscribe(self._watch_states)
        self.reload()

    def closeEvent(self, _):
        self.states.am_unsubscribe(self._watch_states)

    def current_state_record(self):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.items):
            return self.items[selected_index]
        else:
            return None

    def reload(self):
        # current_row = self.currentRow()
        self.clearContents()

        self.items = [QStateTableItem(f) for f in self.states]
        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        # if 0 <= current_row < len(self.items):
        #    self.setCurrentItem(current_row, 0)

    def _on_state_selected(self, *args):  # pylint: disable=unused-argument
        if self._selected is not None:
            self._selected(self.current_state_record())

    def contextMenuEvent(self, event):
        sr = self.current_state_record()

        menu = QMenu("", self)

        menu.addAction("New state...", self._action_new_state)
        menu.addSeparator()

        a = menu.addAction("Duplicate state", self._action_duplicate)
        if sr is None:
            a.setDisabled(True)

        a = menu.addAction("Delete state", self._action_delete)
        if sr is None:
            a.setDisabled(True)

        a = menu.addAction("New simulation manager", self._action_new_simulation_manager)
        if sr is None:
            a.setDisabled(True)

        menu.exec_(event.globalPos())

    def _action_new_state(self):
        dialog = NewState(self.workspace, self.instance, parent=self)
        dialog.exec_()

    def _action_duplicate(self):
        state = self.states[self.currentRow()]
        copy = state.copy()
        copy.gui_data.name = self._get_copied_state_name(copy.gui_data.name)
        self.states.append(copy)
        self.states.am_event(src="duplicate", state=copy)

    def _action_delete(self):
        tmp = self.states.pop(self.currentRow())
        self.states.am_event(src="delete", state=tmp)

    def _action_new_simulation_manager(self):
        state = self.states[self.currentRow()]
        simgr_name = NameGenerator.random_name()
        self.workspace.create_simulation_manager(state, simgr_name)

    def _watch_states(self, **kwargs):  # pylint: disable=unused-argument
        self.reload()

    def _get_copied_state_name(self, current_name):
        """
        Get a non-duplicating name for the copied state.

        :param str current_name:    The current name of the state.
        :return:                    A new name of the copied state.
        :rtype:                     str
        """

        m = re.match(r"^([\s\S]*) copy\s*(\d*)$", current_name)

        if m:
            # ends with copy
            ctr_str = m.group(2)
            ctr = int(ctr_str) + 1 if ctr_str else 1

            current_name = m.group(1)
            name = current_name + " copy %d" % ctr
        else:
            ctr = 0
            name = current_name + " copy"

        # Increment the counter until there is no conflict with existing names
        all_names = {s.gui_data.name for s in self.states}
        while name in all_names:
            ctr += 1
            name = current_name + " copy %d" % ctr
        return name
