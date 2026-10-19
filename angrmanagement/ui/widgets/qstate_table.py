from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QMenu, QTableWidget, QTableWidgetItem

from angrmanagement.present.symexec import copied_state_name, state_row
from angrmanagement.ui.dialogs.new_state import NewState
from angrmanagement.utils.namegen import NameGenerator

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QStateTableItem(QTableWidgetItem):
    """
    An entry within a QStateTable
    """

    def __init__(self, state) -> None:
        super().__init__()

        self.state = state

    def widgets(self):
        state = self.state

        widgets = [QTableWidgetItem(text) for text in state_row(state)]

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

    def __init__(self, workspace: Workspace, instance: Instance, parent, selection_callback=None) -> None:
        super().__init__(parent)

        self._selected = selection_callback

        header_labels = ["Name", "Address", "Changed?", "Base State", "Mode", "Options"]

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        self.items = []
        self.workspace = workspace
        self.instance = instance
        self.states = instance.states

        self.itemDoubleClicked.connect(self._on_state_selected)
        self.cellDoubleClicked.connect(self._on_state_selected)
        self.states.am_subscribe(self._watch_states)
        self.reload()

    def closeEvent(self, _) -> None:
        self.states.am_unsubscribe(self._watch_states)

    def current_state_record(self):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.items):
            return self.items[selected_index]
        else:
            return None

    def reload(self) -> None:
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

    def _on_state_selected(self, *args) -> None:  # pylint: disable=unused-argument
        if self._selected is not None:
            self._selected(self.current_state_record())

    def contextMenuEvent(self, event) -> None:
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

    def _action_new_state(self) -> None:
        dialog = NewState(self.workspace, self.instance, parent=self)
        dialog.exec_()

    def _action_duplicate(self) -> None:
        state = self.states[self.currentRow()]
        copy = state.copy()
        copy.gui_data.name = self._get_copied_state_name(copy.gui_data.name)
        self.states.append(copy)
        self.states.am_event(src="duplicate", state=copy)

    def _action_delete(self) -> None:
        tmp = self.states.pop(self.currentRow())
        self.states.am_event(src="delete", state=tmp)

    def _action_new_simulation_manager(self) -> None:
        state = self.states[self.currentRow()]
        simgr_name = NameGenerator.random_name()
        self.workspace.create_simulation_manager(state, simgr_name)

    def _watch_states(self, **_) -> None:
        self.reload()

    def _get_copied_state_name(self, current_name: str):
        """
        Get a non-duplicating name for the copied state.

        :param str current_name:    The current name of the state.
        :return:                    A new name of the copied state.
        :rtype:                     str
        """

        return copied_state_name(current_name, (s.gui_data.name for s in self.states))
