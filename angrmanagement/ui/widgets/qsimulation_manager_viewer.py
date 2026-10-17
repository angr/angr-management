from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QContextMenuEvent, QCursor
from PySide6.QtWidgets import QAbstractItemView, QInputDialog, QMenu, QMessageBox, QTreeWidget, QTreeWidgetItem

from angrmanagement.present.symexec import create_stash, drop_states, move_states, paste_states, stash_states

if TYPE_CHECKING:
    from angr import SimState


class SimgrViewerAbstractTreeItem(QTreeWidgetItem):
    """A row of the stash tree."""

    def handle_context_menu_event(self, event: QContextMenuEvent):
        """Handles right-click actions on the specific QTreeWidgetItem that was clicked in the view"""
        raise NotImplementedError


class StashTreeItem(SimgrViewerAbstractTreeItem):
    """A stash and, under it, its states."""

    def __init__(self, stash_name: str, simgr_viewer) -> None:
        self.simgr_viewer = simgr_viewer
        self.stash_name = stash_name
        super().__init__(simgr_viewer)
        self.setFlags(self.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        self.refresh()

    def __iter__(self):
        for i in range(self.childCount()):
            yield self.child(i)

    @property
    def states(self):
        return self.simgr_viewer.simgr.stashes[self.stash_name]

    def refresh(self) -> None:
        self.takeChildren()
        for state in stash_states(self.simgr_viewer.simgr, self.stash_name):
            self.addChild(StateTreeItem(state, self.simgr_viewer))
        self.setText(0, f"{self.stash_name} ({len(self.states)})")

    def handle_context_menu_event(self, event) -> None:
        menu = QMenu()
        menu.addAction("Copy states", self.copy_states)
        menu.addAction("Cut states", self.cut_states)
        if self.simgr_viewer.state_clipboard:
            plural = ""
            if len(self.simgr_viewer.state_clipboard) > 1:
                plural += "s"
            menu.addAction("Paste state" + plural, self.paste_states)
        menu.addAction("Delete stash", self.delete_stash)
        if self.stash_name != "active":
            menu.addAction("Move states to here", self.move_states)
        menu.exec_(QCursor.pos())

    def copy_states(self) -> None:
        self.simgr_viewer.state_clipboard = [s.state for s in self]
        self.refresh()

    def cut_states(self) -> None:
        self.simgr_viewer.state_clipboard = [s.state for s in self]
        drop_states(self.simgr_viewer.simgr, self.stash_name, list(self.states))
        self.refresh()

    def delete_stash(self, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        self.simgr_viewer.simgr._stashes.pop(self.stash_name)
        self.simgr_viewer.refresh()

    def paste_states(self, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        self.simgr_viewer.paste_from_clipboard(self.stash_name)
        self.refresh()

    def move_states(self, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        self.simgr_viewer.move_to_stash(self.stash_name)
        self.refresh()


class StateTreeItem(SimgrViewerAbstractTreeItem):
    """A state of a stash."""

    def __init__(self, state, simgr_viewer) -> None:
        self.state = state
        self.simgr_viewer: QSimulationManagerViewer = simgr_viewer
        super().__init__([str(state)])
        self.setData(0, 1, state)

    @property
    def stash_name(self):
        return self.parent().stash_name

    def handle_context_menu_event(self, event) -> None:
        menu = QMenu()
        self.add_menu_action(menu, "Copy state", self.copy_states)
        self.add_menu_action(menu, "Cut state", self.cut_states)
        self.add_menu_action(menu, "Delete state", self.delete_states)
        if self.simgr_viewer.state_clipboard:
            self.add_menu_action(menu, "Paste state", self.paste_states)
        menu.exec_(QCursor.pos())

    def add_menu_action(self, menu, string: str, action) -> None:
        plural = ""
        if len(self.simgr_viewer.selectedItems()) > 1:
            plural = "s"
        menu.addAction(string + plural, action)

    def copy_states(self, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        self.simgr_viewer.copy_selected_to_clipboard()

    def cut_states(self, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        self.simgr_viewer.cut_selected_to_clipboard()

    def delete_states(self, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        self.simgr_viewer.delete_selected_states()

    def paste_states(self, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        self.simgr_viewer.paste_from_clipboard(self.stash_name)


class QSimulationManagerViewer(QTreeWidget):
    """The stash tree of a simulation manager, with a clipboard of states."""

    state_clipboard: list[SimState]

    def __init__(self, simgr, parent=None) -> None:
        super().__init__(parent)

        self.setColumnCount(1)
        self.setHeaderHidden(True)

        self.simgr = simgr
        self.state_clipboard = []

        self._init_widgets()

        self.simgr.am_subscribe(self.refresh)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)

    def _stash_to_selected_states(self):
        stash_to_states = defaultdict(list)
        for state_tree_item in self.selectedItems():
            stash_to_states[state_tree_item.stash_name].append(state_tree_item.state)
        return stash_to_states

    def copy_selected_to_clipboard(self) -> None:
        self.state_clipboard = [item.state.copy() for item in self.selectedItems()]

    def cut_selected_to_clipboard(self) -> None:
        self.copy_selected_to_clipboard()
        self.delete_selected_states()

    def delete_selected_states(self) -> None:
        stash_to_states = self._stash_to_selected_states()
        for stash_name, states in stash_to_states.items():
            drop_states(self.simgr, stash_name, states)
            self.get_stash_tree_item(stash_name).refresh()

    def paste_from_clipboard(self, stash_name: str) -> None:
        paste_states(self.simgr, stash_name, self.state_clipboard)
        self.get_stash_tree_item(stash_name).refresh()

    def move_to_stash(self, stash_name: str):
        lambda_str = ""
        while True:
            lambda_str, accepted = QInputDialog.getText(
                self, "Move state from active to here", "Condition lambda", text=lambda_str
            )
            if not accepted:
                return
            error = move_states(self.simgr, stash_name, lambda_str)
            if error is None:
                return
            QMessageBox.critical(self, "Exception!", error)

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        item = self.itemAt(event.pos())
        if item is not None:
            item.handle_context_menu_event(event)
        else:
            menu = QMenu()
            menu.addAction("Create new stash", self._create_new_stash)
            menu.exec_(QCursor.pos())

    def _create_new_stash(self, *args, **kwargs) -> None:  # pylint: disable=unused-argument
        stash_name, accepted = QInputDialog.getText(self, "Stash name", "Blah")

        if not accepted:
            return
        error = create_stash(self.simgr, stash_name)
        if error:
            QMessageBox.critical(None, "Duplicate stash name", error)
        elif error is None:
            self.refresh()

    def refresh(self, **kwargs) -> None:
        if kwargs.get("src", "") != "simgr_viewer":
            self._init_widgets()

    def current_state(self):
        item = self.currentItem()
        if item is None:
            return None
        return item.data(0, 1)

    def select_state(self, state) -> None:
        if state is None:
            self.setCurrentItem(None)
        else:
            for i in range(self.topLevelItemCount()):
                item = self.topLevelItem(i)
                for j in range(item.childCount()):
                    subitem = item.child(j)
                    if subitem.data(0, 1) == state:
                        self.setCurrentItem(subitem)
                        break
                else:
                    continue
                break

    def get_stash_tree_item(self, stash_name: str):
        return self.stash_tree_items[stash_name]

    def _init_widgets(self) -> None:
        # save expanded state
        expended_stash = {}
        selected_state = set()
        for topidx in range(self.topLevelItemCount()):
            top = self.topLevelItem(topidx)
            expended_stash[top.stash_name] = top.isExpanded()
            for idx in range(top.childCount()):
                item = top.child(idx)
                if item.isSelected():
                    selected_state.add(item.state)

        self.clear()

        if self.simgr.am_none:
            return

        self.stash_tree_items = {}
        for stash_name, _stash in self.simgr.stashes.items():  # pylint: disable=unused-variable
            # if not stash and stash_name not in ('active', 'deadended', 'avoided'):
            #     continue
            item = StashTreeItem(stash_name, simgr_viewer=self)
            self.stash_tree_items[stash_name] = item
            self.addTopLevelItem(item)
            item.setExpanded(expended_stash.get(stash_name, False))
