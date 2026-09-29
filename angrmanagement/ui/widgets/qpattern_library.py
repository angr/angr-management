from __future__ import annotations

import json
from typing import TYPE_CHECKING

from angr.knowledge_plugins.patterns import StoredPattern
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QPatternLibrary(QWidget):
    """The project's patterns: a table with edit, on/off, delete, export and import.

    With ``current_func``, two more columns say what the outliner pass saw of each
    pattern the last time that function was decompiled: verified matches, and how
    many were outlined. A dash means the pass did not search for the pattern there.
    Every change goes through the workspace, which refreshes every library widget.
    """

    COLUMNS = ["Pattern", "Call", "Enabled", "Min similarity", "From"]
    #: with statistics, what a narrow dock should show without scrolling comes first
    STATS_COLUMNS = ["Pattern", "Enabled", "Highlight", "Matches", "Outlined", "Call", "Min similarity", "From"]

    def __init__(
        self,
        workspace: Workspace,
        instance: Instance,
        on_edit: Callable[[StoredPattern], None],
        current_func: Callable[[], int | None] | None = None,
        on_status: Callable[[str], None] | None = None,
        on_toggled: Callable[[StoredPattern], None] | None = None,
        highlight: tuple[Callable[[str], bool], Callable[[str, bool], None]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance
        self._on_edit = on_edit
        self._current_func = current_func
        self._on_status = on_status
        self._on_toggled = on_toggled
        #: (is it highlighted, set it) for a pattern name, when the owner can highlight
        self._highlight = highlight
        self.rows: list[StoredPattern] = []
        # set while the table is being filled, so its own writes are not taken for clicks
        self._filling = False

        self.columns = self.STATS_COLUMNS if current_func is not None else self.COLUMNS
        columns = self.columns
        self.table = QTableWidget(0, len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellDoubleClicked.connect(lambda _row, _col: self._on_edit_clicked())
        self.table.itemChanged.connect(self._on_item_changed)

        buttons = QHBoxLayout()
        for label, handler in (
            ("Edit", self._on_edit_clicked),
            ("On/off", self._on_toggle_clicked),
            ("Delete", self._on_delete_clicked),
            ("Export...", self._on_export_clicked),
            ("Import...", self._on_import_clicked),
        ):
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            buttons.addWidget(btn)
        buttons.addStretch()

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table, 1)
        layout.addLayout(buttons)
        self.setLayout(layout)
        self.reload()

    def reload(self) -> None:
        # a view can exist before any project is loaded
        kb = self.instance.kb
        self.rows = [] if kb is None else sorted(kb.patterns, key=lambda p: p.name)
        func_addr = self._current_func() if self._current_func is not None else None
        self._filling = True
        self.table.setRowCount(len(self.rows))
        for i, stored in enumerate(self.rows):
            values = {
                "Pattern": stored.name,
                "Call": stored.pattern.call_name,
                "Enabled": "on" if stored.enabled else "off",
                "Min similarity": f"{stored.min_similarity:.0%}",
                "From": f"{stored.origin_func:#x}" if stored.origin_func is not None else "",
            }
            stats = None
            if self._current_func is not None:
                stats = self.instance.kb.patterns.stats(func_addr, stored.name) if func_addr is not None else None
                values["Highlight"] = ""
                values["Matches"] = "-" if stats is None else str(stats.matches)
                values["Outlined"] = "-" if stats is None else str(stats.outlined)
            for j, column in enumerate(self.columns):
                item = QTableWidgetItem(values[column])
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if column == "Enabled":
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(Qt.CheckState.Checked if stored.enabled else Qt.CheckState.Unchecked)
                elif column == "Highlight" and self._highlight is not None:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    on = self._highlight[0](stored.name)
                    item.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
                    if stats is None or not stats.call_addrs:
                        item.setToolTip("No call to this pattern in this function to highlight")
                    else:
                        item.setToolTip(f"Highlight the {len(stats.call_addrs)} call(s) to {stored.pattern.call_name}")
                self.table.setItem(i, j, item)
        self._filling = False

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._filling or not (0 <= item.row() < len(self.rows)):
            return
        stored = self.rows[item.row()]
        checked = item.checkState() == Qt.CheckState.Checked
        column = self.columns[item.column()]
        if column == "Enabled" and checked != stored.enabled:
            self.toggle(stored)
        elif column == "Highlight" and self._highlight is not None and checked != self._highlight[0](stored.name):
            self._highlight[1](stored.name, checked)

    def selection(self) -> StoredPattern | None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        if len(rows) != 1:
            return None
        row = next(iter(rows))
        return self.rows[row] if 0 <= row < len(self.rows) else None

    #
    # operations
    #

    def toggle(self, stored: StoredPattern) -> None:
        self.instance.kb.patterns.set_enabled(stored.name, not stored.enabled)
        state = "on" if stored.enabled else "off"
        if self._on_toggled is None:
            self._changed(f"{stored.name} is {state}; it applies the next time a function is decompiled")
            return
        self._changed(f"{stored.name} is {state}")
        self._on_toggled(stored)

    def delete(self, stored: StoredPattern) -> None:
        self.instance.kb.patterns.remove(stored.name)
        self._changed(f"deleted {stored.name}")

    def export(self, stored: StoredPattern, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(stored.to_dict(), f, indent=1)
        self._status(f"exported {stored.name} to {path}")

    def import_(self, path: str) -> StoredPattern:
        with open(path, encoding="utf-8") as f:
            stored = StoredPattern.from_dict(json.load(f))
        self.instance.kb.patterns.store(stored)
        self._changed(f"imported {stored.name} from {path}")
        return stored

    def _changed(self, message: str) -> None:
        self.workspace.on_patterns_changed()
        self._status(message)

    def _status(self, message: str) -> None:
        if self._on_status is not None:
            self._on_status(message)

    #
    # buttons
    #

    def _on_edit_clicked(self) -> None:
        stored = self.selection()
        if stored is not None:
            self._on_edit(stored)

    def _on_toggle_clicked(self) -> None:
        stored = self.selection()
        if stored is not None:
            self.toggle(stored)

    def _on_delete_clicked(self) -> None:
        stored = self.selection()
        if stored is not None:
            self.delete(stored)

    def _on_export_clicked(self) -> None:
        stored = self.selection()
        if stored is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export pattern", f"{stored.name}.json", "JSON (*.json)")
        if path:
            self.export(stored, path)

    def _on_import_clicked(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import pattern", "", "JSON (*.json)")
        if path:
            self.import_(path)
