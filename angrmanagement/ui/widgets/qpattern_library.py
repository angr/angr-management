from __future__ import annotations

import json
from typing import TYPE_CHECKING

from angr.knowledge_plugins.patterns import StoredPattern
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.views.code_view import CodeView
    from angrmanagement.ui.workspace import Workspace


class _KeyItem(QTableWidgetItem):
    """A cell that sorts by a key of its own, so "100%" comes after "83%"."""

    def __init__(self, text: str, key) -> None:
        super().__init__(text)
        self.key = key

    def __lt__(self, other) -> bool:
        if isinstance(other, _KeyItem) and type(self.key) is type(other.key):
            return self.key < other.key
        return super().__lt__(other)


class QPatternLibrary(QWidget):
    """The project's patterns: a table with an Enabled checkbox per row, and edit, delete, export and import.

    With ``current_func``, two more columns say what the outliner pass saw of each
    pattern the last time that function was decompiled: verified matches, and how
    many were outlined. Both are 0 for a pattern that was not enabled then.
    Every change goes through the workspace, which refreshes every library widget.

    With ``on_apply``, a click on Enabled only marks the pattern: its row turns bold and
    reads "(unapplied)" until "Apply Patterns & Redecompile" writes every marked change
    and calls ``on_apply``.
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
        on_apply: Callable[[], None] | None = None,
        highlight: tuple[Callable[[str], bool], Callable[[str, bool], None]] | None = None,
        code_view: Callable[[], CodeView | None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance
        self._on_edit = on_edit
        self._current_func = current_func
        self._on_status = on_status
        self._on_apply = on_apply
        #: pattern name -> the enabled state a click asked for, where it differs from the project's
        self._pending: dict[str, bool] = {}
        #: (is it highlighted, set it) for a pattern name, when the owner can highlight
        self._highlight = highlight
        #: the pseudocode view whose function the highlight actions act on
        self._code_view = code_view or (lambda: self.workspace.view_manager.first_view_in_category("pseudocode"))
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
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.SortOrder.AscendingOrder)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(
            lambda pos: self.context_menu().exec(self.table.viewport().mapToGlobal(pos))
        )

        buttons = QHBoxLayout()
        for label, handler in (
            ("Edit", self._on_edit_clicked),
            ("Delete", self._on_delete_clicked),
            ("Export...", self._on_export_clicked),
            ("Import...", self._on_import_clicked),
        ):
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            buttons.addWidget(btn)
        buttons.addStretch()
        self._buttons = buttons

        self._apply_btn: QPushButton | None = None
        if on_apply is not None:
            # "&&" is a literal ampersand in a button label
            self._apply_btn = self.add_button(
                "Apply Patterns && Redecompile",
                self.apply_pending,
                "Turn the patterns marked (unapplied) on or off, then decompile the function again",
            )

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table, 1)
        layout.addLayout(buttons)
        self.setLayout(layout)
        self.reload()

    def add_button(self, label: str, handler: Callable[[], object], tooltip: str = "") -> QPushButton:
        """A button of the owner's in the row, after the library's own."""
        btn = QPushButton(label)
        btn.clicked.connect(handler)
        if tooltip:
            btn.setToolTip(tooltip)
        # before the stretch, so it sits with the others
        self._buttons.insertWidget(self._buttons.count() - 1, btn)
        return btn

    def reload(self) -> None:
        # a view can exist before any project is loaded
        kb = self.instance.kb
        self.rows = [] if kb is None else sorted(kb.patterns, key=lambda p: p.name)
        # a mark goes away once the project agrees with it, or its pattern is gone
        by_name = {stored.name: stored for stored in self.rows}
        self._pending = {
            name: on for name, on in self._pending.items() if name in by_name and by_name[name].enabled != on
        }
        func_addr = self._current_func() if self._current_func is not None else None
        self._filling = True
        # rows move while sorting is on; fill with it off, then sort once
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for i, stored in enumerate(self.rows):
            pending = stored.name in self._pending
            enabled = self._pending.get(stored.name, stored.enabled)
            values = {
                "Pattern": stored.name,
                "Call": stored.pattern.call_name,
                "Enabled": ("on" if enabled else "off") + (" (unapplied)" if pending else ""),
                "Min similarity": f"{stored.min_similarity:.0%}",
                "From": f"{stored.origin_func:#x}" if stored.origin_func is not None else "",
            }
            keys = {
                "Min similarity": stored.min_similarity,
                "From": stored.origin_func if stored.origin_func is not None else -1,
            }
            stats = None
            if self._current_func is not None:
                stats = self.instance.kb.patterns.stats(func_addr, stored.name) if func_addr is not None else None
                values["Highlight"] = ""
                # the pass records every pattern it searched and drops the rest, so no numbers
                # means the pattern was not enabled when this function was last decompiled
                keys["Matches"] = stats.matches if stats is not None else 0
                keys["Outlined"] = stats.outlined if stats is not None else 0
                values["Matches"] = str(keys["Matches"])
                values["Outlined"] = str(keys["Outlined"])
            for j, column in enumerate(self.columns):
                item = _KeyItem(values[column], keys.get(column, values[column]))
                if j == 0:
                    # rows move when sorted; each knows its pattern
                    item.setData(Qt.ItemDataRole.UserRole, stored.name)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if pending:
                    font = QFont(item.font())
                    font.setBold(True)
                    item.setFont(font)
                if column == "Enabled":
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(Qt.CheckState.Checked if enabled else Qt.CheckState.Unchecked)
                elif column == "Highlight" and self._highlight is not None:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    on = self._highlight[0](stored.name)
                    item.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
                    code_view = self._code_view()
                    calls = code_view.pattern_call_count(stored.name) if code_view is not None else 0
                    if calls:
                        item.setToolTip(f"Highlight the {calls} call(s) to {stored.pattern.call_name}")
                    else:
                        item.setToolTip("No call to this pattern in this function to highlight")
                self.table.setItem(i, j, item)
        self.table.setSortingEnabled(True)
        self._filling = False
        if self._apply_btn is not None:
            self._apply_btn.setEnabled(bool(self._pending))

    def stored_at(self, row: int) -> StoredPattern | None:
        """The pattern shown in ``row``, which sorting moves around."""
        item = self.table.item(row, 0) if row >= 0 else None
        name = None if item is None else item.data(Qt.ItemDataRole.UserRole)
        return None if name is None else self.instance.kb.patterns.get(name)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._filling:
            return
        stored = self.stored_at(item.row())
        if stored is None:
            return
        checked = item.checkState() == Qt.CheckState.Checked
        column = self.columns[item.column()]
        if column == "Enabled" and self._on_apply is not None:
            self.mark(stored, checked)
        elif column == "Enabled" and checked != stored.enabled:
            self.toggle(stored)
        elif column == "Highlight" and self._highlight is not None and checked != self._highlight[0](stored.name):
            self._highlight[1](stored.name, checked)

    def selections(self) -> list[StoredPattern]:
        """The patterns of the selected rows, in table order."""
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        return [s for s in (self.stored_at(r) for r in rows) if s is not None]

    def context_menu(self) -> QMenu:
        selected = self.selections()
        menu = QMenu(self.table)
        pseudocode = menu.addAction("Highlight patterns in pseudocode", lambda: self.highlight_in_pseudocode(selected))
        disassembly = menu.addAction(
            "Highlight patterns in disassembly", lambda: self.highlight_in_disassembly(selected)
        )
        for action in (pseudocode, disassembly):
            action.setEnabled(bool(selected))
        edit = menu.addAction("Edit pattern...", lambda: self._on_edit(selected[0]))
        edit.setEnabled(len(selected) == 1)
        return menu

    def _matches_here(
        self, patterns: list[StoredPattern], calls_count: bool = False
    ) -> tuple[CodeView | None, dict[str, list[frozenset[int]]]]:
        """The pseudocode view, and each pattern's matches in its function at the last decompilation.
        With ``calls_count``, a pattern whose calls the pseudocode shows counts even without them."""
        code_view = self._code_view()
        if code_view is None or code_view.function.am_none:
            self._status("no function is decompiled in the pseudocode view")
            return None, {}
        func_addr = code_view.function.am_obj.addr
        found = {}
        for stored in patterns:
            stats = self.instance.kb.patterns.stats(func_addr, stored.name)
            if stats is not None and stats.matches:
                found[stored.name] = list(stats.match_addrs)
            elif calls_count and code_view.pattern_call_count(stored.name):
                found[stored.name] = []
        missing = [s.name for s in patterns if s.name not in found]
        if missing:
            self._status(
                f"no matches in {code_view.function.am_obj.name} at its last decompilation: {', '.join(missing)}"
            )
        return code_view, found

    def highlight_in_pseudocode(self, patterns: list[StoredPattern]) -> None:
        """Band the patterns' matches in the pseudocode view's function."""
        code_view, found = self._matches_here(patterns, calls_count=True)
        if code_view is None or not found:
            return
        for name in found:
            code_view.set_pattern_highlight(name, True)
        code_view.reload_patterns()
        self.workspace.raise_view(code_view)

    def highlight_in_disassembly(self, patterns: list[StoredPattern]) -> None:
        """Paint every instruction the patterns' matches cover in the pseudocode view's function."""
        _, found = self._matches_here(patterns)
        addrs = {a for copies in found.values() for copy in copies for a in copy}
        if addrs:
            self.workspace.highlight_in_disassembly(addrs)

    def selection(self) -> StoredPattern | None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        if len(rows) != 1:
            return None
        return self.stored_at(next(iter(rows)))

    #
    # operations
    #

    def toggle(self, stored: StoredPattern) -> None:
        self.instance.kb.patterns.set_enabled(stored.name, not stored.enabled)
        state = "on" if stored.enabled else "off"
        self._changed(f"{stored.name} is {state}; it applies the next time a function is decompiled")

    @property
    def pending(self) -> dict[str, bool]:
        """Pattern name -> the enabled state marked for it but not applied yet."""
        return dict(self._pending)

    def mark(self, stored: StoredPattern, enabled: bool) -> None:
        """Mark ``stored`` to be turned on or off by the next apply; marking it back clears the mark."""
        if enabled == stored.enabled:
            self._pending.pop(stored.name, None)
        else:
            self._pending[stored.name] = enabled
        self.reload()
        if self._pending:
            self._status(f"{len(self._pending)} pattern change(s) not applied yet")

    def apply_pending(self) -> bool:
        """Write the marked changes and call ``on_apply``. Returns False, and does not call it,
        when the marks leave the set of enabled patterns as it was."""
        patterns = self.instance.kb.patterns
        changes = {name: on for name, on in self._pending.items() if (s := patterns.get(name)) and s.enabled != on}
        self._pending.clear()
        if not changes:
            self.reload()
            self._status("the enabled patterns did not change; nothing to apply")
            return False
        for name, on in changes.items():
            patterns.set_enabled(name, on)
        self._changed(", ".join(f"{name} is {'on' if on else 'off'}" for name, on in sorted(changes.items())))
        if self._on_apply is not None:
            self._on_apply()
        return True

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
