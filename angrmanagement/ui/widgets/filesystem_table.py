from __future__ import annotations

from PySide6.QtWidgets import QAbstractItemView, QFileDialog, QHeaderView, QMenu, QTableWidget, QTableWidgetItem


class QFileSystemTable(QTableWidget):
    def __init__(self, items, parent) -> None:
        super().__init__(parent)

        header_labels = ["Mount Point", "Host Path"]

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.setRowCount(len(items))
        for idx, item in enumerate(items):
            for i, it in enumerate(item):
                self.setItem(idx, i, QTableWidgetItem(it))

    def contextMenuEvent(self, event) -> None:
        sr = self.currentRow()

        menu = QMenu("", self)

        menu.addAction("Add a Row", self._action_new_row)
        menu.addSeparator()

        a = menu.addAction("Delete this Row", self._action_delete)
        if sr is None:
            a.setDisabled(True)
        b = menu.addAction("Select a File", self._action_select_file)
        if sr is None:
            b.setDisabled(True)
        c = menu.addAction("Select a directory", self._action_select_dir)
        if sr is None:
            c.setDisabled(True)

        menu.exec_(event.globalPos())

    def _action_new_row(self) -> None:
        row = self.rowCount()
        self.insertRow(row)
        self.setItem(row, 0, QTableWidgetItem("Edit Me"))
        self.setItem(row, 1, QTableWidgetItem(""))

    def _action_select_file(self) -> None:
        file_path, succ = QFileDialog.getOpenFileName(
            self,
            "Open a real file",
            "",
            "All executables (*)",
        )
        if succ:
            self.setItem(self.currentRow(), 1, QTableWidgetItem(file_path))

    def _action_select_dir(self) -> None:
        dir_path = QFileDialog.getExistingDirectory(self, "Select a directory")
        if dir_path:
            self.setItem(self.currentRow(), 1, QTableWidgetItem(dir_path))

    def _action_delete(self) -> None:
        self.removeRow(self.currentRow())

    def get_result(self):
        ret = []
        for i in range(self.rowCount()):
            ret.append([self.item(i, 0).text(), self.item(i, 1).text()])
        return ret
