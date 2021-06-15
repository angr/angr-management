from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem
from PySide2.QtCore import QSize, Qt
from ..widgets.filesystem_table import QFileSystemTable

class FilesystemMount(QDialog):
    def __init__(self, fs_config=None, instance=None, parent=None):
        super(FilesystemMount, self).__init__(parent)

        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._instance = instance
        self._parent = parent
        self.fs_config = fs_config or []
        self._init_widgets()

    def _init_widgets(self):
        layout = QVBoxLayout()
        self._table = QFileSystemTable(self.fs_config,self)
        layout.addWidget(self._table,0)
        self.setLayout(layout)

    def closeEvent(self, event):
        self.fs_config = self._table.get_result()
        self.close()
