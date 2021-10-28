from PySide2.QtCore import Qt
from PySide2.QtWidgets import QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox, QTableWidget, QHeaderView, \
    QAbstractItemView, QTableWidgetItem, QWidget, QPushButton

from angrmanagement.ui.views.view import BaseView

try:
    from slacrs import Slacrs
    from slacrs.model import PluginMessage
except ImportError as ex:
    Slacrs = None


class QSummaryItem:
    def __init__(self, plugin, kind, image_id, msg):
        self.plugin = plugin
        self.kind = kind
        self.image_id = image_id
        self.msg = msg

    def widgets(self):
        widgets = [
            QTableWidgetItem(self.plugin),
            QTableWidgetItem(self.kind),
            QTableWidgetItem(self.image_id),
            QTableWidgetItem(self.msg),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QSummaryTable(QTableWidget):
    HEADER = [
        'Plugin',
        'Kind',
        'Image ID',
        'Message',
    ]

    def __init__(self, workspace, parent=None):
        super().__init__(parent)
        self.workspace = workspace

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setHorizontalScrollMode(self.ScrollPerPixel)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self.items = []
        self.cnt = 0

    def reload(self):
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        self.viewport().update()

    def update_table(self):
        # connect to slacrs through chess
        if not Slacrs:
            return
        connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
        if connector is None:
            return
        slacrs_instance = connector.slacrs_instance()
        if slacrs_instance is None:
            return
        session = slacrs_instance.session()
        if not session:
            return

        # we are guaranteed a valid connection
        res = session.query(PluginMessage)
        if not res:
            return



        example_data = QSummaryItem("my_plugin", "dank", f"{self.cnt}", "[+] CRASH FOUND!")
        self.cnt += 1
        self.items.append(example_data)

        self.reload()


class SummaryView(BaseView):
    def __init__(self, workspace):
        super(SummaryView, self).__init__("chess_summary", workspace, "right")
        self.workspace = workspace

        self.summary_table = QSummaryTable(workspace)
        self.update_button = None

        self._init_widgets()

    def _init_widgets(self):
        # button box
        btn_box = QGroupBox(self)
        self.update_button = QPushButton()
        self.update_button.setText("Update")
        self.update_button.clicked.connect(self._handle_btn_click)
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.update_button)
        btn_box.setLayout(btn_layout)

        info_layout = QVBoxLayout()
        info_layout.addWidget(self.summary_table)
        info_layout.addWidget(btn_box)

        info_box = QGroupBox(self)
        info_box.setTitle("Info Table")
        info_box.setLayout(info_layout)

        layout = QVBoxLayout()
        layout.addWidget(info_box)

        self.setLayout(layout)
        self.summary_table.update_table()

    def _handle_btn_click(self):
        self.summary_table.update_table()



