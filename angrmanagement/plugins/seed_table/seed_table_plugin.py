import codecs
from typing import TYPE_CHECKING

from PySide6.QtCore import QAbstractTableModel, QEvent, QModelIndex, QObject, Qt, Signal
from PySide6.QtGui import QContextMenuEvent, QCursor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.views import BaseView

from .seed_table import SeedTable

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class querySignaler(QObject):
    querySignal = Signal(bool)


class SeedTableModel(QAbstractTableModel):
    def __init__(self, workspace, table, dropdown, countlabel):
        super().__init__()
        self.query_signal = querySignaler()
        self.query_signal.querySignal.connect(self.querySignalHandle)
        self.seed_db = SeedTable(workspace, self.query_signal, seed_callback=self.add_seed)
        self.countlabel = countlabel
        self.table = table
        self.workspace = workspace
        self.page_dropdown = dropdown
        self.headers = ["ID", "Input", "NC", "C", "NT", "L", "E"]
        self.seeds = []
        self.displayed_seeds = []

        # pagination support
        self.current_page = 1
        self.max_pages = 1
        self.entries_per_page = 50

        self.set_page(1)

    def rowCount(self, index=QModelIndex()):
        if not self.displayed_seeds:
            return 0
        return len(self.displayed_seeds)

    def columnCount(self, index=QModelIndex()):
        return len(self.headers)

    def querySignalHandle(self, status):
        if status:
            self.countlabel.setText("<font color=#ff0000>Querying..</font>")
            self.countlabel.repaint()

    # probably not useful anymore. kept for not wanting to do it again.
    # def canFetchMore(self, index=QModelIndex()):
    #     return len(self.seeds) > self.num_loaded
    #
    # def fetchMore(self, index=QModelIndex()):
    #     num_to_fetch = min(len(self.seeds) - self.num_loaded, 50)
    #     self.beginInsertRows(QModelIndex(), self.num_loaded, self.num_loaded+num_to_fetch-1)
    #     self.num_loaded += num_to_fetch
    #     self.endInsertRows()
    #     self.table.resizeEvent(QResizeEvent(self.table.size(), QSize()))

    def set_page(self, pagenum):
        self.beginResetModel()
        if self.max_pages >= pagenum > 0:
            self.current_page = pagenum
        else:
            return False
        # load seeds for page
        min_index = (pagenum - 1) * self.entries_per_page
        max_index = min((pagenum * self.entries_per_page) - 1, len(self.seeds))
        # check to ensure we arent out of bounds
        if min_index > len(self.seeds):  # this should REALLY never happen.
            print("ERROR: Invalid page selected.")
            return False
        self.displayed_seeds = self.seeds[min_index:max_index]
        self.endResetModel()
        return True

    def add_seed(self, seed):
        self.beginResetModel()
        # more complex logic here.. probably
        if isinstance(seed, list):
            for s in seed:
                self.seeds.append(s)
        else:
            self.seeds.append(seed)
        # update our page
        self.max_pages = max(len(self.seeds) // self.entries_per_page, 1)
        self.set_page(self.current_page)
        self.page_dropdown.clear()
        self.page_dropdown.addItems(list(map(str, range(1, self.max_pages + 1))))
        self.countlabel.setText("Count: " + str(len(self.seeds)))
        self.endResetModel()

    def clear_seeds(self):
        self.beginResetModel()
        self.seeds = []
        self.displayed_seeds = []
        self.max_pages = max(len(self.seeds) // self.entries_per_page, 1)
        self.page_dropdown.clear()
        self.page_dropdown.addItems(list(map(str, range(1, self.max_pages + 1))))
        self.countlabel.setText("Count: " + str(len(self.seeds)))
        self.endResetModel()
        self.set_page(1)

    def data(self, index, role=Qt.DisplayRole):
        col = index.column()
        seed = self.displayed_seeds[index.row()]
        if role == Qt.DisplayRole:
            if col == 0:
                return seed.id
            elif col == 1:
                return repr(seed.value) if len(seed.value) < 80 else repr(seed.value[:80] + b"...")
            elif col == 2 and "non-crashing" in seed.tags:
                return "x"
            elif col == 3 and "crashing" in seed.tags:
                return "x"
            elif col == 4 and "non-terminating" in seed.tags:
                return "x"
            elif col == 5 and "leaking" in seed.tags:
                return "x"
            elif col == 6 and "exploit" in seed.tags:
                return "x"
            return None
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal and section < len(self.headers):
            return self.headers[section]
        else:
            return None

    def go_next_page(self):
        if self.set_page(self.current_page + 1):
            self.page_dropdown.clear()
            self.page_dropdown.addItems(list(map(str, range(1, self.max_pages + 1))))
            self.page_dropdown.setCurrentIndex(self.current_page - 1)

    def go_prev_page(self):
        if self.set_page(self.current_page - 1):
            self.page_dropdown.clear()
            self.page_dropdown.addItems(list(map(str, range(1, self.max_pages + 1))))
            self.page_dropdown.setCurrentIndex(self.current_page - 1)


class SeedTableWidget(QTableView):
    def __init__(self, parent, workspace):
        super().__init__(parent)
        self.workspace = workspace

    def refresh(self):
        self.viewport().update()

    def init_parameters(self):
        self.horizontalHeader().setVisible(True)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(18)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        rows = self.selectionModel().selectedIndexes()
        contextMenu = QMenu(self)
        saveSeed = contextMenu.addAction("&Save Seed")
        action = contextMenu.exec_(QCursor.pos())
        if action == saveSeed:
            self.saveSeed(rows)

    def saveSeed(self, rows):
        data = self.model().displayed_seeds[rows[0].row()].value
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filename = QFileDialog.getSaveFileName(self, "Save Seed", "", "All Files(*)", options=options)[0]
        try:
            with open(filename, "wb") as outfile:
                outfile.write(data)
        except Exception:
            self.workspace.log("Error saving seed.")


class SeedTableView(BaseView):
    def __init__(self, workspace: Workspace, *args, **kwargs):
        super().__init__("SeedTableView", workspace, *args, **kwargs)
        self.base_caption = "Seed Table"
        self.workspace = workspace
        self.instance = workspace.main_instance
        workspace.main_instance.project.am_subscribe(self.on_project_load)
        self._init_widgets()

    def page_changed(self, i):
        self.table_data.set_page(self.page_dropdown.currentIndex() + 1)

    def _init_widgets(self):
        self.main = QMainWindow()
        self.main.setWindowFlags(Qt.Widget)

        self.container = QWidget()  # create containing widget to keep things nice
        self.container.setLayout(QVBoxLayout())

        # count label
        self.seed_count_label = QLabel("Count:")

        # create table
        self.page_dropdown = QComboBox()
        self.table = SeedTableWidget(self, self.workspace)
        self.table_data = SeedTableModel(self.workspace, self.table, self.page_dropdown, self.seed_count_label)
        self.table.setModel(self.table_data)
        self.table.init_parameters()  # need to set table model before messing with column resizing
        self.container.layout().addWidget(self.table)

        # create bottom section
        self.bottom_widget = QWidget()
        self.bottom_widget.setLayout(QHBoxLayout())
        # page buttons
        self.next_page_btn = QPushButton(">")
        self.next_page_btn.setMaximumWidth(40)
        self.next_page_btn.clicked.connect(self.table_data.go_next_page)
        self.prev_page_btn = QPushButton("<")
        self.prev_page_btn.setMaximumWidth(40)
        self.prev_page_btn.clicked.connect(self.table_data.go_prev_page)
        # page label
        self.page_label = QLabel("Page:")
        # page dropdown
        self.page_dropdown.addItems(list(map(str, range(1, 1))))  # test
        self.page_dropdown.setCurrentIndex(0)
        self.page_dropdown.activated.connect(self.page_changed)
        # filter box
        self.filter_box = SeedTableFilterBox(self)
        self.filter_box.returnPressed.connect(self._on_filter_change)
        # filter checkboxes
        # "NC", "C", "NT", "L", "E"
        self.nc_checkbox = QCheckBox("NC")
        self.nc_checkbox.stateChanged.connect(self._on_filter_change)
        self.c_checkbox = QCheckBox("C")
        self.c_checkbox.stateChanged.connect(self._on_filter_change)
        self.nt_checkbox = QCheckBox("NT")
        self.nt_checkbox.stateChanged.connect(self._on_filter_change)
        self.l_checkbox = QCheckBox("L")
        self.l_checkbox.stateChanged.connect(self._on_filter_change)
        self.e_checkbox = QCheckBox("E")
        self.e_checkbox.stateChanged.connect(self._on_filter_change)

        self.bottom_widget.layout().addWidget(self.seed_count_label)
        self.bottom_widget.layout().addWidget(self.filter_box)
        self.bottom_widget.layout().addWidget(self.nc_checkbox)
        self.bottom_widget.layout().addWidget(self.c_checkbox)
        self.bottom_widget.layout().addWidget(self.nt_checkbox)
        self.bottom_widget.layout().addWidget(self.l_checkbox)
        self.bottom_widget.layout().addWidget(self.e_checkbox)
        # self.bottom_widget.layout().addStretch()
        self.bottom_widget.layout().addWidget(self.prev_page_btn)
        self.bottom_widget.layout().addWidget(self.page_label)
        self.bottom_widget.layout().addWidget(self.page_dropdown)
        self.bottom_widget.layout().addWidget(self.next_page_btn)

        self.container.layout().addWidget(self.bottom_widget)

        self.main.setCentralWidget(self.container)
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.main)
        self.setLayout(main_layout)

    def on_project_load(self, **kwargs):
        if self.instance.project.am_none:
            return
        pass

    def _on_filter_change(self):
        raw_filter = self.filter_box.text()
        inp = None
        if len(raw_filter) > 0:
            inp, _ = codecs.escape_decode(raw_filter, "hex")
        flags = []
        if self.nc_checkbox.isChecked():
            flags.append("non-crashing")
        if self.c_checkbox.isChecked():
            flags.append("crashing")
        if self.l_checkbox.isChecked():
            flags.append("leaking")
        if self.nt_checkbox.isChecked():
            flags.append("non-terminating")
        if self.e_checkbox.isChecked():
            flags.append("exploit")

        self.table_data.clear_seeds()
        if len(flags) == 0 and inp is None:
            data = self.table_data.seed_db.get_all_seeds()
        else:
            if inp:
                data = self.table_data.seed_db.filter_seeds_by_value(inp)
                data = list(filter(lambda s: all([x in s.tags for x in flags]), data))
            else:
                data = self.table_data.seed_db.filter_seeds_by_tag(tags=flags)
        self.table_data.add_seed(data)


class SeedTableFilterBox(QLineEdit):
    def __init__(self, parent):
        super().__init__()

        self._table = parent

        self.installEventFilter(self)

    def eventFilter(self, obj, event):  # pylint:disable=unused-argument
        if event.type() == QEvent.KeyPress:
            if event.key() == Qt.Key_Escape:
                if self.text():
                    # clear the text
                    self.setText("")
                return True

        return False


class SeedTablePlugin(BasePlugin):
    """
    Plugin loader
    """

    def __init__(self, workspace):
        super().__init__(workspace)
        self.seed_table_view = SeedTableView(workspace, "center")
        workspace.default_tabs += [self.seed_table_view]
        workspace.add_view(self.seed_table_view)
