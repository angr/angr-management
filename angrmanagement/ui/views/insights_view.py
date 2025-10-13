from __future__ import annotations

from PySide6.QtCore import QAbstractItemModel, QModelIndex, QSize, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QHBoxLayout, QHeaderView, QTreeView

from .view import BaseView


class InsightsTreeItem:
    """
    Tree item for the insights tree model.
    """

    def __init__(self, item_name: str, count: int, parent=None):
        self.item_name = item_name
        self.count = count
        self.parent = parent
        self.children = []

        if parent:
            parent.add_child(self)

    def add_child(self, child):
        """Add a child item to this item."""
        child.parent = self
        self.children.append(child)

    def child_count(self):
        """Return the number of children."""
        return len(self.children)

    def child(self, row):
        """Return the child at the given row."""
        if 0 <= row < len(self.children):
            return self.children[row]
        return None

    def row(self):
        """Return the row number of this item within its parent."""
        if self.parent:
            return self.parent.children.index(self)
        return 0


class InsightsTreeModel(QAbstractItemModel):
    """
    Tree model for the insights view with Item and Count columns.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.root_item = InsightsTreeItem("Root", 0)
        self._setup_example_data()

    def _setup_example_data(self):
        """Set up example data for the tree model."""
        # Create some example categories and items
        functions = InsightsTreeItem("Functions", 0)
        functions.add_child(InsightsTreeItem("main", 1))
        functions.add_child(InsightsTreeItem("printf", 15))
        functions.add_child(InsightsTreeItem("malloc", 8))
        functions.add_child(InsightsTreeItem("free", 7))

        variables = InsightsTreeItem("Variables", 0)
        variables.add_child(InsightsTreeItem("global_var", 3))
        variables.add_child(InsightsTreeItem("local_var", 12))
        variables.add_child(InsightsTreeItem("temp_var", 5))

        strings = InsightsTreeItem("Strings", 0)
        strings.add_child(InsightsTreeItem("Hello World", 2))
        strings.add_child(InsightsTreeItem("Error: %s", 4))
        strings.add_child(InsightsTreeItem("Success", 1))

        calls = InsightsTreeItem("Function Calls", 0)
        calls.add_child(InsightsTreeItem("Direct Calls", 25))
        calls.add_child(InsightsTreeItem("Indirect Calls", 3))
        calls.add_child(InsightsTreeItem("System Calls", 12))

        # Add all categories to root
        self.root_item.add_child(functions)
        self.root_item.add_child(variables)
        self.root_item.add_child(strings)
        self.root_item.add_child(calls)

    def columnCount(self, parent=QModelIndex()):
        """Return the number of columns."""
        return 2  # Item and Count

    def rowCount(self, parent=QModelIndex()):
        """Return the number of rows under the given parent."""
        if parent.column() > 0:
            return 0

        if not parent.isValid():
            parent_item = self.root_item
        else:
            parent_item = parent.internalPointer()

        return parent_item.child_count()

    def index(self, row, column, parent=QModelIndex()):
        """Create an index for the given row, column, and parent."""
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            parent_item = self.root_item
        else:
            parent_item = parent.internalPointer()

        child_item = parent_item.child(row)
        if child_item:
            return self.createIndex(row, column, child_item)
        return QModelIndex()

    def parent(self, index):
        """Return the parent of the given index."""
        if not index.isValid():
            return QModelIndex()

        child_item = index.internalPointer()
        parent_item = child_item.parent

        if parent_item == self.root_item or parent_item is None:
            return QModelIndex()

        return self.createIndex(parent_item.row(), 0, parent_item)

    def data(self, index, role=Qt.DisplayRole):
        """Return the data for the given index and role."""
        if not index.isValid():
            return None

        item = index.internalPointer()
        column = index.column()

        if role == Qt.DisplayRole:
            if column == 0:
                return item.item_name
            elif column == 1:
                return str(item.count)
        elif role == Qt.FontRole:
            if column == 0 and item.child_count() > 0:
                # Make parent items bold
                font = QFont()
                font.setBold(True)
                return font

        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        """Return the header data for the given section, orientation, and role."""
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if section == 0:
                return "Item"
            elif section == 1:
                return "Count"
        return None


class QInsightsTreeView(QTreeView):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setRootIsDecorated(True)
        self.setUniformRowHeights(True)
        self.setSelectionMode(QTreeView.SelectionMode.SingleSelection)
        self.setSelectionBehavior(QTreeView.SelectionBehavior.SelectRows)
        self.setIndentation(20)

        # Set up the model
        self.model = InsightsTreeModel()
        self.setModel(self.model)

        # Configure header
        header = self.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)


class InsightsView(BaseView):
    def __init__(self, workspace, default_docking_position, instance):
        super().__init__("insights", workspace, default_docking_position)

        self.instance = instance
        self.base_caption = "Insights"

        self._init_widgets()

    def reload(self):
        self._init_widgets()

    def sizeHint(self):
        return QSize(400, 800)

    #
    # Event handlers
    #

    #
    # Private methods
    #

    def _init_widgets(self):

        if self.workspace.main_instance.project.am_none:
            return

        layout = QHBoxLayout()

        tree = QInsightsTreeView()
        layout.addWidget(tree)

        # for name, insight in self.workspace.main_instance.kb.insights.items():
        #     control = QInsightGeneric(name, insight)
        #     layout.addWidget(control)

        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)
