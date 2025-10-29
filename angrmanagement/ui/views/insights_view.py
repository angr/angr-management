from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractItemModel, QModelIndex, QSize, Qt
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import QApplication, QHBoxLayout, QHeaderView, QMenu, QPushButton, QTreeView, QVBoxLayout

from angrmanagement.data.jobs.insights import InsightsJob

from .view import BaseView


class InsightsTreeItem:
    """
    Tree item for the insights tree model.
    """

    def __init__(self, item_name: str, parent=None):
        self.item_name = item_name
        self.parent = parent
        self.children = []
        self.data = ""

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


class AddressItem(InsightsTreeItem):
    def __init__(self, item_name: str, addr: int, parent=None):
        super().__init__(item_name, parent)
        self.addr = addr

    def __repr__(self):
        return f"AddressItem(item_name={self.item_name}, addr={hex(self.addr)})"


class DataItem(InsightsTreeItem):
    def __init__(self, item_name: str, data: str, parent=None):
        super().__init__(item_name, parent)
        self.data = data


class SwitchItem(InsightsTreeItem):
    def __init__(self, description: str, func_addr: int, func_name: str, ref_at: int, parent=None):
        super().__init__(f"Switch @ {func_name} ({hex(func_addr)})", parent)
        self.description = description
        self.func_addr = func_addr
        self.func_name = func_name
        self.ref_at = ref_at

        # setup children
        self.add_child(DataItem("Description", self.description))
        self.add_child(AddressItem(f"Function Name: {self.func_name}", self.func_addr))
        self.add_child(AddressItem(f"Function Address: {hex(self.func_addr)}", self.func_addr))
        self.add_child(AddressItem(f"Referenced at: {hex(self.ref_at)}", self.ref_at))

    def __repr__(self):
        return f"SwitchItem(func_addr={hex(self.func_addr)}, func_name={self.func_name}, ref_at={hex(self.ref_at)})"


class FeatureItem(InsightsTreeItem):
    def __init__(self, feature: str, evidence: list[tuple[int, str]], functions: list[int], parent=None):
        super().__init__(feature, parent)
        self.feature = feature
        self.evidence = evidence
        self.functions = functions

        # setup children
        self.add_child(FeatureEvidenceCollectionItem(evidence))
        self.add_child(FeatureFunctionsCollectionItem(functions))

    def __repr__(self):
        return f"FeatureItem(feature={self.feature})"


class FeatureEvidenceCollectionItem(InsightsTreeItem):
    def __init__(self, evidence: list[tuple[int, str]], parent=None):
        super().__init__(f"Data Evidence ({len(evidence)})", parent)
        self.evidence = evidence
        # setup children
        for md_addr, md_str in evidence:
            self.add_child(FeatureEvidenceItem(md_addr, md_str))


class FeatureEvidenceItem(AddressItem):
    def __init__(self, md_addr: int, md_str: str, parent=None):
        super().__init__(f"String @ {hex(md_addr)}", md_addr, parent)
        self.data = md_str


class FeatureFunctionsCollectionItem(InsightsTreeItem):
    def __init__(self, functions: list[int], parent=None):
        super().__init__(f"Related Functions ({len(functions)})", parent)
        self.functions = functions
        # setup children
        for func_addr in functions:
            self.add_child(AddressItem(f"Function: {hex(func_addr)}", func_addr))


class InsightsTreeModel(QAbstractItemModel):
    """
    Tree model for the insights view with Item and Count columns.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.root_item = InsightsTreeItem("Root")

    def set_insights(self, insights: dict[str, list[dict[str, Any]]]) -> None:
        self.clear_insights()
        self.beginResetModel()
        for category, items in insights.items():
            match category:
                case "Switches":
                    # - description
                    # - func_addr
                    # - func_name
                    # - ref_at
                    category_item = InsightsTreeItem(category)
                    for item in items:
                        item_item = SwitchItem(
                            item["description"], item["func_addr"], item["func_name"], item["ref_at"]
                        )
                        category_item.add_child(item_item)
                case "Sockets":
                    continue
                case "Features":
                    # - feature
                    # - evidence
                    # - functions
                    category_item = InsightsTreeItem(category)
                    for item in items:
                        item_item = FeatureItem(item["feature"], item["evidence"], item["functions"])
                        category_item.add_child(item_item)
                case _:
                    continue
            self.root_item.add_child(category_item)
        self.endResetModel()

    def clear_insights(self) -> None:
        self.beginResetModel()
        self.root_item = InsightsTreeItem("Root", 0)
        self.endResetModel()

    def columnCount(self, parent=None):
        """Return the number of columns."""
        return 2  # Item and Description

    def rowCount(self, parent=None):
        """Return the number of rows under the given parent."""
        if parent.column() > 0:
            return 0

        if parent is None:
            parent = QModelIndex()
        parent_item = parent.internalPointer() if parent.isValid() else self.root_item

        return parent_item.child_count()

    def index(self, row, column, parent=None):
        """Create an index for the given row, column, and parent."""
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if parent is None:
            parent = QModelIndex()
        parent_item = parent.internalPointer() if parent.isValid() else self.root_item

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
                return item.data
        elif role == Qt.FontRole and column == 0 and item.child_count() > 0:
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
                return "Description"
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

        # Enable context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    def _show_context_menu(self, position):
        """Show the context menu at the given position."""
        menu = QMenu(self)

        # Collapse all action
        collapse_action = QAction("Collapse All", self)
        collapse_action.triggered.connect(self._collapse_all)
        menu.addAction(collapse_action)

        # Expand all action
        expand_action = QAction("Expand All", self)
        expand_action.triggered.connect(self._expand_all)
        menu.addAction(expand_action)

        # separator
        menu.addSeparator()

        # Copy current item action
        copy_action = QAction("&Copy", self)
        copy_action.triggered.connect(self._copy_current_item)
        menu.addAction(copy_action)

        # Show the menu
        menu.exec(self.mapToGlobal(position))

    def _collapse_all(self):
        """Collapse all items in the tree."""
        self.collapseAll()

    def _expand_all(self):
        """Expand all items in the tree."""
        self.expandAll()

    def _copy_current_item(self):
        """Copy the current selected item to clipboard."""
        current_index = self.currentIndex()
        if not current_index.isValid():
            return

        item = current_index.internalPointer()
        if item is None:
            return

        # Get the item text from the first column
        item_text = self.model.data(current_index, Qt.DisplayRole)
        if item_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(str(item_text))


class InsightsView(BaseView):
    def __init__(self, workspace, default_docking_position, instance):
        super().__init__("insights", workspace, default_docking_position)

        self.instance = instance
        self.base_caption = "Insights"
        self.tree = None

        self._init_widgets()

    def reload(self):
        if self.workspace.main_instance.project.am_none:
            return
        self.tree.model.set_insights(self.workspace.main_instance.kb.insights.insights)

    def sizeHint(self):
        return QSize(400, 800)

    #
    # Event handlers
    #

    def _on_make_insights_clicked(self):
        if self.workspace.main_instance.project.am_none:
            return
        self.workspace.job_manager.add_job(
            InsightsJob(
                self.workspace.main_instance,
                on_finish=self._on_insights_collected,
            )
        )

    def _on_insights_collected(self, *args, **kwargs):
        if self.tree is None:
            return
        self.reload()

    def _on_clear_clicked(self):
        if self.tree is None:
            return
        self.tree.model.clear_insights()

    def _on_tree_double_clicked(self, index: QModelIndex):
        if self.tree is None:
            return
        item = index.internalPointer()
        if item is None:
            return
        if isinstance(item, AddressItem):
            self.workspace.jump_to(item.addr)

    #
    # Private methods
    #

    def _init_widgets(self):
        layout = QVBoxLayout()

        # buttons
        buttons_layout = QHBoxLayout()
        make_insights_btn = QPushButton("Make Insights")
        make_insights_btn.clicked.connect(self._on_make_insights_clicked)
        buttons_layout.addWidget(make_insights_btn)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._on_clear_clicked)
        buttons_layout.addWidget(clear_btn)

        # tree
        self.tree = QInsightsTreeView()
        # make tree view columns auto resize
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tree.doubleClicked.connect(self._on_tree_double_clicked)
        layout.addLayout(buttons_layout)
        layout.addWidget(self.tree)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)
