from __future__ import annotations

from angr.knowledge_plugins.cfg import MemoryDataSort
from PySide6.QtGui import QAction, QStandardItem, QStandardItemModel, Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QToolButton,
    QTreeView,
    QVBoxLayout,
)

# from angrmanagement.ui.icons import icon
from qtawesome import icon

from angrmanagement.config import Conf
from angrmanagement.logic import GlobalInfo

from .view import InstanceView


def get_instance():
    workspace = GlobalInfo.main_window.workspace
    if workspace:
        instance = workspace.main_instance
        return instance
    return None


def get_project():
    instance = get_instance()
    if instance:
        project = instance.project
        if project is not None and not project.am_none:
            return project.am_obj
    return None


class ExplorerTreeModel(QStandardItemModel):

    Headers = ["Function"]

    def hasChildren(self, index):
        item: ExplorerTreeItem | None = self.itemFromIndex(index)
        if isinstance(item, ExplorerTreeItem):
            return item.expandable
        return super().hasChildren(index)

    def headerData(self, section, orientation, role):  # pylint:disable=unused-argument
        if role != Qt.DisplayRole:
            return None
        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def refresh(self):
        pass


class ExplorerTreeItem(QStandardItem):

    expandable: bool = False

    def __init__(self, title, icon=None):
        super().__init__(*((icon, title) if icon else (title,)))
        self.setEditable(False)

    def expand(self):
        pass

    def collapse(self):
        while self.rowCount() > 0:
            self.removeRow(0)

    def double_clicked(self):
        pass


class ProjectListItem(ExplorerTreeItem):

    expandable = True

    def __init__(self):
        super().__init__("Project")

    def expand(self):
        self.appendRows(
            [
                LoaderListItem(),
                TypesListItem(),
                DataListItem(),
                FunctionsListItem(),
            ]
        )


class LoaderListItem(ExplorerTreeItem):

    expandable = True

    def __init__(self):
        super().__init__("Loader", icon("mdi.cube-outline"))

    def expand(self):
        project = get_project()
        if project:
            for obj in project.loader.all_objects:
                self.appendRow(LoaderObjectItem(obj))


class LoaderObjectItem(ExplorerTreeItem):

    def __init__(self, obj):
        self.obj = obj
        super().__init__(str(self.obj), icon("mdi.cube-outline", color=self._get_color()))

    def _get_color(self):
        if self.obj is self.obj.loader.main_object:
            return Qt.green
        match self.obj.binary:
            case "cle##externs":
                return Qt.red
            case "cle##kernel":
                return Qt.yellow
            case "cle##tls":
                return Qt.magenta
            case _:
                return Conf.function_table_color

    def expand(self):
        for sec in self.obj.sections:
            self.appendRow(LoaderSectionItem(sec))

    @property
    def expandable(self):
        return len(self.obj.sections) > 0


class LoaderSectionItem(ExplorerTreeItem):

    def __init__(self, section):
        self.section = section
        super().__init__(str(self.section), icon("mdi.format-section", color=self._get_color()))

    def _get_color(self):
        return Conf.function_table_color


class DataListItem(ExplorerTreeItem):

    expandable = True

    def __init__(self):
        super().__init__("Data", icon("mdi.data-matrix"))

    def expand(self):
        instance = get_instance()
        if instance and not instance.cfg.am_none:
            for item in sorted(instance.cfg.memory_data.values(), key=lambda i: i.addr):
                self.appendRow(DatumItem(item))


class DatumItem(ExplorerTreeItem):

    def __init__(self, item):
        self.item = item
        project = get_project()
        label = ""
        if project and item.addr in project.kb.labels:
            label = project.kb.labels[item.addr] + ": "
        super().__init__(label + str(item), icon(self._get_icon(), color=self._get_color()))

    def _get_icon(self):
        match self.item.sort:
            case MemoryDataSort.String | MemoryDataSort.UnicodeString:
                return "mdi.code-string"
            case MemoryDataSort.PointerArray | MemoryDataSort.CodeReference:
                return "mdi6.asterisk"
            case MemoryDataSort.Integer | MemoryDataSort.FloatingPoint:
                return "mdi6.pound-box"
            case _:
                return "mdi.data-matrix"

    def _get_color(self):
        match self.item.sort:
            # case MemoryDataSort.Unspecified:
            #     return
            # case MemoryDataSort.Unknown:
            #     return
            case MemoryDataSort.Integer:
                return Conf.feature_map_data_color
            case MemoryDataSort.PointerArray:
                return Conf.feature_map_data_color
            case MemoryDataSort.String:
                return Conf.feature_map_string_color
            case MemoryDataSort.UnicodeString:
                return Conf.feature_map_string_color
            # case MemoryDataSort.SegmentBoundary:
            #     return
            case MemoryDataSort.CodeReference:
                return Conf.function_table_plt_color
            case MemoryDataSort.GOTPLTEntry:
                return Conf.function_table_plt_color
            case MemoryDataSort.ELFHeader:
                return Conf.feature_map_data_color
            case MemoryDataSort.FloatingPoint:
                return Conf.feature_map_data_color
            case _:
                return Conf.feature_map_unknown_color

    def double_clicked(self):
        GlobalInfo.main_window.workspace.jump_to(self.item.addr)


class FunctionsListItem(ExplorerTreeItem):

    expandable = True

    def __init__(self):
        super().__init__("Functions", icon("mdi.function"))

    def expand(self):
        project = get_project()
        if project:
            for func in project.kb.functions.values():
                self.appendRow(FunctionItem(func))


class FunctionItem(ExplorerTreeItem):

    def __init__(self, function):
        self.function = function
        super().__init__(function.name, icon("mdi.function", color=self._get_color()))

    def _get_color(self):
        func = self.function
        if func.is_syscall:
            return Conf.function_table_syscall_color
        elif func.is_plt:
            return Conf.function_table_plt_color
        elif func.is_simprocedure:
            return Conf.function_table_simprocedure_color
        elif func.alignment:
            return Conf.function_table_alignment_color
        else:
            return Conf.function_table_color

    def double_clicked(self):
        GlobalInfo.main_window.workspace.on_function_selected(func=self.function)


class TypesListItem(ExplorerTreeItem):

    expandable = True

    def __init__(self):
        super().__init__("Types", icon("msc.symbol-class"))

    def expand(self):
        project = get_project()
        if project:
            for type_ in project.kb.types.iter_own():
                self.appendRow(TypeItem(type_))


class TypeItem(ExplorerTreeItem):

    def __init__(self, type_):
        self.type = type_
        super().__init__(str(self.type), icon("msc.symbol-class"))

    def double_clicked(self):
        # GlobalInfo.main_window.workspace.on_type_selected(func=self.type)
        pass


class ExplorerView(InstanceView):
    """
    View displaying functions in the project.
    """

    def __init__(self, *args, **kwargs):
        super().__init__("explorer", *args, **kwargs)

        self.base_caption = "Explorer"

        self.instance.cfg.am_subscribe(self.reload)

        self._init_widgets()

        self.width_hint = 375
        self.height_hint = 0
        self.updateGeometry()

        self.function_count = None

        self.reload()

    #
    # Public methods
    #

    def refresh(self):
        self._model.refresh()

    def reload(self):

        self._tree.collapse(self._model.index(0, 0))
        self._tree.expand(self._model.index(0, 0))
        for i in range(self.project_item.rowCount()):
            self._tree.expand(self.project_item.child(i).index())

        # if not self.instance.cfg.am_none:
        #     self._function_table.function_manager = self.instance.kb.functions

    def subscribe_func_select(self, callback):
        """
        Appends the provided function to the list of callbacks to be called when a function is selected in the
        functions table. The callback's only parameter is the `angr.knowledge_plugins.functions.function.Function`
        :param callback: The callback function to call, which must accept **kwargs
        """
        # self._function_table.subscribe_func_select(callback)

    #
    # Private methods
    #

    def _init_widgets(self):
        vlayout = QVBoxLayout()
        vlayout.setSpacing(0)
        vlayout.setContentsMargins(0, 0, 0, 0)

        hlayout = QHBoxLayout()
        hlayout.setSpacing(3)

        tree_options_btn = QToolButton(self)
        tree_options_act = QAction(icon("msc.symbol-class"), "Explorer Options")
        tree_options_btn.setDefaultAction(tree_options_act)
        hlayout.addWidget(tree_options_btn)

        search_box = QLineEdit()
        search_box.setClearButtonEnabled(True)
        search_box.addAction(icon("fa5s.search", color=Conf.palette_placeholdertext), QLineEdit.LeadingPosition)
        search_box.setPlaceholderText("Filter by name...")
        hlayout.addWidget(search_box)

        filter_options_btn = QToolButton(self)
        filter_options_act = QAction(icon("mdi.filter"), "Filter Options")
        filter_options_btn.setDefaultAction(filter_options_act)
        hlayout.addWidget(filter_options_btn)

        hlayout.setContentsMargins(3, 3, 3, 3)
        vlayout.addLayout(hlayout)
        self._tree = QTreeView(self)
        self._model = ExplorerTreeModel(self._tree)
        self._tree.setModel(self._model)
        # self._tree.setFont(QFont(Conf.disasm_font))
        header = self._tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setVisible(False)
        self._tree.expanded.connect(self._on_item_expanded)
        self._tree.collapsed.connect(self._on_item_collapsed)
        self._tree.doubleClicked.connect(self._on_item_double_clicked)
        vlayout.addWidget(self._tree)
        self.setLayout(vlayout)

        # self._tree.setStyleSheet("QTreeView { alternate-background-color: yellow;background-color: red; }")
        self._tree.setAlternatingRowColors(True)
        self.project_item = ProjectListItem()
        self._model.appendRow(self.project_item)

    def _on_item_double_clicked(self, index):
        """
        Handle item double-click event.
        """
        item = self._model.itemFromIndex(index)
        item.double_clicked()

    def _on_item_expanded(self, index):
        """
        Handle item expansion.
        """
        item = self._model.itemFromIndex(index)
        item.expand()

    def _on_item_collapsed(self, index):
        """
        Handle item collapse.
        """
        item = self._model.itemFromIndex(index)
        item.collapse()
